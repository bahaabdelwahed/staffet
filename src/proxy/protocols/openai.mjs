// OpenAI Chat Completions wire format  ⇄  canonical message.
//
// Canonical message (shared by all protocols):
//   { id, model, stop: 'end'|'tool'|'length'|'filter'|'other', usage: {input, output},
//     blocks: [ {type:'text', text} | {type:'tool', id, name, args, argsRaw?, dirty?} | {type:'opaque', raw} ] }
import { randomBytes } from 'node:crypto';
import { BRAND } from '../../brand.mjs';
import { safeJsonParse, clone } from '../../util.mjs';
import { sseData, chunkText } from '../sse.mjs';

const STOP_IN = { stop: 'end', tool_calls: 'tool', function_call: 'tool', length: 'length', content_filter: 'filter' };

function partsText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.filter((p) => p && (p.type === 'text' || p.type === 'input_text') && typeof p.text === 'string').map((p) => p.text).join('\n');
  return '';
}

/** Visit every text segment of a message `content` (string or parts array). */
function walkContent(msg, scope, extra, visitor) {
  if (typeof msg.content === 'string') {
    visitor.text({ scope, ...extra, get: () => msg.content, set: (v) => { msg.content = v; } });
  } else if (Array.isArray(msg.content)) {
    for (const part of msg.content) {
      if (part && typeof part.text === 'string' && (part.type === 'text' || part.type === 'input_text')) {
        visitor.text({ scope, ...extra, get: () => part.text, set: (v) => { part.text = v; } });
      }
    }
  }
}

export const openai = {
  name: 'openai',
  chatPath: '/chat/completions',

  model: (body) => body.model,
  setModel: (body, m) => { body.model = m; },
  isStream: (body) => body.stream === true,
  wantsUsage: (body) => body.stream_options?.include_usage === true,

  validate(body) {
    if (!body || typeof body !== 'object' || !Array.isArray(body.messages)) return 'request body must be a JSON object with a "messages" array';
    if (body.n != null && body.n > 1) return `"n" > 1 is not supported by the ${BRAND.name} firewall (every choice must be inspected)`;
    return null;
  },

  systemText(body) {
    return body.messages.filter((m) => m.role === 'system' || m.role === 'developer').map((m) => partsText(m.content)).join('\n');
  },

  userTexts(body) {
    const users = body.messages.filter((m) => m.role === 'user').map((m) => partsText(m.content)).filter(Boolean);
    return { first: users[0] || '', last: users[users.length - 1] || '' };
  },

  toolDefs(body) {
    const out = [];
    for (const t of body.tools || []) {
      if (t?.type === 'function' && t.function?.name) out.push({ name: t.function.name, schema: t.function.parameters });
      else if (t?.name) out.push({ name: t.name, schema: t.parameters || t.input_schema });
    }
    for (const f of body.functions || []) if (f?.name) out.push({ name: f.name, schema: f.parameters });
    return out;
  },

  /** id → {name, args} for every tool call already in the conversation. */
  historyToolCalls(body) {
    const map = new Map();
    for (const m of body.messages) {
      if (m.role !== 'assistant') continue;
      for (const tc of m.tool_calls || []) {
        if (tc?.id) map.set(tc.id, { name: tc.function?.name, args: safeJsonParse(tc.function?.arguments, {}) });
      }
    }
    return map;
  },

  walkRequest(body, visitor) {
    for (const m of body.messages) {
      if (!m || typeof m !== 'object') continue;
      if (m.role === 'system' || m.role === 'developer') walkContent(m, 'system', {}, visitor);
      else if (m.role === 'user') walkContent(m, 'user', {}, visitor);
      else if (m.role === 'tool') walkContent(m, 'tool_output', { toolCallId: m.tool_call_id }, visitor);
      else if (m.role === 'function') walkContent(m, 'tool_output', { toolName: m.name }, visitor);
    }
  },

  // ───────────── response ─────────────

  /** Fold a chat.completion.chunk stream into a chat.completion object. */
  async accumulate(events) {
    const out = { id: null, object: 'chat.completion', created: Math.floor(Date.now() / 1000), model: null, choices: [], usage: undefined };
    const msg = { role: 'assistant', content: null };
    let finish = null;
    const calls = [];
    for await (const ev of events) {
      if (!ev.data || ev.data === '[DONE]') continue;
      const chunk = safeJsonParse(ev.data);
      if (!chunk) continue;
      if (chunk.error) {
        const e = new Error(chunk.error.message || 'upstream stream error');
        e.upstream = chunk;
        throw e;
      }
      out.id ??= chunk.id;
      out.model ??= chunk.model;
      if (chunk.created) out.created = chunk.created;
      if (chunk.system_fingerprint) out.system_fingerprint = chunk.system_fingerprint;
      if (chunk.service_tier) out.service_tier = chunk.service_tier;
      if (chunk.usage) out.usage = chunk.usage;
      const choice = chunk.choices?.[0];
      if (!choice) continue;
      const d = choice.delta || {};
      if (typeof d.content === 'string') msg.content = (msg.content || '') + d.content;
      if (typeof d.refusal === 'string') msg.refusal = (msg.refusal || '') + d.refusal;
      for (const k of ['reasoning_content', 'reasoning']) {
        if (typeof d[k] === 'string') msg[k] = (msg[k] || '') + d[k];
      }
      for (const tc of d.tool_calls || []) {
        const i = tc.index ?? calls.length;
        const cur = (calls[i] ??= { id: null, type: 'function', function: { name: '', arguments: '' } });
        if (tc.id) cur.id = tc.id;
        if (tc.type) cur.type = tc.type;
        if (tc.function?.name && cur.function.name !== tc.function.name) cur.function.name += tc.function.name;
        if (typeof tc.function?.arguments === 'string') cur.function.arguments += tc.function.arguments;
      }
      if (choice.finish_reason) finish = choice.finish_reason;
    }
    const tool_calls = calls.filter(Boolean);
    if (tool_calls.length) msg.tool_calls = tool_calls;
    out.choices = [{ index: 0, message: msg, finish_reason: finish || (tool_calls.length ? 'tool_calls' : 'stop'), logprobs: null }];
    return out;
  },

  decode(wire) {
    const choice = wire.choices?.[0] || {};
    const m = choice.message || {};
    const blocks = [];
    const text = typeof m.content === 'string' ? m.content : partsText(m.content);
    if (text) blocks.push({ type: 'text', text });
    for (const tc of m.tool_calls || []) {
      const raw = tc.function?.arguments ?? '';
      const parsed = safeJsonParse(raw);
      blocks.push({ type: 'tool', id: tc.id, name: tc.function?.name || '', args: parsed ?? {}, argsRaw: raw, parseError: parsed === undefined && raw !== '' });
    }
    return {
      id: wire.id, model: wire.model, blocks,
      stop: STOP_IN[choice.finish_reason] || (choice.finish_reason ? 'other' : 'end'),
      usage: { input: wire.usage?.prompt_tokens || 0, output: wire.usage?.completion_tokens || 0 },
    };
  },

  /** Write a (possibly modified) canonical message back into a copy of the wire response. */
  encode(wire, message) {
    const out = clone(wire);
    const choice = (out.choices[0] ||= { index: 0, message: { role: 'assistant' } });
    const m = (choice.message ||= { role: 'assistant' });
    const text = message.blocks.filter((b) => b.type === 'text').map((b) => b.text).join('');
    const tools = message.blocks.filter((b) => b.type === 'tool');
    m.content = text || (tools.length ? null : '');
    if (tools.length) {
      m.tool_calls = tools.map((b) => ({ id: b.id, type: 'function', function: { name: b.name, arguments: !b.dirty && typeof b.argsRaw === 'string' ? b.argsRaw : JSON.stringify(b.args ?? {}) } }));
      choice.finish_reason = 'tool_calls';
    } else {
      delete m.tool_calls;
      if (choice.finish_reason === 'tool_calls' || choice.finish_reason === 'function_call') choice.finish_reason = 'stop';
    }
    return out;
  },

  newToolId: (kind = 'call') => `call_${BRAND.slug}_${kind}_${randomBytes(6).toString('hex')}`,

  /**
   * Conversation continuation used by the firewall's own fix loop:
   * the rejected assistant turn + the feedback (as tool results and/or a user message).
   */
  followup(body, wire, { toolResults, userText }) {
    const next = { ...body, messages: [...body.messages] };
    const m = wire.choices[0].message;
    const assistant = { role: 'assistant', content: m.content ?? null };
    if (m.tool_calls?.length) assistant.tool_calls = m.tool_calls;
    if (typeof m.reasoning_content === 'string') assistant.reasoning_content = m.reasoning_content;
    if (!assistant.tool_calls && assistant.content == null) assistant.content = '';
    next.messages.push(assistant);
    for (const tc of m.tool_calls || []) {
      next.messages.push({ role: 'tool', tool_call_id: tc.id, content: toolResults?.get(tc.id) ?? `[${BRAND.name} firewall] Not executed.` });
    }
    if (userText) next.messages.push({ role: 'user', content: userText });
    return next;
  },

  // ───────────── emit ─────────────

  errorBody(status, message, type = 'invalid_request_error', code = null) {
    return { error: { message, type, param: null, code: code || `${BRAND.slug}_${status}` } };
  },

  keepAlive: () => `: ${BRAND.slug} inspecting\n\n`,

  streamError: (message) => sseData({ error: { message, type: 'server_error', code: `${BRAND.slug}_error` } }),

  /** Re-stream a complete chat.completion as chat.completion.chunk events. */
  *streamEvents(wire, { includeUsage = false } = {}) {
    const base = { id: wire.id || `chatcmpl-${BRAND.slug}`, object: 'chat.completion.chunk', created: wire.created || Math.floor(Date.now() / 1000), model: wire.model };
    if (wire.system_fingerprint) base.system_fingerprint = wire.system_fingerprint;
    const choice = wire.choices?.[0] || { message: {}, finish_reason: 'stop' };
    const m = choice.message || {};
    const frame = (delta, finish_reason = null) => sseData({ ...base, choices: [{ index: 0, delta, finish_reason, logprobs: null }], ...(includeUsage ? { usage: null } : {}) });

    yield frame({ role: 'assistant', content: '' });
    for (const k of ['reasoning_content', 'reasoning']) {
      if (typeof m[k] === 'string' && m[k]) for (const piece of chunkText(m[k], 400)) yield frame({ [k]: piece });
    }
    if (typeof m.content === 'string' && m.content) for (const piece of chunkText(m.content)) yield frame({ content: piece });
    if (typeof m.refusal === 'string' && m.refusal) yield frame({ refusal: m.refusal });
    // name first, then arguments — the shape every OpenAI-compatible client expects
    for (let index = 0; index < (m.tool_calls || []).length; index++) {
      const tc = m.tool_calls[index];
      yield frame({ tool_calls: [{ index, id: tc.id, type: 'function', function: { name: tc.function.name, arguments: '' } }] });
      for (const piece of chunkText(tc.function.arguments || '', 400)) yield frame({ tool_calls: [{ index, function: { arguments: piece } }] });
    }
    yield frame({}, choice.finish_reason || 'stop');
    if (includeUsage && wire.usage) yield sseData({ ...base, choices: [], usage: wire.usage });
    yield sseData('[DONE]');
  },
};
