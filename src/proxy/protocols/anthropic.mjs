// Anthropic Messages wire format  ⇄  canonical message (see openai.mjs for the canonical shape).
import { randomBytes } from 'node:crypto';
import { BRAND } from '../../brand.mjs';
import { safeJsonParse, clone } from '../../util.mjs';
import { sseEvent, chunkText } from '../sse.mjs';

const STOP_IN = { end_turn: 'end', stop_sequence: 'end', tool_use: 'tool', max_tokens: 'length', refusal: 'filter', pause_turn: 'other' };

function blocksText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.filter((b) => b?.type === 'text' && typeof b.text === 'string').map((b) => b.text).join('\n');
  return '';
}

function isBinaryDoc(b) {
  return b?.type === 'document' && b.source?.type === 'base64' && typeof b.source.data === 'string';
}

export const anthropic = {
  name: 'anthropic',
  chatPath: '/messages',

  model: (body) => body.model,
  setModel: (body, m) => { body.model = m; },
  isStream: (body) => body.stream === true,
  wantsUsage: () => true,

  validate(body) {
    if (!body || typeof body !== 'object' || !Array.isArray(body.messages)) return 'request body must be a JSON object with a "messages" array';
    return null;
  },

  systemText: (body) => blocksText(body.system),

  userTexts(body) {
    const users = body.messages.filter((m) => m.role === 'user').map((m) => blocksText(m.content)).filter(Boolean);
    return { first: users[0] || '', last: users[users.length - 1] || '' };
  },

  toolDefs(body) {
    return (body.tools || []).filter((t) => t?.name).map((t) => ({ name: t.name, schema: t.input_schema }));
  },

  historyToolCalls(body) {
    const map = new Map();
    for (const m of body.messages) {
      if (m.role !== 'assistant' || !Array.isArray(m.content)) continue;
      for (const b of m.content) if (b?.type === 'tool_use' && b.id) map.set(b.id, { name: b.name, args: b.input || {} });
    }
    return map;
  },

  walkRequest(body, visitor) {
    if (typeof body.system === 'string') {
      visitor.text({ scope: 'system', get: () => body.system, set: (v) => { body.system = v; } });
    } else if (Array.isArray(body.system)) {
      for (const b of body.system) if (b?.type === 'text') visitor.text({ scope: 'system', get: () => b.text, set: (v) => { b.text = v; } });
    }
    for (const m of body.messages) {
      if (!m || m.role !== 'user') continue;
      if (typeof m.content === 'string') {
        visitor.text({ scope: 'user', get: () => m.content, set: (v) => { m.content = v; } });
        continue;
      }
      if (!Array.isArray(m.content)) continue;
      let lastToolUseId = null;
      m.content.forEach((b, i) => {
        if (!b) return;
        if (b.type === 'text') {
          visitor.text({ scope: 'user', get: () => b.text, set: (v) => { b.text = v; } });
        } else if (b.type === 'tool_result') {
          lastToolUseId = b.tool_use_id;
          const extra = { scope: 'tool_output', toolCallId: b.tool_use_id };
          if (typeof b.content === 'string') {
            visitor.text({ ...extra, get: () => b.content, set: (v) => { b.content = v; } });
          } else if (Array.isArray(b.content)) {
            b.content.forEach((c, j) => {
              if (c?.type === 'text') visitor.text({ ...extra, get: () => c.text, set: (v) => { c.text = v; } });
              else if (isBinaryDoc(c) && visitor.document) {
                visitor.document({ toolCallId: b.tool_use_id, mediaType: c.source.media_type, title: c.title, data: () => Buffer.from(c.source.data, 'base64'), replace: (text) => { b.content[j] = { type: 'text', text }; } });
              }
            });
          }
        } else if (isBinaryDoc(b) && visitor.document) {
          // a document attached next to a tool_result belongs to that tool call (e.g. a PDF returned by a Read tool)
          visitor.document({ toolCallId: lastToolUseId, mediaType: b.source.media_type, title: b.title, data: () => Buffer.from(b.source.data, 'base64'), replace: (text) => { m.content[i] = { type: 'text', text }; } });
        }
      });
    }
  },

  // ───────────── response ─────────────

  /** Fold a Messages event stream into a complete message object. */
  async accumulate(events) {
    let message = null;
    const json = new Map();
    for await (const ev of events) {
      const d = safeJsonParse(ev.data);
      if (!d) continue;
      const type = d.type || ev.event;
      if (type === 'error') {
        const e = new Error(d.error?.message || 'upstream stream error');
        e.upstream = d;
        throw e;
      }
      if (type === 'message_start') {
        message = { ...d.message, content: [...(d.message.content || [])], usage: { ...(d.message.usage || {}) } };
      } else if (!message) {
        continue;
      } else if (type === 'content_block_start') {
        message.content[d.index] = clone(d.content_block);
        if (d.content_block.type === 'tool_use' || d.content_block.type === 'server_tool_use') json.set(d.index, '');
      } else if (type === 'content_block_delta') {
        const b = message.content[d.index];
        const delta = d.delta || {};
        if (!b) continue;
        if (delta.type === 'text_delta') b.text = (b.text || '') + delta.text;
        else if (delta.type === 'input_json_delta') json.set(d.index, (json.get(d.index) || '') + (delta.partial_json || ''));
        else if (delta.type === 'thinking_delta') b.thinking = (b.thinking || '') + delta.thinking;
        else if (delta.type === 'signature_delta') b.signature = (b.signature || '') + delta.signature;
        else if (delta.type === 'citations_delta') (b.citations ||= []).push(delta.citation);
      } else if (type === 'content_block_stop') {
        if (json.has(d.index)) {
          const raw = json.get(d.index);
          const b = message.content[d.index];
          const parsed = raw ? safeJsonParse(raw) : {};
          if (parsed === undefined) { b.input = {}; b._parseError = true; } else b.input = parsed;
          json.delete(d.index);
        }
      } else if (type === 'message_delta') {
        Object.assign(message, d.delta || {});
        if (d.usage) Object.assign(message.usage, d.usage);
      }
    }
    if (!message) throw new Error('upstream stream ended before message_start');
    message.content = message.content.filter(Boolean);
    return message;
  },

  decode(wire) {
    const blocks = [];
    for (const b of wire.content || []) {
      if (b.type === 'text') blocks.push({ type: 'text', text: b.text || '', raw: b });
      else if (b.type === 'tool_use') blocks.push({ type: 'tool', id: b.id, name: b.name, args: b.input || {}, parseError: Boolean(b._parseError), raw: b });
      else blocks.push({ type: 'opaque', raw: b });
    }
    return {
      id: wire.id, model: wire.model, blocks,
      stop: STOP_IN[wire.stop_reason] || (wire.stop_reason ? 'other' : 'end'),
      usage: { input: (wire.usage?.input_tokens || 0) + (wire.usage?.cache_read_input_tokens || 0) + (wire.usage?.cache_creation_input_tokens || 0), output: wire.usage?.output_tokens || 0 },
    };
  },

  encode(wire, message) {
    const out = clone(wire);
    out.content = [];
    for (const b of message.blocks) {
      if (b.type === 'text') {
        if (!b.text) continue;                                   // empty text blocks are rejected when replayed
        const same = b.raw && b.raw.text === b.text;
        out.content.push(same ? clone(b.raw) : { type: 'text', text: b.text });
      } else if (b.type === 'tool') {
        const blk = { type: 'tool_use', id: b.id, name: b.name, input: b.args ?? {} };
        out.content.push(blk);
      } else out.content.push(clone(b.raw));
    }
    for (const c of out.content) delete c._parseError;
    const hasTool = out.content.some((c) => c.type === 'tool_use');
    if (hasTool) out.stop_reason = 'tool_use';
    else if (out.stop_reason === 'tool_use') out.stop_reason = 'end_turn';
    if (!out.content.length) out.content.push({ type: 'text', text: ' ' });
    return out;
  },

  newToolId: (kind = 'call') => `toolu_${BRAND.slug}_${kind}_${randomBytes(6).toString('hex')}`,

  followup(body, wire, { toolResults, userText }) {
    const next = { ...body, messages: [...body.messages] };
    const content = (wire.content || []).map((b) => { const c = { ...b }; delete c._parseError; return c; }).filter((b) => !(b.type === 'text' && !b.text));
    next.messages.push({ role: 'assistant', content });
    const user = [];
    for (const b of content) {
      if (b.type === 'tool_use') user.push({ type: 'tool_result', tool_use_id: b.id, is_error: true, content: toolResults?.get(b.id) ?? `[${BRAND.name} firewall] Not executed.` });
    }
    if (userText) user.push({ type: 'text', text: userText });
    if (!user.length) user.push({ type: 'text', text: `[${BRAND.name} firewall] Please revise your previous answer.` });
    next.messages.push({ role: 'user', content: user });
    return next;
  },

  // ───────────── emit ─────────────

  errorBody(status, message, type = 'invalid_request_error') {
    return { type: 'error', error: { type, message } };
  },

  keepAlive: () => sseEvent('ping', { type: 'ping' }),

  streamError: (message) => sseEvent('error', { type: 'error', error: { type: 'api_error', message } }),

  /** Re-stream a complete message as Messages API events. */
  *streamEvents(wire) {
    const { content = [], stop_reason, stop_sequence = null, usage = {}, ...head } = wire;
    yield sseEvent('message_start', { type: 'message_start', message: { ...head, content: [], stop_reason: null, stop_sequence: null, usage: { ...usage, output_tokens: Math.min(usage.output_tokens || 0, 1) } } });
    for (let index = 0; index < content.length; index++) {
      const b = content[index];
      const delta = (d) => sseEvent('content_block_delta', { type: 'content_block_delta', index, delta: d });
      if (b.type === 'text') {
        const { text, citations, ...rest } = b;
        yield sseEvent('content_block_start', { type: 'content_block_start', index, content_block: { ...rest, text: '', ...(citations ? { citations: [] } : {}) } });
        for (const c of citations || []) yield delta({ type: 'citations_delta', citation: c });
        for (const piece of chunkText(text || '')) yield delta({ type: 'text_delta', text: piece });
      } else if (b.type === 'tool_use' || b.type === 'server_tool_use') {
        const { input, ...rest } = b;
        yield sseEvent('content_block_start', { type: 'content_block_start', index, content_block: { ...rest, input: {} } });
        const jsonText = JSON.stringify(input ?? {});
        for (const piece of chunkText(jsonText, 400)) yield delta({ type: 'input_json_delta', partial_json: piece });
      } else if (b.type === 'thinking') {
        const { thinking, signature, ...rest } = b;
        yield sseEvent('content_block_start', { type: 'content_block_start', index, content_block: { ...rest, thinking: '', signature: '' } });
        for (const piece of chunkText(thinking || '', 400)) yield delta({ type: 'thinking_delta', thinking: piece });
        if (signature) yield delta({ type: 'signature_delta', signature });
      } else {
        yield sseEvent('content_block_start', { type: 'content_block_start', index, content_block: b });
      }
      yield sseEvent('content_block_stop', { type: 'content_block_stop', index });
    }
    const { input_tokens, cache_creation_input_tokens, cache_read_input_tokens, ...restUsage } = usage;
    void input_tokens; void cache_creation_input_tokens; void cache_read_input_tokens;
    yield sseEvent('message_delta', { type: 'message_delta', delta: { stop_reason: stop_reason || 'end_turn', stop_sequence }, usage: { ...restUsage, output_tokens: usage.output_tokens || 0 } });
    yield sseEvent('message_stop', { type: 'message_stop' });
  },
};
