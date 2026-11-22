// A scripted stand-in for an LLM provider. Speaks both wire formats (streaming and not).
// Used by the test-suite and by `staffet demo` so the firewall can be exercised without API keys.
import http from 'node:http';

let counter = 0;
const nextId = (p) => `${p}_mock${(++counter).toString(36).padStart(6, '0')}`;

function textOf(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.filter((b) => b && b.type === 'text').map((b) => b.text).join('\n');
  return '';
}

/** Protocol-neutral view of the conversation the proxy forwarded. */
export function describeRequest(protocol, body) {
  const turns = [];
  if (protocol === 'openai') {
    for (const m of body.messages || []) {
      if (m.role === 'tool') turns.push({ role: 'tool', id: m.tool_call_id, text: textOf(m.content) });
      else turns.push({ role: m.role, text: textOf(m.content), toolCalls: (m.tool_calls || []).map((t) => ({ id: t.id, name: t.function?.name, args: safeParse(t.function?.arguments) })) });
    }
  } else {
    const sys = textOf(body.system);
    if (sys) turns.push({ role: 'system', text: sys });
    for (const m of body.messages || []) {
      const blocks = typeof m.content === 'string' ? [{ type: 'text', text: m.content }] : m.content || [];
      for (const b of blocks) if (b.type === 'tool_result') turns.push({ role: 'tool', id: b.tool_use_id, text: textOf(b.content) });
      const text = blocks.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
      const toolCalls = blocks.filter((b) => b.type === 'tool_use').map((b) => ({ id: b.id, name: b.name, args: b.input }));
      if (text || toolCalls.length) turns.push({ role: m.role, text, toolCalls });
    }
  }
  const users = turns.filter((t) => t.role === 'user' && t.text);
  const last = turns[turns.length - 1];
  const trailingTools = [];
  for (let i = turns.length - 1; i >= 0 && (turns[i].role === 'tool' || (turns[i].role === 'user' && i === turns.length - 1)); i--) if (turns[i].role === 'tool') trailingTools.unshift(turns[i]);
  const tail = [...trailingTools.map((t) => t.text), last?.role === 'user' ? last.text : ''].join('\n');
  return {
    protocol, body, turns,
    task: users[0]?.text || '',
    lastUser: users[users.length - 1]?.text || '',
    toolResults: trailingTools,
    feedback: /firewall[^\n]*(?:BLOCKED|automated code review|withheld)|\bfirewall\] (?:BLOCKED|This tool call was NOT executed)/i.test(tail) ? tail : null,
    tools: protocol === 'openai' ? (body.tools || []).map((t) => t.function?.name) : (body.tools || []).map((t) => t.name),
    all: JSON.stringify(body),
  };
}

function safeParse(s) { try { return JSON.parse(s); } catch { return {}; } }

const sse = (res, data, event) => res.write(`${event ? `event: ${event}\n` : ''}data: ${typeof data === 'string' ? data : JSON.stringify(data)}\n\n`);
const pieces = (s, n) => { const out = []; for (let i = 0; i < s.length; i += n) out.push(s.slice(i, i + n)); return out; };

function sendOpenAI(res, body, spec) {
  const id = nextId('chatcmpl');
  const created = Math.floor(Date.now() / 1000);
  const calls = (spec.toolCalls || []).map((t) => ({ id: nextId('call'), type: 'function', function: { name: t.name, arguments: JSON.stringify(t.args ?? {}) } }));
  const usage = { prompt_tokens: Math.ceil(JSON.stringify(body.messages).length / 4), completion_tokens: Math.ceil(((spec.text || '').length + JSON.stringify(calls).length) / 4) };
  usage.total_tokens = usage.prompt_tokens + usage.completion_tokens;
  const finish = calls.length ? 'tool_calls' : 'stop';
  if (!body.stream) {
    const message = { role: 'assistant', content: spec.text || null };
    if (calls.length) message.tool_calls = calls;
    res.writeHead(200, { 'content-type': 'application/json', 'x-request-id': id });
    res.end(JSON.stringify({ id, object: 'chat.completion', created, model: body.model, choices: [{ index: 0, message, finish_reason: finish, logprobs: null }], usage }));
    return;
  }
  res.writeHead(200, { 'content-type': 'text/event-stream', 'x-request-id': id });
  const chunk = (delta, finish_reason = null) => sse(res, { id, object: 'chat.completion.chunk', created, model: body.model, choices: [{ index: 0, delta, finish_reason }] });
  chunk({ role: 'assistant', content: '' });
  for (const p of pieces(spec.text || '', 17)) chunk({ content: p });
  calls.forEach((c, index) => {
    chunk({ tool_calls: [{ index, id: c.id, type: 'function', function: { name: c.function.name, arguments: '' } }] });
    for (const p of pieces(c.function.arguments, 23)) chunk({ tool_calls: [{ index, function: { arguments: p } }] });
  });
  chunk({}, finish);
  if (body.stream_options?.include_usage) sse(res, { id, object: 'chat.completion.chunk', created, model: body.model, choices: [], usage });
  sse(res, '[DONE]');
  res.end();
}

function sendAnthropic(res, body, spec) {
  const id = nextId('msg');
  const content = [];
  if (spec.thinking) content.push({ type: 'thinking', thinking: spec.thinking, signature: 'mock-signature' });
  if (spec.text) content.push({ type: 'text', text: spec.text });
  for (const t of spec.toolCalls || []) content.push({ type: 'tool_use', id: nextId('toolu'), name: t.name, input: t.args ?? {} });
  const usage = { input_tokens: Math.ceil(JSON.stringify(body.messages).length / 4), output_tokens: Math.ceil(JSON.stringify(content).length / 4) };
  const stop_reason = content.some((b) => b.type === 'tool_use') ? 'tool_use' : 'end_turn';
  const head = { id, type: 'message', role: 'assistant', model: body.model };
  if (!body.stream) {
    res.writeHead(200, { 'content-type': 'application/json', 'request-id': id });
    res.end(JSON.stringify({ ...head, content, stop_reason, stop_sequence: null, usage }));
    return;
  }
  res.writeHead(200, { 'content-type': 'text/event-stream', 'request-id': id });
  sse(res, { type: 'message_start', message: { ...head, content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: usage.input_tokens, output_tokens: 1 } } }, 'message_start');
  sse(res, { type: 'ping' }, 'ping');
  content.forEach((b, index) => {
    const delta = (d) => sse(res, { type: 'content_block_delta', index, delta: d }, 'content_block_delta');
    if (b.type === 'text') {
      sse(res, { type: 'content_block_start', index, content_block: { type: 'text', text: '' } }, 'content_block_start');
      for (const p of pieces(b.text, 19)) delta({ type: 'text_delta', text: p });
    } else if (b.type === 'thinking') {
      sse(res, { type: 'content_block_start', index, content_block: { type: 'thinking', thinking: '', signature: '' } }, 'content_block_start');
      for (const p of pieces(b.thinking, 31)) delta({ type: 'thinking_delta', thinking: p });
      delta({ type: 'signature_delta', signature: b.signature });
    } else {
      sse(res, { type: 'content_block_start', index, content_block: { type: 'tool_use', id: b.id, name: b.name, input: {} } }, 'content_block_start');
      for (const p of pieces(JSON.stringify(b.input), 21)) delta({ type: 'input_json_delta', partial_json: p });
    }
    sse(res, { type: 'content_block_stop', index }, 'content_block_stop');
  });
  sse(res, { type: 'message_delta', delta: { stop_reason, stop_sequence: null }, usage: { output_tokens: usage.output_tokens } }, 'message_delta');
  sse(res, { type: 'message_stop' }, 'message_stop');
  res.end();
}

/**
 * @param {(info: object) => ({text?: string, toolCalls?: Array, thinking?: string, status?: number, error?: string}|Promise<object>)} script
 * @param {{delayMs?: number}} opts
 * @returns {Promise<{url: string, port: number, requests: Array, close: () => Promise<void>}>}
 */
export function createMockUpstream(script, opts = {}) {
  const requests = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', async () => {
      const url = new URL(req.url, 'http://x');
      const p = url.pathname.replace(/^\/v1/, '');
      if (req.method === 'GET' && p === '/models') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ object: 'list', data: [{ id: 'mock-model', object: 'model', owned_by: 'mock' }] }));
        return;
      }
      const protocol = p.startsWith('/messages') ? 'anthropic' : 'openai';
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { res.writeHead(400); res.end('{}'); return; }
      const info = describeRequest(protocol, body);
      info.headers = req.headers;
      info.path = p;
      requests.push(info);
      if (p === '/messages/count_tokens') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ input_tokens: Math.ceil(info.all.length / 4) }));
        return;
      }
      if (opts.delayMs) await new Promise((r) => setTimeout(r, opts.delayMs));
      const spec = (await script(info)) || { text: 'OK' };
      if (spec.status) {
        res.writeHead(spec.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(protocol === 'openai' ? { error: { message: spec.error || 'mock error', type: 'mock_error' } } : { type: 'error', error: { type: 'mock_error', message: spec.error || 'mock error' } }));
        return;
      }
      (protocol === 'openai' ? sendOpenAI : sendAnthropic)(res, body, spec);
    });
  });
  return new Promise((resolve) => {
    server.listen(opts.port || 0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({ url: `http://127.0.0.1:${port}/v1`, port, requests, close: () => new Promise((r) => { server.close(() => r()); server.closeAllConnections?.(); }) });
    });
  });
}
