// Test helper: a mock LLM upstream + a Staffet instance in front of it, on random ports.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadConfig } from '../../src/config.mjs';
import { createApp } from '../../src/server.mjs';
import { RuleStore } from '../../src/rules/store.mjs';
import { createMockUpstream } from '../../src/mock/upstream.mjs';
import { deepMerge } from '../../src/util.mjs';

export function tempDir(prefix = 'staffet-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function testConfig(overrides = {}, dir = tempDir()) {
  const base = { server: { host: '127.0.0.1', port: 0 }, dataDir: path.join(dir, 'data'), rulesDir: path.join(dir, 'rules'), policy: { codeScan: { engine: 'builtin' } }, logging: { console: false } };
  return loadConfig(path.join(dir, 'staffet.config.yaml'), deepMerge(base, overrides)).config;
}

export async function ruleView(overrides = {}, profile = '') {
  const config = testConfig(overrides);
  const store = new RuleStore({ config });
  await store.load();
  return { view: store.view(profile), store, config };
}

/** @param {Function} script  mock model behaviour: (info) => ({text, toolCalls}) */
export async function startStack(script, overrides = {}) {
  const mock = await createMockUpstream(script);
  const config = testConfig(deepMerge({
    upstreams: [
      { name: 'mock-openai', protocol: 'openai', baseUrl: mock.url, models: ['*'] },
      { name: 'mock-anthropic', protocol: 'anthropic', baseUrl: mock.url, models: ['*'] },
    ],
  }, overrides));
  const app = await createApp(config, { persist: false, warmup: false });
  const addr = await app.listen();
  const base = `http://127.0.0.1:${addr.port}`;
  return {
    app, mock, base, config,
    async chat(body, headers = {}) {
      const r = await fetch(`${base}/v1/chat/completions`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: 'Bearer sk-test', ...headers }, body: JSON.stringify(body) });
      return { status: r.status, headers: r.headers, json: r.headers.get('content-type')?.includes('json') ? await r.json() : null, text: r.headers.get('content-type')?.includes('event-stream') ? await r.text() : null };
    },
    async messages(body, headers = {}) {
      const r = await fetch(`${base}/v1/messages`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-api-key': 'sk-ant-test', 'anthropic-version': '2023-06-01', ...headers }, body: JSON.stringify(body) });
      return { status: r.status, headers: r.headers, json: r.headers.get('content-type')?.includes('json') ? await r.json() : null, text: r.headers.get('content-type')?.includes('event-stream') ? await r.text() : null };
    },
    async close() { await app.close(); await mock.close(); },
  };
}

/** Parse an SSE body into [{event, data(parsed)}]. */
export function parseSseText(text) {
  return text.split(/\r?\n\r?\n/).map((block) => {
    let event = null; const data = [];
    for (const line of block.split(/\r?\n/)) {
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) data.push(line.slice(5).trimStart());
    }
    if (!data.length) return null;
    const raw = data.join('\n');
    let parsed = raw;
    try { parsed = JSON.parse(raw); } catch { /* [DONE] */ }
    return { event, data: parsed };
  }).filter(Boolean);
}
