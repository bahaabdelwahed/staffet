// HTTP server: model endpoints (OpenAI + Anthropic compatible), admin API, dashboard.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { BRAND, PKG_ROOT } from './brand.mjs';
import { publicConfig, resolvePolicy } from './config.mjs';
import { RuleStore } from './rules/store.mjs';
import { EventBus } from './events/bus.mjs';
import { KeyStore } from './keys.mjs';
import { CodeScanner } from './code/engine.mjs';
import { formatFindings } from './code/report.mjs';
import { LANG_EXT, normaliseLang } from './code/extract.mjs';
import { Firewall, sendJson, ADAPTERS } from './proxy/handler.mjs';
import { Upstreams } from './proxy/upstream.mjs';
import { DocRegistry, loadScanners } from './guards/documents.mjs';
import { redactText } from './guards/redactor.mjs';
import { checkUrl } from './guards/domains.mjs';
import { checkPath } from './guards/paths.mjs';
import { evaluateToolCall } from './guards/toolcalls.mjs';
import { safeJsonParse } from './util.mjs';

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.json': 'application/json', '.png': 'image/png', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };
const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const DASHBOARD_DIR = path.join(PKG_ROOT, 'dashboard');

function bearer(req) {
  const a = req.headers.authorization;
  if (a && /^bearer\s+/i.test(a)) return a.replace(/^bearer\s+/i, '').trim();
  return req.headers['x-api-key'] ? String(req.headers['x-api-key']).trim() : '';
}

function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && timingSafeEqual(x, y);
}

function readBody(req, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > maxBytes) { reject(Object.assign(new Error('request body too large'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Build the whole application. Nothing listens until `listen()` is called.
 * @param {object} config  from loadConfig()
 * @param {{persist?: boolean, warmup?: boolean}} opts
 */
export async function createApp(config, opts = {}) {
  const store = new RuleStore({ config });
  await store.load();
  const bus = new EventBus({ dataDir: config.dataDir, retentionDays: config.logging?.retentionDays, persist: opts.persist !== false });
  if (opts.persist !== false) bus.loadHistory();
  const keys = new KeyStore(path.join(config.dataDir, 'keys.json'));
  const registry = new DocRegistry(path.join(config.dataDir, 'restricted-documents.json'));
  const scanner = new CodeScanner({ config, store });
  // detection can take seconds (Semgrep start-up); listening does not wait for it — built-in rules cover the gap
  const scannerReady = scanner.init({ warmup: opts.warmup !== false }).catch(() => scanner.status());
  const upstreams = new Upstreams(config);
  const firewall = new Firewall({ config, store, scanner, bus, registry, upstreams });
  store.on('reload', ({ count, problems }) => bus.emit('rules.reloaded', problems.length ? 'warning' : 'info', `Rules reloaded: ${count} rules${problems.length ? `, ${problems.length} problem(s)` : ''}`, { count, problems }));

  const maxBody = (config.server.maxBodyMb || 64) * 1024 * 1024;

  // ───────────── identification ─────────────
  function identify(req) {
    const ip = req.socket.remoteAddress || 'unknown';
    const isLocal = LOOPBACK.has(ip);
    const token = bearer(req);
    const rec = keys.verify(token);
    if (rec) return { id: `key:${rec.id}`, name: rec.name, profile: rec.profile || '', isLocal, viaKey: true };
    if (config.auth.mode === 'keys') return null;
    const label = String(req.headers['x-staffet-user'] || '').slice(0, 64).replace(/[^\w .@-]/g, '') || (isLocal ? 'localhost' : ip.replace(/^::ffff:/, ''));
    return { id: `ip:${ip}`, name: label, profile: String(req.headers['x-staffet-profile'] || ''), isLocal };
  }

  function isAdmin(req, url) {
    const token = config.server.adminToken;
    if (!token) return LOOPBACK.has(req.socket.remoteAddress);      // no token configured: local machine only
    const given = bearer(req) || url.searchParams.get('token') || '';
    return Boolean(given) && safeEqual(given, token);
  }

  // ───────────── admin API ─────────────
  const defaultEnv = (profile = '') => {
    const view = store.view(profile);
    const policy = resolvePolicy(config, profile);
    const d = policy.documents || {};
    return { view, policy, harness: { id: 'unknown', cwd: null }, client: { id: 'admin', isLocal: true }, registry, scanOpts: { extraMarkers: view.document.extraMarkers, disabledMarkers: view.document.disabledMarkers, piiThreshold: d.piiThreshold, threshold: d.threshold, rulesVersion: view.version } };
  };

  async function admin(req, res, url) {
    const p = url.pathname.replace(/\/+$/, '');
    const method = req.method;
    const q = url.searchParams;
    const json = async () => safeJsonParse((await readBody(req, 4 * 1024 * 1024)).toString('utf8'), {}) || {};
    const ok = (obj) => sendJson(res, 200, obj);
    const fail = (status, message) => sendJson(res, status, { error: message });

    if (p === '/api/health') return ok({ ok: true, name: BRAND.name, version: BRAND.version, uptimeMs: Date.now() - bus.startedAt });
    if (!isAdmin(req, url)) return fail(401, config.server.adminToken ? 'admin token required (Authorization: Bearer <server.adminToken>)' : 'the admin API is only reachable from this machine until server.adminToken is set');

    try {
      if (p === '/api/overview' && method === 'GET') return ok(bus.overview({ minutes: Math.min(1440, Number(q.get('minutes')) || 60) }));
      if (p === '/api/events' && method === 'GET') return ok({ events: bus.recentEvents({ limit: Math.min(2000, Number(q.get('limit')) || 200), type: q.get('type') || undefined, severity: q.get('severity') || undefined, requestId: q.get('requestId') || undefined }) });
      if (p === '/api/requests' && method === 'GET') return ok({ requests: bus.recentRequests({ limit: Math.min(1000, Number(q.get('limit')) || 200), outcome: q.get('outcome') || undefined, q: q.get('q') || undefined }) });
      if (p.startsWith('/api/requests/') && method === 'GET') {
        const r = bus.getRequest(decodeURIComponent(p.slice('/api/requests/'.length)));
        return r ? ok({ request: r, events: bus.recentEvents({ limit: 200, requestId: r.id }).reverse() }) : fail(404, 'request not found (it may have rotated out of memory)');
      }

      if (p === '/api/stream' && method === 'GET') {
        res.writeHead(200, { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache, no-transform', connection: 'keep-alive', 'x-accel-buffering': 'no' });
        res.write(`data: ${JSON.stringify({ kind: 'hello', version: BRAND.version, now: Date.now() })}\n\n`);
        const unsub = bus.subscribe((msg) => res.write(`data: ${JSON.stringify(msg)}\n\n`));
        const beat = setInterval(() => res.write(': ping\n\n'), 15000);
        req.on('close', () => { clearInterval(beat); unsub(); });
        return;
      }

      if (p === '/api/rules' && method === 'GET') return ok({ rules: store.list(), problems: store.problems, semgrep: store.semgrepDirs(), customFile: store.managedFile });
      if (p === '/api/rules' && method === 'POST') return ok({ rule: await store.addCustom(await json()) });
      if (p === '/api/rules/reload' && method === 'POST') { await store.load(); return ok({ count: store.rules.size, problems: store.problems }); }
      if (p.startsWith('/api/rules/')) {
        const id = decodeURIComponent(p.slice('/api/rules/'.length));
        if (method === 'PATCH') { const b = await json(); return ok({ rule: await store.setEnabled(id, b.enabled !== false) }); }
        if (method === 'DELETE') { await store.removeCustom(id); return ok({ removed: id }); }
      }

      if (p === '/api/system' && method === 'GET') {
        const sc = await loadScanners();
        return ok({
          name: BRAND.name, version: BRAND.version, node: process.version, platform: process.platform, startedAt: bus.startedAt,
          config: publicConfig(config), scanner: scanner.status(),
          documentScanners: sc.error ? { error: sc.error.message } : { extensions: sc.SUPPORTED_EXTENSIONS },
          rules: { total: store.rules.size, enabled: [...store.rules.values()].filter((r) => r.enabled).length, custom: [...store.rules.values()].filter((r) => r.source === 'custom').length, problems: store.problems },
          redactionToken: config.policy.redaction.token,
        });
      }

      if (p === '/api/documents' && method === 'GET') return ok({ documents: registry.list() });
      if (p.startsWith('/api/documents/') && method === 'DELETE') return registry.remove(decodeURIComponent(p.slice('/api/documents/'.length))) ? ok({ removed: true }) : fail(404, 'unknown document');

      if (p === '/api/keys' && method === 'GET') return ok({ keys: keys.list(), mode: config.auth.mode });
      if (p === '/api/keys' && method === 'POST') return ok(keys.create(await json()));
      if (p.startsWith('/api/keys/') && method === 'DELETE') return ok({ key: keys.revoke(decodeURIComponent(p.slice('/api/keys/'.length))) });

      // ── playground ──
      if (p.startsWith('/api/test/') && method === 'POST') {
        const b = await json();
        const env = defaultEnv(b.profile || '');
        const kind = p.slice('/api/test/'.length);
        if (kind === 'redact') return ok(redactText(String(b.text || ''), env.view, { token: env.policy.redaction.token }));
        if (kind === 'url') return ok(checkUrl(String(b.url || ''), env.view, env.policy.toolCalls?.domains?.mode));
        if (kind === 'path') return ok(checkPath(String(b.path || ''), b.op || 'any', env.view, env.policy.toolCalls?.paths, b.cwd || null) || { action: 'allow' });
        if (kind === 'command') return ok(await evaluateToolCall({ id: 't', name: 'Bash', args: { command: String(b.command || '') } }, { ...env, harness: { id: 'unknown', cwd: b.cwd || null } }));
        if (kind === 'toolcall') return ok(await evaluateToolCall({ id: 't', name: String(b.name || 'tool'), args: b.args ?? {} }, { ...env, harness: { id: 'unknown', cwd: b.cwd || null } }));
        if (kind === 'code') {
          const lang = normaliseLang(b.lang || 'python');
          const snippets = [{ id: 's0', origin: 'block', lang, ext: LANG_EXT[lang] || '', code: String(b.code || '') }];
          const r = await scanner.scan(snippets, { view: env.view, policy: { ...env.policy, codeScan: { ...env.policy.codeScan, minSeverity: 'info' }, quality: { ...env.policy.quality, minSeverity: 'info' } } });
          return ok({ ...r, report: formatFindings(r.findings, snippets) });
        }
        if (kind === 'document') {
          const sc = await loadScanners();
          if (sc.error) return fail(500, sc.error.message);
          return ok(await sc.scanText(String(b.text || ''), { ...env.scanOpts, filename: b.filename || 'document.txt' }));
        }
      }
      return fail(404, 'unknown admin endpoint');
    } catch (e) {
      return fail(e.status || 400, e.message);
    }
  }

  // ───────────── dashboard ─────────────
  function serveStatic(res, rel) {
    const file = path.normalize(path.join(DASHBOARD_DIR, rel || 'index.html'));
    if (!file.startsWith(DASHBOARD_DIR)) { res.writeHead(403); res.end(); return; }
    fs.readFile(file, (err, buf) => {
      if (err) { res.writeHead(404, { 'content-type': 'text/plain' }); res.end('not found'); return; }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream', 'cache-control': 'no-cache', 'x-content-type-options': 'nosniff', 'content-security-policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'" });
      res.end(buf);
    });
  }

  // ───────────── model endpoints ─────────────
  async function model(req, res, url) {
    // accepted prefixes: /v1, /openai/v1, /anthropic/v1, or none
    let p = url.pathname;
    let forced = null;
    const pm = /^\/(openai|anthropic)(\/.*)$/.exec(p);
    if (pm) { forced = pm[1]; p = pm[2]; }
    const suffix = p.replace(/^\/v1(?=\/|$)/, '') || '/';
    const guess = () => forced || (req.headers['anthropic-version'] || (req.headers['x-api-key'] && !req.headers.authorization) ? 'anthropic' : 'openai');
    const protocol = suffix.startsWith('/messages') ? 'anthropic' : suffix.startsWith('/chat/completions') ? 'openai' : guess();
    const adapter = ADAPTERS[protocol];

    const client = identify(req);
    if (!client) return sendJson(res, 401, adapter.errorBody(401, `a valid ${BRAND.name} API key is required (auth.mode is "keys")`, 'authentication_error'));

    let raw;
    try { raw = await readBody(req, maxBody); } catch (e) { return sendJson(res, e.status || 400, adapter.errorBody(e.status || 400, e.message)); }

    const io = { req, res, client, protocol, endpoint: suffix, suffix, search: url.search };
    const inspected = req.method === 'POST' && (suffix === '/chat/completions' || suffix === '/messages');
    const requestOnly = req.method === 'POST' && suffix === '/messages/count_tokens';
    if (inspected || requestOnly) {
      const body = safeJsonParse(raw.toString('utf8'));
      if (body === undefined) return sendJson(res, 400, adapter.errorBody(400, 'request body is not valid JSON'));
      return inspected ? firewall.handleInference({ ...io, body }) : firewall.handleRequestOnly({ ...io, body });
    }

    const harmless = req.method === 'GET' || /^\/(?:models|embeddings|moderations|tokenize|detokenize)(?:\/|$)/.test(suffix);
    if (!harmless && config.policy.uninspectedEndpoints !== 'allow') {
      bus.emit('endpoint.blocked', 'warning', `Blocked ${req.method} ${suffix}: this endpoint is not inspected by the firewall`, { path: suffix }, { client: client.name });
      return sendJson(res, 403, adapter.errorBody(403, `${BRAND.name} firewall: "${suffix}" is not an inspected endpoint. Use /v1/chat/completions or /v1/messages, or set policy.uninspectedEndpoints: allow.`, 'permission_error'));
    }
    return firewall.passthrough({ ...io, rawBody: raw });
  }

  const server = http.createServer(async (req, res) => {
    let url;
    try { url = new URL(req.url, 'http://localhost'); } catch { res.writeHead(400); res.end(); return; }
    try {
      const p = url.pathname;
      if (p === '/healthz') return sendJson(res, 200, { ok: true });
      if (p.startsWith('/api/')) return await admin(req, res, url);
      if (p === '/' || p === '/dashboard') { res.writeHead(302, { location: '/dashboard/' }); res.end(); return; }
      if (p.startsWith('/dashboard/')) return serveStatic(res, decodeURIComponent(p.slice('/dashboard/'.length)));
      if (p === '/favicon.ico') return serveStatic(res, 'favicon.svg');
      return await model(req, res, url);
    } catch (e) {
      if (!res.headersSent) sendJson(res, 500, { error: { message: e.message, type: 'server_error' } });
      else res.end();
    }
  });
  server.keepAliveTimeout = 65000;
  server.headersTimeout = 70000;
  server.requestTimeout = 0;          // model calls can legitimately take many minutes

  return {
    config, store, bus, keys, registry, scanner, scannerReady, firewall, upstreams, server,
    listen() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(config.server.port, config.server.host, () => { server.off('error', reject); store.watch(); resolve(server.address()); });
      });
    },
    async close() {
      store.close();
      bus.close();
      await new Promise((r) => { server.close(() => r()); server.closeAllConnections?.(); });
    },
  };
}
