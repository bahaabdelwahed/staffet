// Staffet command line.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { randomBytes } from 'node:crypto';
import { BRAND } from '../brand.mjs';
import { loadConfig, findConfigPath, resolvePolicy, SAMPLE_CONFIG } from '../config.mjs';
import { RuleStore } from '../rules/store.mjs';
import { KeyStore } from '../keys.mjs';
import { c, sym, table, heading, kv, badge, clip, fmtMs, fmtNum, eventLine, requestLine, banner, time } from './ui.mjs';

const OPTIONS = {
  config: { type: 'string', short: 'c' }, port: { type: 'string', short: 'p' }, host: { type: 'string' },
  url: { type: 'string' }, token: { type: 'string' }, json: { type: 'boolean' }, quiet: { type: 'boolean', short: 'q' },
  type: { type: 'string', short: 't' }, limit: { type: 'string', short: 'n' }, outcome: { type: 'string' }, all: { type: 'boolean', short: 'a' },
  name: { type: 'string' }, profile: { type: 'string' }, pattern: { type: 'string' }, action: { type: 'string' }, severity: { type: 'string' },
  message: { type: 'string' }, languages: { type: 'string' }, domains: { type: 'string' }, paths: { type: 'string' }, strength: { type: 'string' },
  flags: { type: 'string' }, group: { type: 'string' }, id: { type: 'string' }, op: { type: 'string' }, lang: { type: 'string' }, cwd: { type: 'string' },
  force: { type: 'boolean' }, once: { type: 'boolean' }, help: { type: 'boolean', short: 'h' }, version: { type: 'boolean', short: 'v' },
};

const HELP = `
${c.bold(BRAND.name)} ${c.dim('v' + BRAND.version)} — ${BRAND.tagline}

${c.bold('Run')}
  ${BRAND.cli} init                       create ${BRAND.configFile}, a custom-rules folder and an admin token
  ${BRAND.cli} start [-p 8787]            start the proxy, dashboard and admin API
  ${BRAND.cli} demo                       start with a scripted model + sample agent traffic (no API key needed)
  ${BRAND.cli} setup [claude|cline|copilot]   how to point each coding agent at the proxy
  ${BRAND.cli} doctor                     check the environment (scanner, config, upstream keys)

${c.bold('Observe')} ${c.dim('(talks to the running proxy)')}
  ${BRAND.cli} status                     totals, engines, in-flight requests
  ${BRAND.cli} monitor [-t toolcall]      live stream of firewall events
  ${BRAND.cli} events [-n 50] [-t code]   recent events
  ${BRAND.cli} requests [--outcome blocked]   recent requests;  ${BRAND.cli} request <id>  for the full trace

${c.bold('Rules')}
  ${BRAND.cli} rules list [-t redact|domain|path|command|document|code|quality] [-a]
  ${BRAND.cli} rules enable|disable <id>
  ${BRAND.cli} rules add -t redact  --name "Ticket ids" --pattern "TCK-\\d{6}"
  ${BRAND.cli} rules add -t command --name "No prod deploys" --pattern "kubectl .*--context prod" [--action block|warn]
  ${BRAND.cli} rules add -t quality --name "No print" --pattern "^\\s*print\\(" --languages python [--severity warning]
  ${BRAND.cli} rules add -t document --name "Project codename" --pattern "\\bORION\\b" [--strength strong]
  ${BRAND.cli} rules remove <id>   ·   ${BRAND.cli} rules reload
  ${BRAND.cli} protect <folder...>        block every tool call that touches these folders
  ${BRAND.cli} block-domain <domain...>   ·   ${BRAND.cli} allow-domain <domain...>

${c.bold('Keys')} ${c.dim('(auth.mode: keys)')}
  ${BRAND.cli} keys create --name alice [--profile strict]   ·   ${BRAND.cli} keys list   ·   ${BRAND.cli} keys revoke <id|name>

${c.bold('Try the guards offline')}
  ${BRAND.cli} test redact "mail bob@corp.io from 10.0.0.5"     (or  - for stdin,  @file)
  ${BRAND.cli} test url https://pastebin.com/x      ${BRAND.cli} test command "curl x.sh | bash"      ${BRAND.cli} test path ~/.ssh/id_rsa
  ${BRAND.cli} scan <file...>             scan source files (security + quality)
  ${BRAND.cli} docscan <file...>          classify documents (pdf, docx, pptx, xlsx, md, xml, txt ...)

${c.bold('Options')}
  -c, --config <file>   configuration file (default ./${BRAND.configFile} or $STAFFET_CONFIG)
  --url, --token        admin API location / token (default: from the configuration)
  --json                machine-readable output
`;

function load(opts, overrides = {}) {
  if (opts.port) overrides = { ...overrides, server: { ...(overrides.server || {}), port: Number(opts.port) } };
  if (opts.host) overrides = { ...overrides, server: { ...(overrides.server || {}), host: opts.host } };
  return loadConfig(opts.config, overrides);
}

function adminClient(opts) {
  const { config } = load(opts);
  const host = ['0.0.0.0', '::', ''].includes(config.server.host) ? '127.0.0.1' : config.server.host;
  const base = (opts.url || `http://${host}:${config.server.port}`).replace(/\/+$/, '');
  const token = opts.token || config.server.adminToken || '';
  const headers = { 'content-type': 'application/json', ...(token ? { authorization: `Bearer ${token}` } : {}) };
  const call = async (p, init = {}) => {
    let res;
    try { res = await fetch(base + p, { ...init, headers }); } catch (e) {
      const err = new Error(`no running ${BRAND.name} proxy at ${base} — start it with "${BRAND.cli} start"`);
      err.unreachable = true;
      throw err;
    }
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.error?.message || body.error || `admin API answered ${res.status}`);
    return body;
  };
  return { base, token, headers, get: (p) => call(p), post: (p, b) => call(p, { method: 'POST', body: JSON.stringify(b || {}) }), patch: (p, b) => call(p, { method: 'PATCH', body: JSON.stringify(b || {}) }), del: (p) => call(p, { method: 'DELETE' }) };
}

/** Prefer the running proxy (changes apply instantly); fall back to editing the files directly. */
async function onlineOrOffline(opts, online, offline, { note = true } = {}) {
  const api = adminClient(opts);
  try { return await online(api); } catch (e) {
    if (!e.unreachable) throw e;
    const { config } = load(opts);
    const store = new RuleStore({ config });
    await store.load();
    const out = await offline(store, config);
    if (note) console.log(c.dim(`  (proxy not running — written to disk, applies on next start)`));
    return out;
  }
}

const out = (opts, data, human) => { if (opts.json) console.log(JSON.stringify(data, null, 2)); else human(); };
const list = (s) => String(s || '').split(',').map((x) => x.trim()).filter(Boolean);

// ───────────────────────── commands ─────────────────────────

async function cmdInit(opts) {
  const file = findConfigPath(opts.config);
  const dir = path.dirname(file);
  if (fs.existsSync(file) && !opts.force) throw new Error(`${file} already exists (use --force to overwrite)`);
  const token = randomBytes(18).toString('base64url');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(file, SAMPLE_CONFIG.replace('__ADMIN_TOKEN__', token));
  const custom = path.join(dir, 'rules', 'custom');
  fs.mkdirSync(path.join(custom, 'semgrep', 'security'), { recursive: true });
  fs.mkdirSync(path.join(custom, 'semgrep', 'quality'), { recursive: true });
  const example = path.join(custom, 'examples.yaml');
  if (!fs.existsSync(example)) {
    fs.writeFileSync(example, `# Your own rules. Every *.yaml file in this folder is loaded and hot-reloaded.\n# Remove "enabled: false" to activate an example. Semgrep-format rules go in ./semgrep/security or ./semgrep/quality.\nversion: 1\nrules:\n  - id: custom.redact.ticket-ids\n    type: redact\n    name: Internal ticket numbers\n    enabled: false\n    pattern: '\\bTCK-\\d{6}\\b'\n\n  - id: custom.domain.partner-api\n    type: domain\n    name: Partner API is allowed\n    enabled: false\n    action: allow\n    domains: ["api.partner.example"]\n\n  - id: custom.path.finance-share\n    type: path\n    name: Finance share\n    enabled: false\n    action: block\n    paths: ["//fileserver/finance/**", "D:/Finance"]\n\n  - id: custom.command.no-prod-kubectl\n    type: command\n    name: No kubectl against production\n    enabled: false\n    action: block\n    pattern: 'kubectl\\b.*--context[= ]prod'\n\n  - id: custom.document.project-codename\n    type: document\n    name: Project codename marks a document as confidential\n    enabled: false\n    strength: strong\n    pattern: '\\bPROJECT\\s+ORION\\b'\n\n  - id: custom.quality.no-print\n    type: quality\n    name: Use logging instead of print\n    enabled: false\n    languages: [python]\n    severity: warning\n    pattern: '^[ \\t]*print\\s*\\('\n    flags: gm\n    message: print() is not allowed in this code base.\n    fix: Use the logging module.\n`);
  }
  console.log(`\n  ${sym.ok} Created ${c.bold(path.relative(process.cwd(), file) || file)}`);
  console.log(`  ${sym.ok} Custom rules folder ${c.bold(path.relative(process.cwd(), custom))}`);
  console.log(`  ${sym.ok} Admin token ${c.bold(token)} ${c.dim('(dashboard login, stored in the config file)')}`);
  console.log(`\n  Next:  ${c.cyan(`${BRAND.cli} doctor`)}  ·  ${c.cyan(`${BRAND.cli} start`)}  ·  ${c.cyan(`${BRAND.cli} setup`)}\n`);
}

async function describeStart(app, addr, extra = []) {
  await app.scannerReady;
  const { config, scanner, store } = app;
  const host = ['0.0.0.0', '::'].includes(config.server.host) ? os.hostname() : config.server.host;
  const base = `http://${host}:${addr.port}`;
  const sc = scanner.status();
  const rules = [...store.rules.values()];
  const up = config.upstreams.map((u) => {
    const hasKey = Boolean(u.apiKey || (u.apiKeyEnv && process.env[u.apiKeyEnv]));
    return `${c.bold(u.name)} ${c.dim(`(${u.protocol})`)} ${sym.arrow} ${u.baseUrl} ${hasKey ? c.green('key set') : c.dim("caller's key is forwarded")}`;
  });
  console.log('\n' + banner(BRAND.name, BRAND.version, BRAND.tagline) + '\n');
  console.log(kv([
    ['Dashboard', c.cyan(`${base}/dashboard/`) + (config.server.adminToken ? c.dim('  (login with server.adminToken)') : c.dim('  (local access only until server.adminToken is set)'))],
    ['OpenAI API', `${c.cyan(`${base}/v1`)}  ${c.dim('Cline, Copilot, any OpenAI SDK')}`],
    ['Anthropic API', `${c.cyan(base)}  ${c.dim('Claude Code (ANTHROPIC_BASE_URL)')}`],
    ['Upstreams', up[0]], ...up.slice(1).map((u) => ['', u]),
    ['Auth', config.auth.mode === 'keys' ? `${BRAND.name} keys required` : 'passthrough'],
    ['Rules', `${rules.filter((r) => r.enabled).length} enabled ${c.dim(`(${rules.filter((r) => r.source === 'custom').length} custom)`)}${store.problems.length ? c.yellow(`  ${store.problems.length} problem(s) — run "${BRAND.cli} doctor"`) : ''}`],
    ['Code scanner', sc.external.available ? `built-in + ${sc.external.kind} ${sc.external.version}` : `built-in ${c.dim('(install semgrep or opengrep for syntax-aware scanning)')}`],
    ...extra,
  ]));
  console.log('');
  return base;
}

function attachConsole(app, opts) {
  if (opts.quiet) return;
  app.bus.subscribe((msg) => {
    if (msg.kind === 'request') console.log(requestLine(msg.request));
    else if (msg.kind === 'event' && msg.event.type !== 'request.completed' && msg.event.severity !== 'info') console.log(eventLine(msg.event));
  });
}

async function cmdStart(opts) {
  const { createApp } = await import('../server.mjs');
  const { config, exists, path: file } = load(opts);
  const app = await createApp(config);
  const addr = await app.listen();
  await describeStart(app, addr);
  if (!exists) console.log(c.dim(`  No ${path.basename(file)} found — running on defaults. "${BRAND.cli} init" creates one.\n`));
  if (!['127.0.0.1', 'localhost', '::1'].includes(config.server.host) && !config.server.adminToken) console.log(`  ${sym.warn} ${c.yellow('Serving the network without server.adminToken: the dashboard and admin API answer local requests only.')}\n`);
  attachConsole(app, opts);
  const stop = async () => { console.log(c.dim('\n  shutting down…')); await app.close(); process.exit(0); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

async function cmdDemo(opts) {
  const { createApp } = await import('../server.mjs');
  const { createMockUpstream } = await import('../mock/upstream.mjs');
  const { demoBrain, startTraffic, runScenario, SCENARIOS } = await import('../mock/demo.mjs');
  const mock = await createMockUpstream(demoBrain, { delayMs: opts.once ? 0 : 450 });
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), `${BRAND.slug}-demo-`));
  const { config } = load(opts, {
    upstreams: [
      { name: 'demo-openai', protocol: 'openai', baseUrl: mock.url, models: ['gpt-*'] },
      { name: 'demo-anthropic', protocol: 'anthropic', baseUrl: mock.url, models: ['claude-*'] },
      { name: 'local', protocol: 'openai', baseUrl: mock.url, models: ['llama-*'] },
    ],
    auth: { mode: 'passthrough' },
    enterprise: { name: 'Northwind (demo)', internalDomains: ['northwind-internal.com'] },
    policy: { toolCalls: { paths: { protected: ['D:/Finance'] } }, documents: { localScan: false } },
    dataDir, rulesDir: path.join(dataDir, 'rules'),
  });
  const app = await createApp(config, { persist: true });
  const addr = await app.listen();
  const base = `http://127.0.0.1:${addr.port}`;
  await describeStart(app, addr, [['Mode', c.magenta('DEMO') + c.dim(' — scripted model, simulated agents (alice, bob, carol, dave, erin)')]]);
  attachConsole(app, opts);
  if (opts.once) {
    for (const s of SCENARIOS) { await runScenario(base, s); }
    const t = app.bus.totals;
    console.log(heading('Demo run complete'));
    console.log(kv([['Requests', String(t.requests)], ['Passed', String(t.clean)], ['Sanitized', String(t.sanitized)], ['Blocked', String(t.blocked)], ['Values redacted', String(t.redactions)], ['Tool calls blocked', String(t.toolCallsBlocked)], ['Code issues fixed', String(t.findingsFixed)], ['Documents withheld', String(t.documentsBlocked)]]));
    await app.close(); await mock.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
    return;
  }
  const traffic = startTraffic(base);
  console.log(c.dim(`  Sample traffic is running. Open the dashboard, then press Ctrl+C to stop.\n`));
  const stop = async () => { traffic.stop(); await app.close(); await mock.close(); fs.rmSync(dataDir, { recursive: true, force: true }); process.exit(0); };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

async function cmdStatus(opts) {
  const api = adminClient(opts);
  const [ov, sys] = await Promise.all([api.get('/api/overview'), api.get('/api/system')]);
  out(opts, { overview: ov, system: sys }, () => {
    const t = ov.totals;
    console.log(heading(`${BRAND.name} ${sys.version} — up ${fmtMs(ov.now - ov.startedAt)} at ${api.base}`));
    console.log(kv([
      ['Requests', `${fmtNum(t.requests)}  ${c.dim(`${fmtNum(t.clean)} passed · ${fmtNum(t.sanitized)} sanitized · ${fmtNum(t.blocked)} blocked · ${fmtNum(t.error)} errors`)}`],
      ['Redactions', fmtNum(t.redactions)],
      ['Tool calls', `${fmtNum(t.toolCallsBlocked)} blocked · ${fmtNum(t.toolCallsWarned)} flagged`],
      ['Code scans', `${fmtNum(t.scans)} scans · ${fmtNum(t.findings)} findings · ${fmtNum(t.findingsFixed)} fixed in ${fmtNum(t.fixLoops)} loops · ${fmtNum(t.findingsUnresolved)} unresolved`],
      ['Documents', `${fmtNum(t.documentsBlocked)} withheld`],
      ['Tokens', `${fmtNum(t.tokensIn)} in · ${fmtNum(t.tokensOut)} out`],
      ['Avg overhead', `${fmtMs(t.avgOverheadMs)} of ${fmtMs(t.avgDurationMs)} per request`],
      ['Engines', sys.scanner.engines.join(' + ') + (sys.scanner.external.available ? ` ${sys.scanner.external.version}` : '')],
      ['Rules', `${sys.rules.enabled}/${sys.rules.total} enabled, ${sys.rules.custom} custom`],
    ]));
    if (ov.inflight.length) {
      console.log(heading('In flight'));
      console.log(table(ov.inflight, [{ key: 'client', title: 'Client' }, { key: 'harness', title: 'Agent' }, { key: 'model', title: 'Model' }, { key: 'stage', title: 'Stage' }, { key: 'iteration', title: 'Loop', align: 'right' }, { key: 'startedAt', title: 'Age', align: 'right', format: (v) => fmtMs(ov.now - v) }]));
    }
    if (ov.topRules.length) {
      console.log(heading('Most triggered rules'));
      console.log(table(ov.topRules, [{ key: 'name', title: 'Rule' }, { key: 'count', title: 'Hits', align: 'right' }]));
    }
    console.log('');
  });
}

async function cmdMonitor(opts) {
  const api = adminClient(opts);
  let res;
  try { res = await fetch(`${api.base}/api/stream`, { headers: api.headers }); } catch { throw new Error(`no running ${BRAND.name} proxy at ${api.base} — start it with "${BRAND.cli} start"`); }
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || `admin API answered ${res.status}`);
  if (!opts.json) console.log(c.dim(`\n  Live events from ${api.base} — Ctrl+C to stop\n`));
  const { parseSSE } = await import('../proxy/sse.mjs');
  for await (const ev of parseSSE(res.body)) {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { continue; }
    if (opts.json) { console.log(JSON.stringify(msg)); continue; }
    if (msg.kind === 'request') console.log(requestLine(msg.request));
    else if (msg.kind === 'event' && msg.event.type !== 'request.completed') {
      if (opts.type && !msg.event.type.startsWith(opts.type)) continue;
      console.log(eventLine(msg.event));
    }
  }
}

async function cmdEvents(opts) {
  const api = adminClient(opts);
  const q = new URLSearchParams({ limit: opts.limit || '40', ...(opts.type ? { type: opts.type } : {}), ...(opts.severity ? { severity: opts.severity } : {}) });
  const { events } = await api.get(`/api/events?${q}`);
  out(opts, events, () => { console.log(''); for (const e of events.slice().reverse()) console.log(eventLine(e)); console.log(''); });
}

async function cmdRequests(opts) {
  const api = adminClient(opts);
  const q = new URLSearchParams({ limit: opts.limit || '30', ...(opts.outcome ? { outcome: opts.outcome } : {}) });
  const { requests } = await api.get(`/api/requests?${q}`);
  out(opts, requests, () => {
    console.log('');
    console.log(table(requests, [
      { key: 'ts', title: 'Time', format: time }, { key: 'outcome', title: 'Outcome', format: badge }, { key: 'client', title: 'Client', width: 16 }, { key: 'harness', title: 'Agent', width: 14 },
      { key: 'model', title: 'Model', width: 22 }, { key: 'redactions', title: 'Redact', align: 'right' }, { key: 'iterations', title: 'Loops', align: 'right' },
      { key: 'durationMs', title: 'Time', align: 'right', format: fmtMs }, { key: 'id', title: 'Id', format: (v) => c.dim(v) },
    ]));
    console.log('');
  });
}

async function cmdRequest(opts, [id]) {
  if (!id) throw new Error(`usage: ${BRAND.cli} request <id>`);
  const api = adminClient(opts);
  const { request: r, events } = await api.get(`/api/requests/${encodeURIComponent(id)}`);
  out(opts, { request: r, events }, () => {
    console.log(heading(`Request ${r.id}  ${badge(r.outcome)}`));
    console.log(kv([
      ['When', new Date(r.ts).toLocaleString()], ['Client', `${r.client}${r.profile ? c.dim(` (profile ${r.profile})`) : ''}`], ['Agent', `${r.harness}${r.cwd ? c.dim(`  ${r.cwd}`) : ''}`],
      ['Model', `${r.model} ${sym.arrow} ${r.upstream} ${c.dim(`(${r.protocol}${r.stream ? ', stream' : ''})`)}`],
      ['Timing', `${fmtMs(r.durationMs)} total · ${fmtMs(r.upstreamMs)} model · ${fmtMs(r.overheadMs)} firewall`],
      ['Tokens', `${fmtNum(r.usage?.input)} in · ${fmtNum(r.usage?.output)} out`],
    ]));
    if (r.redactions?.total) {
      console.log(heading(`Redactions (${r.redactions.total})`));
      console.log(table(r.redactions.rules, [{ key: 'name', title: 'Rule' }, { key: 'count', title: 'Count', align: 'right' }, { key: 'sample', title: 'Masked sample' }]));
    }
    for (const round of r.rounds || []) {
      console.log(heading(`Model pass ${round.iteration + 1}  ${c.dim(fmtMs(round.upstreamMs))}`));
      for (const t of round.toolCalls) {
        const mark = t.action === 'block' ? sym.fail : t.action === 'rewrite' ? sym.warn : t.warnings.length ? sym.warn : sym.ok;
        console.log(`  ${mark} ${clip(t.summary, 110)}`);
        for (const x of [...t.reasons, ...t.warnings]) console.log(`      ${c.dim(`${x.kind}: ${x.message}${x.target ? ` → ${clip(x.target, 70)}` : ''} (${x.ruleId})`)}`);
      }
      if (round.scan) console.log(`  ${c.dim(`scanned ${round.scan.snippets} snippet(s) with ${round.scan.engines.join(' + ')} in ${fmtMs(round.scan.ms)}`)}`);
      for (const f of round.findings) console.log(`  ${f.severity === 'error' ? sym.fail : sym.warn} ${f.ruleId}${f.cwe ? c.dim(` ${f.cwe}`) : ''} ${c.dim(`${f.where || ''}:${f.line}`)}  ${f.message}`);
    }
    if (r.notices?.length) { console.log(heading('Delivered with notice')); for (const n of r.notices) console.log(`  ${n}`); }
    if (r.preview?.user) console.log(heading('Last user message') + `  ${c.dim(clip(r.preview.user.replace(/\s+/g, ' '), 300))}`);
    console.log('');
  });
}

function printRules(rules, opts) {
  let rows = rules;
  if (opts.type) rows = rows.filter((r) => r.type === opts.type);
  if (!opts.all) rows = rows.filter((r) => !(r.type === 'document' && r.strength === 'weak'));
  rows = rows.slice().sort((a, b) => a.type.localeCompare(b.type) || a.id.localeCompare(b.id));
  out(opts, rows, () => {
    console.log('');
    console.log(table(rows, [
      { key: 'enabled', title: 'On', format: (v) => (v ? sym.ok : c.dim('off')) }, { key: 'type', title: 'Type' }, { key: 'id', title: 'Id', width: 44 },
      { key: 'name', title: 'Name', width: 52 }, { key: 'action', title: 'Action', format: (v, r) => v || r.severity || '' }, { key: 'source', title: 'Source', format: (v) => (v === 'custom' ? c.cyan(v) : c.dim(v)) },
    ]));
    console.log(c.dim(`\n  ${rows.filter((r) => r.enabled).length} of ${rows.length} enabled`) + '\n');
  });
}

function ruleFromOptions(opts) {
  if (!opts.type) throw new Error('--type is required (redact, domain, path, command, document, code, quality)');
  const r = { type: opts.type, name: opts.name, id: opts.id };
  for (const k of ['pattern', 'action', 'severity', 'message', 'strength', 'flags']) if (opts[k]) r[k] = opts[k];
  if (opts.group) r.group = Number(opts.group);
  if (opts.languages) r.languages = list(opts.languages);
  if (opts.domains) r.domains = list(opts.domains);
  if (opts.paths) r.paths = list(opts.paths);
  if (!r.name) throw new Error('--name is required');
  return r;
}

async function addRule(opts, rule) {
  const saved = await onlineOrOffline(opts, async (api) => (await api.post('/api/rules', rule)).rule, (store) => store.addCustom(rule));
  console.log(`  ${sym.ok} rule ${c.bold(saved.id)} added ${c.dim(`(${saved.type})`)}`);
  return saved;
}

async function cmdRules(opts, [sub = 'list', ...rest]) {
  if (sub === 'list' || sub === 'ls') {
    const rules = await onlineOrOffline(opts, async (api) => (await api.get('/api/rules')).rules, (store) => store.list(), { note: false });
    return printRules(rules, opts);
  }
  if (sub === 'enable' || sub === 'disable') {
    if (!rest.length) throw new Error(`usage: ${BRAND.cli} rules ${sub} <id...>`);
    for (const id of rest) {
      await onlineOrOffline(opts, (api) => api.patch(`/api/rules/${encodeURIComponent(id)}`, { enabled: sub === 'enable' }), (store) => store.setEnabled(id, sub === 'enable'));
      console.log(`  ${sym.ok} ${id} ${sub}d`);
    }
    return;
  }
  if (sub === 'add') return addRule(opts, ruleFromOptions(opts));
  if (sub === 'remove' || sub === 'rm') {
    if (!rest.length) throw new Error(`usage: ${BRAND.cli} rules remove <id...>`);
    for (const id of rest) {
      await onlineOrOffline(opts, (api) => api.del(`/api/rules/${encodeURIComponent(id)}`), (store) => store.removeCustom(id));
      console.log(`  ${sym.ok} ${id} removed`);
    }
    return;
  }
  if (sub === 'reload') {
    const r = await adminClient(opts).post('/api/rules/reload');
    console.log(`  ${sym.ok} ${r.count} rules loaded${r.problems.length ? c.yellow(` — ${r.problems.length} problem(s):\n    ` + r.problems.join('\n    ')) : ''}`);
    return;
  }
  throw new Error(`unknown rules command "${sub}"`);
}

async function cmdKeys(opts, [sub = 'list', ...rest]) {
  const { config } = load(opts);
  const offline = () => new KeyStore(path.join(config.dataDir, 'keys.json'));
  const api = adminClient(opts);
  const viaApi = async (fn, fallback) => { try { return await fn(); } catch (e) { if (!e.unreachable) throw e; return fallback(); } };
  if (sub === 'create') {
    if (!opts.name) throw new Error('--name is required');
    const r = await viaApi(() => api.post('/api/keys', { name: opts.name, profile: opts.profile || '' }), () => offline().create({ name: opts.name, profile: opts.profile || '' }));
    return out(opts, r, () => {
      console.log(`\n  ${sym.ok} Key for ${c.bold(r.record.name)}${r.record.profile ? c.dim(` (profile ${r.record.profile})`) : ''}\n\n      ${c.bold(c.green(r.key))}\n\n  ${c.dim('Shown once. Give it to the developer as their API key.')}`);
      if (config.auth.mode !== 'keys') console.log(`  ${sym.warn} ${c.yellow('auth.mode is "passthrough": keys are optional and only select a profile. Set auth.mode: keys to require them.')}`);
      console.log('');
    });
  }
  if (sub === 'revoke') {
    if (!rest[0]) throw new Error(`usage: ${BRAND.cli} keys revoke <id|name>`);
    await viaApi(() => api.del(`/api/keys/${encodeURIComponent(rest[0])}`), () => offline().revoke(rest[0]));
    return console.log(`  ${sym.ok} key ${rest[0]} revoked`);
  }
  const keys = await viaApi(async () => (await api.get('/api/keys')).keys, () => offline().list());
  out(opts, keys, () => {
    console.log('');
    console.log(table(keys, [{ key: 'name', title: 'Name' }, { key: 'profile', title: 'Profile', format: (v) => v || c.dim('default') }, { key: 'prefix', title: 'Key', format: (v) => `${v}…` }, { key: 'id', title: 'Id' }, { key: 'createdAt', title: 'Created', format: (v) => new Date(v).toLocaleDateString() }, { key: 'lastUsedAt', title: 'Last used', format: (v) => (v ? new Date(v).toLocaleString() : c.dim('never')) }, { key: 'revoked', title: 'State', format: (v) => (v ? c.red('revoked') : c.green('active')) }]));
    console.log('');
  });
}

async function readInput(arg) {
  if (arg === '-' || arg === undefined) { const chunks = []; for await (const ch of process.stdin) chunks.push(ch); return Buffer.concat(chunks).toString('utf8'); }
  if (arg.startsWith('@')) return fs.readFileSync(arg.slice(1), 'utf8');
  return arg;
}

async function localEnv(opts) {
  const { config } = load(opts);
  const store = new RuleStore({ config });
  await store.load();
  const policy = resolvePolicy(config, opts.profile);
  const view = store.view(opts.profile);
  return { config, store, policy, view, env: { view, policy, harness: { id: 'unknown', cwd: opts.cwd || null }, client: { id: 'cli', isLocal: true }, registry: { get: () => null }, scanOpts: { extraMarkers: view.document.extraMarkers, disabledMarkers: view.document.disabledMarkers, piiThreshold: policy.documents?.piiThreshold, threshold: policy.documents?.threshold, rulesVersion: view.version } } };
}

async function cmdTest(opts, [kind, ...rest]) {
  const { view, policy, env } = await localEnv(opts);
  const verdict = (action) => (action === 'block' ? c.bgRed(' BLOCK ') : action === 'warn' ? c.bgYellow(' WARN ') : c.bgGreen(' ALLOW '));
  if (kind === 'redact') {
    const { redactText } = await import('../guards/redactor.mjs');
    const text = await readInput(rest.length > 1 ? rest.join(' ') : rest[0]);
    const r = redactText(text, view, { token: policy.redaction.token });
    return out(opts, r, () => {
      console.log('\n' + r.text.split('\n').map((l) => '  ' + l.replaceAll(policy.redaction.token, c.bgRed(policy.redaction.token))).join('\n'));
      console.log(c.dim(`\n  ${r.total} value(s) redacted`) + (r.hits.length ? '\n' + table(r.hits, [{ key: 'name', title: 'Rule' }, { key: 'count', title: 'Count', align: 'right' }, { key: 'sample', title: 'Masked sample' }, { key: 'ruleId', title: 'Id', format: (v) => c.dim(v) }]) : ''));
      console.log('');
    });
  }
  if (kind === 'url') {
    const { checkUrl } = await import('../guards/domains.mjs');
    const rows = rest.map((u) => ({ url: u, ...checkUrl(u, view, policy.toolCalls?.domains?.mode) }));
    return out(opts, rows, () => { console.log(''); for (const r of rows) console.log(`  ${verdict(r.action)} ${r.url}${r.reason ? c.dim(`  ${r.reason} (${r.ruleId})`) : ''}${r.warnings?.length ? c.yellow(`  ⚠ ${r.warnings.map((w) => w.reason).join('; ')}`) : ''}`); console.log(c.dim(`\n  mode: ${policy.toolCalls?.domains?.mode}`) + '\n'); });
  }
  if (kind === 'command' || kind === 'cmd') {
    const { evaluateToolCall } = await import('../guards/toolcalls.mjs');
    const r = await evaluateToolCall({ id: 't', name: 'Bash', args: { command: rest.join(' ') } }, env);
    return out(opts, r, () => {
      console.log(`\n  ${verdict(r.action === 'allow' && r.warnings.length ? 'warn' : r.action)} ${rest.join(' ')}`);
      for (const x of r.reasons) console.log(`    ${sym.fail} ${x.kind}: ${x.message}${x.target ? c.dim(` → ${clip(x.target, 80)}`) : ''} ${c.dim(`(${x.ruleId})`)}`);
      for (const x of r.warnings) console.log(`    ${sym.warn} ${x.kind}: ${x.message} ${c.dim(`(${x.ruleId})`)}`);
      console.log('');
    });
  }
  if (kind === 'path') {
    const { checkPath } = await import('../guards/paths.mjs');
    const rows = rest.map((p) => ({ path: p, ...(checkPath(p, opts.op || 'any', view, policy.toolCalls?.paths, opts.cwd || null) || { action: 'allow' }) }));
    return out(opts, rows, () => { console.log(''); for (const r of rows) console.log(`  ${verdict(r.action)} ${r.path}${r.reason ? c.dim(`  ${r.reason} (${r.ruleId})`) : ''}`); console.log(''); });
  }
  throw new Error(`usage: ${BRAND.cli} test redact|url|command|path <input>`);
}

async function cmdScan(opts, files) {
  if (!files.length) throw new Error(`usage: ${BRAND.cli} scan <file...>`);
  const { config, store, view, policy } = await localEnv(opts);
  const { CodeScanner } = await import('../code/engine.mjs');
  const { langFromPath } = await import('../code/extract.mjs');
  const { formatFindings } = await import('../code/report.mjs');
  const scanner = new CodeScanner({ config, store });
  await scanner.init({ warmup: false });
  const snippets = files.map((f, i) => ({ id: `s${i}`, origin: 'tool', toolName: 'file', path: f, code: fs.readFileSync(f, 'utf8'), ...langFromPath(f) }));
  const r = await scanner.scan(snippets, { view, policy: { ...policy, codeScan: { ...policy.codeScan, minSeverity: opts.severity || policy.codeScan.minSeverity }, quality: { ...policy.quality, minSeverity: opts.severity || policy.quality.minSeverity } } });
  out(opts, r, () => {
    console.log(c.dim(`\n  ${files.length} file(s) scanned with ${r.engines.join(' + ')} in ${fmtMs(r.ms)}\n`));
    if (!r.findings.length) console.log(`  ${sym.ok} no findings\n`);
    else console.log(formatFindings(r.findings, snippets).split('\n').map((l) => '  ' + l.replace(/\[ERROR\]/, c.red('[ERROR]')).replace(/\[WARNING\]/, c.yellow('[WARNING]'))).join('\n') + `\n\n  ${c.bold(`${r.findings.length} finding(s)`)}\n`);
    for (const e of r.errors) console.log(`  ${sym.warn} ${c.yellow(e)}`);
  });
  if (r.findings.length) process.exitCode = 2;
}

async function cmdDocscan(opts, files) {
  if (!files.length) throw new Error(`usage: ${BRAND.cli} docscan <file...>`);
  const { env } = await localEnv(opts);
  const { scanDocument } = await import('../../scanners/index.mjs');
  const results = [];
  for (const f of files) results.push(await scanDocument(f, env.scanOpts));
  out(opts, results, () => {
    console.log('');
    for (const v of results) {
      if (v.ok === false) { console.log(`  ${sym.warn} ${v.file}  ${c.yellow(v.error)}`); continue; }
      console.log(`  ${v.confidential ? c.bgRed(` ${v.classification || 'RESTRICTED'} `) : c.bgGreen(' CLEAN ')} ${c.bold(v.file)} ${c.dim(`${v.type} · score ${v.score.toFixed(2)}/${v.threshold} · ${fmtMs(v.stats?.ms)}`)}`);
      for (const reason of (v.reasons || []).slice(0, 6)) console.log(`      ${c.dim('•')} ${reason}`);
    }
    console.log('');
  });
  if (results.some((v) => v.confidential)) process.exitCode = 2;
}

async function cmdDoctor(opts) {
  const rows = [];
  const add = (ok, label, detail = '') => rows.push({ ok, label, detail });
  const major = Number(process.versions.node.split('.')[0]);
  add(major >= 20, `Node.js ${process.versions.node}`, major >= 20 ? '' : 'version 20.18 or newer is required');
  let config, store;
  try {
    const l = load(opts);
    config = l.config;
    add(true, l.exists ? `Configuration ${path.relative(process.cwd(), l.path) || l.path}` : 'Configuration: defaults', l.exists ? '' : `run "${BRAND.cli} init" to create one`);
  } catch (e) { add(false, 'Configuration', e.message.replace(/\n\s*/g, ' ')); }
  if (config) {
    store = new RuleStore({ config });
    await store.load();
    const rules = [...store.rules.values()];
    add(store.problems.length === 0, `${rules.filter((r) => r.enabled).length} rules enabled (${rules.filter((r) => r.source === 'custom').length} custom)`, store.problems.join(' | '));
    for (const u of config.upstreams) {
      const hasKey = Boolean(u.apiKey || (u.apiKeyEnv && process.env[u.apiKeyEnv]));
      add(config.auth.mode !== 'keys' || hasKey ? true : false, `Upstream ${u.name} → ${u.baseUrl}`, hasKey ? 'server-side key set' : config.auth.mode === 'keys' ? `auth.mode is "keys" but ${u.apiKeyEnv || 'apiKey'} is not set` : `callers' own keys are forwarded${u.apiKeyEnv ? ` (${u.apiKeyEnv} not set)` : ''}`);
    }
    if (!['127.0.0.1', 'localhost', '::1'].includes(config.server.host)) add(Boolean(config.server.adminToken) ? true : 'warn', `Listening on ${config.server.host}`, config.server.adminToken ? 'admin token set' : 'no server.adminToken: dashboard reachable from this machine only');
    try { fs.mkdirSync(config.dataDir, { recursive: true }); fs.accessSync(config.dataDir, fs.constants.W_OK); add(true, `Data folder ${path.relative(process.cwd(), config.dataDir) || config.dataDir}`); } catch (e) { add(false, 'Data folder', e.message); }

    const { CodeScanner } = await import('../code/engine.mjs');
    const scanner = new CodeScanner({ config, store });
    const st = await scanner.init({ warmup: false });
    if (st.external.available) {
      const t0 = Date.now();
      const r = await scanner.scan([{ id: 's0', origin: 'block', lang: 'python', ext: 'py', code: 'import os\nos.system("ls " + x)\n' }], { view: store.view(), policy: config.policy });
      const ok = r.engines.includes(st.external.kind) && r.findings.length > 0;
      add(ok ? true : 'warn', `${st.external.kind} ${st.external.version}`, ok ? `test scan ${fmtMs(Date.now() - t0)}${scanner.external.status().fastMode === false ? ' (classic mode — slow start-up)' : ''}` : `test scan failed: ${r.errors.join('; ') || 'no findings'}`);
    } else add('warn', 'Semgrep / Opengrep not found', 'built-in rules still run; install one for syntax-aware scanning (e.g. "uv tool install semgrep" or "pipx install semgrep")');
    try {
      const sc = await import('../../scanners/index.mjs');
      add(true, `Document scanners: ${sc.SUPPORTED_EXTENSIONS.length} file types`, sc.SUPPORTED_EXTENSIONS.join(' '));
    } catch (e) { add(false, 'Document scanners', e.message); }
    try {
      const api = adminClient(opts);
      const h = await api.get('/api/health');
      add(true, `Proxy running at ${api.base}`, `v${h.version}, up ${fmtMs(h.uptimeMs)}`);
    } catch { add('warn', 'Proxy is not running', `"${BRAND.cli} start"`); }
  }
  out(opts, rows, () => {
    console.log(heading(`${BRAND.name} doctor`));
    for (const r of rows) console.log(`  ${r.ok === true ? sym.ok : r.ok === 'warn' ? sym.warn : sym.fail} ${r.label}${r.detail ? c.dim(`  — ${r.detail}`) : ''}`);
    console.log('');
  });
  if (rows.some((r) => r.ok === false)) process.exitCode = 1;
}

async function cmdSetup(opts, [which = 'all']) {
  const { config } = load(opts);
  const host = ['0.0.0.0', '::'].includes(config.server.host) ? '<proxy-host>' : config.server.host;
  const base = opts.url || `http://${host}:${config.server.port}`;
  const keyed = config.auth.mode === 'keys';
  const key = keyed ? '<your Staffet key: rk_…>' : '<your provider API key>';
  const sections = {
    claude: [c.bold('Claude Code'), c.dim('  Anthropic-compatible endpoint. Set before launching `claude`:'), '',
      c.cyan(`    # bash / zsh\n    export ANTHROPIC_BASE_URL=${base}${keyed ? `\n    export ANTHROPIC_AUTH_TOKEN=${key}` : ''}`), '',
      c.cyan(`    # PowerShell\n    $env:ANTHROPIC_BASE_URL = "${base}"${keyed ? `\n    $env:ANTHROPIC_AUTH_TOKEN = "${key}"` : ''}`), '',
      c.dim('  or permanently in ~/.claude/settings.json:  { "env": { "ANTHROPIC_BASE_URL": "' + base + '" } }'),
      c.dim('  Restricted-document rules are written to .claude/rules/ in the project.')],
    cline: [c.bold('Cline'), c.dim('  Settings → API Provider: "OpenAI Compatible"'),
      `    Base URL   ${c.cyan(`${base}/v1`)}`, `    API Key    ${c.cyan(key)}`, `    Model ID   ${c.cyan('the upstream model name, e.g. gpt-4.1  (or  <upstream>/<model>  to pick an upstream)')}`,
      c.dim('  For Claude models through Cline, choose provider "Anthropic", tick "Use custom base URL" and enter ' + base),
      c.dim('  Restricted-document rules are written to .clinerules/ in the project.')],
    copilot: [c.bold('GitHub Copilot (VS Code, bring-your-own-model)'), c.dim('  Chat model picker → Manage Models → add an "OpenAI Compatible" provider (menu names vary by VS Code version)'),
      `    Base URL   ${c.cyan(`${base}/v1`)}`, `    API Key    ${c.cyan(key)}`,
      c.dim('  Only traffic sent through this custom model is inspected — Copilot\'s built-in GitHub-hosted models do not pass through the proxy.'),
      c.dim('  Restricted-document rules are written to .github/instructions/ in the project.')],
    sdk: [c.bold('Any OpenAI / Anthropic SDK or agent'),
      c.cyan(`    OPENAI_BASE_URL=${base}/v1        # OpenAI SDKs, Codex-style agents, LangChain, LiteLLM ...`), c.cyan(`    ANTHROPIC_BASE_URL=${base}        # Anthropic SDKs`),
      c.dim(`  Optional headers: x-staffet-user: <name> (label in the dashboard), x-staffet-profile: <profile>`)],
  };
  const pick = which === 'all' ? Object.keys(sections) : [which];
  console.log('');
  for (const k of pick) { if (!sections[k]) throw new Error(`unknown agent "${k}" (claude, cline, copilot, sdk)`); console.log(sections[k].join('\n') + '\n'); }
  if (keyed) console.log(c.dim(`  Create a key per developer:  ${BRAND.cli} keys create --name <name> [--profile <profile>]\n`));
}

// ───────────────────────── entry ─────────────────────────

export async function main(argv) {
  const { values: opts, positionals } = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: false });
  const [cmd, ...rest] = positionals;
  if (opts.version || cmd === 'version') return console.log(BRAND.version);
  if (opts.help || cmd === 'help') return console.log(HELP);
  if (!cmd) return cmdStart(opts); // bare `staffet` starts the proxy with defaults
  switch (cmd) {
    case 'init': return cmdInit(opts);
    case 'start': case 'serve': return cmdStart(opts);
    case 'demo': return cmdDemo(opts);
    case 'status': return cmdStatus(opts);
    case 'monitor': case 'tail': return cmdMonitor(opts);
    case 'events': return cmdEvents(opts);
    case 'requests': return cmdRequests(opts);
    case 'request': return cmdRequest(opts, rest);
    case 'rules': return cmdRules(opts, rest);
    case 'protect':
      if (!rest.length) throw new Error(`usage: ${BRAND.cli} protect <folder...>`);
      for (const folder of rest) await addRule(opts, { type: 'path', name: `Protected: ${folder}`, action: 'block', paths: [folder], severity: 'critical' });
      return;
    case 'block-domain': case 'allow-domain':
      if (!rest.length) throw new Error(`usage: ${BRAND.cli} ${cmd} <domain...>`);
      return addRule(opts, { type: 'domain', name: `${cmd === 'block-domain' ? 'Blocked' : 'Allowed'}: ${rest.join(', ')}`, action: cmd === 'block-domain' ? 'block' : 'allow', domains: rest.flatMap((d) => (d.startsWith('*.') ? [d] : [d, `*.${d}`])) });
    case 'keys': return cmdKeys(opts, rest);
    case 'test': return cmdTest(opts, rest);
    case 'scan': return cmdScan(opts, rest);
    case 'docscan': return cmdDocscan(opts, rest);
    case 'doctor': return cmdDoctor(opts);
    case 'setup': return cmdSetup(opts, rest);
    default: throw new Error(`unknown command "${cmd}" — run "${BRAND.cli} help"`);
  }
}
