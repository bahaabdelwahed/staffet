// The firewall pipeline. One instance serves all requests.
//
//   request  → redact tool outputs → withhold classified document content
//            → upstream model
//   response → guard every tool call (commands, paths, domains, documents)
//            → scan generated code (security + quality)
//            → if anything is wrong: tell the model, let it fix, repeat (bounded)
//            → rewrite / strip what is still wrong → deliver
import { BRAND } from '../brand.mjs';
import { resolvePolicy } from '../config.mjs';
import { uid, shortHash, truncate, safeJsonParse } from '../util.mjs';
import { openai } from './protocols/openai.mjs';
import { anthropic } from './protocols/anthropic.mjs';
import { expandXml, collapseXml, XML_RESULT_RE } from './protocols/xmltools.mjs';
import { parseSSE } from './sse.mjs';
import { detectHarness } from './harness.mjs';
import { Upstreams } from './upstream.mjs';
import { redactText, mergeHits } from '../guards/redactor.mjs';
import { classifyTool, extractPathArgs, extractCommand } from '../guards/toolsem.mjs';
import { extractShellPaths } from '../guards/paths.mjs';
import { evaluateToolCall, describeCall, blockFeedback } from '../guards/toolcalls.mjs';
import { DocRegistry, isDocumentPath, scanContent, withheldNotice, buildRuleWrite, verdictReason } from '../guards/documents.mjs';
import { extractSnippets } from '../code/extract.mjs';
import { scanFeedback, toolScanFeedback, SIBLING_NOT_EXECUTED, inlineNotice } from '../code/report.mjs';

export const ADAPTERS = { openai, anthropic };

const NO_SCAN = Object.freeze({ findings: [], engines: [], ms: 0, errors: [] });
const plural = (n, word, suffix = 's') => `${n} ${word}${n === 1 ? '' : suffix}`;

export class Firewall {
  constructor({ config, store, scanner, bus, registry, upstreams }) {
    this.config = config;
    this.store = store;
    this.scanner = scanner;
    this.bus = bus;
    this.registry = registry;
    this.upstreams = upstreams || new Upstreams(config);
  }

  // ───────────────────────── context ─────────────────────────
  _context(req, adapter, body, client, endpoint) {
    const policy = resolvePolicy(this.config, client.profile);
    const view = this.store.view(client.profile);
    const users = adapter.userTexts(body);
    const tools = adapter.toolDefs(body);
    const harness = detectHarness({ system: adapter.systemText(body), firstUser: users.first, lastUser: users.last, toolNames: tools.map((t) => t.name), userAgent: req.headers['user-agent'] });
    const docs = policy.documents || {};
    const id = uid('r');
    const record = {
      id, ts: Date.now(), protocol: adapter.name, endpoint,
      client: client.name, clientId: client.id, profile: client.profile || undefined,
      session: shortHash(`${client.id}|${users.first.slice(0, 400)}`, 10),
      model: adapter.model(body), upstream: null,
      harness: harness.label, harnessId: harness.id, cwd: harness.cwd || undefined,
      stream: adapter.isStream(body),
      stages: [], rounds: [], iterations: 0,
      redactions: { total: 0, rules: [] }, documents: [], notices: [],
      counts: { toolCalls: 0, toolCallsBlocked: 0, toolCallsWarned: 0, documentsBlocked: 0, scans: 0, findings: 0, findingsFixed: 0, findingsUnresolved: 0 },
      flags: {}, usage: { input: 0, output: 0 }, outcome: 'clean', status: 0,
      upstreamMs: 0, overheadMs: 0, durationMs: 0,
      preview: {},
    };
    return {
      id, adapter, client, policy, view, harness, tools, record,
      pendingDocs: [], t0: Date.now(),
      evt: { id, client: client.name, model: record.model },
      scanOpts: { extraMarkers: view.document.extraMarkers, disabledMarkers: view.document.disabledMarkers, piiThreshold: docs.piiThreshold, threshold: docs.threshold, rulesVersion: view.version },
    };
  }

  _stage(ctx, name, detail = {}) {
    ctx.record.stages.push({ name, at: Date.now() - ctx.t0, ...detail });
    this.bus.stage(ctx.record, name, detail);
  }

  // ───────────────────────── request side ─────────────────────────
  /** Redact tool outputs and withhold classified document content. Mutates `body`. */
  async inspectRequest(ctx, body) {
    const { adapter, policy, view } = ctx;
    const red = policy.redaction || {};
    const docs = policy.documents || {};
    const scopes = new Set(red.scopes || ['tool_output']);
    const hist = adapter.historyToolCalls(body);
    const segments = [];
    const binaries = [];
    adapter.walkRequest(body, { text: (s) => segments.push(s), document: (d) => binaries.push(d) });

    const hits = new Map();
    const originOf = (toolCallId) => {
      const call = toolCallId && hist.get(toolCallId);
      if (!call) return null;
      const semantic = classifyTool(call.name, call.args);
      let paths = [];
      if (semantic === 'shell') { const cmd = extractCommand(call.args); if (cmd) paths = extractShellPaths(cmd).map((p) => p.path); }
      else if (call.args && typeof call.args === 'object') paths = extractPathArgs(call.args);
      return { ...call, semantic, paths };
    };

    for (const seg of segments) {
      let text = seg.get();
      if (typeof text !== 'string' || !text) continue;
      let scope = seg.scope;
      let origin = scope === 'tool_output' ? originOf(seg.toolCallId) : null;
      if (ctx.harness.xmlTools && scope === 'user') {
        const m = XML_RESULT_RE.exec(text);
        if (m) { scope = 'tool_output'; origin = { name: m[1], semantic: classifyTool(m[1], {}), paths: m[2] ? [m[2]] : [] }; }
      }

      // classified documents: the content never reaches the model
      if (scope === 'tool_output' && docs.enabled !== false && docs.scanToolOutputs !== false && origin) {
        const docPath = origin.paths.find((p) => isDocumentPath(p, docs.extensions || []));
        const known = origin.paths.map((p) => this.registry.get(DocRegistry.key(ctx.client.id, ctx.harness.cwd, p))).find(Boolean);
        if (known && !text.startsWith(BRAND.redactionToken) && !/\bfirewall\] BLOCKED\b/.test(text)) {
          seg.set(withheldNotice(known.path, { classification: known.classification, reasons: known.reasons }, red.token));
          continue;
        }
        if (docPath && (origin.semantic === 'read' || origin.semantic === 'shell' || origin.semantic === 'other') && text.length > 20) {
          const verdict = await scanContent(text, { ...ctx.scanOpts, filename: docPath });
          if (verdict?.ok !== false && verdict?.confidential) {
            seg.set(withheldNotice(docPath, verdict, red.token));
            this._documentFound(ctx, docPath, verdict, 'content-scan');
            continue;
          }
        }
      }

      if (red.enabled !== false && scopes.has(scope)) {
        const r = redactText(text, view, { token: red.token });
        if (r.total) { seg.set(r.text); mergeHits(hits, r.hits.map((h) => ({ ...h, scope }))); }
      }
    }

    // binary documents attached to tool results (e.g. a PDF returned by a Read tool)
    if (docs.enabled !== false && docs.scanToolOutputs !== false) {
      for (const d of binaries) {
        const origin = originOf(d.toolCallId);
        const docPath = origin?.paths[0] || d.title || 'attached document';
        try {
          const verdict = await scanContent(d.data(), { ...ctx.scanOpts, filename: docPath });
          if (verdict?.ok !== false && verdict?.confidential) {
            d.replace(withheldNotice(docPath, verdict, red.token));
            this._documentFound(ctx, docPath, verdict, 'content-scan');
          }
        } catch { /* unreadable attachment: leave untouched */ }
      }
    }

    if (hits.size) {
      const rules = [...hits.values()].sort((a, b) => b.count - a.count);
      const total = rules.reduce((n, h) => n + h.count, 0);
      ctx.record.redactions = { total, rules: rules.map(({ ruleId, name, category, count, sample }) => ({ ruleId, name, category, count, sample })) };
      ctx.record.flags.redacted = true;
      // history is re-sent on every turn; only announce when the redacted set changes for this session
      const sig = `${ctx.record.session}|${rules.map((r) => `${r.ruleId}:${r.count}`).join(',')}`;
      if (this._lastRedaction?.get(ctx.record.session) !== sig) {
        (this._lastRedaction ||= new Map()).set(ctx.record.session, sig);
        if (this._lastRedaction.size > 2000) this._lastRedaction.delete(this._lastRedaction.keys().next().value);
        this.bus.emit('redaction', 'notice', `Redacted ${plural(total, 'confidential value')} before they reached the model (${rules.slice(0, 4).map((r) => `${r.name} ×${r.count}`).join(', ')})`, { total, rules: ctx.record.redactions.rules, ruleIds: rules.map((r) => r.ruleId) }, ctx.evt);
      }
    }
  }

  _documentFound(ctx, docPath, verdict, via) {
    const key = DocRegistry.key(ctx.client.id, ctx.harness.cwd, docPath);
    const known = this.registry.get(key);
    ctx.record.flags.blocked = true;
    ctx.record.flags.docBlocked = true;
    if (!ctx.record.documents.some((d) => d.path === docPath)) {
      ctx.record.documents.push({ path: docPath, classification: verdict.classification, reason: verdictReason(verdict), via, score: verdict.score });
    }
    if (known) return known;
    ctx.record.counts.documentsBlocked++;
    const entry = this.registry.add({ key, path: docPath, cwd: ctx.harness.cwd || null, client: ctx.client.name, harness: ctx.harness.id, classification: verdict.classification || 'RESTRICTED', reasons: (verdict.reasons || []).slice(0, 4), via, ruleFile: null });
    ctx.pendingDocs.push({ key, path: docPath, verdict });
    this.bus.emit('document.blocked', 'critical', `Document "${truncate(docPath, 80)}" is ${verdict.classification || 'restricted'} — content withheld from the model`, { path: docPath, classification: verdict.classification, reasons: verdict.reasons, via, ruleIds: [...new Set((verdict.findings || []).map((f) => f.markerId).filter(Boolean))].slice(0, 5) }, ctx.evt);
    return entry;
  }

  // ───────────────────────── response side ─────────────────────────
  async inspectResponse(ctx, message) {
    const { policy, view } = ctx;
    const tools = message.blocks.filter((b) => b.type === 'tool');
    for (const b of tools) b.semantic = classifyTool(b.name, b.args);
    const env = { view, policy, harness: ctx.harness, client: ctx.client, registry: this.registry, scanOpts: ctx.scanOpts };
    const evals = await Promise.all(tools.map((b) => (b.parseError
      ? { id: b.id, name: b.name, semantic: b.semantic, summary: describeCall(b, b.semantic), action: 'allow', reasons: [], warnings: [] }
      : evaluateToolCall(b, env))));

    for (const e of evals) {
      if (e.action !== 'rewrite') continue;
      e.ruleWrite = policy.documents?.writeHarnessRule !== false
        ? buildRuleWrite({ harness: ctx.harness, tools: ctx.tools, docPath: e.doc.path, verdict: e.doc.verdict, targets: policy.documents?.ruleTargets })
        : null;
      if (!e.ruleWrite) {
        // this harness cannot persist a rule: block the call and tell the model instead
        this._documentFound(ctx, e.doc.path, e.doc.verdict, e.doc.via);
        ctx.pendingDocs = ctx.pendingDocs.filter((d) => d.path !== e.doc.path);
        e.action = 'block';
      }
    }

    let snippets = [];
    let scan = NO_SCAN;
    if (policy.codeScan?.enabled !== false || policy.quality?.enabled !== false) {
      const held = new Set(evals.filter((e) => e.action !== 'allow').map((e) => e.id));
      snippets = extractSnippets(message, { codeBlocks: policy.codeScan?.scanCodeBlocks !== false, toolWrites: policy.codeScan?.scanToolWrites !== false })
        .filter((s) => !(s.toolCallId && held.has(s.toolCallId)));
      for (const s of snippets) s.blockRef = message.blocks[s.blockIndex];
      if (snippets.length) {
        this._stage(ctx, 'scan', { iteration: ctx.record.iterations, note: plural(snippets.length, 'snippet') });
        scan = await this.scanner.scan(snippets, { view, policy });
      }
    }
    return { evals, snippets, scan };
  }

  /** Feedback for the model when its turn is rejected. */
  _feedback(ctx, message, review, findings, round, maxRounds) {
    const meta = { iteration: round, maxIterations: maxRounds, engines: review.scan.engines.length ? review.scan.engines : ['builtin'] };
    const snipById = new Map(review.snippets.map((s) => [s.id, s]));
    const byCall = new Map();
    const textFindings = [];
    for (const f of findings) {
      const s = snipById.get(f.snippetId);
      if (s?.toolCallId) { if (!byCall.has(s.toolCallId)) byCall.set(s.toolCallId, []); byCall.get(s.toolCallId).push(f); }
      else textFindings.push(f);
    }
    const evalById = new Map(review.evals.map((e) => [e.id, e]));
    const toolResults = new Map();
    const userParts = [];
    const describe = (b) => {
      const e = evalById.get(b.id);
      if (e?.action === 'block') return blockFeedback(e, BRAND.name);
      if (e?.action === 'rewrite') { this._documentFound(ctx, e.doc.path, e.doc.verdict, e.doc.via); return withheldNotice(e.doc.path, e.doc.verdict, ctx.policy.redaction?.token); }
      if (byCall.has(b.id)) return toolScanFeedback(byCall.get(b.id), review.snippets, meta);
      return null;
    };
    for (const b of message.blocks) {
      if (b.type !== 'tool') continue;
      const text = describe(b);
      if (b.transport === 'xml') { if (text) userParts.push(`About your <${b.name}> tool use:\n${text}`); }
      else toolResults.set(b.id, text || SIBLING_NOT_EXECUTED);
    }
    if (textFindings.length) userParts.push(scanFeedback(textFindings, review.snippets, meta));
    return { toolResults, userText: userParts.join('\n\n') || undefined };
  }

  _recordRound(ctx, review, { iteration, upstreamMs }) {
    const rec = ctx.record;
    const findings = review.scan.findings;
    const round = {
      iteration, upstreamMs,
      toolCalls: review.evals.map((e) => ({ name: e.name, summary: e.summary, semantic: e.semantic, action: e.action, reasons: e.reasons, warnings: e.warnings })),
      scan: review.snippets.length ? { engines: review.scan.engines, ms: review.scan.ms, snippets: review.snippets.length, errors: review.scan.errors } : null,
      findings: findings.map((f) => {
        const s = review.snippets.find((x) => x.id === f.snippetId);
        return { ruleId: f.ruleId, engine: f.engine, category: f.category, severity: f.severity, message: f.message, cwe: f.cwe, line: f.line, excerpt: f.excerpt, where: s ? (s.path || `${s.lang} code block`) : undefined };
      }),
    };
    rec.rounds.push(round);
    rec.counts.toolCalls += review.evals.length;
    if (review.snippets.length) rec.counts.scans++;

    for (const e of review.evals) {
      if (e.action === 'block') {
        rec.counts.toolCallsBlocked++;
        rec.flags.blocked = true;
        const kinds = [...new Set(e.reasons.map((r) => r.kind))].join('+');
        this.bus.emit(`toolcall.blocked`, 'critical', `Blocked ${kinds} — ${truncate(e.summary, 90)}: ${e.reasons.map((r) => r.message).join('; ')}`, { call: e.summary, tool: e.name, reasons: e.reasons, iteration, ruleIds: e.reasons.map((r) => r.ruleId) }, ctx.evt);
      } else if (e.warnings.length) {
        rec.counts.toolCallsWarned++;
        rec.flags.warned = true;
        this.bus.emit('toolcall.warned', 'warning', `Risky tool call allowed — ${truncate(e.summary, 90)}: ${e.warnings.map((r) => r.message).join('; ')}`, { call: e.summary, tool: e.name, warnings: e.warnings, iteration, ruleIds: e.warnings.map((r) => r.ruleId) }, ctx.evt);
      }
    }
    if (findings.length) {
      const sec = findings.filter((f) => f.category === 'security').length;
      this.bus.emit('code.findings', sec ? 'warning' : 'notice', `Code scan (pass ${iteration + 1}): ${[sec && plural(sec, 'security issue'), findings.length - sec && plural(findings.length - sec, 'quality issue')].filter(Boolean).join(', ')} — ${[...new Set(findings.map((f) => f.ruleId))].slice(0, 4).join(', ')}`, { iteration, engines: review.scan.engines, ms: review.scan.ms, findings: round.findings, ruleIds: [...new Set(findings.map((f) => f.ruleId))] }, ctx.evt);
    }
    for (const err of review.scan.errors) this.bus.emit('scanner.error', 'warning', `Scanner problem: ${truncate(err, 160)}`, {}, ctx.evt);
    return round;
  }

  /** Apply everything that is still wrong after the loop, then inject rule writes and the notice. */
  _finalize(ctx, message, review, { rounds }) {
    const { policy, adapter } = ctx;
    const rec = ctx.record;
    const notices = [];
    const drop = new Set();
    const snipById = new Map(review.snippets.map((s) => [s.id, s]));

    for (const e of review.evals) {
      if (e.action !== 'block') continue;
      drop.add(e.id);
      notices.push(`Blocked tool call \`${truncate(e.summary, 100)}\` — ${e.reasons.map((r) => r.message).join('; ')}.`);
    }

    const unresolved = (findings, mode, label) => {
      if (!findings.length) return;
      rec.counts.findingsUnresolved += findings.length;
      rec.flags.unresolved = true;
      this.bus.emit('code.unresolved', 'critical', `${plural(findings.length, `${label} issue`)} could not be fixed after ${plural(rounds, 'attempt')} — ${mode === 'block' ? 'code withheld' : mode === 'annotate' ? 'delivered with a warning' : 'delivered'}`, { mode, findings: findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, line: f.line, message: f.message })), ruleIds: [...new Set(findings.map((f) => f.ruleId))] }, ctx.evt);
      if (mode === 'allow') return;
      const list = findings.slice(0, 6).map((f) => `${f.ruleId}${f.cwe ? ` (${f.cwe})` : ''} line ${f.line}: ${f.message}`);
      notices.push(`${plural(findings.length, `${label} issue`)} remained after ${plural(rounds, 'automatic fix attempt')}${mode === 'block' ? ' — the affected code was withheld' : ''}:`, ...list.map((l) => `  ${l}`));
      if (mode !== 'block') return;
      rec.flags.blocked = true;
      const textEdits = new Map();
      for (const f of findings) {
        const s = snipById.get(f.snippetId);
        if (!s) continue;
        if (s.toolCallId) drop.add(s.toolCallId);
        else if (s.blockRef) { if (!textEdits.has(s.blockRef)) textEdits.set(s.blockRef, new Map()); textEdits.get(s.blockRef).set(s.id, s); }
      }
      for (const [block, snips] of textEdits) {
        for (const s of [...snips.values()].sort((a, b) => b.start - a.start)) {
          block.text = `${block.text.slice(0, s.start)}[code withheld by the ${BRAND.name} firewall: unresolved ${label} issues]${block.text.slice(s.end)}`;
          block.dirty = true;
        }
      }
    };
    unresolved(review.scan.findings.filter((f) => f.category === 'security'), policy.codeScan?.onUnresolved || 'block', 'security');
    unresolved(review.scan.findings.filter((f) => f.category === 'quality'), policy.quality?.onUnresolved || 'annotate', 'code-quality');

    // classified document: overwrite the tool call with one that records the rule in the harness
    const ruleCall = (rw) => ({ type: 'tool', id: adapter.newToolId('rule'), name: rw.name, args: rw.args, dirty: true, synthetic: true, ...(rw.xml ? { transport: 'xml' } : {}) });
    const injected = [];
    for (const e of review.evals) {
      if (e.action !== 'rewrite') continue;
      const entry = this._documentFound(ctx, e.doc.path, e.doc.verdict, e.doc.via);
      ctx.pendingDocs = ctx.pendingDocs.filter((d) => d.key !== entry.key);
      const idx = message.blocks.findIndex((b) => b.type === 'tool' && b.id === e.id);
      if (e.ruleWrite && idx >= 0) {
        message.blocks[idx] = ruleCall(e.ruleWrite);
        injected.push(message.blocks[idx]);
        this.registry.update(entry.key, { ruleFile: e.ruleWrite.ruleFile });
        notices.push(`Document \`${truncate(e.doc.path, 100)}\` is ${e.doc.verdict.classification || 'restricted'} — the request was replaced by a rule (\`${e.ruleWrite.ruleFile}\`) forbidding access.`);
        this.bus.emit('document.rule', 'warning', `Tool call rewritten: ${ctx.harness.label} is now writing ${e.ruleWrite.ruleFile} (never open "${truncate(e.doc.path, 60)}")`, { path: e.doc.path, ruleFile: e.ruleWrite.ruleFile, tool: e.ruleWrite.name }, ctx.evt);
      } else {
        drop.add(e.id);
        notices.push(`Document \`${truncate(e.doc.path, 100)}\` is ${e.doc.verdict.classification || 'restricted'} — access blocked.`);
      }
    }
    // documents discovered from their content (or earlier in the loop): add the rule-writing call
    for (const d of ctx.pendingDocs) {
      const rw = policy.documents?.writeHarnessRule !== false
        ? buildRuleWrite({ harness: ctx.harness, tools: ctx.tools, docPath: d.path, verdict: d.verdict, targets: policy.documents?.ruleTargets })
        : null;
      if (rw) {
        const call = ruleCall(rw);
        message.blocks.push(call);
        injected.push(call);
        this.registry.update(d.key, { ruleFile: rw.ruleFile });
        this.bus.emit('document.rule', 'warning', `Rule injected: ${ctx.harness.label} is now writing ${rw.ruleFile} (never open "${truncate(d.path, 60)}")`, { path: d.path, ruleFile: rw.ruleFile, tool: rw.name }, ctx.evt);
      }
      notices.push(`Document \`${truncate(d.path, 100)}\` is ${d.verdict.classification || 'restricted'} — its content was withheld${rw ? ` and a rule (\`${rw.ruleFile}\`) forbids opening it again` : ''}.`);
    }
    ctx.pendingDocs = [];

    message.blocks = message.blocks.filter((b) => !(b.type === 'tool' && drop.has(b.id)));
    // XML tool protocol executes one tool per message: ours goes first, the model re-issues the rest
    if (ctx.harness.xmlTools && injected.length) {
      message.blocks = [...message.blocks.filter((b) => b.type !== 'tool'), injected[0]];
    }

    const hasContent = message.blocks.some((b) => (b.type === 'text' && b.text.trim()) || b.type === 'tool');
    if (notices.length && (policy.notifyInline !== false || !hasContent)) {
      const firstTool = message.blocks.findIndex((b) => b.type === 'tool');
      const note = { type: 'text', text: inlineNotice(notices), dirty: true };
      if (firstTool < 0) message.blocks.push(note); else message.blocks.splice(firstTool, 0, note);
    }
    rec.notices = notices;
    return message;
  }

  // ───────────────────────── orchestration ─────────────────────────
  /**
   * Full inspection of a chat / messages request.
   * @param {object} io  { req, res, body, client, endpoint, suffix, search }
   */
  async handleInference({ req, res, body, client, protocol, endpoint, suffix, search = '' }) {
    const adapter = ADAPTERS[protocol];
    const invalid = adapter.validate(body);
    if (invalid) return sendJson(res, 400, adapter.errorBody(400, invalid));

    const ctx = this._context(req, adapter, body, client, endpoint);
    const rec = ctx.record;
    const policy = ctx.policy;
    const abort = new AbortController();
    let keepAlive = null;
    let committed = false;
    res.on('close', () => { if (!res.writableEnded) abort.abort(); });
    this.bus.requestStart(rec);

    const commitStream = (headers = {}) => {
      if (committed || !rec.stream) return;
      committed = true;
      res.writeHead(200, { ...headers, 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache, no-transform', connection: 'keep-alive', 'x-accel-buffering': 'no', 'x-staffet-request-id': rec.id });
      res.write(adapter.keepAlive());
      keepAlive = setInterval(() => { if (!res.writableEnded) res.write(adapter.keepAlive()); }, 5000);
    };

    try {
      const route = this.upstreams.pick(protocol, rec.model || '');
      if (!route) throw httpError(502, `no upstream configured for the ${protocol} protocol`);
      rec.upstream = route.upstream.name;
      if (route.model !== rec.model) adapter.setModel(body, route.model);
      const headers = this.upstreams.headers(req.headers, route.upstream, { requireKey: this.config.auth.mode === 'keys' });

      this._stage(ctx, 'inspect-request');
      const tIn = Date.now();
      await this.inspectRequest(ctx, body);
      let overhead = Date.now() - tIn;
      rec.preview.user = this._preview(ctx, adapter.userTexts(body).last);

      const maxRounds = Math.max(0, policy.loop?.maxIterations ?? 3);
      const qualRounds = Math.max(0, policy.quality?.maxIterations ?? 2);
      let working = body;
      let iteration = 0;
      let wire, message, review, upstreamHeaders = {};
      let firstFindings = null;

      for (;;) {
        this._stage(ctx, 'upstream', { iteration, note: iteration ? `fix attempt ${iteration}` : undefined });
        const tUp = Date.now();
        let resp;
        try {
          resp = await this.upstreams.fetch(route.upstream, suffix, { headers, body: JSON.stringify(working), signal: abort.signal, search });
        } catch (e) {
          if (iteration === 0) throw httpError(502, `upstream "${route.upstream.name}" is unreachable: ${e.cause?.message || e.message}`, 'api_error');
          this.bus.emit('upstream.error', 'warning', `Fix attempt ${iteration} failed (upstream unreachable) — keeping the previous answer`, {}, ctx.evt);
          break;
        }
        if (!resp.ok) {
          const text = await resp.text().catch(() => '');
          if (iteration === 0) {
            rec.status = resp.status;
            rec.outcome = 'error';
            rec.error = truncate(text, 400);
            this.bus.emit('upstream.error', 'warning', `Upstream ${route.upstream.name} answered ${resp.status}`, { status: resp.status, body: truncate(text, 400) }, ctx.evt);
            res.writeHead(resp.status, { ...Upstreams.relayHeaders(resp), 'x-staffet-request-id': rec.id });
            res.end(text);
            return;
          }
          this.bus.emit('upstream.error', 'warning', `Fix attempt ${iteration} failed (upstream ${resp.status}) — keeping the previous answer`, { status: resp.status }, ctx.evt);
          break;
        }
        if (iteration === 0) { upstreamHeaders = Upstreams.relayHeaders(resp); commitStream(upstreamHeaders); }

        let w;
        try {
          const isSse = /text\/event-stream/i.test(resp.headers.get('content-type') || '');
          w = isSse ? await adapter.accumulate(parseSSE(resp.body)) : await resp.json();
        } catch (e) {
          if (abort.signal.aborted) throw e;
          if (iteration === 0) throw httpError(502, `upstream "${route.upstream.name}" sent an unreadable response: ${e.message}`, 'api_error');
          break;
        }
        const upMs = Date.now() - tUp;
        rec.upstreamMs += upMs;

        const tInspect = Date.now();
        const msg = adapter.decode(w);
        if (ctx.harness.xmlTools) expandXml(msg);
        rec.usage.input += msg.usage.input;
        rec.usage.output += msg.usage.output;
        this._stage(ctx, 'inspect-response', { iteration });
        const rv = await this.inspectResponse(ctx, msg);
        this._recordRound(ctx, rv, { iteration, upstreamMs: upMs });
        overhead += Date.now() - tInspect;
        wire = w; message = msg; review = rv;
        if (iteration > 0) overhead += upMs;        // extra model round-trips are firewall overhead too

        const sec = rv.scan.findings.filter((f) => f.category === 'security');
        const qual = rv.scan.findings.filter((f) => f.category === 'quality');
        firstFindings ??= rv.scan.findings.length;
        const loopFindings = [...sec, ...(iteration < qualRounds ? qual : [])];
        const blocked = rv.evals.filter((e) => e.action === 'block');
        const wantsLoop = blocked.length > 0 || loopFindings.length > 0;
        if (!wantsLoop || iteration >= maxRounds || msg.stop === 'length' || msg.stop === 'filter') break;

        const fb = this._feedback(ctx, msg, rv, loopFindings, iteration + 1, maxRounds);
        working = adapter.followup(working, w, fb);
        iteration++;
        rec.iterations = iteration;
        this._stage(ctx, 'fix-loop', { iteration, note: [blocked.length && plural(blocked.length, 'blocked call'), loopFindings.length && plural(loopFindings.length, 'finding')].filter(Boolean).join(', ') });
      }

      // ── finalize ──
      const tFin = Date.now();
      const remaining = review.scan.findings.length;
      if (iteration > 0 && firstFindings) {
        const fixed = Math.max(0, firstFindings - remaining);
        rec.counts.findingsFixed = fixed;
        if (fixed) {
          rec.flags.fixed = true;
          this.bus.emit('code.fixed', 'notice', `${plural(fixed, 'code issue')} fixed by the model after ${plural(iteration, 'review pass', 'es')}${remaining ? ` (${remaining} remaining)` : ''}`, { fixed, remaining, iterations: iteration }, ctx.evt);
        }
      }
      rec.counts.findings = firstFindings || 0;
      this._finalize(ctx, message, review, { rounds: iteration });
      if (ctx.harness.xmlTools) collapseXml(message);
      const finalWire = adapter.encode(wire, message);
      overhead += Date.now() - tFin;

      rec.preview.assistant = this._preview(ctx, message.blocks.filter((b) => b.type === 'text').map((b) => b.text).join('\n'));
      rec.preview.toolCalls = message.blocks.filter((b) => b.type === 'tool').map((b) => truncate(describeCall(b, b.semantic || classifyTool(b.name, b.args)), 120)).slice(0, 12);
      rec.outcome = rec.flags.blocked ? 'blocked' : (rec.flags.redacted || rec.flags.fixed || rec.flags.unresolved) ? 'sanitized' : 'clean';
      rec.status = 200;
      rec.overheadMs = overhead;

      this._stage(ctx, 'deliver');
      if (rec.stream) {
        commitStream(upstreamHeaders);
        clearInterval(keepAlive);
        for (const frame of adapter.streamEvents(finalWire, { includeUsage: adapter.wantsUsage(body) })) res.write(frame);
        res.end();
      } else {
        sendJson(res, 200, finalWire, { ...upstreamHeaders, 'x-staffet-request-id': rec.id, 'x-staffet-outcome': rec.outcome });
      }
    } catch (e) {
      clearInterval(keepAlive);
      if (abort.signal.aborted) {
        rec.outcome = 'error'; rec.status = 499; rec.error = 'client disconnected';
      } else {
        const status = e.status || 500;
        rec.outcome = 'error'; rec.status = status; rec.error = e.message;
        this.bus.emit('proxy.error', 'warning', `Request failed: ${truncate(e.message, 200)}`, { status }, ctx.evt);
        if (committed) { if (!res.writableEnded) { res.write(adapter.streamError(e.message)); res.end(); } }
        else if (!res.headersSent) sendJson(res, status, adapter.errorBody(status, e.message, e.type || 'api_error'));
      }
    } finally {
      clearInterval(keepAlive);
      rec.durationMs = Date.now() - ctx.t0;
      this.bus.emit('request.completed', rec.outcome === 'blocked' ? 'warning' : 'info',
        `${rec.model || 'model'} · ${rec.harness} · ${rec.outcome}${rec.iterations ? ` · ${plural(rec.iterations, 'fix loop')}` : ''}`,
        { outcome: rec.outcome, status: rec.status, durationMs: rec.durationMs, overheadMs: rec.overheadMs, iterations: rec.iterations, redactions: rec.redactions.total, flags: rec.flags }, ctx.evt);
      this.bus.requestEnd(rec);
    }
  }

  /** Endpoints that send the conversation upstream but return no model output (e.g. count_tokens). */
  async handleRequestOnly({ req, res, body, client, protocol, endpoint, suffix, search = '' }) {
    const adapter = ADAPTERS[protocol];
    if (adapter.validate(body)) return this.passthrough({ req, res, protocol, suffix, search, rawBody: Buffer.from(JSON.stringify(body)) });
    const ctx = this._context(req, adapter, body, client, endpoint);
    const route = this.upstreams.pick(protocol, ctx.record.model || '');
    if (!route) return sendJson(res, 502, adapter.errorBody(502, `no upstream configured for the ${protocol} protocol`));
    if (route.model !== ctx.record.model) adapter.setModel(body, route.model);
    await this.inspectRequest(ctx, body);
    return this.passthrough({ req, res, protocol, suffix, search, rawBody: Buffer.from(JSON.stringify(body)), upstream: route.upstream });
  }

  /** Transparent relay for endpoints without model traffic to inspect (models list, embeddings ...). */
  async passthrough({ req, res, protocol, suffix, search = '', rawBody, upstream }) {
    const adapter = ADAPTERS[protocol];
    const up = upstream || this.upstreams.byProtocol(protocol)[0];
    if (!up) return sendJson(res, 502, adapter.errorBody(502, `no upstream configured for the ${protocol} protocol`));
    try {
      const headers = this.upstreams.headers(req.headers, up, { requireKey: this.config.auth.mode === 'keys' });
      const hasBody = !['GET', 'HEAD'].includes(req.method);
      const resp = await this.upstreams.fetch(up, suffix, { method: req.method, headers, body: hasBody ? rawBody : undefined, search });
      res.writeHead(resp.status, Upstreams.relayHeaders(resp));
      if (resp.body) for await (const chunk of resp.body) res.write(chunk);
      res.end();
    } catch (e) {
      if (!res.headersSent) sendJson(res, e.status || 502, adapter.errorBody(502, `upstream "${up.name}" is unreachable: ${e.cause?.message || e.message}`, 'api_error'));
      else res.end();
    }
  }

  _preview(ctx, text) {
    const mode = this.config.logging?.capture || 'preview';
    if (mode === 'none' || !text) return undefined;
    const limit = mode === 'full' ? 20000 : 400;
    // audit logs never store raw secrets, whatever the redaction scopes are
    return redactText(String(text).slice(0, limit), ctx.view, { token: ctx.policy.redaction?.token }).text;
  }
}

export function httpError(status, message, type) {
  const e = new Error(message);
  e.status = status;
  e.type = type;
  return e;
}

export function sendJson(res, status, obj, headers = {}) {
  const buf = Buffer.from(JSON.stringify(obj));
  const h = { ...headers, 'content-type': 'application/json; charset=utf-8', 'content-length': buf.length };
  res.writeHead(status, h);
  res.end(buf);
}

export { safeJsonParse };
