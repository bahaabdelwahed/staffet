// Event bus: live state for the dashboard / CLI, rolling statistics, JSONL audit log.
import fs from 'node:fs';
import path from 'node:path';
import { uid } from '../util.mjs';

const MAX_EVENTS = 3000;
const MAX_REQUESTS = 1000;
const MINUTE = 60_000;

const day = (t = Date.now()) => new Date(t).toISOString().slice(0, 10);

const emptyTotals = () => ({
  requests: 0, clean: 0, sanitized: 0, blocked: 0, error: 0,
  redactions: 0, toolCallsBlocked: 0, toolCallsWarned: 0, documentsBlocked: 0,
  scans: 0, findings: 0, findingsFixed: 0, findingsUnresolved: 0, fixLoops: 0,
  tokensIn: 0, tokensOut: 0, overheadMs: 0, durationMs: 0,
});

export class EventBus {
  constructor({ dataDir, retentionDays = 30, persist = true } = {}) {
    this.dataDir = dataDir;
    this.persist = persist && Boolean(dataDir);
    this.retentionDays = retentionDays;
    this.startedAt = Date.now();
    this.events = [];
    this.requests = [];
    this.inflight = new Map();
    this.subscribers = new Set();
    this.totals = emptyTotals();
    this.minutes = new Map();            // minute timestamp -> {clean, sanitized, blocked, error}
    this.ruleHits = new Map();           // rule id -> count
    this.byClient = new Map();
    this.byModel = new Map();
    this.byHarness = new Map();
    this.streams = {};
    if (this.persist) {
      try { fs.mkdirSync(dataDir, { recursive: true }); } catch { this.persist = false; }
    }
  }

  // ───────────── persistence ─────────────
  _append(kind, obj) {
    if (!this.persist) return;
    const file = path.join(this.dataDir, `${kind}-${day()}.jsonl`);
    let s = this.streams[kind];
    if (!s || s.file !== file) {
      s?.stream.end();
      s = this.streams[kind] = { file, stream: fs.createWriteStream(file, { flags: 'a' }) };
      s.stream.on('error', () => { this.persist = false; });
    }
    s.stream.write(JSON.stringify(obj) + '\n');
  }

  /** Reload today's history so a restart does not blank the dashboard; prune old logs. */
  loadHistory() {
    if (!this.persist) return;
    try {
      const cutoff = Date.now() - this.retentionDays * 86_400_000;
      for (const f of fs.readdirSync(this.dataDir)) {
        const m = /^(?:events|requests)-(\d{4}-\d{2}-\d{2})\.jsonl$/.exec(f);
        if (m && new Date(m[1]).getTime() < cutoff) fs.rmSync(path.join(this.dataDir, f), { force: true });
      }
      const read = (kind) => {
        const file = path.join(this.dataDir, `${kind}-${day()}.jsonl`);
        if (!fs.existsSync(file)) return [];
        return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
      };
      for (const r of read('requests')) this._account(r);
      this.requests = read('requests').slice(-MAX_REQUESTS);
      this.events = read('events').slice(-MAX_EVENTS);
    } catch { /* history is a convenience */ }
  }

  close() {
    for (const s of Object.values(this.streams)) s.stream.end();
  }

  // ───────────── publish ─────────────
  subscribe(fn) {
    this.subscribers.add(fn);
    return () => this.subscribers.delete(fn);
  }

  _publish(msg) {
    for (const fn of this.subscribers) { try { fn(msg); } catch { /* a broken subscriber must not break traffic */ } }
  }

  /**
   * @param {string} type      e.g. redaction, toolcall.blocked, code.findings, document.blocked, request.completed
   * @param {'info'|'notice'|'warning'|'critical'} severity
   * @param {string} summary   one line, human readable
   */
  emit(type, severity, summary, data = {}, ctx = null) {
    const ev = { id: uid('e'), ts: Date.now(), type, severity, summary, requestId: ctx?.id, client: ctx?.client, model: ctx?.model, data };
    this.events.push(ev);
    if (this.events.length > MAX_EVENTS) this.events.splice(0, this.events.length - MAX_EVENTS);
    for (const id of data.ruleIds || []) this.ruleHits.set(id, (this.ruleHits.get(id) || 0) + 1);
    this._append('events', ev);
    this._publish({ kind: 'event', event: ev });
    return ev;
  }

  requestStart(rec) {
    this.inflight.set(rec.id, { id: rec.id, startedAt: rec.ts, client: rec.client, model: rec.model, harness: rec.harness, protocol: rec.protocol, stream: rec.stream, stage: 'received', iteration: 0 });
    this._publish({ kind: 'inflight', inflight: this.inflight.get(rec.id) });
  }

  stage(rec, stage, detail = {}) {
    const f = this.inflight.get(rec.id);
    if (!f) return;
    f.stage = stage;
    if (detail.iteration != null) f.iteration = detail.iteration;
    if (detail.note) f.note = detail.note;
    if (rec.model) f.model = rec.model;
    if (rec.harness) f.harness = rec.harness;
    this._publish({ kind: 'inflight', inflight: f });
  }

  requestEnd(rec) {
    this.inflight.delete(rec.id);
    this._account(rec);
    this.requests.push(rec);
    if (this.requests.length > MAX_REQUESTS) this.requests.splice(0, this.requests.length - MAX_REQUESTS);
    this._append('requests', rec);
    this._publish({ kind: 'request', request: summarise(rec), done: rec.id });
  }

  _account(rec) {
    const t = this.totals;
    t.requests++;
    t[rec.outcome] = (t[rec.outcome] || 0) + 1;
    t.redactions += rec.redactions?.total || 0;
    t.toolCallsBlocked += rec.counts?.toolCallsBlocked || 0;
    t.toolCallsWarned += rec.counts?.toolCallsWarned || 0;
    t.documentsBlocked += rec.counts?.documentsBlocked || 0;
    t.scans += rec.counts?.scans || 0;
    t.findings += rec.counts?.findings || 0;
    t.findingsFixed += rec.counts?.findingsFixed || 0;
    t.findingsUnresolved += rec.counts?.findingsUnresolved || 0;
    t.fixLoops += rec.iterations || 0;
    t.tokensIn += rec.usage?.input || 0;
    t.tokensOut += rec.usage?.output || 0;
    t.overheadMs += rec.overheadMs || 0;
    t.durationMs += rec.durationMs || 0;
    const minute = Math.floor(rec.ts / MINUTE) * MINUTE;
    const b = this.minutes.get(minute) || { clean: 0, sanitized: 0, blocked: 0, error: 0 };
    b[rec.outcome] = (b[rec.outcome] || 0) + 1;
    this.minutes.set(minute, b);
    if (this.minutes.size > 1500) {
      const cutoff = Date.now() - 25 * 60 * MINUTE;
      for (const k of this.minutes.keys()) if (k < cutoff) this.minutes.delete(k);
    }
    const bump = (map, key) => { if (key) map.set(key, (map.get(key) || 0) + 1); };
    bump(this.byClient, rec.client);
    bump(this.byModel, rec.model);
    bump(this.byHarness, rec.harness);
  }

  // ───────────── queries ─────────────
  /** Per-minute outcome counts for the last `minutes` minutes (zero-filled). */
  series(minutes = 60) {
    const now = Math.floor(Date.now() / MINUTE) * MINUTE;
    const out = [];
    for (let i = minutes - 1; i >= 0; i--) {
      const t = now - i * MINUTE;
      const b = this.minutes.get(t) || { clean: 0, sanitized: 0, blocked: 0, error: 0 };
      out.push({ t, clean: b.clean || 0, sanitized: b.sanitized || 0, blocked: b.blocked || 0, error: b.error || 0 });
    }
    return out;
  }

  overview({ minutes = 60 } = {}) {
    const top = (map, n = 8) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([name, count]) => ({ name, count }));
    const t = this.totals;
    return {
      startedAt: this.startedAt,
      now: Date.now(),
      totals: { ...t, avgOverheadMs: t.requests ? Math.round(t.overheadMs / t.requests) : 0, avgDurationMs: t.requests ? Math.round(t.durationMs / t.requests) : 0 },
      series: this.series(minutes),
      inflight: [...this.inflight.values()],
      topRules: top(this.ruleHits, 10),
      clients: top(this.byClient),
      models: top(this.byModel),
      harnesses: top(this.byHarness),
    };
  }

  recentEvents({ limit = 200, type, severity, requestId } = {}) {
    let list = this.events;
    if (type) list = list.filter((e) => e.type === type || e.type.startsWith(type + '.'));
    if (severity) list = list.filter((e) => e.severity === severity);
    if (requestId) list = list.filter((e) => e.requestId === requestId);
    return list.slice(-limit).reverse();
  }

  recentRequests({ limit = 200, outcome, q } = {}) {
    let list = this.requests;
    if (outcome) list = list.filter((r) => r.outcome === outcome);
    if (q) {
      const s = q.toLowerCase();
      list = list.filter((r) => [r.client, r.model, r.harness, r.id, r.preview?.user].some((v) => String(v || '').toLowerCase().includes(s)));
    }
    return list.slice(-limit).reverse().map(summarise);
  }

  getRequest(id) {
    return this.requests.find((r) => r.id === id) || null;
  }
}

/** Row shape for request tables (the full record is fetched on demand). */
export function summarise(r) {
  return {
    id: r.id, ts: r.ts, client: r.client, model: r.model, harness: r.harness, protocol: r.protocol, stream: r.stream,
    outcome: r.outcome, flags: r.flags, status: r.status, iterations: r.iterations,
    redactions: r.redactions?.total || 0, counts: r.counts, durationMs: r.durationMs, overheadMs: r.overheadMs,
    usage: r.usage, preview: r.preview?.user ? { user: r.preview.user.slice(0, 140) } : undefined,
  };
}
