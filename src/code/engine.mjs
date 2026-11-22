// Code scanning orchestration: built-in rules + Semgrep/Opengrep, cached per snippet.
import { LRU, sha1 } from '../util.mjs';
import { runBuiltin } from './builtin.mjs';
import { ExternalScanner } from './semgrep.mjs';

const RANK = { info: 0, warning: 1, error: 2 };
// languages the external engine can parse; others are covered by the built-in rules only
const EXTERNAL_LANGS = new Set(['python', 'javascript', 'typescript', 'java', 'go', 'c', 'cpp', 'csharp', 'php', 'ruby', 'shell', 'kotlin', 'swift', 'rust', 'scala', 'yaml', 'json', 'terraform', 'html', 'lua', 'dart', 'dockerfile']);

export class CodeScanner {
  constructor({ config, store }) {
    this.config = config;
    this.store = store;
    const cs = config.policy.codeScan;
    this.external = new ExternalScanner({ engine: cs.engine, binary: cs.binary || undefined, timeoutMs: cs.timeoutMs, maxConcurrent: cs.maxConcurrent });
    this.cache = new LRU(800);
    this.stats = { scans: 0, cacheHits: 0, externalMs: 0, externalRuns: 0 };
  }

  async init({ warmup = true } = {}) {
    await this.external.detect();
    if (this.external.available && warmup) {
      // first run pays for interpreter start-up and rule parsing; do it before real traffic arrives
      const dirs = this.store.semgrepDirs();
      this.external.scan([{ id: 'warm', code: 'x = 1\n', lang: 'python', ext: 'py' }], [...dirs.security, ...dirs.quality]).catch(() => {});
    }
    return this.status();
  }

  status() {
    const ext = this.external.status();
    return { engines: ['builtin', ...(ext.available ? [ext.kind] : [])], external: ext, stats: this.stats };
  }

  /**
   * @param {Array} snippets       from extractSnippets()
   * @param {{view: object, policy: object}} ctx
   * @returns {Promise<{findings: Array, engines: string[], ms: number, errors: string[]}>}
   */
  async scan(snippets, { view, policy }) {
    const t0 = Date.now();
    const doSec = policy.codeScan?.enabled !== false;
    const doQual = policy.quality?.enabled !== false;
    const errors = [];
    if (!snippets.length || (!doSec && !doQual)) return { findings: [], engines: [], ms: 0, errors };
    this.stats.scans++;

    const flags = `${view.version}|${doSec}|${doQual}|${this.external.available}|${(policy.codeScan?.extraConfigs || []).join(',')}`;
    const keyOf = (s) => `${flags}|${s.lang}|${sha1(s.code)}`;
    const fresh = [];
    const findings = [];
    const engines = new Set(['builtin']);
    for (const s of snippets) {
      const hit = this.cache.get(keyOf(s));
      if (hit) {
        this.stats.cacheHits++;
        findings.push(...hit.findings.map((f) => ({ ...f, snippetId: s.id })));
        for (const e of hit.engines) engines.add(e);       // report the engines that produced the cached verdict
      } else fresh.push(s);
    }

    if (fresh.length) {
      const rules = [...(doSec ? view.code : []), ...(doQual ? view.quality : [])];
      const builtin = runBuiltin(fresh, rules);

      let external = [];
      const ranOn = new Set();
      if (this.external.available) {
        const dirs = this.store.semgrepDirs();
        const configs = [...(doSec ? dirs.security : []), ...(doQual ? dirs.quality : []), ...(doSec ? policy.codeScan?.extraConfigs || [] : [])];
        const targets = fresh.filter((s) => EXTERNAL_LANGS.has(s.lang) && s.ext);
        if (configs.length && targets.length) {
          const r = await this.external.scan(targets, configs);
          this.stats.externalRuns++;
          this.stats.externalMs += r.ms;
          if (r.error) errors.push(`${this.external.kind}: ${r.error}`);
          else { engines.add(this.external.kind); for (const s of targets) ranOn.add(s.id); }
          external = r.findings.filter((f) => (f.category === 'quality' ? doQual : doSec));
        }
      }

      const merged = dedupe([...external, ...builtin]);
      for (const s of fresh) {
        const mine = merged.filter((f) => f.snippetId === s.id);
        if (!errors.length) this.cache.set(keyOf(s), { findings: mine, engines: ranOn.has(s.id) ? ['builtin', this.external.kind] : ['builtin'] });
        findings.push(...mine);
      }
    }

    const minSec = RANK[policy.codeScan?.minSeverity] ?? 1;
    const minQual = RANK[policy.quality?.minSeverity] ?? 1;
    const kept = findings.filter((f) => (RANK[f.severity] ?? 1) >= (f.category === 'quality' ? minQual : minSec));
    kept.sort((a, b) => (RANK[b.severity] - RANK[a.severity]) || a.snippetId.localeCompare(b.snippetId) || a.line - b.line);
    return { findings: kept, engines: [...engines], ms: Date.now() - t0, errors };
  }
}

/** The external engine and the built-in rules often flag the same line for the same weakness — keep one. */
function dedupe(findings) {
  const seen = new Map();
  const out = [];
  for (const f of findings) {
    const key = `${f.snippetId}|${f.line}|${f.category}|${f.cwe || f.ruleId.split('.').pop()}`;
    if (seen.has(key)) continue;
    seen.set(key, true);
    out.push(f);
  }
  return out;
}
