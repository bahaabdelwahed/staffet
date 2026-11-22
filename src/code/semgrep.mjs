// External scanner: Semgrep or Opengrep (same rule format, same JSON output).
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { BRAND } from '../brand.mjs';
import { Semaphore } from '../util.mjs';

const SEV = { ERROR: 'error', CRITICAL: 'error', HIGH: 'error', WARNING: 'warning', MEDIUM: 'warning', INFO: 'info', LOW: 'info' };

function run(bin, args, { timeoutMs = 30000, env } = {}) {
  return new Promise((resolve) => {
    let out = '', err = '', done = false;
    let child;
    try {
      child = spawn(bin, args, { env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    } catch (e) { resolve({ code: -1, out, err: e.message, spawnError: true }); return; }
    const timer = setTimeout(() => { if (!done) { done = true; child.kill('SIGKILL'); resolve({ code: -1, out, err: err + '\ntimeout', timedOut: true }); } }, timeoutMs);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { if (err.length < 20000) err += d; });
    child.on('error', (e) => { if (!done) { done = true; clearTimeout(timer); resolve({ code: -1, out, err: e.message, spawnError: true }); } });
    child.on('close', (code) => { if (!done) { done = true; clearTimeout(timer); resolve({ code, out, err }); } });
  });
}

export class ExternalScanner {
  /**
   * @param {{engine?: 'auto'|'semgrep'|'opengrep'|'builtin', binary?: string, timeoutMs?: number, maxConcurrent?: number}} opts
   */
  constructor(opts = {}) {
    this.opts = opts;
    this.available = false;
    this.kind = null;            // 'semgrep' | 'opengrep'
    this.binary = null;
    this.version = null;
    this.experimental = true;    // semgrep: native (osemgrep) code path — ~10x faster start-up
    this.lastError = null;
    this.sem = new Semaphore(opts.maxConcurrent || 4);
    this.env = { ...process.env, PYTHONUTF8: '1', PYTHONIOENCODING: 'utf-8', SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0', NO_COLOR: '1' };
  }

  async detect() {
    const engine = this.opts.engine || 'auto';
    if (engine === 'builtin') return this.status();
    const candidates = this.opts.binary ? [this.opts.binary] : engine === 'opengrep' ? ['opengrep'] : engine === 'semgrep' ? ['semgrep'] : ['semgrep', 'opengrep'];
    for (const bin of candidates) {
      const r = await run(bin, ['--version'], { timeoutMs: 60000, env: this.env });
      const v = /(\d+\.\d+\.\d+)/.exec(r.out + r.err)?.[1];
      if (r.code === 0 && v) {
        this.available = true;
        this.binary = bin;
        this.version = v;
        this.kind = /opengrep/i.test(bin) || /opengrep/i.test(r.out + r.err) ? 'opengrep' : 'semgrep';
        break;
      }
    }
    return this.status();
  }

  status() {
    return { available: this.available, kind: this.kind, binary: this.binary, version: this.version, fastMode: this.kind === 'semgrep' ? this.experimental : null, lastError: this.lastError };
  }

  _args(configs, target, experimental) {
    const cfg = configs.flatMap((c) => ['--config', c]);
    if (this.kind === 'opengrep') return ['scan', ...cfg, '--json', '--quiet', '--no-git-ignore', '--timeout', '10', target];
    return ['scan', ...(experimental ? ['--experimental'] : []), ...cfg, '--json', '--quiet', '--metrics=off', '--disable-version-check', '--no-git-ignore', '--timeout', '10', target];
  }

  /**
   * @param {Array<{id, code, lang, ext}>} snippets
   * @param {string[]} configs   rule directories / files / registry packs
   * @returns {Promise<{findings: Array, ms: number, error?: string}>}
   */
  async scan(snippets, configs) {
    if (!this.available || !snippets.length || !configs.length) return { findings: [], ms: 0 };
    return this.sem.run(async () => {
      const t0 = Date.now();
      const dir = await fs.mkdtemp(path.join(os.tmpdir(), `${BRAND.slug}-scan-`));
      const byFile = new Map();
      try {
        await Promise.all(snippets.map((s, i) => {
          const name = s.lang === 'dockerfile' ? `s${i}.Dockerfile` : `s${i}.${s.ext || 'txt'}`;
          byFile.set(name.toLowerCase(), s);
          return fs.writeFile(path.join(dir, name), s.code.endsWith('\n') ? s.code : s.code + '\n');
        }));
        let r = await run(this.binary, this._args(configs, dir, this.experimental), { timeoutMs: this.opts.timeoutMs || 30000, env: this.env });
        let json = parseJson(r.out);
        if (!json && this.kind === 'semgrep' && this.experimental && !r.timedOut) {
          // native mode unavailable in this build → fall back to the classic entry point once and remember
          this.experimental = false;
          r = await run(this.binary, this._args(configs, dir, false), { timeoutMs: Math.max(this.opts.timeoutMs || 30000, 90000), env: this.env });
          json = parseJson(r.out);
        }
        if (!json) {
          this.lastError = (r.timedOut ? 'scan timed out' : r.err.trim().split('\n').slice(-3).join(' ')) || `exit code ${r.code}`;
          return { findings: [], ms: Date.now() - t0, error: this.lastError };
        }
        this.lastError = null;
        const findings = [];
        for (const res of json.results || []) {
          const s = byFile.get(path.basename(String(res.path)).toLowerCase());
          if (!s) continue;
          const meta = res.extra?.metadata || {};
          const id = String(res.check_id || 'rule');
          const line = res.start?.line || 1;
          const cwe = Array.isArray(meta.cwe) ? meta.cwe[0] : meta.cwe;
          findings.push({
            engine: this.kind,
            ruleId: id.includes(`${BRAND.slug}.`) ? id.slice(id.lastIndexOf(`${BRAND.slug}.`)) : id.split('.').slice(-3).join('.'),
            category: meta.category === 'quality' ? 'quality' : 'security',
            severity: SEV[String(res.extra?.severity || 'WARNING').toUpperCase()] || 'warning',
            message: String(res.extra?.message || '').trim(),
            cwe: cwe ? String(cwe).split(':')[0].trim() : null,
            fix: meta.fix || res.extra?.fix || null,
            snippetId: s.id, line, col: res.start?.col || 1, endLine: res.end?.line || line,
            excerpt: (s.code.split('\n')[line - 1] || '').trim().slice(0, 240),
          });
        }
        return { findings, ms: Date.now() - t0 };
      } finally {
        fs.rm(dir, { recursive: true, force: true }).catch(() => {});
      }
    });
  }
}

function parseJson(out) {
  const i = out.indexOf('{');
  if (i < 0) return null;
  try { return JSON.parse(out.slice(i)); } catch { return null; }
}
