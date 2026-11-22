import { createHash, randomBytes } from 'node:crypto';

export const sha1 = (s) => createHash('sha1').update(s).digest('hex');
export const sha256 = (s) => createHash('sha256').update(s).digest('hex');
export const shortHash = (s, n = 8) => sha1(String(s)).slice(0, n);

let seq = 0;
/** Time-sortable unique id (base36 time + counter + random). */
export function uid(prefix = '') {
  seq = (seq + 1) % 1296;
  return prefix + Date.now().toString(36) + seq.toString(36).padStart(2, '0') + randomBytes(3).toString('hex');
}

export function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Deep merge `src` into a copy of `base`. Arrays and scalars in `src` replace. */
export function deepMerge(base, src) {
  if (!isPlainObject(base) || !isPlainObject(src)) return src === undefined ? base : src;
  const out = { ...base };
  for (const [k, v] of Object.entries(src)) {
    if (v === undefined) continue;
    out[k] = isPlainObject(v) && isPlainObject(base[k]) ? deepMerge(base[k], v) : v;
  }
  return out;
}

export const clone = (v) => (v === undefined ? v : structuredClone(v));

export function safeJsonParse(s, fallback = undefined) {
  if (typeof s !== 'string') return fallback;
  try { return JSON.parse(s); } catch { return fallback; }
}

export function truncate(s, n = 200) {
  s = String(s ?? '');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

const RE_SPECIAL = /[.+^${}()|[\]\\]/g;
export const escapeRegExp = (s) => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** `*.example.com`, `gpt-*` style wildcard → case-insensitive anchored RegExp. */
export function wildcardToRegExp(pattern) {
  const src = String(pattern).replace(RE_SPECIAL, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
  return new RegExp(`^${src}$`, 'i');
}

/**
 * Path glob → RegExp over normalised (forward-slash, lower-case) paths.
 *   **  any depth    *  within one segment    ?  one char
 * A pattern that is not anchored (does not start with `/`, `~`, a drive or `**`)
 * matches at any depth. A pattern naming a directory also matches everything below it.
 */
export function globToRegExp(glob) {
  let g = String(glob).trim().replace(/\\/g, '/').toLowerCase();
  if (g.length > 1) g = g.replace(/\/+$/, '');
  const anchored = /^(\/|~|[a-z]:|\*\*)/.test(g);
  let src = '';
  let openEnded = false;
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === '/' && g.slice(i) === '/**') { src += '(?:/.*)?'; openEnded = true; break; }
    if (c === '*') {
      if (g[i + 1] === '*') {
        if (g[i + 2] === '/') { src += '(?:.*/)?'; i += 2; }
        else { src += '.*'; i += 1; openEnded = i === g.length - 1; }
      } else src += '[^/]*';
    } else if (c === '?') src += '[^/]';
    else src += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  const head = anchored ? '^' : '^(?:.*/)?';
  const tail = openEnded ? '$' : '(?:/.*)?$';
  return new RegExp(head + src + tail);
}

/** Tiny LRU cache (Map insertion order). */
export class LRU {
  constructor(max = 500) { this.max = max; this.map = new Map(); }
  get(k) {
    if (!this.map.has(k)) return undefined;
    const v = this.map.get(k);
    this.map.delete(k); this.map.set(k, v);
    return v;
  }
  set(k, v) {
    this.map.delete(k);
    this.map.set(k, v);
    if (this.map.size > this.max) this.map.delete(this.map.keys().next().value);
  }
  has(k) { return this.map.has(k); }
  clear() { this.map.clear(); }
}

/** Run at most `limit` async jobs at once. */
export class Semaphore {
  constructor(limit) { this.limit = Math.max(1, limit); this.active = 0; this.queue = []; }
  async run(fn) {
    if (this.active >= this.limit) await new Promise((r) => this.queue.push(r));
    this.active++;
    try { return await fn(); } finally {
      this.active--;
      const next = this.queue.shift();
      if (next) next();
    }
  }
}

/** Collect every string leaf of a JSON value. `visit(value, keyPath)` */
export function walkStrings(value, visit, keyPath = [], depth = 0) {
  if (depth > 12) return;
  if (typeof value === 'string') visit(value, keyPath);
  else if (Array.isArray(value)) value.forEach((v, i) => walkStrings(v, visit, [...keyPath, i], depth + 1));
  else if (isPlainObject(value)) for (const [k, v] of Object.entries(value)) walkStrings(v, visit, [...keyPath, k], depth + 1);
}

/** Mask a value for audit logs: never store the full secret. */
export function maskValue(v) {
  v = String(v);
  if (v.length <= 4) return '•'.repeat(v.length);
  return v.slice(0, 2) + '•••' + ` (${v.length} chars)`;
}

export function fmtMs(ms) {
  if (ms == null) return '-';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m${Math.round((ms % 60000) / 1000)}s`;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
