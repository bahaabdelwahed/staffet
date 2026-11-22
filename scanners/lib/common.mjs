// Shared plumbing for the document scanners: input loading, verdict assembly, XML helpers, CLI runner.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeZones } from './analyze.mjs';

export const MAX_FILE_BYTES = 100 * 1024 * 1024;

export class ScanError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ScanError';
  }
}

/** Lower-case extension without the dot ('' when there is none). */
export function extOf(filename) {
  const base = String(filename ?? '').split(/[\\/]/).pop() || '';
  const i = base.lastIndexOf('.');
  return i > 0 ? base.slice(i + 1).toLowerCase() : '';
}

/**
 * Resolve a scanner input to bytes.
 * @param {string | {buffer: Buffer|Uint8Array, filename?: string}} input
 * @returns {Promise<{buffer: Buffer, filename: string, file: string}>}
 */
export async function loadInput(input) {
  if (typeof input === 'string') {
    let st;
    try {
      st = await fs.promises.stat(input);
    } catch (err) {
      throw new ScanError(err.code === 'ENOENT' ? `file not found: ${input}` : `cannot access file: ${err.message}`);
    }
    if (!st.isFile()) throw new ScanError(`not a regular file: ${input}`);
    if (st.size > MAX_FILE_BYTES) {
      throw new ScanError(`file too large to scan (${(st.size / 1048576).toFixed(1)} MB > 100 MB)`);
    }
    return { buffer: await fs.promises.readFile(input), filename: path.basename(input), file: input };
  }
  if (input && input.buffer != null) {
    const raw = input.buffer;
    const buffer = Buffer.isBuffer(raw)
      ? raw
      : raw instanceof Uint8Array
        ? Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength)
        : typeof raw === 'string'
          ? Buffer.from(raw, 'utf8')
          : null;
    if (!buffer) throw new ScanError('invalid input: buffer must be a Buffer, Uint8Array or string');
    if (buffer.length > MAX_FILE_BYTES) {
      throw new ScanError(`file too large to scan (${(buffer.length / 1048576).toFixed(1)} MB > 100 MB)`);
    }
    const filename = String(input.filename ?? '');
    return { buffer, filename: filename.split(/[\\/]/).pop() || filename, file: filename || null };
  }
  throw new ScanError('invalid input: expected a file path or { buffer, filename }');
}

/** Describe an input for error verdicts without touching the disk. */
export function describeInput(input) {
  if (typeof input === 'string') return input;
  if (input && typeof input === 'object' && input.filename) return String(input.filename);
  return null;
}

/** Decode text bytes: honours BOMs, falls back to Windows-1252 when the bytes are not valid UTF-8. */
export function decodeText(buffer) {
  if (typeof buffer === 'string') return buffer;
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) return buffer.subarray(2).toString('utf16le');
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    const swapped = Buffer.from(buffer.subarray(2));
    if (swapped.length % 2) return swapped.subarray(0, swapped.length - 1).swap16().toString('utf16le');
    return swapped.swap16().toString('utf16le');
  }
  const start = buffer.length >= 3 && buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf ? 3 : 0;
  const body = start ? buffer.subarray(start) : buffer;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(body);
  } catch {
    try {
      return new TextDecoder('windows-1252').decode(body);
    } catch {
      return body.toString('latin1');
    }
  }
}

/** Assemble the public verdict from extracted zones. */
export function buildVerdict({ file, type, scanner, zones, opts = {}, started, stats = {}, limited = false }) {
  const core = analyzeZones(zones, opts);
  const verdict = {
    ok: true,
    file: file ?? null,
    type,
    scanner,
    confidential: core.confidential,
    score: core.score,
    threshold: core.threshold,
    classification: core.classification,
    reasons: core.reasons,
    findings: core.findings,
    pii: core.pii,
    stats: { chars: core.stats.chars, ms: Math.round((performance.now() - started) * 10) / 10 },
  };
  for (const k of ['pages', 'slides', 'sheets']) if (Number.isFinite(stats[k])) verdict.stats[k] = stats[k];
  if (limited) verdict.limited = true;
  return verdict;
}

export function errorVerdict({ file, type, error }) {
  return { ok: false, error: String(error?.message ?? error ?? 'scan failed'), file: file ?? null, type: type ?? null };
}

/** Wrap an extractor into the public `scan(input, opts)` contract (never throws). */
export function makeScanner({ type, scanner, extract }) {
  return async function scan(input, opts = {}) {
    const started = performance.now();
    let file = describeInput(input);
    try {
      const src = await loadInput(input);
      file = src.file;
      const res = await extract(src, opts);
      return buildVerdict({
        file,
        type: res.type || type,
        scanner,
        zones: res.zones,
        opts: { ...opts, ...(res.optsOverride || {}) },
        started,
        stats: res.stats,
        limited: res.limited,
      });
    } catch (err) {
      return errorVerdict({ file, type, scanner, error: err });
    }
  };
}

// ---------------------------------------------------------------------------------------------
// XML helpers (regex based - good enough for well-formed office XML, never resolves entities/DTDs)
// ---------------------------------------------------------------------------------------------
const NAMED_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '©', reg: '®', ndash: '–', mdash: '—', hellip: '…', laquo: '«', raquo: '»', eacute: 'é', egrave: 'è', ecirc: 'ê', agrave: 'à', ccedil: 'ç', uuml: 'ü', ouml: 'ö', auml: 'ä', szlig: 'ß' };

export function decodeEntities(s) {
  if (!s || s.indexOf('&') < 0) return s || '';
  return s.replace(/&(#x[0-9a-fA-F]{1,6}|#\d{1,7}|[a-zA-Z][a-zA-Z0-9]{1,10});/g, (m, e) => {
    if (e[0] === '#') {
      const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      if (!Number.isFinite(code) || code <= 0 || code > 0x10ffff) return ' ';
      try {
        return String.fromCodePoint(code);
      } catch {
        return ' ';
      }
    }
    return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, e) ? NAMED_ENTITIES[e] : m;
  });
}

/** Text content of an XML fragment (tags removed, entities decoded). */
export function stripTags(xml) {
  return decodeEntities(String(xml ?? '').replace(/<[^>]*>/g, ''));
}

/** Value of an attribute inside one start tag, or null. */
export function xmlAttr(tag, name) {
  const re = new RegExp(`(?:^|[\\s"'])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*=\\s*(?:"([^"]*)"|'([^']*)')`);
  const m = re.exec(tag);
  return m ? decodeEntities(m[1] ?? m[2] ?? '') : null;
}

/** Text of every <tag>…</tag> occurrence (tag given with its namespace prefix, e.g. "dc:title"). */
export function xmlElements(xml, tag) {
  const out = [];
  if (!xml) return out;
  const t = tag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`<${t}(?:\\s[^>]*)?>([\\s\\S]*?)</${t}>`, 'g');
  let m;
  while ((m = re.exec(xml))) {
    const text = stripTags(m[1]).trim();
    if (text) out.push(text);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------
const useColor = () => process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== 'dumb';
const paint = (code, s) => (useColor() ? `\x1b[${code}m${s}\x1b[0m` : s);
export const color = {
  red: (s) => paint('31;1', s),
  green: (s) => paint('32;1', s),
  yellow: (s) => paint('33', s),
  dim: (s) => paint('2', s),
  bold: (s) => paint('1', s),
};

/** True when the module at `metaUrl` is the script node was started with. */
export function isMain(metaUrl) {
  if (!process.argv[1]) return false;
  try {
    const self = fs.realpathSync(fileURLToPath(metaUrl));
    const entry = fs.realpathSync(path.resolve(process.argv[1]));
    return process.platform === 'win32' ? self.toLowerCase() === entry.toLowerCase() : self === entry;
  } catch {
    return false;
  }
}

export function parseCliArgs(argv) {
  const out = { files: [], json: false, help: false, opts: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') out.json = true;
    else if (a === '-h' || a === '--help') out.help = true;
    else if (a === '--pii-threshold') out.opts.piiThreshold = Number(argv[++i]);
    else if (a === '--threshold') out.opts.threshold = Number(argv[++i]);
    else if (a === '--no-pii-block') out.opts.piiBlock = false;
    else if (a === '--markers') {
      const file = argv[++i];
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      out.opts.extraMarkers = Array.isArray(parsed) ? parsed : parsed.markers || [];
    } else if (a.startsWith('--')) throw new ScanError(`unknown option: ${a}`);
    else out.files.push(a);
  }
  for (const k of ['piiThreshold', 'threshold']) {
    if (k in out.opts && !Number.isFinite(out.opts[k])) throw new ScanError(`--${k === 'piiThreshold' ? 'pii-threshold' : k} expects a number`);
  }
  return out;
}

export function formatVerdict(v) {
  const lines = [];
  const name = v.file || '(buffer)';
  if (!v.ok) {
    lines.push(`${color.yellow('! ERROR       ')} ${color.bold(name)}  ${color.dim(`(${v.type || 'unknown type'})`)}`);
    lines.push(`    ${v.error}`);
    return lines.join('\n');
  }
  const head = v.confidential ? color.red('✖ CONFIDENTIAL') : color.green('✔ clean       ');
  const meta = `(${v.type}${v.limited ? ', limited extraction' : ''}, score ${v.score.toFixed(2)} / threshold ${v.threshold.toFixed(2)}, ${v.stats.ms} ms)`;
  lines.push(`${head} ${color.bold(name)}  ${color.dim(meta)}`);
  if (v.classification) lines.push(`    classification: ${color.bold(v.classification)}`);
  for (const r of v.reasons) lines.push(`    - ${r}`);
  if (!v.reasons.length) lines.push(color.dim('    no classification markers or private-information clusters found'));
  return lines.join('\n');
}

/**
 * Standard CLI entry for a scanner.
 * Exit codes: 0 = clean, 2 = at least one confidential document, 1 = error.
 */
export async function runCli({ name, description, extensions }, scanFn) {
  let args;
  try {
    args = parseCliArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`${name}: ${err.message}\n`);
    process.exit(1);
  }
  if (args.help || !args.files.length) {
    process.stdout.write(
      [
        `${name} - ${description}`,
        '',
        `Usage: node scanners/${name}.mjs <file...> [--json] [--pii-threshold N] [--threshold X] [--markers extra.json] [--no-pii-block]`,
        extensions ? `Handles: ${extensions}` : '',
        'Exit codes: 0 = clean, 2 = confidential, 1 = error',
        '',
      ]
        .filter((l) => l !== '')
        .join('\n') + '\n',
    );
    process.exit(args.help ? 0 : 1);
  }
  const verdicts = [];
  for (const file of args.files) verdicts.push(await scanFn(file, args.opts));
  if (args.json) {
    process.stdout.write(JSON.stringify(verdicts.length === 1 ? verdicts[0] : verdicts, null, 2) + '\n');
  } else {
    process.stdout.write(verdicts.map(formatVerdict).join('\n') + '\n');
  }
  // set exitCode instead of exit() so stdout is flushed when piped
  process.exitCode = verdicts.some((v) => v.ok && v.confidential) ? 2 : verdicts.some((v) => !v.ok) ? 1 : 0;
}
