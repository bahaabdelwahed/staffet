// Terminal presentation helpers (no dependencies). Colour is dropped when piped or NO_COLOR is set.
const useColor = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR && process.env.TERM !== 'dumb';
const wrap = (open, close) => (s) => (useColor ? `\x1b[${open}m${s}\x1b[${close}m` : String(s));

export const c = {
  bold: wrap(1, 22), dim: wrap(2, 22), italic: wrap(3, 23), underline: wrap(4, 24),
  red: wrap(31, 39), green: wrap(32, 39), yellow: wrap(33, 39), blue: wrap(34, 39), magenta: wrap(35, 39), cyan: wrap(36, 39), gray: wrap(90, 39), white: wrap(97, 39),
  bgRed: wrap('41;97', '49;39'), bgGreen: wrap('42;30', '49;39'), bgYellow: wrap('43;30', '49;39'), bgBlue: wrap('44;97', '49;39'), bgGray: wrap('100;97', '49;39'),
};

const ANSI = /\x1b\[[0-9;]*m/g;
export const visibleLength = (s) => String(s).replace(ANSI, '').length;
export const pad = (s, n, right = false) => { const gap = Math.max(0, n - visibleLength(s)); return right ? ' '.repeat(gap) + s : s + ' '.repeat(gap); };
export const clip = (s, n) => { s = String(s ?? ''); return s.length > n ? s.slice(0, Math.max(0, n - 1)) + '…' : s; };

export const sym = useColor
  ? { ok: c.green('✔'), fail: c.red('✖'), warn: c.yellow('▲'), info: c.blue('●'), dot: c.gray('·'), arrow: c.gray('→'), shield: '🛡' }
  : { ok: '[ok]', fail: '[x]', warn: '[!]', info: '[i]', dot: '-', arrow: '->', shield: '' };

export function badge(outcome) {
  switch (outcome) {
    case 'clean': return c.bgGray(' PASSED ');
    case 'sanitized': return c.bgBlue(' SANITIZED ');
    case 'blocked': return c.bgRed(' BLOCKED ');
    case 'error': return c.bgYellow(' ERROR ');
    default: return c.bgGray(` ${String(outcome).toUpperCase()} `);
  }
}

export function severityColor(sev) {
  return sev === 'critical' ? c.red : sev === 'warning' ? c.yellow : sev === 'notice' ? c.cyan : c.gray;
}

export const time = (ts) => new Date(ts).toLocaleTimeString('en-GB', { hour12: false });

/**
 * @param {Array<object>} rows
 * @param {Array<{key: string, title: string, width?: number, align?: 'right', format?: Function}>} columns
 */
export function table(rows, columns) {
  if (!rows.length) return c.dim('  (none)');
  const cells = rows.map((r) => columns.map((col) => String(col.format ? col.format(r[col.key], r) : r[col.key] ?? '')));
  const widths = columns.map((col, i) => Math.min(col.width || 200, Math.max(visibleLength(col.title), ...cells.map((row) => visibleLength(row[i])))));
  const line = (vals, style = (x) => x) => '  ' + vals.map((v, i) => pad(style(visibleLength(v) > widths[i] ? clip(v.replace(ANSI, ''), widths[i]) : v), widths[i], columns[i].align === 'right')).join('  ');
  return [line(columns.map((col) => col.title), c.dim), line(widths.map((w) => '─'.repeat(w)), c.dim), ...cells.map((row) => line(row))].join('\n');
}

export function heading(text) {
  return `\n${c.bold(text)}\n`;
}

export function kv(pairs, indent = 2) {
  const w = Math.max(...pairs.map(([k]) => k.length));
  return pairs.map(([k, v]) => `${' '.repeat(indent)}${c.dim(pad(k, w))}  ${v}`).join('\n');
}

export function fmtMs(ms) {
  if (ms == null) return '-';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
  return `${Math.floor(ms / 60000)}m${String(Math.round((ms % 60000) / 1000)).padStart(2, '0')}s`;
}

export function fmtNum(n) {
  n = Number(n) || 0;
  if (n < 10000) return n.toLocaleString('en-US');
  if (n < 1e6) return `${(n / 1e3).toFixed(n < 1e5 ? 1 : 0)}K`;
  return `${(n / 1e6).toFixed(1)}M`;
}

/** One line per event, used by `start` and `monitor`. */
export function eventLine(ev) {
  const col = severityColor(ev.severity);
  const who = ev.client ? c.dim(clip(ev.client, 14).padEnd(14)) : ' '.repeat(14);
  return `${c.dim(time(ev.ts))}  ${col(pad(ev.type, 18))} ${who} ${ev.severity === 'critical' ? c.bold(ev.summary) : ev.summary}`;
}

export function requestLine(r) {
  const extras = [r.redactions ? `${r.redactions} redacted` : '', r.iterations ? `${r.iterations} fix loop${r.iterations > 1 ? 's' : ''}` : '', r.counts?.toolCallsBlocked ? `${r.counts.toolCallsBlocked} call${r.counts.toolCallsBlocked > 1 ? 's' : ''} blocked` : ''].filter(Boolean).join(', ');
  return `${c.dim(time(r.ts))}  ${pad(badge(r.outcome), 11)} ${pad(clip(r.client || '-', 14), 14)} ${pad(clip(r.harness || '-', 14), 14)} ${pad(clip(r.model || '-', 22), 22)} ${pad(fmtMs(r.durationMs), 7, true)}  ${c.dim(extras)}`;
}

export function banner(name, version, tagline) {
  const art = useColor
    ? [c.cyan('  ╔═╦═╗'), c.cyan('  ║ ║ ║'), c.cyan('  ╚╗║╔╝'), c.cyan('   ╚╩╝ ')]
    : ['', '', '', ''];
  const text = ['', `${c.bold(name)} ${c.dim('v' + version)}`, c.dim(tagline), ''];
  return art.map((a, i) => `${a}  ${text[i]}`).join('\n');
}
