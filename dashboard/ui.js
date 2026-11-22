// DOM helpers. All data reaches the page through textContent — never innerHTML.

const SVG_NS = 'http://www.w3.org/2000/svg';

/** h('div', {class:'x', onclick}, child, 'text', [more]) */
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
      else if (k === 'value' || k === 'checked' || k === 'disabled' || k === 'selected') el[k] = v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, String(v));
  for (const c of children.flat()) if (c != null) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}

export const clear = (el) => { el.replaceChildren(); return el; };

/** Replace an element's content. Unlike the native append(), nulls are skipped and arrays are flattened. */
export const fill = (el, ...children) => append(clear(el), children);

// Static icon paths (24px grid, stroke icons). These are constants, not data.
const ICONS = {
  pulse: 'M3 12h4l2.5-7 5 14 2.5-7h4',
  list: 'M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01',
  rules: 'M4 5h16M4 12h10M4 19h7M17 15l2 2 4-4',
  flask: 'M9 3h6M10 3v6l-5.5 9.5A2 2 0 0 0 6.2 21h11.6a2 2 0 0 0 1.7-2.5L14 9V3',
  doc: 'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8zM14 3v5h5M9 13h6M9 17h4',
  cog: 'M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7zM19.4 13a7.6 7.6 0 0 0 0-2l2-1.5-2-3.5-2.4 1a7.6 7.6 0 0 0-1.7-1L15 3.5h-4l-.3 2.5a7.6 7.6 0 0 0-1.7 1l-2.4-1-2 3.5 2 1.5a7.6 7.6 0 0 0 0 2l-2 1.5 2 3.5 2.4-1a7.6 7.6 0 0 0 1.7 1l.3 2.5h4l.3-2.5a7.6 7.6 0 0 0 1.7-1l2.4 1 2-3.5z',
  shield: 'M12 3 4.5 6v5.5c0 4.6 3.1 8.2 7.5 9.5 4.4-1.3 7.5-4.9 7.5-9.5V6z',
  block: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM5.6 5.6l12.8 12.8',
  check: 'M5 12.5l4.5 4.5L19 7.5',
  warn: 'M12 4 2.5 20h19zM12 10v4.5M12 17.5h.01',
  info: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 11v6M12 7.5h.01',
  eyeoff: 'M3 3l18 18M10.6 6.2A9.8 9.8 0 0 1 12 6c5 0 8.5 4 9.5 6a13 13 0 0 1-2.6 3.4M6.5 7.7A13 13 0 0 0 2.5 12c1 2 4.5 6 9.5 6 1.3 0 2.5-.3 3.6-.7M9.9 9.9a3 3 0 0 0 4.2 4.2',
  code: 'M8.5 7 3.5 12l5 5M15.5 7l5 5-5 5M13.5 4l-3 16',
  x: 'M6 6l12 12M18 6 6 18',
  plus: 'M12 5v14M5 12h14',
  trash: 'M4 7h16M9 7V4h6v3M6.5 7l1 13h9l1-13M10 11v5M14 11v5',
  sun: 'M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM12 2v2M12 20v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M2 12h2M20 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4',
  moon: 'M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z',
  table: 'M4 5h16v14H4zM4 10h16M4 15h16M10 5v14',
  chart: 'M5 20V10M12 20V4M19 20v-7',
  key: 'M14.5 9.5a4 4 0 1 1-3 3L3 21v-3h3v-3h3l2.5-2.5',
  clock: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3.5 2',
  repeat: 'M4 12a8 8 0 0 1 13.7-5.7L20 8.5M20 4v4.5h-4.5M20 12a8 8 0 0 1-13.7 5.7L4 15.5M4 20v-4.5h4.5',
  copy: 'M9 9h10v11H9zM5 15V4h10',
};

export function icon(name, title) {
  const el = svg('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.8, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': title ? null : 'true', role: title ? 'img' : null });
  if (title) el.append(svg('title', {}, title));
  el.append(svg('path', { d: ICONS[name] || ICONS.info }));
  return el;
}

export function logo() {
  const el = svg('svg', { viewBox: '0 0 32 32', 'aria-hidden': 'true' });
  el.append(svg('path', { d: 'M16 2.5 4.5 6.8v8.4c0 7 4.7 12.4 11.5 14.3 6.8-1.9 11.5-7.3 11.5-14.3V6.8L16 2.5Z', fill: 'var(--accent)' }));
  el.append(svg('path', { d: 'M10.5 12.5h11M10.5 16.5h11M13.5 12.5v4M18.5 16.5v4M10.5 20.5h11', stroke: '#fff', 'stroke-width': 1.8, 'stroke-linecap': 'round', fill: 'none' }));
  return el;
}

export function fmtNum(n) {
  n = Number(n) || 0;
  if (Math.abs(n) < 10000) return n.toLocaleString('en-US');
  if (Math.abs(n) < 1e6) return `${(n / 1e3).toFixed(n < 1e5 ? 1 : 0)}K`;
  return `${(n / 1e6).toFixed(1)}M`;
}

export function fmtMs(ms) {
  if (ms == null || Number.isNaN(ms)) return '–';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  if (ms < 60000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(ms / 60000)}m ${String(Math.round((ms % 60000) / 1000)).padStart(2, '0')}s`;
}

export const fmtTime = (ts) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
export const fmtClock = (ts) => new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });
export const fmtDate = (ts) => new Date(ts).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' });

export function ago(ts, now = Date.now()) {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

const OUTCOME = { clean: ['passed', 'Passed', 'check'], sanitized: ['sanitized', 'Sanitized', 'shield'], blocked: ['blocked', 'Blocked', 'block'], error: ['error', 'Error', 'warn'] };
export function outcomeBadge(outcome) {
  const [cls, label, ico] = OUTCOME[outcome] || ['passed', outcome, 'info'];
  return h('span', { class: `badge ${cls}` }, icon(ico), label);
}

export function toast(text) {
  document.querySelector('.toast')?.remove();
  const el = h('div', { class: 'toast', role: 'status' }, text);
  document.body.append(el);
  setTimeout(() => el.remove(), 2600);
}

export const store = {
  get(k, d = '') { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  del(k) { try { localStorage.removeItem(k); } catch { /* private mode */ } },
};
