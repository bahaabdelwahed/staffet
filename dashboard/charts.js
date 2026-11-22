// Hand-rolled SVG charts: thin marks, 2px surface gaps, hairline grid, hover tooltips, table twin.
import { h, svg, clear, fmtNum, fmtClock } from './ui.js';

const SERIES = [
  { key: 'clean', label: 'Passed', color: 'var(--series-passed)' },
  { key: 'sanitized', label: 'Sanitized', color: 'var(--series-sanitized)' },
  { key: 'blocked', label: 'Blocked', color: 'var(--series-blocked)' },
];

/** Axis maximum whose four gridline steps are whole, round numbers (4, 8, 20, 40, 100 ...). */
function niceMax(v) {
  const raw = Math.max(1, v) / 4;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * pow).find((s) => s >= raw) || 10 * pow;
  return Math.max(1, Math.round(step)) * 4;
}

/** Merge minute buckets so a long range still draws bars a person can hit. */
function bucketise(data, maxBars) {
  const size = Math.ceil(data.length / maxBars);
  if (size <= 1) return { rows: data, minutes: 1 };
  const rows = [];
  for (let i = 0; i < data.length; i += size) {
    const part = data.slice(i, i + size);
    rows.push(part.reduce((a, b) => ({ t: a.t, clean: a.clean + b.clean, sanitized: a.sanitized + b.sanitized, blocked: a.blocked + b.blocked, error: a.error + b.error }), { t: part[0].t, clean: 0, sanitized: 0, blocked: 0, error: 0 }));
  }
  return { rows, minutes: size };
}

export function legend() {
  return h('div', { class: 'legend' }, SERIES.map((s) => h('span', null, h('i', { style: `background:${s.color}` }), s.label)));
}

/**
 * Stacked columns: requests per time bucket, split by outcome.
 * @param {HTMLElement} host
 * @param {Array<{t, clean, sanitized, blocked, error}>} data  one row per minute
 */
export function trafficChart(host, data) {
  clear(host);
  host.classList.add('chart');
  const W = 760, H = 232, padL = 34, padR = 8, padT = 10, padB = 24;
  const { rows, minutes } = bucketise(data, 60);
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const totals = rows.map((r) => r.clean + r.sanitized + r.blocked);
  const max = niceMax(Math.max(1, ...totals));
  const band = plotW / rows.length;
  const barW = Math.max(3, Math.min(24, band - 3));
  const y = (v) => padT + plotH - (v / max) * plotH;

  const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Requests over time by outcome. Use the table view for exact values.' });
  // grid + y ticks
  for (let i = 0; i <= 4; i++) {
    const v = (max / 4) * i;
    const yy = y(v);
    root.append(svg('line', { x1: padL, x2: W - padR, y1: yy, y2: yy, stroke: i === 0 ? 'var(--axis)' : 'var(--grid)', 'stroke-width': 1 }));
    root.append(svg('text', { x: padL - 6, y: yy + 3.5, 'text-anchor': 'end' }, Number.isInteger(v) ? fmtNum(v) : v.toFixed(1)));
  }
  // x ticks: about six labels
  const step = Math.max(1, Math.round(rows.length / 6));
  rows.forEach((r, i) => {
    if (i % step !== 0 && i !== rows.length - 1) return;
    if (i === rows.length - 1 && (rows.length - 1) % step < step / 2 && (rows.length - 1) % step !== 0) return;
    root.append(svg('text', { x: padL + band * i + band / 2, y: H - 7, 'text-anchor': 'middle' }, fmtClock(r.t)));
  });

  const tip = h('div', { class: 'tooltip', hidden: true });
  const showTip = (r, i, evt) => {
    clear(tip);
    const end = r.t + minutes * 60000;
    tip.append(h('div', { class: 't' }, minutes > 1 ? `${fmtClock(r.t)} – ${fmtClock(end)}` : fmtClock(r.t)));
    for (const s of [...SERIES].reverse()) tip.append(h('div', { class: 'r' }, h('i', { style: `background:${s.color}` }), h('b', null, fmtNum(r[s.key])), h('span', null, s.label)));
    if (r.error) tip.append(h('div', { class: 'r' }, h('i', { style: 'background:var(--warning)' }), h('b', null, fmtNum(r.error)), h('span', null, 'Upstream errors')));
    tip.hidden = false;
    const box = host.getBoundingClientRect();
    const px = ((padL + band * i + band / 2) / W) * box.width;
    const left = px > box.width - 190 ? px - 170 : px + 12;
    tip.style.left = `${Math.max(0, left)}px`;
    tip.style.top = `${evt ? Math.max(0, Math.min(box.height - 110, evt.clientY - box.top - 40)) : 12}px`;
  };

  rows.forEach((r, i) => {
    const x = padL + band * i + (band - barW) / 2;
    let acc = 0;
    const present = SERIES.filter((s) => r[s.key] > 0);
    present.forEach((s, k) => {
      const y0 = y(acc), y1 = y(acc + r[s.key]);
      acc += r[s.key];
      const top = k === present.length - 1;
      const gap = k > 0 ? 2 : 0;                           // 2px surface gap between stacked segments
      const hh = Math.max(1, y0 - y1 - gap);
      const rad = top ? Math.min(4, barW / 2, hh) : 0;       // rounded data-end, square baseline
      const yTop = y0 - gap - hh;
      const d = rad
        ? `M${x},${yTop + hh}V${yTop + rad}Q${x},${yTop} ${x + rad},${yTop}H${x + barW - rad}Q${x + barW},${yTop} ${x + barW},${yTop + rad}V${yTop + hh}Z`
        : `M${x},${yTop}H${x + barW}V${yTop + hh}H${x}Z`;
      root.append(svg('path', { d, fill: s.color }));
    });
    // hit target is the whole band, not the painted pixels
    const hit = svg('rect', { class: 'hit', x: padL + band * i, y: padT, width: band, height: plotH, tabindex: totals[i] ? 0 : null, 'aria-label': `${fmtClock(r.t)}: ${r.clean} passed, ${r.sanitized} sanitized, ${r.blocked} blocked` });
    const hl = svg('rect', { class: 'hl', x: padL + band * i + band / 2 - 0.5, y: padT, width: 1, height: plotH });
    hit.addEventListener('pointermove', (e) => { showTip(r, i, e); hl.classList.add('on'); });
    hit.addEventListener('pointerleave', () => { tip.hidden = true; hl.classList.remove('on'); });
    hit.addEventListener('focus', () => { showTip(r, i); hl.classList.add('on'); });
    hit.addEventListener('blur', () => { tip.hidden = true; hl.classList.remove('on'); });
    root.append(hit, hl);
  });
  host.append(root, tip);
}

/** The accessible twin of the traffic chart. */
export function trafficTable(host, data) {
  clear(host);
  const { rows, minutes } = bucketise(data, 60);
  const busy = rows.filter((r) => r.clean + r.sanitized + r.blocked + r.error > 0).reverse();
  if (!busy.length) { host.append(h('div', { class: 'empty' }, 'No requests in this period.')); return; }
  host.append(h('div', { class: 'table-wrap', style: 'max-height:232px;overflow-y:auto' }, h('table', { class: 'data' },
    h('thead', null, h('tr', null, h('th', null, minutes > 1 ? `Period (${minutes} min)` : 'Minute'), h('th', { class: 'num' }, 'Passed'), h('th', { class: 'num' }, 'Sanitized'), h('th', { class: 'num' }, 'Blocked'), h('th', { class: 'num' }, 'Errors'))),
    h('tbody', null, busy.map((r) => h('tr', null, h('td', null, fmtClock(r.t)), h('td', { class: 'num' }, r.clean), h('td', { class: 'num' }, r.sanitized), h('td', { class: 'num' }, r.blocked), h('td', { class: 'num' }, r.error)))))));
}

/** Sparkline: 2px line in the de-emphasis colour, current value marked in the accent. */
export function sparkline(values) {
  const W = 84, H = 24, pad = 3;
  const el = svg('svg', { class: 'spark', viewBox: `0 0 ${W} ${H}`, 'aria-hidden': 'true' });
  if (!values.length || values.every((v) => v === 0)) return el;
  const max = Math.max(...values);
  const pts = values.map((v, i) => [pad + (i / Math.max(1, values.length - 1)) * (W - pad * 2), H - pad - (v / max) * (H - pad * 2)]);
  el.append(svg('polyline', { points: pts.map((p) => p.map((n) => n.toFixed(1)).join(',')).join(' '), fill: 'none', stroke: 'var(--series-passed)', 'stroke-width': 2, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
  const last = pts[pts.length - 1];
  el.append(svg('circle', { cx: last[0], cy: last[1], r: 3.5, fill: 'var(--accent)', stroke: 'var(--surface)', 'stroke-width': 2 }));
  return el;
}

/** Ranked horizontal bars, one hue, value at the end of each row. */
export function rankedBars(host, rows, { empty = 'Nothing yet.' } = {}) {
  clear(host);
  if (!rows.length) { host.append(h('div', { class: 'empty' }, empty)); return; }
  const max = Math.max(...rows.map((r) => r.count));
  host.append(h('div', { class: 'bars' }, rows.map((r) => h('div', { class: 'bar-row', title: `${r.name}: ${r.count}` },
    h('span', { class: 'name mono' }, r.name), h('span', { class: 'val' }, fmtNum(r.count)),
    h('span', { class: 'track' }, h('i', { style: `width:${Math.max(2, (r.count / max) * 100)}%` }))))));
}
