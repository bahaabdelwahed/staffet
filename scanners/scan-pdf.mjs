#!/usr/bin/env node
// PDF scanner.
//   Info dictionary + XMP packet                  -> metadata
//   text in the top ~12% / bottom ~12% of a page   -> header / footer
//   rotated text (diagonal stamps)                 -> watermark
//   everything else                                -> body
// Primary path: pdf.js through the `unpdf` package (positions, fonts, encodings handled properly).
// Fallback (unpdf missing or failing): dependency-free extraction - inflate Flate streams, read the
// text-showing operators and the Info dictionary / XMP packet. No positions there, so `limited: true`.
import zlib from 'node:zlib';
import { makeScanner, ScanError, decodeEntities, runCli, isMain } from './lib/common.mjs';
import { isClassificationName } from './lib/analyze.mjs';

export const TYPE = 'pdf';
export const SCANNER = 'scan-pdf';
export const EXTENSIONS = ['pdf'];

const HEADER_BAND = 0.12;
const FOOTER_BAND = 0.12;
const MAX_PAGES = 2000;
const INFO_KEYS = ['Title', 'Subject', 'Keywords', 'Author', 'Category', 'Classification', 'Sensitivity', 'Security'];
const SKIP_INFO = new Set(['Producer', 'Creator', 'CreationDate', 'ModDate', 'Trapped', 'PDFFormatVersion', 'Language', 'EncryptFilterName',
  'IsLinearized', 'IsAcroFormPresent', 'IsXFAPresent', 'IsCollectionPresent', 'IsSignaturesPresent', 'Custom']);

// ---------------------------------------------------------------------------------------------
// Primary: pdf.js (unpdf)
// ---------------------------------------------------------------------------------------------
async function extractWithPdfjs(buffer) {
  const { getDocumentProxy } = await import('unpdf');
  // pdf.js takes ownership of the array it is given: hand it a copy.
  const data = new Uint8Array(buffer.byteLength);
  data.set(buffer);
  let pdf;
  try {
    pdf = await getDocumentProxy(data, { verbosity: 0, useSystemFonts: false, isEvalSupported: false });
  } catch (err) {
    if (err && (err.name === 'PasswordException' || /password/i.test(String(err.message)))) {
      const e = new ScanError('PDF is password-protected (encrypted): content cannot be inspected');
      e.fatal = true;
      throw e;
    }
    throw err;
  }

  const metadata = [];
  try {
    const meta = await pdf.getMetadata();
    const info = meta?.info || {};
    for (const [k, v] of Object.entries(info)) {
      if (SKIP_INFO.has(k) || v == null || typeof v === 'object' || typeof v === 'boolean') continue;
      metadata.push({ name: k, value: String(v) });
    }
    if (info.Custom && typeof info.Custom === 'object') {
      for (const [k, v] of Object.entries(info.Custom)) if (v != null && typeof v !== 'object') metadata.push({ name: k, value: String(v) });
    }
    const xmp = meta?.metadata;
    let all = null;
    if (xmp && typeof xmp.getAll === 'function') all = xmp.getAll();
    else if (xmp && typeof xmp === 'object') all = xmp;
    if (all && typeof all === 'object') {
      for (const [k, v] of Object.entries(all instanceof Map ? Object.fromEntries(all) : all)) {
        if (v == null) continue;
        const name = String(k);
        if (/^(?:xmp|xap|xmpmm|pdfx?:producer|pdf:producer|xmptpg)[:.]/i.test(name) && !isClassificationName(name)) continue;
        const value = Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? '' : String(v);
        if (value) metadata.push({ name: name.replace(/^[\w.-]+:/, ''), value });
      }
    }
  } catch {
    /* metadata is optional */
  }

  const header = [];
  const footer = [];
  const watermark = [];
  const body = [];
  const seen = { header: new Set(), footer: new Set(), watermark: new Set() };
  const pushUnique = (zone, list, text, page) => {
    const t = text.replace(/\s+/g, ' ').trim();
    if (!t) return;
    const key = t.replace(/\d+/g, '#').toLowerCase(); // "Page 3 of 10" repeats on every page
    if (seen[zone].has(key)) return;
    seen[zone].add(key);
    list.push({ text: t, where: `page ${page}` });
  };

  const pages = Math.min(pdf.numPages, MAX_PAGES);
  for (let p = 1; p <= pages; p++) {
    const page = await pdf.getPage(p);
    const viewport = page.getViewport({ scale: 1 });
    const content = await page.getTextContent();
    const height = viewport.height || 1;
    /** @type {Map<string, {zone: string, y: number, parts: {x: number, w: number, s: string}[]}>} */
    const lines = new Map();
    for (const item of content.items) {
      if (typeof item.str !== 'string' || !item.str) continue;
      const tr = item.transform || [1, 0, 0, 1, 0, 0];
      const angle = Math.abs((Math.atan2(tr[1], tr[0]) * 180) / Math.PI);
      const rotated = angle > 5 && angle < 175;
      const [vx, vy] = viewport.convertToViewportPoint(tr[4], tr[5]);
      const rel = vy / height; // 0 = top of the page, 1 = bottom
      let zone = 'body';
      if (rotated) zone = 'watermark';
      else if (rel <= HEADER_BAND) zone = 'header';
      else if (rel >= 1 - FOOTER_BAND) zone = 'footer';
      // Rotated runs are grouped along their own baseline: position = projection on the text direction.
      let key;
      let x = vx;
      if (rotated) {
        const len = Math.hypot(tr[0], tr[1]) || 1;
        const ux = tr[0] / len;
        const uy = tr[1] / len;
        x = tr[4] * ux + tr[5] * uy;
        const perp = -tr[4] * uy + tr[5] * ux;
        key = `watermark|${Math.round(angle / 3)}|${Math.round(perp / 6)}`;
      } else {
        key = `${zone}|${Math.round(vy / 2)}`;
      }
      let line = lines.get(key);
      if (!line) {
        line = { zone, y: vy, parts: [] };
        lines.set(key, line);
      }
      line.parts.push({ x, w: item.width || 0, s: item.str });
    }
    const ordered = [...lines.values()].sort((a, b) => a.y - b.y);
    const pageBody = [];
    for (const line of ordered) {
      line.parts.sort((a, b) => a.x - b.x);
      let text = '';
      let prevEnd = null;
      for (const part of line.parts) {
        if (prevEnd != null && part.x - prevEnd > 1.5 && !text.endsWith(' ') && !part.s.startsWith(' ')) text += ' ';
        text += part.s;
        prevEnd = part.x + part.w;
      }
      if (line.zone === 'header') pushUnique('header', header, text, p);
      else if (line.zone === 'footer') pushUnique('footer', footer, text, p);
      else if (line.zone === 'watermark') pushUnique('watermark', watermark, text, p);
      else if (text.trim()) pageBody.push(text.trim());
    }
    if (pageBody.length) body.push(pageBody.join('\n'));
    page.cleanup?.();
  }
  const numPages = pdf.numPages;
  try {
    await pdf.destroy?.();
  } catch {
    /* ignore */
  }
  return { zones: { metadata, header, footer, watermark, body: body.join('\n') }, stats: { pages: numPages } };
}

// ---------------------------------------------------------------------------------------------
// Fallback: dependency-free
// ---------------------------------------------------------------------------------------------
const PDFDOC_ESCAPES = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', '(': '(', ')': ')', '\\': '\\' };

/** Decode a PDF literal string body (without the outer parentheses) to bytes (as a latin1 string). */
function unescapeLiteral(s) {
  return s.replace(/\\(\r\n|\r|\n|[0-7]{1,3}|.)/g, (m, e) => {
    if (e === '\r\n' || e === '\r' || e === '\n') return '';
    if (/^[0-7]/.test(e)) return String.fromCharCode(parseInt(e, 8) & 0xff);
    return PDFDOC_ESCAPES[e] ?? e;
  });
}
function hexToBytes(hex) {
  let h = hex.replace(/\s+/g, '');
  if (h.length % 2) h += '0';
  let out = '';
  for (let i = 0; i < h.length; i += 2) out += String.fromCharCode(parseInt(h.slice(i, i + 2), 16));
  return out;
}
/** Bytes (latin1 string) -> text for document-level strings (UTF-16BE with BOM, UTF-8 with BOM, or PDFDocEncoding). */
function decodeDocString(bytes) {
  if (bytes.startsWith('\xfe\xff')) {
    let out = '';
    for (let i = 2; i + 1 < bytes.length; i += 2) out += String.fromCharCode((bytes.charCodeAt(i) << 8) | bytes.charCodeAt(i + 1));
    return out;
  }
  if (bytes.startsWith('\xef\xbb\xbf')) return Buffer.from(bytes.slice(3), 'latin1').toString('utf8');
  return bytes;
}

/** Parse the bfchar / bfrange sections of a ToUnicode CMap into code -> string. */
function parseCMap(text) {
  const map = new Map();
  const hexStr = (h) => {
    let out = '';
    for (let i = 0; i + 3 < h.length; i += 4) out += String.fromCharCode(parseInt(h.slice(i, i + 4), 16));
    return out;
  };
  let m;
  const charSec = /beginbfchar([\s\S]*?)endbfchar/g;
  while ((m = charSec.exec(text))) {
    const pair = /<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>/g;
    let p;
    while ((p = pair.exec(m[1]))) map.set(parseInt(p[1], 16), hexStr(p[2]));
  }
  const rangeSec = /beginbfrange([\s\S]*?)endbfrange/g;
  while ((m = rangeSec.exec(text))) {
    const row = /<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(?:<([0-9A-Fa-f]+)>|\[([^\]]*)\])/g;
    let r;
    while ((r = row.exec(m[1]))) {
      const lo = parseInt(r[1], 16);
      const hi = Math.min(parseInt(r[2], 16), lo + 4096);
      if (r[3]) {
        const base = parseInt(r[3], 16);
        for (let c = lo; c <= hi; c++) map.set(c, r[3].length <= 4 ? String.fromCharCode(base + (c - lo)) : hexStr(r[3]));
      } else if (r[4]) {
        const items = r[4].match(/<([0-9A-Fa-f]+)>/g) || [];
        for (let c = lo; c <= hi && c - lo < items.length; c++) map.set(c, hexStr(items[c - lo].slice(1, -1)));
      }
    }
  }
  return map;
}

/** Decode a text-operator string: try the ToUnicode maps (2-byte codes), else treat bytes as Latin-1. */
function decodeShown(bytes, cmaps) {
  if (bytes.startsWith('\xfe\xff')) return decodeDocString(bytes);
  if (cmaps.length && bytes.length >= 2 && bytes.length % 2 === 0) {
    let best = '';
    let bestHits = 0;
    for (const cmap of cmaps) {
      let out = '';
      let hits = 0;
      for (let i = 0; i + 1 < bytes.length; i += 2) {
        const u = cmap.get((bytes.charCodeAt(i) << 8) | bytes.charCodeAt(i + 1));
        if (u != null) {
          out += u;
          hits++;
        }
      }
      if (hits > bestHits) {
        bestHits = hits;
        best = out;
      }
    }
    if (bestHits >= bytes.length / 2 / 2) return best; // at least half the codes resolved
  }
  if (cmaps.length) {
    // single-byte codes through a ToUnicode map (simple fonts with custom encodings)
    let best = '';
    let bestHits = 0;
    for (const cmap of cmaps) {
      let out = '';
      let hits = 0;
      for (let i = 0; i < bytes.length; i++) {
        const u = cmap.get(bytes.charCodeAt(i));
        if (u != null) {
          out += u;
          hits++;
        } else out += bytes[i];
      }
      if (hits > bestHits) {
        bestHits = hits;
        best = out;
      }
    }
    // only trust it when the plain reading is not already readable text
    if (bestHits === bytes.length && !/^[\x20-\x7e]*$/.test(bytes)) return best;
  }
  return bytes;
}

function textFromContentStream(stream, cmaps) {
  const out = [];
  const blockRe = /BT\b([\s\S]*?)\bET\b/g;
  let b;
  while ((b = blockRe.exec(stream))) {
    let line = '';
    // (literal) Tj | (literal) ' | (literal) " | <hex> Tj | [ ... ] TJ | T* / Td / TD -> line break
    const opRe = /\((?:\\[\s\S]|[^\\()]|\((?:\\[\s\S]|[^\\()])*\))*\)\s*(?:Tj|'|")|<([0-9A-Fa-f\s]*)>\s*Tj|\[((?:\\[\s\S]|[^\]\\])*)\]\s*TJ|\bT\*|\b(?:Td|TD)\b/g;
    let op;
    while ((op = opRe.exec(b[1]))) {
      const tok = op[0];
      if (tok === 'T*' || tok === 'Td' || tok === 'TD') {
        if (line.trim()) out.push(line);
        line = '';
      } else if (op[2] != null) {
        const partRe = /\(((?:\\[\s\S]|[^\\()]|\((?:\\[\s\S]|[^\\()])*\))*)\)|<([0-9A-Fa-f\s]*)>|(-?\d+(?:\.\d+)?)/g;
        let part;
        while ((part = partRe.exec(op[2]))) {
          if (part[1] != null) line += decodeShown(unescapeLiteral(part[1]), cmaps);
          else if (part[2] != null) line += decodeShown(hexToBytes(part[2]), cmaps);
          else if (Number(part[3]) < -180) line += ' '; // large negative kerning = word gap
        }
      } else if (op[1] != null) {
        line += decodeShown(hexToBytes(op[1]), cmaps);
      } else {
        const lit = /^\(([\s\S]*)\)\s*(?:Tj|'|")$/.exec(tok);
        if (lit) line += decodeShown(unescapeLiteral(lit[1]), cmaps);
      }
    }
    if (line.trim()) out.push(line);
  }
  return out;
}

function ascii85Decode(buf) {
  let s = buf.toString('latin1').replace(/\s+/g, '');
  if (s.startsWith('<~')) s = s.slice(2);
  const end = s.indexOf('~>');
  if (end >= 0) s = s.slice(0, end);
  const out = [];
  let group = [];
  const flush = (pad) => {
    let v = 0;
    for (let i = 0; i < 5; i++) v = v * 85 + (group[i] ?? 84);
    const bytes = [(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255];
    out.push(...bytes.slice(0, 4 - pad));
    group = [];
  };
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 122 && group.length === 0) {
      out.push(0, 0, 0, 0); // 'z' = four zero bytes
      continue;
    }
    if (c < 33 || c > 117) return null;
    group.push(c - 33);
    if (group.length === 5) flush(0);
  }
  if (group.length === 1) return null;
  if (group.length > 1) flush(5 - group.length);
  return Buffer.from(out);
}

/** Undo the /Filter chain of a stream. Returns null for filters the fallback does not support. */
function applyFilters(data, dict) {
  const fm = /\/Filter\s*(\[[^\]]*\]|\/\w+)/.exec(dict);
  const filters = fm ? (fm[1].match(/\/(\w+)/g) || []).map((f) => f.slice(1)) : [];
  let out = data;
  for (const f of filters) {
    if (f === 'FlateDecode' || f === 'Fl') {
      try {
        out = zlib.inflateSync(out, { maxOutputLength: 50 * 1024 * 1024, finishFlush: zlib.constants.Z_SYNC_FLUSH });
      } catch {
        try {
          out = zlib.inflateRawSync(out, { maxOutputLength: 50 * 1024 * 1024 });
        } catch {
          return null;
        }
      }
    } else if (f === 'ASCII85Decode' || f === 'A85') {
      out = ascii85Decode(out);
      if (!out) return null;
    } else if (f === 'ASCIIHexDecode' || f === 'AHx') {
      const hex = out.toString('latin1').replace(/\s+/g, '').replace(/>.*$/, '');
      out = Buffer.from(hex.length % 2 ? `${hex}0` : hex, 'hex');
    } else {
      return null;
    }
  }
  return out;
}

export function extractFallback(buffer) {
  const raw = buffer.toString('latin1');
  if (!/%PDF-\d/.test(raw.slice(0, 1024))) throw new ScanError('not a PDF document');
  if (/\/Encrypt\s+\d+\s+\d+\s+R|\/Encrypt\s*<</.test(raw)) {
    throw new ScanError('PDF is encrypted: content cannot be inspected without pdf.js');
  }

  // 1. collect decoded streams
  const decoded = [];
  let budget = 150 * 1024 * 1024;
  const streamRe = /stream\r?\n/g;
  let m;
  while ((m = streamRe.exec(raw))) {
    const start = m.index + m[0].length;
    const end = raw.indexOf('endstream', start);
    if (end < 0) break;
    const dictStart = raw.lastIndexOf('<<', m.index);
    const dict = dictStart >= 0 && m.index - dictStart < 4000 ? raw.slice(dictStart, m.index) : '';
    streamRe.lastIndex = end + 9;
    if (/\/Subtype\s*\/(?:Image|Type1C|CIDFontType0C|OpenType)|\/DCTDecode|\/JPXDecode|\/CCITTFaxDecode|\/JBIG2Decode|\/FontFile/.test(dict)) continue;
    const data = applyFilters(buffer.subarray(start, end), dict);
    if (!data) continue; // LZW / unknown filter / corrupt data: not handled by the fallback
    budget -= data.length;
    if (budget < 0) break;
    decoded.push(data.toString('latin1'));
  }

  // 2. ToUnicode maps, 3. text
  const cmaps = [];
  for (const s of decoded) if (s.includes('beginbfchar') || s.includes('beginbfrange')) {
    const map = parseCMap(s);
    if (map.size) cmaps.push(map);
  }
  const lines = [];
  for (const s of decoded) if (/\bBT\b/.test(s) && /\bET\b/.test(s)) lines.push(...textFromContentStream(s, cmaps));

  // 4. Info dictionary (may live in the raw file or inside an object stream) + XMP packet
  const metadata = [];
  const haystack = [raw, ...decoded.filter((s) => !/\bBT\b/.test(s) || s.length < 20000)];
  const seenMeta = new Set();
  const infoRe = new RegExp(`/(${INFO_KEYS.join('|')})\\s*(?:\\(((?:\\\\[\\s\\S]|[^\\\\()]|\\((?:\\\\[\\s\\S]|[^\\\\()])*\\))*)\\)|<([0-9A-Fa-f\\s]+)>)`, 'g');
  for (const h of haystack) {
    let im;
    while ((im = infoRe.exec(h))) {
      const value = decodeDocString(im[2] != null ? unescapeLiteral(im[2]) : hexToBytes(im[3])).trim();
      const key = `${im[1]}=${value}`;
      if (value && !seenMeta.has(key)) {
        seenMeta.add(key);
        metadata.push({ name: im[1], value });
      }
    }
    const xmpRe = /<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/g;
    let xm;
    while ((xm = xmpRe.exec(h))) {
      const xmp = Buffer.from(xm[0], 'latin1').toString('utf8');
      const elRe = /<([A-Za-z_][\w.-]*):([\w.-]+)(?:\s[^<>]*)?>([^<]{1,500})<\/\1:\2>/g;
      let el;
      while ((el = elRe.exec(xmp))) {
        const name = el[2];
        if (!(isClassificationName(name) || /^(?:title|subject|description|keywords|li)$/i.test(name))) continue;
        const value = decodeEntities(el[3]).trim();
        const key = `${name}=${value}`;
        if (value && !seenMeta.has(key)) {
          seenMeta.add(key);
          metadata.push({ name: name === 'li' ? 'xmp' : name, value });
        }
      }
      const attrRe = /([A-Za-z_][\w.-]*):([\w.-]+)\s*=\s*"([^"]{1,300})"/g;
      let at;
      while ((at = attrRe.exec(xmp))) {
        if (isClassificationName(at[2])) metadata.push({ name: at[2], value: decodeEntities(at[3]) });
      }
    }
  }

  const pages = (raw.match(/\/Type\s*\/Page(?![s\w])/g) || []).length || undefined;
  return { zones: { metadata, body: lines.join('\n') }, stats: pages ? { pages } : {}, limited: true };
}

async function extract(src, opts) {
  if (!/%PDF-\d/.test(src.buffer.subarray(0, 1024).toString('latin1'))) throw new ScanError('not a PDF document');
  if (opts.pdfEngine !== 'fallback') {
    try {
      return await extractWithPdfjs(src.buffer);
    } catch (err) {
      if (err && err.fatal) throw err; // encrypted: the fallback cannot do better
      // fall through to the dependency-free extraction
    }
  }
  return extractFallback(src.buffer);
}

export const scan = makeScanner({ type: TYPE, scanner: SCANNER, extract });

if (isMain(import.meta.url)) {
  runCli({ name: SCANNER, description: 'confidentiality scanner for PDF documents', extensions: EXTENSIONS.join(', ') }, scan);
}
