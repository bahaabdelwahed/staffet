#!/usr/bin/env node
// RTF scanner.
//   {\info ...} (title, subject, keywords, comment, category, user properties) -> metadata
//   {\header ...} / {\footer ...} groups (all variants)                         -> header / footer
//   WordArt watermark text (gtextUNICODE shape property)                        -> watermark
//   de-RTF'd document text                                                      -> body
import { makeScanner, ScanError, runCli, isMain } from './lib/common.mjs';

export const TYPE = 'rtf';
export const SCANNER = 'scan-rtf';
export const EXTENSIONS = ['rtf'];

// Destinations whose content is not document text.
const SKIP_DEST = new Set([
  'fonttbl', 'colortbl', 'stylesheet', 'pict', 'object', 'objdata', 'themedata', 'colorschememapping', 'datastore', 'latentstyles',
  'generator', 'listtable', 'listoverridetable', 'rsidtbl', 'xmlnstbl', 'mmathPr', 'filetbl', 'revtbl', 'pgdsctbl', 'fldinst',
  'bkmkstart', 'bkmkend', 'wgrffmtfilter', 'blipuid', 'panose', 'falt', 'operator', 'author', 'manager', 'company', 'creatim',
  'revtim', 'printim', 'buptim', 'vern', 'nofpages', 'nofwords', 'nofchars', 'template', 'hlinkbase', 'password', 'passwordhash',
  'sp', 'sn', 'sv', 'shpinst', 'nonshppict', 'picprop', 'ud',
]);
const INFO_FIELDS = { title: 'title', subject: 'subject', keywords: 'keywords', doccomm: 'comments', category: 'category' };
const HEADER_DEST = /^header[lrf]?$/;
const FOOTER_DEST = /^footer[lrf]?$/;

const cp1252 = new TextDecoder('windows-1252');

/** Walk the RTF token stream, routing text to the destination of the enclosing group. */
function parseRtf(rtf) {
  const out = { body: '', header: '', footer: '', info: {}, props: [], watermark: [] };
  const stack = [];
  let state = { dest: 'body', uc: 1 };
  let skipChars = 0; // ANSI fallback characters to drop after a \uN escape
  let pendingStar = false;
  let propName = null;
  let propValue = null;

  const emit = (text) => {
    if (!text) return;
    if (skipChars > 0) {
      const drop = Math.min(skipChars, text.length);
      skipChars -= drop;
      text = text.slice(drop);
      if (!text) return;
    }
    const d = state.dest;
    if (d === 'body') out.body += text;
    else if (d === 'header') out.header += text;
    else if (d === 'footer') out.footer += text;
    else if (d.startsWith('info:')) out.info[d.slice(5)] = (out.info[d.slice(5)] || '') + text;
    else if (d === 'propname') propName = (propName || '') + text;
    else if (d === 'staticval') propValue = (propValue || '') + text;
  };

  const n = rtf.length;
  let i = 0;
  while (i < n) {
    const ch = rtf[i];
    if (ch === '{') {
      stack.push(state);
      state = { ...state };
      i++;
    } else if (ch === '}') {
      const closing = state.dest;
      state = stack.pop() || { dest: 'body', uc: 1 };
      if (closing === 'staticval' && state.dest !== 'staticval') {
        if (propName != null && propValue != null) out.props.push({ name: propName.trim(), value: propValue });
        propName = null;
        propValue = null;
      }
      pendingStar = false;
      i++;
    } else if (ch === '\\') {
      const next = rtf[i + 1];
      if (next === '\\' || next === '{' || next === '}') {
        emit(next);
        i += 2;
      } else if (next === "'") {
        const hex = rtf.slice(i + 2, i + 4);
        const code = parseInt(hex, 16);
        if (Number.isFinite(code)) emit(cp1252.decode(Uint8Array.of(code)));
        i += 4;
      } else if (next === '*') {
        pendingStar = true;
        i += 2;
      } else if (next === '~') {
        emit(' ');
        i += 2;
      } else if (next === '-' || next === '_' || next === '|' || next === ':') {
        if (next === '_') emit('-');
        i += 2;
      } else if (next === '\n' || next === '\r') {
        emit('\n');
        i += 2;
      } else {
        const m = /^\\([a-zA-Z]+)(-?\d+)? ?/.exec(rtf.slice(i, i + 48));
        if (!m) {
          i += 2;
          continue;
        }
        i += m[0].length;
        const word = m[1];
        const arg = m[2] != null ? Number(m[2]) : null;
        if (word === 'u' && arg != null) {
          const fallback = state.uc;
          emit(String.fromCharCode(arg < 0 ? arg + 65536 : arg));
          skipChars = fallback;
        } else if (word === 'uc' && arg != null) {
          state.uc = arg;
        } else if (word === 'par' || word === 'line' || word === 'sect' || word === 'page' || word === 'row') {
          emit('\n');
        } else if (word === 'tab' || word === 'cell') {
          emit('\t');
        } else if (word === 'emdash') emit('—');
        else if (word === 'endash') emit('–');
        else if (word === 'lquote') emit('‘');
        else if (word === 'rquote') emit('’');
        else if (word === 'ldblquote') emit('“');
        else if (word === 'rdblquote') emit('”');
        else if (word === 'bullet') emit('•');
        else if (word === 'bin' && arg != null) {
          i += Math.max(0, arg); // raw binary payload
        } else if (word === 'info') state.dest = 'info';
        else if (state.dest === 'info' && INFO_FIELDS[word]) state.dest = `info:${INFO_FIELDS[word]}`;
        else if (word === 'userprops') state.dest = 'userprops';
        else if (word === 'propname') state.dest = 'propname';
        else if (word === 'staticval') state.dest = 'staticval';
        else if (HEADER_DEST.test(word)) state.dest = 'header';
        else if (FOOTER_DEST.test(word)) state.dest = 'footer';
        else if (SKIP_DEST.has(word)) state.dest = 'skip';
        else if (pendingStar && (state.dest === 'body' || state.dest === 'header' || state.dest === 'footer')) {
          // unknown ignorable destination ({\*\foo ...}) - except shape text, which is real content
          if (word !== 'shptxt' && word !== 'shprslt') state.dest = 'skip';
        }
        pendingStar = false;
      }
    } else if (ch === '\r' || ch === '\n') {
      i++;
    } else {
      // plain text run
      let j = i + 1;
      while (j < n) {
        const c = rtf[j];
        if (c === '\\' || c === '{' || c === '}' || c === '\r' || c === '\n') break;
        j++;
      }
      emit(rtf.slice(i, j));
      i = j;
    }
  }

  // WordArt watermark: {\sp{\sn gtextUNICODE}{\sv CONFIDENTIAL}}
  const wm = /\{\\sn\s+gtextUNICODE\}\s*\{\\sv\s+([^}]*)\}/g;
  let m;
  while ((m = wm.exec(rtf))) {
    const t = m[1].replace(/\\u(-?\d+)\??/g, (x, c) => String.fromCharCode(Number(c) < 0 ? Number(c) + 65536 : Number(c))).trim();
    if (t) out.watermark.push(t);
  }
  return out;
}

function extract(src) {
  const rtf = src.buffer.toString('latin1');
  if (!/^\s*\{\\rtf/.test(rtf.slice(0, 64))) throw new ScanError('not an RTF document');
  const parsed = parseRtf(rtf);
  const metadata = [];
  for (const [name, value] of Object.entries(parsed.info)) if (value.trim()) metadata.push({ name, value: value.trim() });
  for (const p of parsed.props) if (p.name && p.value.trim()) metadata.push({ name: p.name, value: p.value.trim() });
  const lines = (s, where) => s.split('\n').map((l) => l.trim()).filter(Boolean).map((text) => ({ text, where }));
  return {
    zones: {
      metadata,
      header: lines(parsed.header, 'page header'),
      footer: lines(parsed.footer, 'page footer'),
      watermark: parsed.watermark.map((text) => ({ text, where: 'watermark shape' })),
      body: parsed.body,
    },
    stats: {},
  };
}

export const scan = makeScanner({ type: TYPE, scanner: SCANNER, extract });

if (isMain(import.meta.url)) {
  runCli({ name: SCANNER, description: 'confidentiality scanner for RTF documents', extensions: EXTENSIONS.join(', ') }, scan);
}
