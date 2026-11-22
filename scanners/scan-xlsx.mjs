#!/usr/bin/env node
// Excel scanner: xlsx, xlsm, xltx.
//   docProps                                  -> metadata
//   sheet names                               -> title
//   print headers / footers (<headerFooter>)  -> header / footer
//   cell comments                             -> comments
//   shared + inline strings                   -> body (one cell per line, so a "CONFIDENTIAL" cell is a banner)
import { makeScanner, ScanError, decodeEntities, xmlAttr, runCli, isMain } from './lib/common.mjs';
import { openPackage, entryText, ooxmlMetadata } from './lib/ooxml.mjs';

export const TYPE = 'xlsx';
export const SCANNER = 'scan-xlsx';
export const EXTENSIONS = ['xlsx', 'xlsm', 'xltx'];

const MAX_BODY_CHARS = 4_000_000;

/** Strip Excel header/footer formatting codes: &L &C &R &P &N &D &T &A &F &Z &G &"font,style" &12 &K000000 ... */
function cleanHeaderFooter(s) {
  return decodeEntities(s)
    .replace(/&&/g, '\u0001')
    .replace(/&"[^"]*"/g, ' ')
    .replace(/&K[0-9A-Fa-f]{6}/g, ' ')
    .replace(/&\d+/g, ' ')
    .replace(/&[LCRPNDTAFZGBIUESXYO]/gi, ' ')
    .replace(/\u0001/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
}

/** Concatenated <t> runs of each <si> / <is> / <comment> element. */
function stringItems(xml, tag) {
  const out = [];
  if (!xml) return out;
  const re = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)</${tag}>`, 'g');
  let m;
  let chars = 0;
  while ((m = re.exec(xml))) {
    // skip phonetic runs (<rPh>) - they duplicate the text
    const inner = m[1].replace(/<rPh\b[\s\S]*?<\/rPh>/g, '');
    let text = '';
    const tRe = /<t(?:\s[^>]*)?>([^<]*)<\/t>/g;
    let t;
    while ((t = tRe.exec(inner))) text += decodeEntities(t[1]);
    text = text.trim();
    if (!text) continue;
    out.push(text);
    chars += text.length;
    if (chars > MAX_BODY_CHARS) break;
  }
  return out;
}

function extract(src) {
  const zip = openPackage(src.buffer, 'Excel workbook');
  const workbook = entryText(zip, 'xl/workbook.xml');
  if (workbook == null) throw new ScanError('not an Excel workbook (xl/workbook.xml missing)');

  const metadata = ooxmlMetadata(zip);
  const title = [];
  const header = [];
  const footer = [];
  const comments = [];
  const body = [];

  const sheetRe = /<sheet\b[^>]*>/g;
  let m;
  let sheets = 0;
  while ((m = sheetRe.exec(workbook))) {
    sheets++;
    const name = xmlAttr(m[0], 'name');
    if (name) title.push({ text: name, where: 'sheet name' });
  }

  body.push(...stringItems(entryText(zip, 'xl/sharedStrings.xml'), 'si'));

  const seen = new Set();
  for (const name of [...zip.match(/^xl\/worksheets\/sheet\d+\.xml$/), ...zip.match(/^xl\/chartsheets\/sheet\d+\.xml$/)]) {
    const xml = entryText(zip, name);
    if (!xml) continue;
    const hf = /<headerFooter\b[^>]*>([\s\S]*?)<\/headerFooter>/.exec(xml);
    if (hf) {
      const partRe = /<(odd|even|first)(Header|Footer)(?:\s[^>]*)?>([\s\S]*?)<\/\1\2>/g;
      let p;
      while ((p = partRe.exec(hf[1]))) {
        const text = cleanHeaderFooter(p[3]);
        const key = `${p[2]}|${text.toLowerCase()}`;
        if (!text || seen.has(key)) continue;
        seen.add(key);
        (p[2] === 'Header' ? header : footer).push({ text, where: `print ${p[2].toLowerCase()}, ${name.split('/').pop()}` });
      }
    }
    if (xml.includes('<is>')) body.push(...stringItems(xml, 'is'));
  }

  for (const name of zip.match(/^xl\/comments\d*\.xml$/)) {
    for (const c of stringItems(entryText(zip, name), 'comment')) comments.push({ text: c, where: 'cell comment' });
  }

  return { zones: { metadata, title, header, footer, comments, body: body.join('\n') }, stats: { sheets } };
}

export const scan = makeScanner({ type: TYPE, scanner: SCANNER, extract });

if (isMain(import.meta.url)) {
  runCli({ name: SCANNER, description: 'confidentiality scanner for Excel workbooks', extensions: EXTENSIONS.join(', ') }, scan);
}
