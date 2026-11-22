#!/usr/bin/env node
// XML / HTML scanner: xml, html, htm, xhtml, svg.
//   comments                                        -> comments
//   <title>, <desc> (svg)                           -> title
//   <meta name=… content=…>, root-element attributes,
//   elements / attributes with a classification-like name -> metadata
//   text content                                    -> body
// Purely textual: DOCTYPE subsets and entities are never resolved, nothing is ever fetched.
import { makeScanner, decodeText, decodeEntities, extOf, xmlAttr, runCli, isMain } from './lib/common.mjs';
import { isClassificationName } from './lib/analyze.mjs';

export const TYPE = 'xml';
export const SCANNER = 'scan-xml';
export const EXTENSIONS = ['xml', 'html', 'htm', 'xhtml', 'svg'];

const MAX_META = 200;
const local = (name) => name.replace(/^[\w.-]+:/, '');
const HTML_BLOCK = /<\/?(?:p|div|h[1-6]|li|ul|ol|tr|td|th|table|thead|tbody|br|hr|title|section|article|header|footer|nav|aside|main|pre|blockquote|dd|dt|dl|form|option|figcaption)\b[^>]*>/gi;

export function extractFromXml(text, filename = '') {
  const ext = extOf(filename);
  let s = text.replace(/^﻿/, '');
  const metadata = [];
  const comments = [];
  const title = [];
  const pushMeta = (name, value) => {
    const v = decodeEntities(String(value ?? '')).replace(/\s+/g, ' ').trim();
    if (name && v && metadata.length < MAX_META) metadata.push({ name, value: v.slice(0, 1000) });
  };

  // DOCTYPE (with or without an internal subset) is dropped, never interpreted.
  s = s.replace(/<!DOCTYPE[^>[]*(?:\[[\s\S]*?\])?[^>]*>/gi, ' ');
  s = s.replace(/<!--([\s\S]*?)-->/g, (m, c) => {
    const t = decodeEntities(c).trim();
    if (t && comments.length < 500) comments.push(t.slice(0, 2000));
    return ' ';
  });
  s = s.replace(/<\?[\s\S]*?\?>/g, ' ');
  s = s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, (m, c) => c.replace(/&/g, '&amp;').replace(/</g, '&lt;'));

  const isHtml = ext === 'html' || ext === 'htm' || ext === 'xhtml' || /<html[\s>]/i.test(s.slice(0, 2000));
  if (isHtml) s = s.replace(/<(script|style|noscript|template)\b[\s\S]*?<\/\1\s*>/gi, ' ');

  // titles
  const titleRe = /<(?:[\w.-]+:)?(title|desc)(?:\s[^>]*)?>([\s\S]*?)<\/(?:[\w.-]+:)?\1\s*>/gi;
  let m;
  while ((m = titleRe.exec(s)) && title.length < 5) {
    const t = decodeEntities(m[2].replace(/<[^>]*>/g, ' ')).replace(/\s+/g, ' ').trim();
    if (t) title.push({ text: t.slice(0, 500), where: `<${m[1]}>` });
  }

  // <meta name="…" content="…">
  const metaRe = /<meta\b[^>]*>/gi;
  while ((m = metaRe.exec(s))) {
    const name = xmlAttr(m[0], 'name') || xmlAttr(m[0], 'property') || xmlAttr(m[0], 'http-equiv') || xmlAttr(m[0], 'itemprop');
    const content = xmlAttr(m[0], 'content');
    if (name && content) pushMeta(name, content);
  }

  // root element attributes
  const root = /<([A-Za-z_][\w:.-]*)((?:\s+[^<>]*?)?)\s*\/?>/.exec(s);
  if (root && root[2]) {
    const attrRe = /([A-Za-z_][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;
    let a;
    while ((a = attrRe.exec(root[2]))) {
      if (/^xmlns(?::|$)/i.test(a[1]) || /^xsi:/i.test(a[1])) continue;
      pushMeta(local(a[1]), a[2] ?? a[3]);
    }
  }

  // elements whose name is classification-like: <Classification>Confidential</Classification>
  const elRe = /<([A-Za-z_][\w:.-]*)(?:\s[^<>]*)?>([^<]{1,300})<\/\1\s*>/g;
  while ((m = elRe.exec(s))) {
    if (isClassificationName(local(m[1]))) pushMeta(local(m[1]), m[2]);
  }
  // attributes whose name is classification-like, anywhere: <doc sensitivity="internal">
  const anyAttr = /([A-Za-z_][\w:.-]*)\s*=\s*(?:"([^"]{1,300})"|'([^']{1,300})')/g;
  let seenRootEnd = root ? root.index + root[0].length : 0;
  anyAttr.lastIndex = seenRootEnd;
  while ((m = anyAttr.exec(s))) {
    if (isClassificationName(local(m[1]))) pushMeta(local(m[1]), m[2] ?? m[3]);
  }

  // body text
  let bodySrc = s;
  if (isHtml) bodySrc = bodySrc.replace(HTML_BLOCK, '\n').replace(/<[^>]*>/g, '');
  else bodySrc = bodySrc.replace(/<[^>]*>/g, '\n');
  const body = decodeEntities(bodySrc)
    .split('\n')
    .map((l) => l.replace(/[ \t\r\f\v]+/g, ' ').trim())
    .filter(Boolean)
    .join('\n');

  return { zones: { metadata, title, comments, body }, stats: { html: isHtml } };
}

export const scan = makeScanner({
  type: TYPE,
  scanner: SCANNER,
  extract: (src) => {
    const res = extractFromXml(decodeText(src.buffer), src.filename);
    return { zones: res.zones, stats: {} };
  },
});

if (isMain(import.meta.url)) {
  runCli({ name: SCANNER, description: 'confidentiality scanner for XML / HTML documents', extensions: EXTENSIONS.join(', ') }, scan);
}
