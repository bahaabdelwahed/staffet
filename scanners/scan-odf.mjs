#!/usr/bin/env node
// OpenDocument scanner: odt, ods, odp.
//   meta.xml (title, subject, keywords, user-defined fields)  -> metadata
//   styles.xml master-page headers / footers                  -> header / footer
//   first level-1 heading                                     -> title
//   annotations                                               -> comments
//   content.xml                                               -> body
import { makeScanner, ScanError, decodeEntities, xmlAttr, xmlElements, runCli, isMain } from './lib/common.mjs';
import { openPackage, entryText } from './lib/ooxml.mjs';

export const TYPE = 'odf';
export const SCANNER = 'scan-odf';
export const EXTENSIONS = ['odt', 'ods', 'odp'];

/** Paragraph / heading texts of an ODF fragment. */
function odfParagraphs(xml) {
  const out = [];
  if (!xml) return out;
  const text = xml
    .replace(/<text:(?:s|tab)\b[^>]*\/>/g, ' ')
    .replace(/<text:line-break\b[^>]*\/>/g, '\n')
    .replace(/<\/(?:text:p|text:h|table:table-cell)>/g, '\n')
    .replace(/<[^>]*>/g, '');
  for (const line of decodeEntities(text).split('\n')) {
    const t = line.replace(/[ \t\r]+/g, ' ').trim();
    if (t) out.push(t);
  }
  return out;
}

function extract(src) {
  const zip = openPackage(src.buffer, 'OpenDocument file');
  const content = entryText(zip, 'content.xml');
  const mimetype = entryText(zip, 'mimetype') || '';
  if (content == null || (mimetype && !/opendocument/i.test(mimetype))) {
    throw new ScanError('not an OpenDocument file (content.xml / mimetype missing)');
  }

  const metadata = [];
  const meta = entryText(zip, 'meta.xml');
  if (meta) {
    for (const [tag, name] of [['dc:title', 'title'], ['dc:subject', 'subject'], ['dc:description', 'description'], ['meta:keyword', 'keywords']]) {
      for (const value of xmlElements(meta, tag)) metadata.push({ name, value });
    }
    const re = /<meta:user-defined\b([^>]*)>([\s\S]*?)<\/meta:user-defined>/g;
    let m;
    while ((m = re.exec(meta))) {
      const name = xmlAttr(m[1], 'meta:name');
      const value = decodeEntities(m[2].replace(/<[^>]*>/g, '')).trim();
      if (name && value) metadata.push({ name, value });
    }
  }

  const header = [];
  const footer = [];
  const styles = entryText(zip, 'styles.xml');
  if (styles) {
    const seen = new Set();
    const re = /<style:(header|footer)(?:-left|-first)?\b[^>]*>([\s\S]*?)<\/style:\1(?:-left|-first)?>/g;
    let m;
    while ((m = re.exec(styles))) {
      for (const p of odfParagraphs(m[2])) {
        const key = `${m[1]}|${p.toLowerCase()}`;
        if (seen.has(key)) continue;
        seen.add(key);
        (m[1] === 'header' ? header : footer).push({ text: p, where: `master page ${m[1]}` });
      }
    }
  }

  const comments = [];
  let bodyXml = content.replace(/<office:annotation\b[^>]*>([\s\S]*?)<\/office:annotation>/g, (m, inner) => {
    const text = odfParagraphs(inner.replace(/<dc:(?:creator|date)>[\s\S]*?<\/dc:(?:creator|date)>/g, '')).join(' ');
    if (text) comments.push({ text, where: 'annotation' });
    return ' ';
  });

  const title = [];
  const h1 = /<text:h\b[^>]*text:outline-level="1"[^>]*>([\s\S]*?)<\/text:h>/.exec(bodyXml);
  if (h1) {
    const t = odfParagraphs(h1[0]).join(' ');
    if (t) title.push({ text: t, where: 'heading 1' });
  }

  const stats = {};
  const kind = /opendocument\.(\w+)/.exec(mimetype)?.[1];
  if (kind === 'spreadsheet') stats.sheets = (content.match(/<table:table\b/g) || []).length;
  if (kind === 'presentation') stats.slides = (content.match(/<draw:page\b/g) || []).length;

  return { zones: { metadata, title, header, footer, comments, body: odfParagraphs(bodyXml).join('\n') }, stats };
}

export const scan = makeScanner({ type: TYPE, scanner: SCANNER, extract });

if (isMain(import.meta.url)) {
  runCli({ name: SCANNER, description: 'confidentiality scanner for OpenDocument files', extensions: EXTENSIONS.join(', ') }, scan);
}
