#!/usr/bin/env node
// Word scanner: docx, docm, dotx, dotm.
//   docProps/core.xml, custom.xml (MSIP sensitivity labels)  -> metadata
//   word/header*.xml / word/footer*.xml                      -> header / footer
//   VML / WordArt watermark text                             -> watermark
//   word/comments.xml                                        -> comments
//   Title / Heading 1 paragraphs                             -> title
//   word/document.xml (+ footnotes, endnotes)                -> body
import { makeScanner, ScanError, decodeEntities, xmlAttr, runCli, isMain } from './lib/common.mjs';
import { openPackage, entryText, ooxmlMetadata, paragraphs } from './lib/ooxml.mjs';

export const TYPE = 'docx';
export const SCANNER = 'scan-docx';
export const EXTENSIONS = ['docx', 'docm', 'dotx', 'dotm'];

const TITLE_STYLE = /^(?:title|titre|titel|t[ií]tulo|titolo|subtitle|heading\s?1|titre\s?1|[üu]berschrift\s?1|t[ií]tulo\s?1|titolo\s?1)$/i;
const base = (name) => name.split('/').pop();

function watermarkStrings(xml) {
  const out = [];
  if (!xml) return out;
  const re = /<v:textpath\b[^>]*>/g;
  let m;
  while ((m = re.exec(xml))) {
    const s = xmlAttr(m[0], 'string');
    if (s && s.trim()) out.push(s.trim());
  }
  return out;
}

function extract(src) {
  const zip = openPackage(src.buffer, 'Word document');
  const doc = entryText(zip, 'word/document.xml');
  if (doc == null) throw new ScanError('not a Word document (word/document.xml missing)');

  const metadata = ooxmlMetadata(zip);
  const header = [];
  const footer = [];
  const watermark = [];
  const comments = [];
  const title = [];

  for (const name of zip.match(/^word\/header\d*\.xml$/)) {
    const xml = entryText(zip, name);
    const marks = watermarkStrings(xml);
    for (const w of marks) watermark.push({ text: w, where: base(name) });
    const isWatermarkPart = /docPartGallery\s+w:val="Watermarks"|WaterMarkObject/i.test(xml);
    for (const p of paragraphs(xml, 'w:p', 'w:t')) {
      // text of a watermark text box belongs to the watermark zone
      if (isWatermarkPart && !marks.length && p.length <= 80) watermark.push({ text: p, where: base(name) });
      else header.push({ text: p, where: base(name) });
    }
  }
  for (const name of zip.match(/^word\/footer\d*\.xml$/)) {
    const xml = entryText(zip, name);
    for (const w of watermarkStrings(xml)) watermark.push({ text: w, where: base(name) });
    for (const p of paragraphs(xml, 'w:p', 'w:t')) footer.push({ text: p, where: base(name) });
  }
  for (const w of watermarkStrings(doc)) watermark.push({ text: w, where: 'document.xml' });

  const commentsXml = entryText(zip, 'word/comments.xml');
  for (const p of paragraphs(commentsXml, 'w:p', 'w:t')) comments.push({ text: p, where: 'review comment' });

  // Title / Heading 1 paragraphs (first few only)
  const paraRe = /<w:p\b[^>]*>([\s\S]*?)<\/w:p>/g;
  let m;
  let scanned = 0;
  while ((m = paraRe.exec(doc)) && title.length < 5 && scanned++ < 400) {
    const style = /<w:pStyle\b[^>]*w:val="([^"]+)"/.exec(m[1]);
    if (style && TITLE_STYLE.test(decodeEntities(style[1]).replace(/[_-]/g, ' ').replace(/([a-z])(\d)/i, '$1 $2'))) {
      const text = paragraphs(m[0], 'w:p', 'w:t').join(' ');
      if (text) title.push({ text, where: `${decodeEntities(style[1])} paragraph` });
    }
  }

  const bodyParts = paragraphs(doc, 'w:p', 'w:t');
  for (const extra of ['word/footnotes.xml', 'word/endnotes.xml']) bodyParts.push(...paragraphs(entryText(zip, extra), 'w:p', 'w:t'));

  return { zones: { metadata, title, header, footer, watermark, comments, body: bodyParts.join('\n') }, stats: {} };
}

export const scan = makeScanner({ type: TYPE, scanner: SCANNER, extract });

if (isMain(import.meta.url)) {
  runCli({ name: SCANNER, description: 'confidentiality scanner for Word documents', extensions: EXTENSIONS.join(', ') }, scan);
}
