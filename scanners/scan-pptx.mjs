#!/usr/bin/env node
// PowerPoint scanner: pptx, pptm, potx, ppsx.
//   docProps                                            -> metadata
//   title of the first slide                            -> title
//   footer / header / date placeholders                 -> footer
//   static text on slide masters / layouts (stamps)     -> watermark
//   speaker notes, comments                             -> comments
//   all other slide text                                -> body
import { makeScanner, ScanError, decodeEntities, runCli, isMain } from './lib/common.mjs';
import { openPackage, entryText, ooxmlMetadata, paragraphs } from './lib/ooxml.mjs';

export const TYPE = 'pptx';
export const SCANNER = 'scan-pptx';
export const EXTENSIONS = ['pptx', 'pptm', 'potx', 'ppsx'];

const FOOTER_PH = new Set(['ftr', 'hdr', 'dt']);
const TITLE_PH = new Set(['title', 'ctrTitle', 'subTitle']);
const num = (name) => Number(/(\d+)\.xml$/.exec(name)?.[1] ?? 0);

/** Split a slide-like part into shapes: [{ph: placeholder type | null, isPlaceholder, lines: string[]}] + loose text. */
function shapes(xml) {
  const out = [];
  if (!xml) return { shapes: out, rest: [] };
  const rest = xml.replace(/<p:sp>([\s\S]*?)<\/p:sp>/g, (m, inner) => {
    const ph = /<p:ph\b([^>]*)\/?>/.exec(inner);
    const type = ph ? /\btype="([^"]+)"/.exec(ph[1])?.[1] ?? 'body' : null;
    const lines = paragraphs(inner, 'a:p', 'a:t');
    if (lines.length) out.push({ ph: type, isPlaceholder: Boolean(ph), lines });
    return ' ';
  });
  return { shapes: out, rest: paragraphs(rest, 'a:p', 'a:t') }; // tables, groups without p:sp wrappers, ...
}

function extract(src) {
  const zip = openPackage(src.buffer, 'PowerPoint document');
  if (!zip.has('ppt/presentation.xml')) throw new ScanError('not a PowerPoint document (ppt/presentation.xml missing)');

  const metadata = ooxmlMetadata(zip);
  const title = [];
  const footer = [];
  const watermark = [];
  const comments = [];
  const body = [];
  const seenFooter = new Set();
  const pushFooter = (text, where) => {
    const key = text.replace(/\d+/g, '#').toLowerCase();
    if (seenFooter.has(key)) return;
    seenFooter.add(key);
    footer.push({ text, where });
  };

  const slideNames = zip.match(/^ppt\/slides\/slide\d+\.xml$/);
  for (const name of slideNames) {
    const n = num(name);
    const { shapes: sps, rest } = shapes(entryText(zip, name));
    for (const sp of sps) {
      if (sp.ph === 'sldNum') continue;
      if (sp.ph && FOOTER_PH.has(sp.ph)) for (const l of sp.lines) pushFooter(l, `slide ${n}`);
      else if (sp.ph && TITLE_PH.has(sp.ph) && n === 1) {
        title.push({ text: sp.lines.join(' '), where: 'slide 1' });
      } else body.push(...sp.lines);
    }
    body.push(...rest);
  }

  // Masters / layouts: placeholders hold prompt text ("Click to edit Master title style") - ignore those,
  // keep real footer text and any free-standing text box (typical "CONFIDENTIAL" stamp).
  const seenStamp = new Set();
  for (const name of [...zip.match(/^ppt\/slideMasters\/slideMaster\d+\.xml$/), ...zip.match(/^ppt\/slideLayouts\/slideLayout\d+\.xml$/)]) {
    const where = name.includes('slideMasters') ? 'slide master' : 'slide layout';
    const { shapes: sps } = shapes(entryText(zip, name));
    for (const sp of sps) {
      if (sp.ph && FOOTER_PH.has(sp.ph)) {
        for (const l of sp.lines) pushFooter(l, where);
      } else if (!sp.isPlaceholder) {
        for (const l of sp.lines) {
          const key = l.toLowerCase();
          if (!seenStamp.has(key)) {
            seenStamp.add(key);
            watermark.push({ text: l, where });
          }
        }
      }
    }
  }

  for (const name of zip.match(/^ppt\/notesSlides\/notesSlide\d+\.xml$/)) {
    const { shapes: sps } = shapes(entryText(zip, name));
    for (const sp of sps) {
      if (sp.ph === 'sldNum' || sp.ph === 'sldImg' || sp.ph === 'dt' || sp.ph === 'hdr' || sp.ph === 'ftr') continue;
      for (const l of sp.lines) comments.push({ text: l, where: `notes of slide ${num(name)}` });
    }
  }
  for (const name of zip.match(/^ppt\/comments\/.*\.xml$/)) {
    const xml = entryText(zip, name) || '';
    const re = /<(?:p:text|a:t)(?:\s[^>]*)?>([^<]*)<\/(?:p:text|a:t)>/g;
    let m;
    while ((m = re.exec(xml))) {
      const t = decodeEntities(m[1]).trim();
      if (t) comments.push({ text: t, where: 'comment' });
    }
  }

  return { zones: { metadata, title, footer, watermark, comments, body: body.join('\n') }, stats: { slides: slideNames.length } };
}

export const scan = makeScanner({ type: TYPE, scanner: SCANNER, extract });

if (isMain(import.meta.url)) {
  runCli({ name: SCANNER, description: 'confidentiality scanner for PowerPoint documents', extensions: EXTENSIONS.join(', ') }, scan);
}
