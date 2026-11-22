// Helpers shared by the Office Open XML scanners (docx / pptx / xlsx).
import { readZip, ZipError } from './zip.mjs';
import { ScanError, decodeEntities, xmlAttr, xmlElements } from './common.mjs';

/** Open an OOXML / ODF package, turning ZIP problems into scan errors with a useful message. */
export function openPackage(buffer, what = 'document') {
  try {
    return readZip(buffer);
  } catch (err) {
    if (err instanceof ZipError) throw new ScanError(`cannot open ${what}: ${err.message}`);
    throw err;
  }
}

/** Read an entry as text; a missing entry is null, an unreadable one (encrypted / oversized) throws ScanError. */
export function entryText(zip, name) {
  try {
    return zip.text(name);
  } catch (err) {
    if (err instanceof ZipError) throw new ScanError(`cannot read ${name}: ${err.message}`);
    throw err;
  }
}

const CORE_FIELDS = [
  ['dc:title', 'title'],
  ['dc:subject', 'subject'],
  ['dc:description', 'description'],
  ['cp:keywords', 'keywords'],
  ['cp:category', 'category'],
  ['cp:contentStatus', 'contentStatus'],
];

/** docProps/core.xml + docProps/custom.xml (incl. Microsoft Purview / MSIP sensitivity labels) -> metadata. */
export function ooxmlMetadata(zip) {
  const metadata = [];
  const core = entryText(zip, 'docProps/core.xml');
  if (core) {
    for (const [tag, name] of CORE_FIELDS) for (const value of xmlElements(core, tag)) metadata.push({ name, value });
  }
  const custom = entryText(zip, 'docProps/custom.xml');
  if (custom) {
    const re = /<property\b([^>]*)>([\s\S]*?)<\/property>/g;
    let m;
    while ((m = re.exec(custom)) && metadata.length < 400) {
      const name = xmlAttr(m[1], 'name');
      const value = decodeEntities(m[2].replace(/<[^>]*>/g, '')).trim();
      if (name && value) metadata.push({ name, value });
    }
  }
  return metadata;
}

/**
 * Paragraph texts of a DrawingML / WordprocessingML fragment.
 * @param {string} xml
 * @param {string} p  paragraph tag ("w:p" or "a:p")
 * @param {string} t  text-run tag ("w:t" or "a:t")
 */
export function paragraphs(xml, p, t) {
  const out = [];
  if (!xml) return out;
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const ns = p.split(':')[0];
  // text runs, paragraph ends, explicit breaks and tabs - in document order
  const re = new RegExp(
    `<${esc(t)}(?:\\s[^>]*)?>([^<]*)</${esc(t)}>|<${ns}:delText(?:\\s[^>]*)?>([^<]*)</${ns}:delText>|(</${esc(p)}>)|(<${ns}:br\\b[^>]*>|<${ns}:cr\\b[^>]*>)|(<${ns}:tab\\b[^>]*>)`,
    'g',
  );
  let cur = '';
  let m;
  while ((m = re.exec(xml))) {
    if (m[1] != null) cur += decodeEntities(m[1]);
    else if (m[2] != null) cur += decodeEntities(m[2]);
    else if (m[3] || m[4]) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
    } else if (m[5]) cur += '\t';
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}
