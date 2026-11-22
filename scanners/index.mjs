#!/usr/bin/env node
// Document scanner dispatcher.
//
//   import { scanDocument, scanText, detectType, SUPPORTED_EXTENSIONS, DEFAULT_MARKERS } from './scanners/index.mjs'
//   node scanners/index.mjs <file...> [--json]        (exit 2 when any document is confidential)
//
// scanDocument() never throws: failures come back as { ok: false, error, file, type }.
import { readZip } from './lib/zip.mjs';
import {
  loadInput, describeInput, extOf, buildVerdict, errorVerdict, runCli, isMain,
} from './lib/common.mjs';
import * as textScanner from './scan-text.mjs';
import * as markdownScanner from './scan-markdown.mjs';
import * as xmlScanner from './scan-xml.mjs';
import * as pdfScanner from './scan-pdf.mjs';
import * as docxScanner from './scan-docx.mjs';
import * as pptxScanner from './scan-pptx.mjs';
import * as xlsxScanner from './scan-xlsx.mjs';
import * as odfScanner from './scan-odf.mjs';
import * as rtfScanner from './scan-rtf.mjs';
import * as legacyScanner from './scan-legacy-office.mjs';

export { DEFAULT_MARKERS } from './lib/markers.mjs';
export { analyzeZones } from './lib/analyze.mjs';

const SCANNERS = {
  text: textScanner,
  markdown: markdownScanner,
  xml: xmlScanner,
  pdf: pdfScanner,
  docx: docxScanner,
  pptx: pptxScanner,
  xlsx: xlsxScanner,
  odf: odfScanner,
  rtf: rtfScanner,
  'legacy-office': legacyScanner,
};

const EXT_TYPE = {};
for (const [type, mod] of Object.entries(SCANNERS)) for (const ext of mod.EXTENSIONS) EXT_TYPE[ext] = type;

/** Lower-case extensions (without dot) that have a dedicated scanner. */
export const SUPPORTED_EXTENSIONS = Object.freeze(Object.keys(EXT_TYPE).sort());

const OLE_MAGIC = [0xd0, 0xcf, 0x11, 0xe0];

function sniffZip(buf) {
  // Full archive available: look at the entry names.
  try {
    const zip = readZip(buf);
    if (zip.has('word/document.xml')) return 'docx';
    if (zip.has('ppt/presentation.xml')) return 'pptx';
    if (zip.has('xl/workbook.xml')) return 'xlsx';
    if (zip.has('mimetype') && zip.has('content.xml')) return 'odf';
    if (zip.names.some((n) => n.startsWith('word/'))) return 'docx';
    if (zip.names.some((n) => n.startsWith('ppt/'))) return 'pptx';
    if (zip.names.some((n) => n.startsWith('xl/'))) return 'xlsx';
    return null;
  } catch {
    // Only the head of the file: the first local headers still show the entry names.
    const head = buf.subarray(0, Math.min(buf.length, 8192)).toString('latin1');
    if (head.includes('mimetypeapplication/vnd.oasis.opendocument')) return 'odf';
    if (head.includes('word/')) return 'docx';
    if (head.includes('ppt/')) return 'pptx';
    if (head.includes('xl/')) return 'xlsx';
    return null;
  }
}

/**
 * Decide which scanner handles a document.
 * Magic bytes (when a buffer is given) win over the file extension.
 * @param {string} filename
 * @param {Buffer|Uint8Array} [headBuffer] the file, or at least its first bytes
 * @returns {'pdf'|'docx'|'pptx'|'xlsx'|'odf'|'rtf'|'legacy-office'|'markdown'|'xml'|'text'|null}
 */
export function detectType(filename, headBuffer) {
  const ext = extOf(filename);
  const byExt = EXT_TYPE[ext] || null;
  if (headBuffer && headBuffer.length) {
    const buf = Buffer.isBuffer(headBuffer) ? headBuffer : Buffer.from(headBuffer.buffer, headBuffer.byteOffset, headBuffer.byteLength);
    const head = buf.subarray(0, Math.min(buf.length, 1024));
    const pdfAt = head.toString('latin1').indexOf('%PDF-');
    if (pdfAt >= 0 && pdfAt <= 32) return 'pdf';
    if (head.length >= 4 && OLE_MAGIC.every((b, i) => head[i] === b)) return 'legacy-office';
    if (head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b && (head[2] === 0x03 || head[2] === 0x05) && (head[3] === 0x04 || head[3] === 0x06)) {
      const zipType = sniffZip(buf);
      if (zipType) return zipType;
      return ['docx', 'pptx', 'xlsx', 'odf'].includes(byExt) ? byExt : null; // some other archive
    }
    const start = head.toString('latin1').replace(/^(?:\xef\xbb\xbf|\xff\xfe|\xfe\xff)/, '').trimStart();
    if (/^\{\\rtf/.test(start)) return 'rtf';
    // A binary extension over non-matching bytes: trust the bytes (it is text if it has no NULs).
    const binaryExt = ['pdf', 'docx', 'pptx', 'xlsx', 'odf', 'legacy-office'].includes(byExt);
    const looksText = !head.includes(0) || (head[0] === 0xff && head[1] === 0xfe) || (head[0] === 0xfe && head[1] === 0xff);
    if (byExt && !binaryExt) return byExt;
    if (!looksText) return binaryExt ? byExt : null;
    if (/^<\?xml\b|^<!DOCTYPE\s+html|^<html[\s>]|^<svg[\s>]/i.test(start)) return 'xml';
    return 'text';
  }
  return byExt;
}

/**
 * Scan a document for confidentiality markers and private information.
 * @param {string | {buffer: Buffer|Uint8Array, filename?: string}} input  file path, or bytes + file name
 * @param {object} [opts] threshold, piiThreshold, piiBlock, extraMarkers, disabledMarkers, maxBodyChars
 * @returns {Promise<object>} verdict - `{ok: false, error, file, type}` on failure, never throws
 */
export async function scanDocument(input, opts = {}) {
  let file = describeInput(input);
  let type = null;
  try {
    const src = await loadInput(input);
    file = src.file;
    type = detectType(src.filename, src.buffer);
    if (!type) return errorVerdict({ file, type: null, error: `unsupported document type${extOf(src.filename) ? ` (.${extOf(src.filename)})` : ''}` });
    const verdict = await SCANNERS[type].scan({ buffer: src.buffer, filename: src.filename }, opts);
    verdict.file = file;
    return verdict;
  } catch (err) {
    return errorVerdict({ file, type, error: err });
  }
}

/**
 * Scan text that was already extracted from a document (e.g. a tool result read by the harness).
 * `opts.filename` selects the flavour: markdown, xml/html, csv, eml, source code, or plain text.
 * @param {string} text
 * @param {object} [opts] same options as scanDocument, plus `filename`
 * @returns {Promise<object>} verdict
 */
export async function scanText(text, opts = {}) {
  const started = performance.now();
  const filename = opts.filename ? String(opts.filename) : '';
  let type = 'text';
  try {
    const byExt = EXT_TYPE[extOf(filename)];
    type = byExt === 'markdown' || byExt === 'xml' ? byExt : 'text'; // pdf/docx/... arrive here already as text
    const str = typeof text === 'string' ? text : String(text ?? '');
    let res;
    if (type === 'markdown') res = markdownScanner.extractFromMarkdown(str);
    else if (type === 'xml') res = xmlScanner.extractFromXml(str, filename);
    else res = textScanner.extractFromText(str, byExt && byExt !== 'text' ? '' : filename, opts);
    return buildVerdict({
      file: filename || null,
      type,
      scanner: SCANNERS[type].SCANNER,
      zones: res.zones,
      opts: { ...opts, ...(res.optsOverride || {}) },
      started,
      stats: {},
    });
  } catch (err) {
    return errorVerdict({ file: filename || null, type, scanner: SCANNERS[type]?.SCANNER, error: err });
  }
}

if (isMain(import.meta.url)) {
  runCli(
    { name: 'index', description: 'confidentiality scanner for documents (type auto-detected)', extensions: SUPPORTED_EXTENSIONS.join(', ') },
    scanDocument,
  );
}
