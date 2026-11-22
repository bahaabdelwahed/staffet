#!/usr/bin/env node
// Legacy binary Office scanner: doc, dot, xls, ppt, pps, msg (OLE compound files).
// These formats are not parsed structurally: readable ASCII / UTF-16LE strings are pulled out of the
// binary and analysed as body text, so header / footer attribution is unavailable (`limited: true`).
import { makeScanner, ScanError, runCli, isMain } from './lib/common.mjs';

export const TYPE = 'legacy-office';
export const SCANNER = 'scan-legacy-office';
export const EXTENSIONS = ['doc', 'dot', 'xls', 'ppt', 'pps', 'msg'];

const OLE_MAGIC = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
const MIN_RUN = 4;
const MAX_BODY_CHARS = 4_000_000;

const mostlyText = (s) => {
  let good = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 32 || c >= 0xc0) good++;
  }
  return good / s.length >= 0.6;
};

/** Readable strings from a binary buffer: 8-bit (cp1252) runs and UTF-16LE runs. */
export function extractStrings(buffer) {
  const out = [];
  let chars = 0;
  const push = (s) => {
    for (const piece of s.split(/[\r\n\x0b\x0c]+/)) {
      const t = piece.replace(/[\t ]+/g, ' ').trim();
      if (t.length >= MIN_RUN && mostlyText(t)) {
        out.push(t);
        chars += t.length;
      }
    }
  };
  const latin = buffer.toString('latin1');

  // UTF-16LE: printable char + 0x00 (Latin-1 range only - enough for western classification markers)
  const wide = /(?:[\x20-\x7e\xa0-\xff\t\r\n]\x00){4,}/g;
  let m;
  while ((m = wide.exec(latin)) && chars < MAX_BODY_CHARS) {
    let s = '';
    for (let i = 0; i < m[0].length; i += 2) s += m[0][i];
    push(s);
  }
  // 8-bit runs (Word stores "compressed" text as cp1252)
  const narrow = /[\x20-\x7e\xc0-\xff\t\r\n]{4,}/g;
  while ((m = narrow.exec(latin)) && chars < MAX_BODY_CHARS) push(m[0]);
  return out;
}

function extract(src) {
  const buf = src.buffer;
  if (buf.length < 8 || !buf.subarray(0, 8).equals(OLE_MAGIC)) {
    throw new ScanError('not a legacy Office (OLE compound) document');
  }
  // Password-protected OOXML files are OLE containers holding an "EncryptedPackage" stream.
  if (buf.includes(Buffer.from('EncryptedPackage', 'utf16le'))) {
    throw new ScanError('document is password-protected (encrypted): content cannot be inspected');
  }
  const lines = extractStrings(buf);
  // de-duplicate (the same text is often stored twice: 8-bit and 16-bit, or in several streams)
  const seen = new Set();
  const body = [];
  for (const l of lines) {
    if (seen.has(l)) continue;
    seen.add(l);
    body.push(l);
  }
  return { zones: { body: body.join('\n') }, stats: {}, limited: true };
}

export const scan = makeScanner({ type: TYPE, scanner: SCANNER, extract });

if (isMain(import.meta.url)) {
  runCli({ name: SCANNER, description: 'confidentiality scanner for legacy binary Office documents', extensions: EXTENSIONS.join(', ') }, scan);
}
