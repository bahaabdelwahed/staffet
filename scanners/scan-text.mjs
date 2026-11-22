#!/usr/bin/env node
// Plain-text scanner: txt, log, csv/tsv, json, yaml, rst, eml (and source code, see "code" flavour).
//
//   text  first 15 non-empty lines = header zone, last 10 = footer zone, rest = body.
//         A text file has no real page header, so those zones are "loose": a marker there only gets
//         full weight when the line reads as a banner ("CONFIDENTIAL", "Classification: Internal").
//   csv   first row = header zone, rest = body (private-information clusters matter most here).
//   eml   mail headers (Subject, Sensitivity, X-Classification ...) = metadata, message = text.
//   code  only comment banners near the top of the file are considered and private-information
//         counting never blocks (source files routinely list author e-mails / test IPs).
import { makeScanner, decodeText, extOf, runCli, isMain } from './lib/common.mjs';

export const TYPE = 'text';
export const SCANNER = 'scan-text';
export const EXTENSIONS = ['txt', 'text', 'log', 'csv', 'tsv', 'json', 'yaml', 'yml', 'rst', 'eml'];

const HEADER_LINES = 15;
const FOOTER_LINES = 10;
const CODE_HEADER_LINES = 40;

const CODE_EXTENSIONS = new Set([
  'py', 'pyw', 'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'mts', 'cts', 'c', 'h', 'cc', 'cpp', 'cxx', 'hpp', 'hh', 'hxx', 'ino',
  'cs', 'java', 'kt', 'kts', 'go', 'rs', 'rb', 'php', 'swift', 'scala', 'm', 'mm', 'pl', 'pm', 'lua', 'r', 'dart', 'sh', 'bash',
  'zsh', 'fish', 'ps1', 'psm1', 'bat', 'cmd', 'sql', 'css', 'scss', 'sass', 'less', 'vue', 'svelte', 'gradle', 'groovy', 'tf',
  'hcl', 'cmake', 'asm', 's', 'vhd', 'vhdl', 'v', 'sv', 'ex', 'exs', 'erl', 'hs', 'clj', 'ml', 'fs', 'vb', 'pas', 'proto',
  'graphql', 'ld', 'mk',
]);

const COMMENT_LINE = /^\s*(?:\/\/+|\/\*+|\*+\/?|#+!?|--+|;+|%+|<!--|'''|"""|REM\b|::)\s?(.*?)\s*(?:\*\/|-->|'''|""")?\s*$/i;

export function flavourOf(filename, opts = {}) {
  if (opts.flavour) return opts.flavour;
  const ext = extOf(filename);
  if (ext === 'csv' || ext === 'tsv') return 'csv';
  if (ext === 'eml') return 'eml';
  if (CODE_EXTENSIONS.has(ext)) return 'code';
  return 'text';
}

function splitZones(text, startLine = 1) {
  const lines = text.split(/\r\n|\r|\n/);
  const idx = [];
  for (let i = 0; i < lines.length; i++) if (lines[i].trim()) idx.push(i);
  const header = [];
  const footer = [];
  const headIdx = idx.slice(0, HEADER_LINES);
  const rest = idx.slice(HEADER_LINES);
  const footIdx = rest.slice(Math.max(0, rest.length - FOOTER_LINES));
  const skip = new Set([...headIdx, ...footIdx]);
  for (const i of headIdx) header.push({ text: lines[i], where: `line ${i + startLine}`, loose: true });
  for (const i of footIdx) footer.push({ text: lines[i], where: `line ${i + startLine}`, loose: true });
  const body = [];
  for (let i = 0; i < lines.length; i++) if (!skip.has(i)) body.push(lines[i]);
  return { header, footer, body: body.join('\n'), lines: lines.length };
}

function decodeMimeWords(s) {
  return s.replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (m, charset, enc, data) => {
    try {
      const bytes =
        enc.toLowerCase() === 'b'
          ? Buffer.from(data, 'base64')
          : Buffer.from(data.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (x, h) => String.fromCharCode(parseInt(h, 16))), 'latin1');
      return new TextDecoder(charset.toLowerCase()).decode(bytes);
    } catch {
      return m;
    }
  });
}

const MAIL_META = /^(?:subject|sensitivity|keywords|importance|x-[\w-]*(?:classif|sensitiv|confidential|protective|marking)[\w-]*|x-ms-exchange-organization-classification|msip_labels?)$/i;

function extractEml(text) {
  const split = /\r?\n\r?\n/.exec(text);
  const headEnd = split ? split.index : text.length;
  const rawHeaders = text.slice(0, headEnd).replace(/\r?\n[ \t]+/g, ' ');
  const metadata = [];
  for (const line of rawHeaders.split(/\r?\n/)) {
    const m = /^([!-9;-~]+):\s*(.*)$/.exec(line);
    if (!m) continue;
    if (MAIL_META.test(m[1])) metadata.push({ name: m[1], value: decodeMimeWords(m[2]) });
  }
  let body = split ? text.slice(headEnd + split[0].length) : '';
  if (/^content-transfer-encoding:\s*quoted-printable/im.test(rawHeaders) || /=\r?\n/.test(body)) {
    body = body
      .replace(/=\r?\n/g, '')
      .replace(/(?:=[0-9A-Fa-f]{2})+/g, (run) => {
        try {
          return Buffer.from(run.replace(/=/g, ''), 'hex').toString('utf8');
        } catch {
          return run;
        }
      });
  }
  const z = splitZones(body);
  return { zones: { metadata, header: z.header, footer: z.footer, body: z.body }, stats: { lines: z.lines } };
}

function extractCsv(text) {
  const nl = text.search(/\r\n|\r|\n/);
  const first = nl < 0 ? text : text.slice(0, nl);
  const rest = nl < 0 ? '' : text.slice(nl);
  return {
    zones: { header: [{ text: first, where: 'header row', loose: true }], body: rest },
    stats: { lines: text.split(/\r\n|\r|\n/).length },
  };
}

function extractCode(text) {
  const lines = text.split(/\r\n|\r|\n/);
  const header = [];
  for (let i = 0; i < Math.min(lines.length, CODE_HEADER_LINES); i++) {
    const m = COMMENT_LINE.exec(lines[i]);
    if (m && m[1] && m[1].trim()) header.push({ text: m[1], where: `line ${i + 1}`, loose: true, bannerOnly: true });
  }
  return {
    zones: { header, body: '' },
    stats: { lines: lines.length, flavour: 'code' },
    optsOverride: { piiBlock: false },
  };
}

/**
 * Extract zones from already-decoded text.
 * @returns {{zones: object, stats: object, optsOverride?: object}}
 */
export function extractFromText(text, filename = '', opts = {}) {
  const flavour = flavourOf(filename, opts);
  if (flavour === 'eml') return extractEml(text);
  if (flavour === 'csv') return extractCsv(text);
  if (flavour === 'code') {
    const res = extractCode(text);
    if (opts.codePiiBlock === true) delete res.optsOverride;
    return res;
  }
  const z = splitZones(text);
  return { zones: { header: z.header, footer: z.footer, body: z.body }, stats: { lines: z.lines } };
}

export const scan = makeScanner({
  type: TYPE,
  scanner: SCANNER,
  extract: (src, opts) => extractFromText(decodeText(src.buffer), src.filename, opts),
});

if (isMain(import.meta.url)) {
  runCli({ name: SCANNER, description: 'confidentiality scanner for plain-text documents', extensions: EXTENSIONS.join(', ') }, scan);
}
