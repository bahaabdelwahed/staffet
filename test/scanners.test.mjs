// Tests for the document scanners (scanners/).
// Synthetic fixtures are built in-process (tiny ZIP writer, hand-written PDF / RTF / OLE);
// the real-*.{docx,pptx,xlsx,pdf,odt} files in test/fixtures/docs come from python-docx, python-pptx,
// openpyxl, reportlab and odfpy (see test/fixtures/docs/generate.py).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { scanDocument, scanText, detectType, SUPPORTED_EXTENSIONS, DEFAULT_MARKERS } from '../scanners/index.mjs';
import { readZip, ZipError } from '../scanners/lib/zip.mjs';
import { countPII, maskPII, luhnValid, ibanValid, isRealIPv4 } from '../scanners/lib/pii.mjs';
import { analyzeZones, isClassificationName } from '../scanners/lib/analyze.mjs';
import { scan as scanTextFile } from '../scanners/scan-text.mjs';
import { scan as scanMarkdown } from '../scanners/scan-markdown.mjs';
import { scan as scanXml } from '../scanners/scan-xml.mjs';
import { scan as scanPdf } from '../scanners/scan-pdf.mjs';
import { scan as scanDocx } from '../scanners/scan-docx.mjs';
import { scan as scanPptx } from '../scanners/scan-pptx.mjs';
import { scan as scanXlsx } from '../scanners/scan-xlsx.mjs';
import { scan as scanOdf } from '../scanners/scan-odf.mjs';
import { scan as scanRtf } from '../scanners/scan-rtf.mjs';
import { scan as scanLegacy } from '../scanners/scan-legacy-office.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const DOCS = path.join(HERE, 'fixtures', 'docs');
const fixture = (name) => path.join(DOCS, name);

// ------------------------------------------------------------------------------------------------
// test-only helpers
// ------------------------------------------------------------------------------------------------
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** Minimal ZIP writer: { name: string|Buffer } -> Buffer. `opts.store` names are stored, the rest deflated. */
function makeZip(files, opts = {}) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, content] of Object.entries(files)) {
    const data = Buffer.isBuffer(content) ? content : Buffer.from(content, 'utf8');
    const stored = opts.store?.includes(name);
    const body = stored ? data : zlib.deflateRawSync(data);
    const nameBuf = Buffer.from(name, 'utf8');
    const flags = 0x800 | (opts.encrypted?.includes(name) ? 1 : 0);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(stored ? 0 : 8, 8);
    local.writeUInt32LE(crc32(data), 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(opts.fakeSize?.[name] ?? data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(stored ? 0 : 8, 10);
    central.writeUInt32LE(crc32(data), 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(opts.fakeSize?.[name] ?? data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuf, body);
    centrals.push(central, nameBuf);
    offset += 30 + nameBuf.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Object.keys(files).length, 8);
  end.writeUInt16LE(Object.keys(files).length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

const CONTENT_TYPES = '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>';
const W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"';
const wp = (text, style) => `<w:p>${style ? `<w:pPr><w:pStyle w:val="${style}"/></w:pPr>` : ''}<w:r><w:t xml:space="preserve">${text}</w:t></w:r></w:p>`;
const wdoc = (...paras) => `<?xml version="1.0"?><w:document ${W}><w:body>${paras.join('')}</w:body></w:document>`;

function makeDocx({ body = [wp('Hello world')], header, footer, custom, core, comments, watermark } = {}) {
  const files = { '[Content_Types].xml': CONTENT_TYPES, 'word/document.xml': wdoc(...body) };
  if (header) files['word/header1.xml'] = `<?xml version="1.0"?><w:hdr ${W}>${header}</w:hdr>`;
  if (watermark) {
    files['word/header2.xml'] = `<?xml version="1.0"?><w:hdr ${W} xmlns:v="urn:schemas-microsoft-com:vml"><w:p><w:r><w:pict><v:shape id="PowerPlusWaterMarkObject1"><v:textpath style="font-family:Calibri" string="${watermark}"/></v:shape></w:pict></w:r></w:p></w:hdr>`;
  }
  if (footer) files['word/footer1.xml'] = `<?xml version="1.0"?><w:ftr ${W}>${footer}</w:ftr>`;
  if (comments) files['word/comments.xml'] = `<?xml version="1.0"?><w:comments ${W}><w:comment w:id="0">${comments}</w:comment></w:comments>`;
  if (core) files['docProps/core.xml'] = `<?xml version="1.0"?><cp:coreProperties xmlns:cp="x" xmlns:dc="y">${core}</cp:coreProperties>`;
  if (custom) {
    files['docProps/custom.xml'] = `<?xml version="1.0"?><Properties xmlns:vt="v">${Object.entries(custom)
      .map(([k, v], i) => `<property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="${i + 2}" name="${k}"><vt:lpwstr>${v}</vt:lpwstr></property>`)
      .join('')}</Properties>`;
  }
  return makeZip(files);
}

const sp = (text, ph) =>
  `<p:sp><p:nvSpPr><p:cNvPr id="2" name="x"/><p:cNvSpPr/><p:nvPr>${ph ? `<p:ph type="${ph}"/>` : ''}</p:nvPr></p:nvSpPr><p:spPr/><p:txBody><a:bodyPr/><a:p><a:r><a:t>${text}</a:t></a:r></a:p></p:txBody></p:sp>`;
const slide = (...shapes) => `<?xml version="1.0"?><p:sld xmlns:p="p" xmlns:a="a"><p:cSld><p:spTree>${shapes.join('')}</p:spTree></p:cSld></p:sld>`;
function makePptx({ slides, master, notes } = {}) {
  const files = { '[Content_Types].xml': CONTENT_TYPES, 'ppt/presentation.xml': '<?xml version="1.0"?><p:presentation xmlns:p="p"/>' };
  slides.forEach((s, i) => (files[`ppt/slides/slide${i + 1}.xml`] = s));
  if (master) files['ppt/slideMasters/slideMaster1.xml'] = master;
  if (notes) files['ppt/notesSlides/notesSlide1.xml'] = notes;
  return makeZip(files);
}

function makeXlsx({ strings = [], sheetXml = '<sheetData/>', sheets = ['Sheet1'], custom } = {}) {
  const files = {
    '[Content_Types].xml': CONTENT_TYPES,
    'xl/workbook.xml': `<?xml version="1.0"?><workbook><sheets>${sheets.map((n, i) => `<sheet name="${n}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`).join('')}</sheets></workbook>`,
    'xl/sharedStrings.xml': `<?xml version="1.0"?><sst>${strings.map((s) => `<si><t>${s}</t></si>`).join('')}</sst>`,
    'xl/worksheets/sheet1.xml': `<?xml version="1.0"?><worksheet>${sheetXml}</worksheet>`,
  };
  if (custom) {
    files['docProps/custom.xml'] = `<?xml version="1.0"?><Properties xmlns:vt="v">${Object.entries(custom)
      .map(([k, v], i) => `<property pid="${i + 2}" name="${k}"><vt:lpwstr>${v}</vt:lpwstr></property>`)
      .join('')}</Properties>`;
  }
  return makeZip(files);
}

function makeOdt({ paragraphs = ['Hello'], header, userDefined } = {}) {
  return makeZip(
    {
      mimetype: 'application/vnd.oasis.opendocument.text',
      'content.xml': `<?xml version="1.0"?><office:document-content xmlns:office="o" xmlns:text="t"><office:body><office:text>${paragraphs.map((p) => `<text:p>${p}</text:p>`).join('')}</office:text></office:body></office:document-content>`,
      'styles.xml': `<?xml version="1.0"?><office:document-styles xmlns:office="o" xmlns:style="s" xmlns:text="t"><office:master-styles><style:master-page style:name="Standard">${header ? `<style:header><text:p>${header}</text:p></style:header>` : ''}</style:master-page></office:master-styles></office:document-styles>`,
      'meta.xml': `<?xml version="1.0"?><office:document-meta xmlns:office="o" xmlns:meta="m" xmlns:dc="d"><office:meta><dc:title>Notes</dc:title>${Object.entries(userDefined || {}).map(([k, v]) => `<meta:user-defined meta:name="${k}">${v}</meta:user-defined>`).join('')}</office:meta></office:document-meta>`,
    },
    { store: ['mimetype'] },
  );
}

/** Hand-written single-page PDF with an uncompressed content stream. Each entry: [x, y, text]. */
function makePdf(texts, { title } = {}) {
  const content = texts.map(([x, y, t]) => `BT /F1 12 Tf ${x} ${y} Td (${t.replace(/([()\\])/g, '\\$1')}) Tj ET`).join('\n');
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
    `<< /Title (${title || 'Untitled'}) /Producer (test) >>`,
  ];
  let out = '%PDF-1.4\n';
  const offsets = [];
  objs.forEach((o, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R /Info 6 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

function makeOle(paragraphs, { wide = true } = {}) {
  const magic = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]);
  const junk = Buffer.alloc(504, 0x01);
  const text = Buffer.from(paragraphs.join('\r'), wide ? 'utf16le' : 'latin1');
  return Buffer.concat([magic, junk, text, Buffer.alloc(64, 0x02)]);
}

const VERDICT_KEYS = ['ok', 'file', 'type', 'scanner', 'confidential', 'score', 'threshold', 'classification', 'reasons', 'findings', 'pii', 'stats'];
function assertVerdictShape(v) {
  for (const k of VERDICT_KEYS) assert.ok(k in v, `verdict key "${k}" missing`);
  assert.equal(v.ok, true);
  assert.equal(typeof v.confidential, 'boolean');
  assert.equal(typeof v.score, 'number');
  assert.ok(Array.isArray(v.reasons) && Array.isArray(v.findings));
  assert.deepEqual(Object.keys(v.pii).sort(), ['cards', 'emails', 'ibans', 'ipv4', 'total']);
  assert.equal(typeof v.stats.chars, 'number');
  assert.equal(typeof v.stats.ms, 'number');
  for (const f of v.findings) {
    assert.deepEqual(Object.keys(f).sort(), ['context', 'kind', 'markerId', 'match', 'strength', 'weight', 'zone']);
    assert.ok(f.context.length <= 120, 'finding context must stay short');
  }
}
const zonesOf = (v) => v.findings.map((f) => `${f.zone}:${f.markerId}`);

// ------------------------------------------------------------------------------------------------
// lib/zip
// ------------------------------------------------------------------------------------------------
test('zip: reads stored and deflated entries', () => {
  const zip = readZip(makeZip({ 'a.txt': 'alpha', 'dir/b.xml': '<b>β</b>' }, { store: ['a.txt'] }));
  assert.deepEqual(zip.names.sort(), ['a.txt', 'dir/b.xml']);
  assert.equal(zip.text('a.txt'), 'alpha');
  assert.equal(zip.text('dir/b.xml'), '<b>β</b>');
  assert.equal(zip.text('missing'), null);
  assert.deepEqual(zip.match(/\.xml$/), ['dir/b.xml']);
});

test('zip: rejects bombs, encrypted entries and non-archives', () => {
  const big = makeZip({ 'big.bin': Buffer.alloc(200_000, 0x41) });
  assert.throws(() => readZip(big, { maxEntryBytes: 1000 }).read('big.bin'), (e) => e instanceof ZipError && e.code === 'EBOMB');
  // declared size lies (small) but the data inflates past the cap
  const liar = makeZip({ 'big.bin': Buffer.alloc(200_000, 0x41) }, { fakeSize: { 'big.bin': 10 } });
  assert.throws(() => readZip(liar, { maxEntryBytes: 1000 }).read('big.bin'), (e) => e instanceof ZipError && e.code === 'EBOMB');
  const many = makeZip({ a: Buffer.alloc(600, 1), b: Buffer.alloc(600, 2) });
  const z = readZip(many, { maxTotalBytes: 1000 });
  z.read('a');
  assert.throws(() => z.read('b'), (e) => e.code === 'EBOMB');
  const enc = makeZip({ 's.txt': 'secret' }, { encrypted: ['s.txt'] });
  assert.throws(() => readZip(enc).read('s.txt'), (e) => e.code === 'EENCRYPTED');
  assert.throws(() => readZip(Buffer.from('definitely not a zip archive, just text')), (e) => e.code === 'ENOTZIP');
});

// ------------------------------------------------------------------------------------------------
// lib/pii
// ------------------------------------------------------------------------------------------------
test('pii: counts distinct identifiers and skips look-alikes', () => {
  const text = [
    'alice@corp.io, ALICE@corp.io, bob@corp.io, user@example.com, git@github.com:org/repo.git, logo@2x.png',
    'servers 10.20.30.40 and 10.20.30.40 and 192.168.1.17; loopback 127.0.0.1, mask 255.255.255.0, any 0.0.0.0',
    'version 10.2.3.44 of the tool, section 1.2.3.4',
    'card 4111 1111 1111 1111, not a card 1234 5678 9012 3456',
    'IBAN DE89 3704 0044 0532 0130 00, bad IBAN DE00 3704 0044 0532 0130 00',
  ].join('\n');
  const c = countPII(text);
  assert.equal(c.emails, 2);
  assert.equal(c.ipv4, 2);
  assert.equal(c.cards, 1);
  assert.equal(c.ibans, 1);
  assert.equal(c.total, 6);
  assert.ok(c.samples.length <= 5);
  for (const s of c.samples) assert.ok(!/alice@corp\.io|10\.20\.30\.40|4111111111111111/.test(s), `sample leaks a value: ${s}`);
});

test('pii: validators and masking', () => {
  assert.equal(luhnValid('4111111111111111'), true);
  assert.equal(luhnValid('4111111111111112'), false);
  assert.equal(ibanValid('GB82 WEST 1234 5698 7654 32'), true);
  assert.equal(ibanValid('GB82 WEST 1234 5698 7654 33'), false);
  assert.equal(isRealIPv4('172.16.4.9'), true);
  assert.equal(isRealIPv4('127.0.0.1'), false);
  const masked = maskPII('contact alice@corp.io from 10.20.30.40');
  assert.ok(!masked.includes('alice@corp.io') && !masked.includes('10.20.30.40'));
});

// ------------------------------------------------------------------------------------------------
// lib/analyze
// ------------------------------------------------------------------------------------------------
test('analyze: zone weights', () => {
  assert.equal(analyzeZones({ header: ['Acme Corp - Confidential'] }).score, 1);
  assert.equal(analyzeZones({ footer: ['This document contains confidential information of Acme Corporation, Inc.'] }).confidential, true);
  assert.equal(analyzeZones({ watermark: ['C O N F I D E N T I A L'] }).confidential, true);
  assert.equal(analyzeZones({ header: ['Restricted'] }).score, 0.6); // medium, privileged
  assert.equal(analyzeZones({ header: ['Internal'] }).score, 0.34); // weak, privileged
  assert.equal(analyzeZones({ body: 'CONFIDENTIAL\nplan for next year' }).score, 1); // banner line
  assert.equal(analyzeZones({ body: 'please keep this confidential, thanks a lot everyone' }).score, 0.34); // prose
  assert.equal(analyzeZones({ body: 'the restricted area of the plant is described here in detail' }).score, 0.2); // medium body
  assert.equal(analyzeZones({ body: 'an internal function with a private field and a secret santa' }).score, 0); // weak body
  assert.deepEqual(analyzeZones({ body: 'an internal function with a private field' }).findings, []);
});

test('analyze: body repeats are capped, markers do not double count', () => {
  const many = Array.from({ length: 12 }, (_, i) => `sentence ${i} that says something is confidential for the team`).join('\n');
  const v = analyzeZones({ body: many });
  assert.equal(v.score, 1); // 3 x 0.34 capped at 1.0
  assert.equal(v.confidential, true);
  const one = analyzeZones({ header: ['Proprietary and Confidential'] });
  assert.equal(one.findings.length, 1);
  assert.equal(one.findings[0].markerId, 'doc.marker.proprietary-confidential');
  // the same header on many pages is one signal
  assert.equal(analyzeZones({ header: Array.from({ length: 30 }, (_, i) => ({ text: 'CONFIDENTIAL', where: `page ${i + 1}` })) }).score, 1);
});

test('analyze: titles, metadata values and loose zones need a banner or tag', () => {
  assert.equal(analyzeZones({ title: ['Confidential data handling guide for new employees'] }).confidential, false);
  assert.equal(analyzeZones({ title: ['Roadmap 2026 — Confidential'] }).confidential, true);
  assert.equal(analyzeZones({ title: ['[CONFIDENTIAL] Q3 results'] }).confidential, true);
  assert.equal(analyzeZones({ metadata: [{ name: 'Keywords', value: 'pricing, confidential, 2026' }] }).confidential, true);
  assert.equal(analyzeZones({ metadata: [{ name: 'Subject', value: 'How we treat confidential customer records' }] }).confidential, false);
  assert.equal(analyzeZones({ header: [{ text: 'Please keep the API key confidential and rotate it', loose: true }] }).confidential, false);
  assert.equal(analyzeZones({ header: [{ text: 'CONFIDENTIAL', loose: true }] }).confidential, true);
});

test('analyze: classification-like metadata', () => {
  assert.equal(isClassificationName('MSIP_Label_1a2b_Name'), true);
  assert.equal(isClassificationName('dc:creator'), false);
  const label = analyzeZones({ metadata: [{ name: 'MSIP_Label_f42aa342-8706-4288-bd11-ebb85995028c_Name', value: 'Highly Confidential' }] });
  assert.equal(label.confidential, true);
  assert.equal(label.classification, 'HIGHLY CONFIDENTIAL');
  assert.equal(label.findings[0].kind, 'metadata');
  assert.equal(analyzeZones({ metadata: [{ name: 'Sensitivity', value: 'General' }] }).confidential, false);
  assert.equal(analyzeZones({ metadata: [{ name: 'Classification', value: 'Public' }] }).confidential, false);
  assert.equal(analyzeZones({ metadata: [{ name: 'confidential', value: 'true' }] }).confidential, true);
  assert.equal(analyzeZones({ metadata: [{ name: 'confidential', value: 'false' }] }).confidential, false);
  assert.equal(analyzeZones({ metadata: [{ name: 'visibility', value: 'internal' }] }).classification, 'INTERNAL');
});

test('analyze: options (threshold, pii, extra and disabled markers)', () => {
  const emails = Array.from({ length: 6 }, (_, i) => `person${i}@corp.io`).join('\n');
  const pii = analyzeZones({ body: emails });
  assert.equal(pii.confidential, true);
  assert.equal(pii.classification, 'PII');
  assert.equal(pii.pii.emails, 6);
  assert.equal(pii.findings[0].kind, 'pii');
  assert.ok(!JSON.stringify(pii).includes('person0@corp.io'), 'verdict must not contain raw identifiers');
  assert.equal(analyzeZones({ body: emails }, { piiThreshold: 10 }).confidential, false);
  assert.equal(analyzeZones({ body: emails }, { piiBlock: false }).confidential, false);
  assert.equal(analyzeZones({ body: 'ok' }).classification, null);

  assert.equal(analyzeZones({ header: ['Restricted'] }, { threshold: 0.5 }).confidential, true);
  assert.equal(analyzeZones({ header: ['CONFIDENTIAL'] }, { threshold: 2 }).confidential, false);

  const extra = [{ id: 'doc.marker.custom.falcon', label: 'Project Falcon', pattern: '\\bproject\\s+falcon\\b', flags: 'i', strength: 'strong' }];
  const custom = analyzeZones({ header: ['Project Falcon'] }, { extraMarkers: extra });
  assert.equal(custom.confidential, true);
  assert.equal(custom.classification, 'PROJECT FALCON');
  assert.equal(analyzeZones({ header: ['Project Falcon'] }).confidential, false);
  assert.equal(analyzeZones({ header: ['CONFIDENTIAL'] }, { disabledMarkers: ['doc.marker.confidential'] }).confidential, false);
  // an invalid custom pattern is ignored, not fatal
  assert.equal(analyzeZones({ header: ['CONFIDENTIAL'] }, { extraMarkers: [{ id: 'x', pattern: '(' }] }).confidential, true);
});

test('analyze: multi-language markers', () => {
  for (const banner of [
    'CONFIDENTIEL', 'Strictement confidentiel', 'Usage interne uniquement', 'Diffusion restreinte', 'Ne pas diffuser',
    'Streng vertraulich', 'Nur für den internen Gebrauch', 'CONFIDENCIAL', 'Solo para uso interno', 'Riservato', 'Confidenziale',
    'Internal use only', 'Do not distribute', 'Privileged & Confidential', 'TLP:RED', 'Trade secret', 'TOP SECRET',
    'Classification: C3', 'Sensitivity: Internal',
  ]) {
    assert.equal(analyzeZones({ header: [banner] }).confidential, true, `header "${banner}" should be confidential`);
  }
  assert.ok(DEFAULT_MARKERS.length >= 25);
  for (const m of DEFAULT_MARKERS) {
    assert.ok(m.id && m.label && m.pattern && ['strong', 'medium', 'weak'].includes(m.strength), `marker ${m.id} is malformed`);
    assert.doesNotThrow(() => new RegExp(m.pattern, m.flags));
  }
});

// ------------------------------------------------------------------------------------------------
// scan-text
// ------------------------------------------------------------------------------------------------
test('scan-text: confidential and clean', async () => {
  const conf = await scanTextFile({ buffer: Buffer.from('CONFIDENTIAL\n\nMerger timeline\nStep 1: sign the term sheet.\n'), filename: 'notes.txt' });
  assertVerdictShape(conf);
  assert.equal(conf.type, 'text');
  assert.equal(conf.scanner, 'scan-text');
  assert.equal(conf.confidential, true);
  assert.equal(conf.classification, 'CONFIDENTIAL');
  assert.match(conf.reasons[0], /header \(line 1\)/);

  const clean = await scanTextFile({ buffer: Buffer.from('Release notes\n\n- fixed the login page\n- please keep your token confidential\n'), filename: 'CHANGELOG.txt' });
  assertVerdictShape(clean);
  assert.equal(clean.confidential, false);
  assert.equal(clean.classification, null);

  const footer = Array.from({ length: 40 }, (_, i) => `line ${i}`).concat(['Internal use only']).join('\n');
  assert.equal((await scanTextFile({ buffer: Buffer.from(footer), filename: 'a.log' })).confidential, true);
  // UTF-16 with BOM
  const utf16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('DIFFUSION RESTREINTE\nBonjour', 'utf16le')]);
  assert.equal((await scanTextFile({ buffer: utf16, filename: 'a.txt' })).confidential, true);
});

test('scan-text: csv, eml and source-code flavours', async () => {
  const rows = ['name,email,ip'].concat(Array.from({ length: 4 }, (_, i) => `user${i},user${i}@corp.io,10.1.2.${i + 10}`)).join('\n');
  const csv = await scanTextFile({ buffer: Buffer.from(rows), filename: 'export.csv' });
  assert.equal(csv.confidential, true);
  assert.equal(csv.classification, 'PII');
  assert.equal(csv.pii.total, 8);
  assert.equal((await scanTextFile({ buffer: Buffer.from('CONFIDENTIAL\nitem,qty\npens,3\n'), filename: 'stock.csv' })).confidential, true);
  assert.equal((await scanTextFile({ buffer: Buffer.from('item,qty\npens,3\n'), filename: 'stock.csv' })).confidential, false);

  const eml = 'From: a@corp.io\r\nTo: b@corp.io\r\nSubject: Offer\r\nSensitivity: Company-Confidential\r\n\r\nSee attached.\r\n';
  const mail = await scanTextFile({ buffer: Buffer.from(eml), filename: 'offer.eml' });
  assert.equal(mail.confidential, true);
  assert.equal(mail.findings[0].kind, 'metadata');
  assert.equal((await scanTextFile({ buffer: Buffer.from('From: a@corp.io\r\nSubject: Lunch\r\n\r\nPizza at noon?\r\n'), filename: 'l.eml' })).confidential, false);

  // code: enum values and identifiers are not classification banners, and author e-mails do not block
  const code = [
    '// Authors: a@corp.io b@corp.io c@corp.io d@corp.io e@corp.io f@corp.io',
    'export enum Level { PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED }',
    'const labels = {',
    '  CONFIDENTIAL: "c",',
    '};',
  ].join('\n');
  const ts = await scanText(code, { filename: 'levels.ts' });
  assert.equal(ts.confidential, false);
  assert.equal(ts.pii.emails, 6);
  const banner = await scanText('/*\n * CONFIDENTIAL - do not distribute\n */\nint main(void) { return 0; }\n', { filename: 'main.c' });
  assert.equal(banner.confidential, true);
});

// ------------------------------------------------------------------------------------------------
// scan-markdown
// ------------------------------------------------------------------------------------------------
test('scan-markdown: front matter, comments, headings', async () => {
  const fm = await scanMarkdown({ buffer: Buffer.from('---\ntitle: Pricing\nclassification: Restricted\ntags: [a, b]\n---\n# Pricing\n\nNumbers.\n'), filename: 'pricing.md' });
  assertVerdictShape(fm);
  assert.equal(fm.type, 'markdown');
  assert.equal(fm.confidential, true);
  assert.equal(fm.classification, 'RESTRICTED');
  assert.deepEqual(zonesOf(fm), ['metadata:doc.metadata.classification']);

  const comment = await scanMarkdown({ buffer: Buffer.from('# Design\n\n<!-- INTERNAL USE ONLY -->\n\nText.\n'), filename: 'd.md' });
  assert.equal(comment.confidential, true);
  assert.deepEqual(zonesOf(comment), ['comments:doc.marker.internal-use-only']);

  const heading = await scanMarkdown({ buffer: Buffer.from('Roadmap (Confidential)\n======================\n\nText.\n'), filename: 'r.md' });
  assert.equal(heading.confidential, true);
  assert.deepEqual(zonesOf(heading), ['title:doc.marker.confidential']);

  const tags = await scanMarkdown({ buffer: Buffer.from('---\ntags:\n  - finance\n  - confidential\n---\nText.\n'), filename: 't.md' });
  assert.equal(tags.confidential, true);

  const clean = await scanMarkdown({
    buffer: Buffer.from('---\ntitle: Guide\nvisibility: public\n---\n# Setup guide\n\n## Handling confidential data\n\nKeep your API key confidential.\n'),
    filename: 'README.md',
  });
  assertVerdictShape(clean);
  assert.equal(clean.confidential, false);
});

// ------------------------------------------------------------------------------------------------
// scan-xml
// ------------------------------------------------------------------------------------------------
test('scan-xml: xml and html', async () => {
  const xml = await scanXml({ buffer: Buffer.from('<?xml version="1.0"?>\n<report sensitivity="internal"><title>Q3</title><p>Numbers</p></report>'), filename: 'r.xml' });
  assertVerdictShape(xml);
  assert.equal(xml.type, 'xml');
  assert.equal(xml.confidential, true);
  assert.equal(xml.classification, 'INTERNAL');

  const element = await scanXml({ buffer: Buffer.from('<doc><meta><Classification>Company Confidential</Classification></meta><body>x</body></doc>'), filename: 'd.xml' });
  assert.equal(element.confidential, true);

  const html = await scanXml({
    buffer: Buffer.from('<!DOCTYPE html><html><head><title>Spec</title><meta name="classification" content="Confidential"><style>.confidential{}</style></head><body><p>Hi</p><script>var confidential = 1;</script></body></html>'),
    filename: 'spec.html',
  });
  assert.equal(html.confidential, true);
  assert.deepEqual(zonesOf(html), ['metadata:doc.metadata.classification']); // script / style content is ignored

  const comment = await scanXml({ buffer: Buffer.from('<cfg><!-- CONFIDENTIAL --><a>1</a></cfg>'), filename: 'c.xml' });
  assert.equal(comment.confidential, true);

  const clean = await scanXml({ buffer: Buffer.from('<html><head><title>Docs</title></head><body><h1>Public API</h1><p>Hello &amp; welcome.</p></body></html>'), filename: 'i.html' });
  assertVerdictShape(clean);
  assert.equal(clean.confidential, false);
});

test('scan-xml: external entities are never resolved', async () => {
  const xxe = '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd"><!ENTITY y SYSTEM "http://127.0.0.1:9/x">]><d><a>&x;</a><b>&y;</b></d>';
  const v = await scanXml({ buffer: Buffer.from(xxe), filename: 'x.xml' });
  assert.equal(v.ok, true);
  assert.equal(v.confidential, false);
});

// ------------------------------------------------------------------------------------------------
// scan-pdf
// ------------------------------------------------------------------------------------------------
test('scan-pdf: fallback handles compressed real PDFs, encrypted PDFs are reported', async () => {
  for (const name of ['real-confidential.pdf', 'real-confidential-ttf.pdf', 'real-keywords.pdf']) {
    const v = await scanPdf(fixture(name), { pdfEngine: 'fallback' });
    assert.equal(v.ok, true, name);
    assert.equal(v.limited, true, name);
    assert.equal(v.confidential, true, name);
  }
  assert.equal((await scanPdf(fixture('real-clean.pdf'), { pdfEngine: 'fallback' })).confidential, false);

  const enc = await scanPdf(fixture('real-encrypted.pdf'));
  assert.equal(enc.ok, false);
  assert.match(enc.error, /password|encrypt/i);
  assert.deepEqual(Object.keys(enc).sort(), ['error', 'file', 'ok', 'type']);
  const encFb = await scanPdf(fixture('real-encrypted.pdf'), { pdfEngine: 'fallback' });
  assert.equal(encFb.ok, false);
});

// ------------------------------------------------------------------------------------------------
// scan-docx
// ------------------------------------------------------------------------------------------------
test('scan-docx: synthetic documents', async () => {
  const header = await scanDocx({ buffer: makeDocx({ header: wp('Acme &amp; Co — CONFIDENTIAL') }), filename: 'a.docx' });
  assertVerdictShape(header);
  assert.equal(header.type, 'docx');
  assert.equal(header.confidential, true);
  assert.deepEqual(zonesOf(header), ['header:doc.marker.confidential']);

  const label = await scanDocx({
    buffer: makeDocx({ custom: { 'MSIP_Label_0b1c_Enabled': 'true', 'MSIP_Label_0b1c_Name': 'Confidential' } }),
    filename: 'b.docx',
  });
  assert.equal(label.confidential, true);
  assert.equal(label.findings[0].kind, 'metadata');

  const general = await scanDocx({ buffer: makeDocx({ custom: { 'MSIP_Label_0b1c_Name': 'General' } }), filename: 'b2.docx' });
  assert.equal(general.confidential, false);

  const wm = await scanDocx({ buffer: makeDocx({ watermark: 'DO NOT COPY' }), filename: 'c.docx' });
  assert.equal(wm.confidential, true);
  assert.deepEqual(zonesOf(wm), ['watermark:doc.marker.do-not-distribute']);

  const title = await scanDocx({ buffer: makeDocx({ body: [wp('Strictly Confidential', 'Title'), wp('Body text')] }), filename: 'd.docx' });
  assert.equal(title.confidential, true);
  assert.ok(zonesOf(title).includes('title:doc.marker.strictly-confidential'));

  const footer = await scanDocx({ buffer: makeDocx({ footer: wp('Usage interne uniquement') }), filename: 'e.docx' });
  assert.deepEqual(zonesOf(footer), ['footer:doc.marker.usage-interne']);

  const clean = await scanDocx({
    buffer: makeDocx({ header: wp('Acme newsletter'), body: [wp('Welcome'), wp('Keep your badge private please')], comments: wp('is this confidential? no') }),
    filename: 'f.docx',
  });
  assertVerdictShape(clean);
  assert.equal(clean.confidential, false);

  assert.equal((await scanDocx({ buffer: makeZip({ 'hello.txt': 'x' }), filename: 'g.docx' })).ok, false);
  assert.equal((await scanDocx({ buffer: Buffer.from('nope'), filename: 'h.docx' })).ok, false);
});

test('scan-docx: real python-docx documents', async () => {
  const v = await scanDocx(fixture('real-confidential.docx'));
  assertVerdictShape(v);
  assert.equal(v.confidential, true);
  assert.deepEqual(zonesOf(v).sort(), ['footer:doc.marker.internal-use-only', 'header:doc.marker.confidential']);
  const clean = await scanDocx(fixture('real-clean.docx'));
  assert.equal(clean.confidential, false);
  assert.equal(clean.findings.length, 0);
});

// ------------------------------------------------------------------------------------------------
// scan-pptx
// ------------------------------------------------------------------------------------------------
test('scan-pptx: synthetic presentations', async () => {
  const footer = await scanPptx({
    buffer: makePptx({ slides: [slide(sp('Roadmap', 'ctrTitle'), sp('Company Confidential', 'ftr')), slide(sp('Agenda', 'title'), sp('Company Confidential', 'ftr'))] }),
    filename: 'a.pptx',
  });
  assertVerdictShape(footer);
  assert.equal(footer.type, 'pptx');
  assert.equal(footer.stats.slides, 2);
  assert.equal(footer.confidential, true);
  assert.deepEqual(zonesOf(footer), ['footer:doc.marker.strictly-confidential']);

  const title = await scanPptx({ buffer: makePptx({ slides: [slide(sp('Roadmap — Confidential', 'ctrTitle'))] }), filename: 'b.pptx' });
  assert.deepEqual(zonesOf(title), ['title:doc.marker.confidential']);

  const master = await scanPptx({
    buffer: makePptx({
      slides: [slide(sp('Roadmap', 'title'))],
      master: slide(sp('Click to edit Master title style', 'title'), sp('INTERNAL USE ONLY')),
    }),
    filename: 'c.pptx',
  });
  assert.deepEqual(zonesOf(master), ['watermark:doc.marker.internal-use-only']);

  const notes = await scanPptx({
    buffer: makePptx({ slides: [slide(sp('Roadmap', 'title'))], notes: slide(sp('Do not distribute', 'body'), sp('3', 'sldNum')) }),
    filename: 'd.pptx',
  });
  assert.equal(notes.confidential, true);
  assert.deepEqual(zonesOf(notes), ['comments:doc.marker.do-not-distribute']);

  const clean = await scanPptx({
    buffer: makePptx({ slides: [slide(sp('Team offsite', 'ctrTitle'), sp('Agenda and logistics', 'subTitle')), slide(sp('Day 1', 'title'), sp('Arrival'))] }),
    filename: 'e.pptx',
  });
  assertVerdictShape(clean);
  assert.equal(clean.confidential, false);
  assert.equal((await scanPptx({ buffer: makeDocx(), filename: 'f.pptx' })).ok, false);
});

test('scan-pptx: real python-pptx presentations', async () => {
  const v = await scanPptx(fixture('real-confidential.pptx'));
  assertVerdictShape(v);
  assert.equal(v.confidential, true);
  assert.equal(v.stats.slides, 2);
  assert.deepEqual(zonesOf(v), ['watermark:doc.marker.confidential']); // stamp on the slide master
  const clean = await scanPptx(fixture('real-clean.pptx'));
  assert.equal(clean.confidential, false);
  assert.equal(clean.findings.length, 0);
});

// ------------------------------------------------------------------------------------------------
// scan-xlsx
// ------------------------------------------------------------------------------------------------
test('scan-xlsx: synthetic workbooks', async () => {
  const hf = await scanXlsx({
    buffer: makeXlsx({ strings: ['Region', 'Margin'], sheetXml: '<sheetData/><headerFooter><oddHeader>&amp;C&amp;"Arial,Bold"&amp;14CONFIDENTIAL</oddHeader><oddFooter>&amp;RPage &amp;P of &amp;N</oddFooter></headerFooter>' }),
    filename: 'a.xlsx',
  });
  assertVerdictShape(hf);
  assert.equal(hf.type, 'xlsx');
  assert.equal(hf.stats.sheets, 1);
  assert.equal(hf.confidential, true);
  assert.deepEqual(zonesOf(hf), ['header:doc.marker.confidential']);

  const cell = await scanXlsx({ buffer: makeXlsx({ strings: ['Internal use only', 'Region', 'Margin'] }), filename: 'b.xlsx' });
  assert.equal(cell.confidential, true);
  assert.deepEqual(zonesOf(cell), ['body:doc.marker.internal-use-only']);

  const sheetName = await scanXlsx({ buffer: makeXlsx({ sheets: ['Summary', 'Confidential'] }), filename: 'c.xlsx' });
  assert.equal(sheetName.confidential, true);
  assert.equal(sheetName.stats.sheets, 2);

  const people = Array.from({ length: 6 }, (_, i) => `staff${i}@corp.io`);
  const pii = await scanXlsx({ buffer: makeXlsx({ strings: ['Email', ...people] }), filename: 'd.xlsx' });
  assert.equal(pii.confidential, true);
  assert.equal(pii.classification, 'PII');

  const clean = await scanXlsx({ buffer: makeXlsx({ strings: ['Item', 'Qty', 'Pens'], sheets: ['Stock'] }), filename: 'e.xlsx' });
  assertVerdictShape(clean);
  assert.equal(clean.confidential, false);
});

test('scan-xlsx: real openpyxl workbooks', async () => {
  const v = await scanXlsx(fixture('real-confidential.xlsx'));
  assertVerdictShape(v);
  assert.equal(v.confidential, true);
  assert.equal(v.classification, 'STRICTLY CONFIDENTIAL');
  assert.deepEqual(zonesOf(v), ['header:doc.marker.strictly-confidential']);
  const clean = await scanXlsx(fixture('real-clean.xlsx'));
  assert.equal(clean.confidential, false);
  assert.equal(clean.findings.length, 0);
});

// ------------------------------------------------------------------------------------------------
// scan-odf
// ------------------------------------------------------------------------------------------------
test('scan-odf: synthetic and real OpenDocument files', async () => {
  const header = await scanOdf({ buffer: makeOdt({ header: 'Vertraulich' }), filename: 'a.odt' });
  assertVerdictShape(header);
  assert.equal(header.type, 'odf');
  assert.equal(header.confidential, true);
  assert.deepEqual(zonesOf(header), ['header:doc.marker.vertraulich']);

  const meta = await scanOdf({ buffer: makeOdt({ userDefined: { Classification: 'Confidential' } }), filename: 'b.odt' });
  assert.equal(meta.confidential, true);
  assert.equal(meta.findings[0].kind, 'metadata');

  const clean = await scanOdf({ buffer: makeOdt({ header: 'Newsletter', paragraphs: ['Hello', 'World'] }), filename: 'c.odt' });
  assertVerdictShape(clean);
  assert.equal(clean.confidential, false);

  const real = await scanOdf(fixture('real-confidential.odt'));
  assert.equal(real.confidential, true);
  assert.deepEqual(zonesOf(real).sort(), ['header:doc.marker.usage-interne', 'metadata:doc.metadata.classification']);
  assert.equal((await scanOdf(fixture('real-clean.odt'))).confidential, false);
  assert.equal((await scanOdf({ buffer: makeDocx(), filename: 'd.odt' })).ok, false);
});

// ------------------------------------------------------------------------------------------------
// scan-rtf
// ------------------------------------------------------------------------------------------------
test('scan-rtf: header group, info group, body', async () => {
  const rtfHeader = String.raw`{\rtf1\ansi\deff0{\fonttbl{\f0 Arial;}}{\info{\title Pricing}{\author Jane}}{\header \pard\qc CONFIDENTIEL \u8212? usage interne\par}\pard Les prix sont n\'e9goci\'e9s.\par}`;
  const v = await scanRtf({ buffer: Buffer.from(rtfHeader, 'latin1'), filename: 'p.rtf' });
  assertVerdictShape(v);
  assert.equal(v.type, 'rtf');
  assert.equal(v.confidential, true);
  assert.deepEqual(zonesOf(v).sort(), ['header:doc.marker.confidentiel', 'header:doc.marker.usage-interne']);

  const rtfInfo = String.raw`{\rtf1\ansi{\info{\title Plan}{\keywords budget, confidential}{\*\userprops {\propname Classification}\proptype30{\staticval Restricted}}}\pard Text.\par}`;
  const info = await scanRtf({ buffer: Buffer.from(rtfInfo, 'latin1'), filename: 'i.rtf' });
  assert.equal(info.confidential, true);
  assert.ok(zonesOf(info).includes('metadata:doc.metadata.classification'));
  assert.ok(zonesOf(info).includes('metadata:doc.marker.confidential'));

  const rtfBody = String.raw`{\rtf1\ansi{\fonttbl{\f0 Confidential Sans;}}\pard INTERNAL USE ONLY\par Minutes of the meeting.\par}`;
  const body = await scanRtf({ buffer: Buffer.from(rtfBody, 'latin1'), filename: 'b.rtf' });
  assert.deepEqual(zonesOf(body), ['body:doc.marker.internal-use-only']); // the font table is not document text

  const rtfClean = String.raw`{\rtf1\ansi{\fonttbl{\f0 Arial;}}{\header \pard Newsletter\par}\pard Hello {\b world}.\par}`;
  const clean = await scanRtf({ buffer: Buffer.from(rtfClean, 'latin1'), filename: 'c.rtf' });
  assertVerdictShape(clean);
  assert.equal(clean.confidential, false);
  assert.equal((await scanRtf({ buffer: Buffer.from('plain text'), filename: 'd.rtf' })).ok, false);
});

// ------------------------------------------------------------------------------------------------
// scan-legacy-office
// ------------------------------------------------------------------------------------------------
test('scan-legacy-office: strings from OLE binaries', async () => {
  const wide = await scanLegacy({ buffer: makeOle(['CONFIDENTIAL', 'Supplier pricing for the next fiscal year.']), filename: 'p.doc' });
  assertVerdictShape(wide);
  assert.equal(wide.type, 'legacy-office');
  assert.equal(wide.limited, true);
  assert.equal(wide.confidential, true);

  const narrow = await scanLegacy({ buffer: makeOle(['Diffusion restreinte', 'Tarifs négociés.'], { wide: false }), filename: 'p.xls' });
  assert.equal(narrow.confidential, true);

  const clean = await scanLegacy({ buffer: makeOle(['Spring newsletter', 'The cafeteria menu has been refreshed.']), filename: 'n.doc' });
  assertVerdictShape(clean);
  assert.equal(clean.confidential, false);

  const encrypted = await scanLegacy({ buffer: makeOle(['EncryptedPackage', 'EncryptionInfo']), filename: 'locked.docx' });
  assert.equal(encrypted.ok, false);
  assert.match(encrypted.error, /password|encrypt/i);
  assert.equal((await scanLegacy({ buffer: Buffer.from('not ole at all'), filename: 'x.doc' })).ok, false);
});

// ------------------------------------------------------------------------------------------------
// index
// ------------------------------------------------------------------------------------------------
test('index: SUPPORTED_EXTENSIONS and detectType', () => {
  for (const ext of ['txt', 'pdf', 'docx', 'xml', 'md', 'pptx', 'xlsx', 'csv', 'html', 'rtf', 'odt', 'doc', 'ppt', 'xls', 'eml', 'json', 'yaml']) {
    assert.ok(SUPPORTED_EXTENSIONS.includes(ext), `.${ext} should be supported`);
  }
  assert.ok(SUPPORTED_EXTENSIONS.every((e) => e === e.toLowerCase() && !e.startsWith('.')));

  assert.equal(detectType('a.PDF'), 'pdf');
  assert.equal(detectType('C:\\docs\\plan.docx'), 'docx');
  assert.equal(detectType('deck.pptm'), 'pptx');
  assert.equal(detectType('book.xlsm'), 'xlsx');
  assert.equal(detectType('x.ods'), 'odf');
  assert.equal(detectType('x.rtf'), 'rtf');
  assert.equal(detectType('old.doc'), 'legacy-office');
  assert.equal(detectType('README.md'), 'markdown');
  assert.equal(detectType('page.htm'), 'xml');
  assert.equal(detectType('data.csv'), 'text');
  assert.equal(detectType('archive.zip'), null);
  assert.equal(detectType('noext'), null);

  // magic bytes win over the extension
  assert.equal(detectType('report.txt', makePdf([[72, 700, 'x']])), 'pdf');
  assert.equal(detectType('report.pdf', makeDocx()), 'docx');
  assert.equal(detectType('deck.docx', makePptx({ slides: [slide(sp('x'))] })), 'pptx');
  assert.equal(detectType('x.bin', makeXlsx()), 'xlsx');
  assert.equal(detectType('x.bin', makeOdt()), 'odf');
  assert.equal(detectType('x.docx', makeOle(['hello there'])), 'legacy-office');
  assert.equal(detectType('x.txt', Buffer.from('{\\rtf1 hello}')), 'rtf');
  assert.equal(detectType('x.docx', Buffer.from('just some text')), 'text');
  assert.equal(detectType('unknown.bin', Buffer.from('<?xml version="1.0"?><a/>')), 'xml');
  assert.equal(detectType('unknown.bin', Buffer.from([0, 1, 2, 3, 0, 0, 9])), null);
  assert.equal(detectType('x.zip', makeZip({ 'a.txt': 'x' })), null);
  // only the head of a real OOXML file is available
  const head = fs.readFileSync(fixture('real-confidential.docx')).subarray(0, 4096);
  assert.equal(detectType('upload.bin', head), 'docx');
});

test('index: scanDocument dispatches and never throws', async () => {
  for (const [name, type, confidential] of [
    ['real-confidential.docx', 'docx', true], ['real-clean.docx', 'docx', false],
    ['real-confidential.pptx', 'pptx', true], ['real-clean.pptx', 'pptx', false],
    ['real-confidential.xlsx', 'xlsx', true], ['real-clean.xlsx', 'xlsx', false],
    ['real-confidential.pdf', 'pdf', true], ['real-clean.pdf', 'pdf', false],
    ['real-confidential.odt', 'odf', true], ['real-clean.odt', 'odf', false],
  ]) {
    const v = await scanDocument(fixture(name));
    assertVerdictShape(v);
    assert.equal(v.type, type, name);
    assert.equal(v.confidential, confidential, name);
    assert.equal(v.file, fixture(name));
  }

  // buffer input, extension lies
  const lied = await scanDocument({ buffer: fs.readFileSync(fixture('real-confidential.pdf')), filename: 'notes.txt' });
  assert.equal(lied.type, 'pdf');
  assert.equal(lied.confidential, true);
  assert.equal(lied.file, 'notes.txt');

  const missing = await scanDocument(path.join(DOCS, 'does-not-exist.pdf'));
  assert.deepEqual(Object.keys(missing).sort(), ['error', 'file', 'ok', 'type']);
  assert.equal(missing.ok, false);
  assert.match(missing.error, /not found/);

  const unsupported = await scanDocument({ buffer: Buffer.from([0, 1, 2, 3, 0, 0]), filename: 'blob.bin' });
  assert.equal(unsupported.ok, false);
  assert.match(unsupported.error, /unsupported/);

  for (const bad of [null, undefined, 42, {}, { buffer: 12 }]) {
    const v = await scanDocument(bad);
    assert.equal(v.ok, false);
  }
  assert.equal((await scanDocument(DOCS)).ok, false); // a directory

  // size guard: a sparse 101 MB file is refused without being read
  const tmp = path.join(os.tmpdir(), `staffet-big-${process.pid}.txt`);
  fs.writeFileSync(tmp, 'x');
  fs.truncateSync(tmp, 101 * 1024 * 1024);
  try {
    const big = await scanDocument(tmp);
    assert.equal(big.ok, false);
    assert.match(big.error, /too large/);
  } finally {
    fs.rmSync(tmp, { force: true });
  }

  // options reach the analyzer
  const strict = await scanDocument(fixture('real-clean.docx'), {
    extraMarkers: [{ id: 'doc.marker.custom.newsletter', label: 'NEWSLETTER', pattern: '\\bnewsletter\\b', strength: 'strong' }],
  });
  assert.equal(strict.confidential, true);
  assert.equal(strict.classification, 'NEWSLETTER');
});

test('index: scanText picks the flavour from the file name', async () => {
  const md = await scanText('---\nsensitivity: confidential\n---\nText', { filename: 'docs/plan.md' });
  assertVerdictShape(md);
  assert.equal(md.type, 'markdown');
  assert.equal(md.scanner, 'scan-markdown');
  assert.equal(md.file, 'docs/plan.md');
  assert.equal(md.confidential, true);

  const html = await scanText('<html><body><p>CONFIDENTIAL</p><p>x</p></body></html>', { filename: 'a.html' });
  assert.equal(html.type, 'xml');
  assert.equal(html.confidential, true);

  // text a harness extracted from a binary document is plain text
  const fromPdf = await scanText('Northwind Trading - CONFIDENTIAL\nSection 1\nFigures', { filename: 'C:\\docs\\report.pdf' });
  assert.equal(fromPdf.type, 'text');
  assert.equal(fromPdf.confidential, true);

  const none = await scanText('just a note about lunch');
  assertVerdictShape(none);
  assert.equal(none.file, null);
  assert.equal(none.confidential, false);
  assert.equal((await scanText('')).confidential, false);
  assert.equal((await scanText(null)).confidential, false);
  assert.equal((await scanText('Restricted', { filename: 'a.txt', threshold: 0.5 })).confidential, true);
});

// ------------------------------------------------------------------------------------------------
// CLIs
// ------------------------------------------------------------------------------------------------
function cli(script, args) {
  return spawnSync(process.execPath, [path.join(ROOT, 'scanners', script), ...args], { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
}

test('cli: exit codes and --json', () => {
  const conf = cli('index.mjs', [fixture('real-confidential.docx'), '--json']);
  assert.equal(conf.status, 2, conf.stderr);
  const verdict = JSON.parse(conf.stdout);
  assert.equal(verdict.confidential, true);
  assert.equal(verdict.type, 'docx');

  const clean = cli('index.mjs', [fixture('real-clean.docx')]);
  assert.equal(clean.status, 0, clean.stderr);
  assert.match(clean.stdout, /clean/);

  const multi = cli('index.mjs', [fixture('real-clean.pdf'), fixture('real-confidential.xlsx'), '--json']);
  assert.equal(multi.status, 2);
  assert.equal(JSON.parse(multi.stdout).length, 2);

  const missing = cli('index.mjs', [path.join(DOCS, 'nope.pdf')]);
  assert.equal(missing.status, 1);
  assert.equal(cli('index.mjs', []).status, 1);
  assert.equal(cli('index.mjs', ['--help']).status, 0);
});

test('cli: every scanner script runs standalone', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'staffet-cli-'));
  try {
    const write = (name, data) => {
      const p = path.join(tmp, name);
      fs.writeFileSync(p, data);
      return p;
    };
    const cases = [
      ['scan-text.mjs', write('a.txt', 'CONFIDENTIAL\nplan\n'), 2],
      ['scan-text.mjs', write('b.txt', 'hello\n'), 0],
      ['scan-markdown.mjs', write('a.md', '# Plan\n\n<!-- internal use only -->\n'), 2],
      ['scan-xml.mjs', write('a.xml', '<d classification="restricted"/>'), 2],
      ['scan-pdf.mjs', fixture('real-confidential.pdf'), 2],
      ['scan-pdf.mjs', fixture('real-clean.pdf'), 0],
      ['scan-pdf.mjs', fixture('real-encrypted.pdf'), 1],
      ['scan-docx.mjs', fixture('real-confidential.docx'), 2],
      ['scan-pptx.mjs', fixture('real-confidential.pptx'), 2],
      ['scan-xlsx.mjs', fixture('real-clean.xlsx'), 0],
      ['scan-odf.mjs', fixture('real-confidential.odt'), 2],
      ['scan-rtf.mjs', write('a.rtf', String.raw`{\rtf1\ansi{\header \pard Confidential\par}\pard Text\par}`), 2],
      ['scan-legacy-office.mjs', write('a.doc', makeOle(['TOP SECRET', 'the plan'])), 2],
    ];
    for (const [script, file, code] of cases) {
      const r = cli(script, [file, '--json']);
      assert.equal(r.status, code, `${script} ${path.basename(file)}: ${r.stderr || r.stdout}`);
      const v = JSON.parse(r.stdout);
      assert.equal(v.ok, code !== 1);
    }
    // options
    const strict = cli('scan-text.mjs', [write('c.txt', 'Restricted\nnotes\n'), '--threshold', '0.5']);
    assert.equal(strict.status, 2);
    const markers = write('markers.json', JSON.stringify([{ id: 'doc.marker.custom.x', label: 'Codename', pattern: '\\bbluebird\\b', strength: 'strong' }]));
    assert.equal(cli('scan-text.mjs', [write('d.txt', 'Bluebird\nnotes\n'), '--markers', markers]).status, 2);
    const emails = write('e.txt', Array.from({ length: 6 }, (_, i) => `p${i}@corp.io`).join('\n'));
    assert.equal(cli('scan-text.mjs', [emails]).status, 2);
    assert.equal(cli('scan-text.mjs', [emails, '--pii-threshold', '50']).status, 0);
    assert.equal(cli('scan-text.mjs', [emails, '--bogus']).status, 1);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});
