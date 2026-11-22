// Zone-based confidentiality scoring shared by every document scanner.
//
// A scanner extracts text into zones and calls analyzeZones():
//   metadata  [{name, value}]   document properties (title, keywords, sensitivity labels ...)
//   title     string[]          document / slide / sheet titles
//   header    string[]          running page headers
//   footer    string[]          running page footers
//   watermark string[]          watermark / stamp text
//   comments  string[]          review comments, HTML comments, speaker notes
//   body      string            everything else
//
// Zone items may be plain strings or { text, where, loose } objects:
//   where - location shown in reasons ("page 2", "slide 1", "header1.xml")
//   loose - the zone is only a guess (first lines of a text file): the marker gets full weight only
//           when the line looks like a banner / classification tag, otherwise it counts as body prose.
//   bannerOnly - (with loose) a line that is not a banner is ignored altogether (comments in source code).
//
// Weights (score >= threshold => confidential):
//   strong marker   header / footer / watermark ............................ 1.00
//                   banner-like in title / metadata / comments / body ...... 1.00
//                   inside running prose .................................... 0.34
//   medium marker   privileged zone (or banner-like title/metadata/comment)  0.60, body 0.20
//   weak marker     privileged zone (or banner-like title/metadata/comment)  0.34, body 0.00
//   classification-like metadata field with a restrictive value ............ 1.00
//   distinct private identifiers >= piiThreshold ............................ 1.00
// Body-class contributions count each marker at most 3 times and are capped at 1.0 in total.

import { DEFAULT_MARKERS } from './markers.mjs';
import { countPII, maskPII } from './pii.mjs';

const STRENGTH_RANK = { strong: 3, medium: 2, weak: 1 };
const PRIVILEGED_WEIGHT = { strong: 1.0, medium: 0.6, weak: 0.34 };
const BANNER_WEIGHT = { strong: 1.0, medium: 0.2, weak: 0 }; // banner line in the body
const PROSE_WEIGHT = { strong: 0.34, medium: 0.2, weak: 0 };
const BODY_CAP = 1.0;
const MAX_PER_MARKER_BODY = 3;
const MAX_MATCHES_PER_MARKER = 200;

const STRICT_ZONES = new Set(['header', 'footer', 'watermark']);
const ZONE_LABEL = {
  metadata: 'document metadata',
  title: 'title',
  header: 'header',
  footer: 'footer',
  watermark: 'watermark',
  comments: 'comments',
  body: 'body',
};

// Unicode-aware replacement for \b (JS \b is ASCII-only, so "privé" would never end on a boundary).
// Explicit letter ranges instead of \p{L}: V8 compiles /\p{L}/iu classes very slowly (~5 ms per marker).
const WORD =
  '[0-9A-Za-z_\\u00AA\\u00B5\\u00BA\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u024F\\u0370-\\u03FF\\u0400-\\u052F\\u0590-\\u06FF\\u0900-\\u0E7F\\u1E00-\\u1FFF\\u3040-\\u30FF\\u3400-\\u9FFF\\uAC00-\\uD7AF]';
const UNICODE_BOUNDARY = `(?:(?<!${WORD})(?=${WORD})|(?<=${WORD})(?!${WORD}))`;

const DECORATION = /[#*_>|=~\-–—:;.,!?"'“”«»()[\]{}<>/\\•·+^`]/g;
const TAG_DELIM_END = /[-–—:|/()[\]{}<>•·*#=~!]$/;
const TAG_DELIM_START = /^[-–—:|/()[\]{}<>•·*#=~!]/;

/** Normalize text for matching: NFKC, exotic spaces -> space, zero-width chars removed, spaced caps collapsed. */
export function norm(input) {
  let s = String(input ?? '');
  if (!s) return '';
  s = s
    .normalize('NFKC')
    .replace(/[   -   　]/g, ' ')
    .replace(/[​-‍⁠﻿­]/g, '');
  // "C O N F I D E N T I A L" (letter-spaced watermark / banner) -> "CONFIDENTIAL"
  if (/\p{L} \p{L} \p{L} \p{L}/u.test(s)) {
    s = s.replace(/(?<![\p{L}\p{N}])(?:\p{L} ){4,}\p{L}(?![\p{L}\p{N}])/gu, (m) => m.replace(/ /g, ''));
  }
  return s;
}

function compileOne(m) {
  if (!m || typeof m.pattern !== 'string' || !m.pattern) return null;
  const strength = STRENGTH_RANK[m.strength] ? m.strength : 'strong';
  const flagSet = new Set(String(m.flags ?? 'i').replace(/[^dimsuy]/g, '').split(''));
  flagSet.add('g');
  let re = null;
  try {
    re = new RegExp(m.pattern.replace(/\\b/g, UNICODE_BOUNDARY), [...flagSet].join(''));
  } catch {
    try {
      re = new RegExp(m.pattern, [...flagSet].join(''));
    } catch {
      return null; // invalid user pattern: ignore rather than fail the scan
    }
  }
  const label = String(m.label || m.id || 'MARKER').toUpperCase();
  return { id: m.id || `doc.marker.custom.${label.toLowerCase().replace(/\W+/g, '-')}`, label, strength, re };
}

let defaultCompiled = null;
function compileMarkers(opts) {
  const extras = Array.isArray(opts.extraMarkers) ? opts.extraMarkers : [];
  const disabled = Array.isArray(opts.disabledMarkers) ? opts.disabledMarkers : [];
  if (!extras.length && !disabled.length) {
    if (!defaultCompiled) defaultCompiled = sortMarkers(DEFAULT_MARKERS.map(compileOne).filter(Boolean));
    return defaultCompiled;
  }
  const off = new Set(disabled);
  // custom markers first so that they win overlaps against built-ins of the same strength
  return sortMarkers([...extras, ...DEFAULT_MARKERS].map(compileOne).filter((m) => m && !off.has(m.id)));
}
function sortMarkers(list) {
  return list
    .map((m, i) => [m, i])
    .sort((a, b) => STRENGTH_RANK[b[0].strength] - STRENGTH_RANK[a[0].strength] || a[1] - b[1])
    .map(([m]) => m);
}

/** All non-overlapping marker matches in a string; stronger / more specific markers win overlaps. */
function findMarkers(text, markers) {
  const hits = [];
  if (!text) return hits;
  for (const marker of markers) {
    const re = marker.re;
    re.lastIndex = 0;
    let m;
    let n = 0;
    while ((m = re.exec(text))) {
      if (m[0].length === 0) {
        re.lastIndex++;
        continue;
      }
      const start = m.index;
      const end = start + m[0].length;
      let overlaps = false;
      for (const h of hits) {
        if (start < h.end && end > h.start) {
          overlaps = true;
          break;
        }
      }
      if (!overlaps) hits.push({ marker, start, end, match: m[0] });
      if (++n >= MAX_MATCHES_PER_MARKER) break;
    }
  }
  return hits;
}

/**
 * A line reads as a classification banner / tag when it is short and mostly made of markers
 * ("CONFIDENTIAL", "Company Confidential") or when a capitalized marker is set off by delimiters
 * ("Roadmap 2026 — Confidential", "[CONFIDENTIAL] Q3 results", "CONFIDENTIAL - Page 3 of 10").
 */
function isBannerLike(line, lineHits, lineStart) {
  const stripped = line.replace(DECORATION, ' ').replace(/\s+/g, ' ').trim();
  if (!stripped) return false;
  let covered = 0;
  let capitalized = false;
  for (const h of lineHits) {
    covered += h.match.replace(DECORATION, ' ').replace(/\s+/g, ' ').trim().length;
    if (/^\p{Lu}/u.test(h.match)) capitalized = true;
  }
  if (stripped.length <= 80) {
    const coverage = covered / stripped.length;
    // the line is nothing but the marker, or a short capitalized label ("Acme Corp Confidential") -
    // a lower-case mention in a short sentence ("is this confidential? no") is not a banner
    if (coverage >= 0.9 || (capitalized && coverage >= 0.5)) return true;
  }
  if (line.length > 200) return false;
  for (const h of lineHits) {
    if (!/^\p{Lu}/u.test(h.match)) continue;
    const before = line.slice(0, h.start - lineStart).trimEnd();
    const after = line.slice(h.end - lineStart).trimStart();
    if ((before === '' || TAG_DELIM_END.test(before)) && (after === '' || TAG_DELIM_START.test(after))) return true;
  }
  return false;
}

function clip(s, max = 120) {
  const t = String(s).replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 1)}…` : t;
}
function contextAround(text, start, end, max = 120) {
  const pad = Math.max(0, Math.floor((max - (end - start)) / 2));
  const a = Math.max(0, start - pad);
  const b = Math.min(text.length, end + pad);
  return clip(maskPII(`${a > 0 ? '…' : ''}${text.slice(a, b)}${b < text.length ? '…' : ''}`), max);
}

const CLASSIFICATION_NAME =
  /(?:classification|classif(?:ication)?$|sensitivity|sensibilit|confidential|confidentiel|protective[\s_-]?marking|security[\s_-]?(?:level|class|marking|label)|^security$|^distribution(?:[\s_-]?(?:level|statement|scope))?$|^visibility$|dissemination|vertraulich|^access[\s_-]?level$|^handling(?:[\s_-]?caveat)?$)/i;
const FLAG_NAME = /^(?:is[\s_-]?)?(?:confidential|confidentiel|classified|restricted)$/i;

/** True for property / element / attribute names that carry a classification ("Sensitivity", "MSIP_Label_..._Name"). */
export function isClassificationName(name) {
  const n = String(name ?? '').trim().replace(/^[\w.-]+:/, ''); // drop XML namespace prefix
  if (!n) return false;
  if (/^msip_label_.*_name$/i.test(n)) return true;
  return CLASSIFICATION_NAME.test(n);
}

const RESTRICTIVE_VALUES = [
  [/\b(?:top[\s-]+secret|streng\s+geheim|tr[èe]s\s+secret)\b/i, 'TOP SECRET'],
  [/\b(?:highly|strictly|strictement|hautement)[\s-]+confiden[tc]i[ae]l(?:le)?\b/i, 'HIGHLY CONFIDENTIAL'],
  [/\bcompany[\s-]+confidential\b/i, 'COMPANY CONFIDENTIAL'],
  [/\bconfiden[tcz]i[ae]l(?:le|e)?\b/i, 'CONFIDENTIAL'],
  [/\b(?:vertraulich|riservat[oa])\b/i, 'CONFIDENTIAL'],
  [/\b(?:restricted|restreint[e]?|restringido|eingeschr(?:ä|ae)nkt|limited|controlled)\b/i, 'RESTRICTED'],
  [/\b(?:secret|geheim|secreto|segreto)\b/i, 'SECRET'],
  [/\b(?:internal|interne?|interno|intern)\b/i, 'INTERNAL'],
  [/\b(?:private|priv[ée]e?|privat|privado|personal)\b/i, 'PRIVATE'],
  [/\b(?:sensitive|sensible)\b/i, 'SENSITIVE'],
  [/^\s*c[23]\s*$/i, 'CONFIDENTIAL'],
];
const LABEL_RANK = {
  'TOP SECRET': 9, 'HIGHLY CONFIDENTIAL': 8, 'STRICTLY CONFIDENTIAL': 8, 'COMPANY CONFIDENTIAL': 7, CONFIDENTIAL: 6,
  RESTRICTED: 5, SECRET: 5, INTERNAL: 3, PRIVATE: 2, SENSITIVE: 2,
};
const labelRank = (label) => LABEL_RANK[label] ?? 4;
// Fields that hold a list of tags: every entry is judged on its own ("pricing, confidential, 2026").
const KEYWORD_FIELD = /^(?:keywords?|tags?|categor(?:y|ies)|labels?|content[\s_-]?status|status)$/i;
const PERMISSIVE_VALUE = /\b(?:public|publique|[öo]ffentlich|general|unclassified|non[\s-]?classifi[ée]|unrestricted|open|none|n\/a)\b/i;

/** Classification label ("CONFIDENTIAL", "RESTRICTED", ...) carried by a classification-like field, or null. */
function classificationLabel(name, value) {
  const v = norm(value).trim();
  if (!v) return null;
  const bare = String(name).trim().replace(/^[\w.-]+:/, '');
  if (FLAG_NAME.test(bare) || /confiden[tc]i/i.test(bare)) {
    if (/^(?:true|yes|oui|ja|s[ií]|1|y|high|strict)$/i.test(v)) return bare.replace(/^is[\s_-]?/i, '').toUpperCase();
    if (/^(?:false|no|non|nein|0|n|none|low)$/i.test(v)) return null;
  }
  if (PERMISSIVE_VALUE.test(v) && !/\bnot\s+(?:for\s+)?public\b/i.test(v)) return null;
  for (const [re, label] of RESTRICTIVE_VALUES) if (re.test(v)) return label;
  return null;
}

function toItems(list, zone) {
  const out = [];
  if (list == null) return out;
  for (const it of Array.isArray(list) ? list : [list]) {
    if (it == null) continue;
    if (typeof it === 'string') {
      const text = norm(it).trim();
      if (text) out.push({ text, where: '', loose: !STRICT_ZONES.has(zone) });
    } else if (typeof it === 'object' && it.text != null) {
      const text = norm(it.text).trim();
      if (text) {
        out.push({
          text,
          where: it.where ? String(it.where) : '',
          loose: it.loose ?? !STRICT_ZONES.has(zone),
          bannerOnly: it.bannerOnly === true, // ignore the item entirely unless it reads as a banner
        });
      }
    }
  }
  return out;
}

/**
 * Score the extracted zones of a document.
 * @param {object} zones
 * @param {{threshold?: number, piiThreshold?: number, piiBlock?: boolean, extraMarkers?: object[],
 *          disabledMarkers?: string[], maxBodyChars?: number}} [opts]
 * @returns {{confidential: boolean, score: number, threshold: number, classification: string|null,
 *            reasons: string[], findings: object[], pii: object, stats: {chars: number}}}
 */
export function analyzeZones(zones = {}, opts = {}) {
  const threshold = Number.isFinite(Number(opts.threshold)) ? Number(opts.threshold) : 1.0;
  const piiThreshold = Number.isFinite(Number(opts.piiThreshold)) ? Number(opts.piiThreshold) : 5;
  const piiBlock = opts.piiBlock !== false;
  const maxBodyChars = Number.isFinite(Number(opts.maxBodyChars)) ? Number(opts.maxBodyChars) : 2_000_000;
  const markers = compileMarkers(opts);

  // key -> aggregated finding
  const agg = new Map();
  const add = (f) => {
    // one finding per marker + zone: a header repeated on 50 pages is still a single signal
    const key = `${f.kind}|${f.markerId}|${f.zone}|${f.cls}|${f.kind === 'metadata' ? f.match : ''}`;
    const cur = agg.get(key);
    if (cur) cur.count++;
    else agg.set(key, { ...f, count: 1 });
  };

  let chars = 0;
  const piiParts = [];

  // ---- metadata --------------------------------------------------------------------------------
  for (const entry of Array.isArray(zones.metadata) ? zones.metadata : []) {
    if (!entry || entry.value == null) continue;
    const name = String(entry.name ?? '').trim();
    const value = norm(Array.isArray(entry.value) ? entry.value.join(', ') : entry.value).trim().slice(0, 4000);
    if (!value) continue;
    chars += value.length;
    piiParts.push(value);
    if (isClassificationName(name)) {
      const label = classificationLabel(name, value);
      if (label) {
        add({
          kind: 'metadata', markerId: 'doc.metadata.classification', zone: 'metadata', cls: 'privileged', where: name,
          match: label, label, strength: 'strong', weightEach: 1.0, context: clip(maskPII(`${name} = ${value}`)),
        });
      }
      continue;
    }
    const bare = name.replace(/^[\w.-]+:/, '');
    const parts = KEYWORD_FIELD.test(bare) ? value.split(/[,;|\n]+/).map((p) => p.trim()).filter(Boolean) : [value];
    for (const part of parts) {
      const hits = findMarkers(part, markers);
      if (!hits.length) continue;
      const banner = isBannerLike(part, hits, 0);
      for (const h of hits) {
        const s = h.marker.strength;
        add({
          kind: 'marker', markerId: h.marker.id, zone: 'metadata', cls: banner ? 'privileged' : 'prose', where: name,
          match: h.match, label: h.marker.label, strength: s, weightEach: banner ? PRIVILEGED_WEIGHT[s] : PROSE_WEIGHT[s],
          context: clip(maskPII(`${name} = ${value}`)),
        });
      }
    }
  }

  // ---- title / header / footer / watermark / comments -----------------------------------------
  for (const zone of ['title', 'header', 'footer', 'watermark', 'comments']) {
    for (const item of toItems(zones[zone], zone)) {
      chars += item.text.length;
      piiParts.push(item.text);
      // multi-line items are judged line by line
      for (const line of item.text.split(/\r?\n/)) {
        if (!line.trim()) continue;
        const hits = findMarkers(line, markers);
        if (!hits.length) continue;
        const privileged = !item.loose || isBannerLike(line, hits, 0);
        if (!privileged && item.bannerOnly) continue;
        // a guessed header / footer line that is not a banner is just body text
        const zoneName = !privileged && (zone === 'header' || zone === 'footer') ? 'body' : zone;
        for (const h of hits) {
          const s = h.marker.strength;
          add({
            kind: 'marker', markerId: h.marker.id, zone: zoneName, cls: privileged ? 'privileged' : 'prose', where: item.where,
            match: h.match, label: h.marker.label, strength: s,
            weightEach: privileged ? PRIVILEGED_WEIGHT[s] : PROSE_WEIGHT[s],
            context: contextAround(line, h.start, h.end),
          });
        }
      }
    }
  }

  // ---- body ------------------------------------------------------------------------------------
  const bodyRaw = Array.isArray(zones.body) ? zones.body.join('\n') : String(zones.body ?? '');
  const body = norm(bodyRaw.length > maxBodyChars ? bodyRaw.slice(0, maxBodyChars) : bodyRaw);
  chars += body.length;
  if (body) {
    piiParts.push(body);
    const hits = findMarkers(body, markers).sort((a, b) => a.start - b.start);
    let i = 0;
    while (i < hits.length) {
      // group hits that sit on the same line
      const ls = body.lastIndexOf('\n', hits[i].start - 1) + 1;
      let le = body.indexOf('\n', hits[i].start);
      if (le < 0) le = body.length;
      const lineHits = [];
      while (i < hits.length && hits[i].start < le) lineHits.push(hits[i++]);
      const line = body.slice(ls, le);
      const banner = isBannerLike(line, lineHits, ls);
      for (const h of lineHits) {
        const s = h.marker.strength;
        const weightEach = banner ? BANNER_WEIGHT[s] : PROSE_WEIGHT[s];
        add({
          kind: 'marker', markerId: h.marker.id, zone: 'body', cls: banner ? 'banner' : 'prose', where: '',
          match: h.match, label: h.marker.label, strength: s, weightEach,
          context: contextAround(body, h.start, h.end),
        });
      }
    }
  }

  // ---- private information ---------------------------------------------------------------------
  const piiCount = countPII(piiParts.join('\n'));
  const pii = { emails: piiCount.emails, ipv4: piiCount.ipv4, cards: piiCount.cards, ibans: piiCount.ibans, total: piiCount.total };

  // ---- score -----------------------------------------------------------------------------------
  const findings = [];
  const reasons = [];
  let privilegedScore = 0;
  let bodyScore = 0;
  let best = null; // strongest contributor -> classification label

  const ordered = [...agg.values()].sort(
    (a, b) => b.weightEach - a.weightEach || STRENGTH_RANK[b.strength] - STRENGTH_RANK[a.strength],
  );
  for (const f of ordered) {
    let weight;
    if (f.cls === 'privileged') {
      weight = f.weightEach; // a header repeated on every page still counts once
      privilegedScore += weight;
    } else {
      weight = f.weightEach * Math.min(f.count, MAX_PER_MARKER_BODY);
      bodyScore += weight;
    }
    weight = Math.round(weight * 100) / 100;
    if (weight <= 0) continue; // weak words in running text carry no signal: do not report them
    findings.push({
      kind: f.kind, markerId: f.markerId, zone: f.zone, match: clip(f.match, 80), strength: f.strength, weight, context: f.context,
    });
    const zoneLabel = ZONE_LABEL[f.zone] || f.zone;
    const times = f.count > 1 ? ` (×${f.count})` : '';
    if (f.kind === 'metadata') {
      reasons.push(`Metadata field "${f.where}" is classified ${f.match}`);
    } else if (f.cls === 'privileged') {
      const where = f.zone === 'metadata' ? ` "${f.where}"` : f.where ? ` (${f.where})` : '';
      reasons.push(`Marker "${clip(f.match, 60)}" in ${zoneLabel}${where}${times}`);
    } else if (f.cls === 'banner') {
      reasons.push(`Marker "${clip(f.match, 60)}" as a banner line in ${zoneLabel}${times}`);
    } else {
      const where = f.zone === 'metadata' ? ` "${f.where}"` : '';
      reasons.push(`Mention of "${clip(f.match, 60)}" in ${zoneLabel}${where} text${times}`);
    }
    const cand = { weight, strength: f.strength, label: f.label };
    if (
      !best ||
      cand.weight > best.weight ||
      (cand.weight === best.weight && STRENGTH_RANK[cand.strength] > STRENGTH_RANK[best.strength]) ||
      (cand.weight === best.weight && cand.strength === best.strength && labelRank(cand.label) > labelRank(best.label))
    ) {
      best = cand;
    }
  }

  const markerScore = privilegedScore + Math.min(bodyScore, BODY_CAP);
  let score = markerScore;
  let piiTriggered = false;
  if (piiThreshold > 0 && pii.total >= piiThreshold) {
    const parts = [];
    if (pii.emails) parts.push(`${pii.emails} e-mail address${pii.emails > 1 ? 'es' : ''}`);
    if (pii.ipv4) parts.push(`${pii.ipv4} IP address${pii.ipv4 > 1 ? 'es' : ''}`);
    if (pii.cards) parts.push(`${pii.cards} card number${pii.cards > 1 ? 's' : ''}`);
    if (pii.ibans) parts.push(`${pii.ibans} IBAN${pii.ibans > 1 ? 's' : ''}`);
    const weight = piiBlock ? 1.0 : 0;
    if (piiBlock) {
      score += weight;
      piiTriggered = true;
    }
    findings.push({
      kind: 'pii', markerId: 'doc.pii.threshold', zone: 'body', match: `${pii.total} private identifiers`, strength: 'strong', weight,
      context: clip(`${parts.join(', ')}${piiCount.samples.length ? ` — e.g. ${piiCount.samples.slice(0, 3).join(', ')}` : ''}`),
    });
    reasons.push(`${pii.total} distinct private identifiers (${parts.join(', ')})${piiBlock ? '' : ' — reported only'}`);
  }

  score = Math.round(score * 100) / 100;
  const confidential = score >= threshold;
  let classification = null;
  if (confidential) {
    if (best && (markerScore >= threshold || !piiTriggered)) classification = best.label;
    else if (piiTriggered) classification = best && best.weight >= 1 ? best.label : 'PII';
    else if (best) classification = best.label;
  }

  return { confidential, score, threshold, classification, reasons, findings, pii, stats: { chars } };
}
