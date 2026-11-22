// Small, self-contained private-information detector used by the document scanners.
// It only COUNTS distinct identifiers and produces masked samples - full values never leave this module.

const MAX_SCAN_CHARS = 2_000_000;

export const PII_PATTERNS = Object.freeze({
  email: /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}(?![A-Za-z0-9-])/g,
  ipv4: /(?<![\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w]|\.\d)/g,
  card: /(?<![\w.-])\d(?:[ -]?\d){12,18}(?![\w-]|\.\d)/g,
  iban: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g,
});

const PLACEHOLDER_EMAIL_DOMAIN = /(?:^|\.)(?:example\.(?:com|org|net)|example|test|invalid|localhost|domain\.com|email\.com)$/i;
const ASSET_TLD = /\.(?:png|jpe?g|gif|svg|webp|ico|bmp|css|js|json|map)$/i;
const VERSION_CONTEXT = /(?:version|ver\.?|v|release|build|rev(?:ision)?|firmware|fw|sw|section|chapter|§)\s*[:=#]?\s*$/i;

/** True when an e-mail match is a real-looking address (not an asset name, SSH user or placeholder). */
export function isRealEmail(email) {
  const at = email.lastIndexOf('@');
  if (at < 1) return false;
  const local = email.slice(0, at);
  const domain = email.slice(at + 1);
  if (ASSET_TLD.test(domain)) return false; // logo@2x.png
  if (PLACEHOLDER_EMAIL_DOMAIN.test(domain)) return false;
  if (/^(?:git|hg|svn)$/i.test(local)) return false; // git@host:org/repo.git
  return true;
}

/**
 * True when an IPv4 match should count as private network information.
 * Skips loopback, unspecified, netmasks, broadcast and version-like contexts ("version 1.2.3.4").
 */
export function isRealIPv4(ip, text = '', index = 0) {
  const o = ip.split('.').map(Number);
  if (o.length !== 4 || o.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  if (o[0] === 127 || o[0] === 0 || o[0] === 255) return false;
  if (o.every((n) => n <= 9)) return false; // 1.2.3.4 - section numbers / versions
  if (o[0] >= 224) return false; // multicast / reserved
  if (text && index > 0 && VERSION_CONTEXT.test(text.slice(Math.max(0, index - 16), index))) return false;
  return true;
}

export function luhnValid(digits) {
  if (!/^\d{13,19}$/.test(digits)) return false;
  if (/^(\d)\1+$/.test(digits)) return false;
  if (!/^[2-6]/.test(digits)) return false; // major card networks
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}

export function ibanValid(raw) {
  const s = String(raw).replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(s)) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const val = code >= 65 ? String(code - 55) : ch;
    for (const d of val) rem = (rem * 10 + (d.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

function maskEmail(e) {
  const at = e.lastIndexOf('@');
  const tld = e.slice(e.lastIndexOf('.'));
  return `${e.slice(0, Math.min(2, at))}•••@•••${tld}`;
}
const maskIp = (ip) => `${ip.split('.')[0]}.•.•.•`;
const maskCard = (d) => `•••• ${d.slice(-4)}`;
const maskIban = (s) => `${s.slice(0, 4)}••••`;

/**
 * Count distinct private identifiers in a text.
 * @returns {{emails: number, ipv4: number, cards: number, ibans: number, total: number, samples: string[]}}
 */
export function countPII(input) {
  const text = String(input ?? '').slice(0, MAX_SCAN_CHARS);
  const emails = new Set();
  const ips = new Set();
  const cards = new Set();
  const ibans = new Set();
  let m;

  if (text.includes('@')) {
    const re = new RegExp(PII_PATTERNS.email.source, 'g');
    while ((m = re.exec(text))) if (isRealEmail(m[0])) emails.add(m[0].toLowerCase());
  }
  {
    const re = new RegExp(PII_PATTERNS.ipv4.source, 'g');
    while ((m = re.exec(text))) if (isRealIPv4(m[0], text, m.index)) ips.add(m[0]);
  }
  {
    const re = new RegExp(PII_PATTERNS.card.source, 'g');
    while ((m = re.exec(text))) {
      const digits = m[0].replace(/[ -]/g, '');
      if (luhnValid(digits)) cards.add(digits);
    }
  }
  {
    const re = new RegExp(PII_PATTERNS.iban.source, 'g');
    while ((m = re.exec(text))) {
      const s = m[0].replace(/\s+/g, '');
      if (ibanValid(s)) ibans.add(s);
    }
  }

  const samples = [];
  const push = (set, mask) => {
    for (const v of set) {
      if (samples.length >= 5) return;
      samples.push(mask(v));
    }
  };
  push(emails, maskEmail);
  push(ips, maskIp);
  push(cards, maskCard);
  push(ibans, maskIban);

  return {
    emails: emails.size,
    ipv4: ips.size,
    cards: cards.size,
    ibans: ibans.size,
    total: emails.size + ips.size + cards.size + ibans.size,
    samples,
  };
}

/** Mask any private identifier inside a short display string (used for finding contexts). */
export function maskPII(input) {
  let s = String(input ?? '');
  if (s.includes('@')) s = s.replace(new RegExp(PII_PATTERNS.email.source, 'g'), (e) => (isRealEmail(e) ? maskEmail(e) : e));
  s = s.replace(new RegExp(PII_PATTERNS.ipv4.source, 'g'), (ip, idx) => (isRealIPv4(ip, s, idx) ? maskIp(ip) : ip));
  s = s.replace(new RegExp(PII_PATTERNS.card.source, 'g'), (c) => {
    const digits = c.replace(/[ -]/g, '');
    return luhnValid(digits) ? maskCard(digits) : c;
  });
  s = s.replace(new RegExp(PII_PATTERNS.iban.source, 'g'), (c) => (ibanValid(c) ? maskIban(c.replace(/\s+/g, '')) : c));
  return s;
}
