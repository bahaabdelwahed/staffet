// Validators referenced by redaction rules (`validator: <name>`).
// Signature: (value, { text, index, match }) -> boolean  (true = really is sensitive, redact it)

const NETMASK = /^(?:255|254|252|248|240|224|192|128|0)\.(?:255|254|252|248|240|224|192|128|0)\.(?:255|254|252|248|240|224|192|128|0)\.(?:255|254|252|248|240|224|192|128|0)$/;

export function isSensitiveIPv4(value, ctx = {}) {
  const parts = value.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !(n >= 0 && n <= 255))) return false;
  if (parts[0] === 127 || parts[0] === 0) return false;                 // loopback / unspecified
  if (parts[0] >= 224) return false;                                    // multicast, broadcast
  if (NETMASK.test(value) && parts[0] === 255) return false;            // subnet masks
  if (ctx.text != null && ctx.index != null) {
    const before = ctx.text.slice(Math.max(0, ctx.index - 18), ctx.index);
    if (/(?<![A-Za-z])(?:version|ver\.?|release|build|rev(?:ision)?|v)\s*[:=]?\s*["']?$/i.test(before)) return false;   // "version 1.2.3.4" (but not "server 1.2.3.4")
    const after = ctx.text.slice(ctx.index + value.length, ctx.index + value.length + 2);
    if (/^-[A-Za-z]/.test(after)) return false;                         // 1.2.3.4-beta
  }
  return true;
}

export function isSensitiveIPv6(value) {
  if (value.length < 6) return false;
  if (/^(?:fe80)?::1$/i.test(value)) return false;                      // loopback
  if (!/[a-f]/i.test(value) && !value.includes('::')) return false;     // 12:30:45:... style timestamps
  if (/^\d{1,2}:\d{2}:\d{2}/.test(value) && !/[a-f]/i.test(value)) return false;
  return true;
}

const IIN = /^(?:4\d{12}(?:\d{3}){0,2}|(?:5[1-5]|2[2-7])\d{14}|3[47]\d{13}|3(?:0[0-5]|[68]\d)\d{11}|6(?:011|5\d\d)\d{12}|35\d{14})$/;

export function luhnValid(value) {
  const d = value.replace(/[^\d]/g, '');
  if (d.length < 13 || d.length > 19 || !IIN.test(d)) return false;
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

export function ibanValid(value) {
  const s = value.replace(/\s+/g, '').toUpperCase();
  if (s.length < 15 || s.length > 34 || !/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(s)) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of rearranged) {
    const v = ch >= 'A' ? String(ch.charCodeAt(0) - 55) : ch;
    for (const digit of v) rem = (rem * 10 + (digit.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

/** Looks like a machine-generated token: letters and digits mixed. */
export function looksLikeToken(value) {
  return /\d/.test(value) && /[A-Za-z]/.test(value);
}

/** Unquoted "name: value" — only treat it as a secret when it does not look like code. */
export function looksLikeSecretValue(value) {
  if (value.length < 8) return false;
  if (/[()]/.test(value) || /[;,{]$/.test(value)) return false;         // calls, statements, type annotations
  if (/^(?:string|number|boolean|object|array|any|unknown|null|undefined|true|false|none|str|int|bool|required|optional)\b/i.test(value)) return false;
  if (/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/.test(value)) return false;    // member access: config.token
  return /\d/.test(value) || /[!@#%^&*_+=/\\-]/.test(value);
}

/** Inline name=value: stricter, because `token=auth_token` is ordinary code. */
export function looksLikeInlineSecret(value) {
  if (!/\d/.test(value) || !/[A-Za-z]/.test(value)) return false;
  if (/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/.test(value)) return false;    // member access
  if (/^(?:true|false|null|none|undefined)$/i.test(value)) return false;
  return true;
}

export const VALIDATORS = {
  'secret-inline': looksLikeInlineSecret,
  ipv4: isSensitiveIPv4,
  ipv6: isSensitiveIPv6,
  luhn: luhnValid,
  iban: ibanValid,
  'secret-token': looksLikeToken,
  'secret-value': looksLikeSecretValue,
};
