import { BRAND } from '../brand.mjs';
import { LRU, sha1, maskValue } from '../util.mjs';
import { VALIDATORS } from './validators.mjs';

const cache = new LRU(4000);

/**
 * Replace every sensitive value in `text` with the redaction token.
 * @returns {{ text: string, total: number, hits: Array<{ruleId, name, category, severity, count, sample}> }}
 */
export function redactText(text, view, { token = BRAND.redactionToken } = {}) {
  if (typeof text !== 'string' || text.length < 3) return { text, total: 0, hits: [] };

  const cacheKey = text.length >= 64 ? `${view.version}:${token}:${sha1(text)}` : null;
  if (cacheKey) {
    const hit = cache.get(cacheKey);
    if (hit) return hit;
  }

  const lower = text.toLowerCase();
  let out = text;
  let total = 0;
  const hits = [];

  for (const rule of view.redact) {
    if (rule.keywords && !rule.keywords.some((k) => lower.includes(k))) continue;
    let count = 0;
    let sample = null;
    const replacement = rule.replacement || token;
    rule.re.lastIndex = 0;
    out = out.replace(rule.re, (...args) => {
      const match = args[0];
      const offIdx = args.findIndex((a, i) => i > 0 && typeof a === 'number');
      const index = args[offIdx];
      const whole = args[offIdx + 1];
      const value = rule.group ? args[rule.group] : match;
      if (value == null || value === '' || value.includes(token)) return match;
      if (rule.allow.length && rule.allow.some((a) => a.test(value))) return match;
      if (rule.validator) {
        const fn = VALIDATORS[rule.validator];
        if (fn && !fn(value, { text: whole, index: rule.group ? index + match.lastIndexOf(value) : index, match })) return match;
      }
      count++;
      sample ??= maskValue(value);
      if (!rule.group) return replacement;
      const at = match.lastIndexOf(value);
      return match.slice(0, at) + replacement + match.slice(at + value.length);
    });
    if (count) {
      total += count;
      hits.push({ ruleId: rule.id, name: rule.name, category: rule.category, severity: rule.severity, count, sample });
    }
  }

  const result = { text: out, total, hits };
  if (cacheKey) cache.set(cacheKey, result);
  return result;
}

/** Merge per-segment hits into a per-rule summary. */
export function mergeHits(target, hits) {
  for (const h of hits) {
    const cur = target.get(h.ruleId);
    if (cur) cur.count += h.count;
    else target.set(h.ruleId, { ...h });
  }
  return target;
}
