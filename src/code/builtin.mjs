// In-process regex engine: runs in milliseconds on every response, with or without Semgrep.

const HASH_COMMENT = new Set(['python', 'shell', 'ruby', 'yaml', 'powershell', 'perl', 'r', 'dockerfile', 'toml', 'terraform', 'makefile']);
const DASH_COMMENT = new Set(['sql', 'lua', 'haskell']);

function isCommentLine(line, lang) {
  const t = line.trimStart();
  if (!t) return false;
  if (t.startsWith('//') || t.startsWith('/*') || t.startsWith('* ') || t === '*' || t.startsWith('*/') || t.startsWith('<!--')) return !HASH_COMMENT.has(lang) || t.startsWith('<!--');
  if (t.startsWith('#')) {
    if (HASH_COMMENT.has(lang)) return !t.startsWith('#!');
    if (lang === 'c' || lang === 'cpp' || lang === 'csharp') return false;       // preprocessor
    return lang === 'unknown' && !/^#(?:include|define|if|ifdef|ifndef|endif|pragma|!)/.test(t);
  }
  if (t.startsWith('--') && DASH_COMMENT.has(lang)) return true;
  if (lang === 'batch' && /^(?:rem\b|::)/i.test(t)) return true;
  return false;
}

function lineIndex(code) {
  const starts = [0];
  for (let i = 0; i < code.length; i++) if (code.charCodeAt(i) === 10) starts.push(i + 1);
  return starts;
}

function locate(starts, offset) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= offset) lo = mid; else hi = mid - 1;
  }
  return { line: lo + 1, col: offset - starts[lo] + 1 };
}

/**
 * @param {Array} snippets  [{id, lang, code}]
 * @param {Array} rules     compiled code / quality rules (view.code, view.quality)
 * @returns {Array} findings
 */
export function runBuiltin(snippets, rules) {
  const findings = [];
  for (const s of snippets) {
    let starts = null;
    let lines = null;
    for (const rule of rules) {
      if (rule.languages && !rule.languages.has(s.lang)) continue;
      const re = rule.re;
      re.lastIndex = 0;
      let m, n = 0;
      const seenLines = new Set();
      while ((m = re.exec(s.code)) && n < 5) {
        if (m[0] === '') { re.lastIndex++; continue; }
        starts ??= lineIndex(s.code);
        lines ??= s.code.split('\n');
        const { line, col } = locate(starts, m.index);
        if (seenLines.has(line)) continue;
        const text = lines[line - 1] ?? '';
        if (!rule.matchComments && isCommentLine(text, s.lang)) continue;
        if (rule.exclude && rule.exclude.test(text)) continue;
        seenLines.add(line);
        n++;
        findings.push({
          engine: 'builtin', ruleId: rule.id, category: rule.category, severity: rule.severity,
          message: rule.message, cwe: rule.cwe, fix: rule.fix,
          snippetId: s.id, line, col, excerpt: text.trim().slice(0, 240),
        });
      }
    }
  }
  return findings;
}
