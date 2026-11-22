// Pull the code out of a model response: fenced blocks in text and code inside file-writing tool calls.
import { extractPathArgs } from '../guards/toolsem.mjs';

const LANG_ALIASES = {
  py: 'python', python3: 'python', python2: 'python', ipython: 'python',
  js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript', node: 'javascript', ecmascript: 'javascript',
  ts: 'typescript', tsx: 'typescript',
  'c++': 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp', hh: 'cpp', h: 'c',
  cs: 'csharp', 'c#': 'csharp', dotnet: 'csharp',
  rb: 'ruby', golang: 'go', kt: 'kotlin', kts: 'kotlin', rs: 'rust',
  sh: 'shell', bash: 'shell', zsh: 'shell', ksh: 'shell', shellscript: 'shell',
  ps1: 'powershell', pwsh: 'powershell', ps: 'powershell', psm1: 'powershell',
  yml: 'yaml', docker: 'dockerfile', tf: 'terraform', hcl: 'terraform', bat: 'batch', cmd: 'batch',
};
const EXT_LANG = {
  py: 'python', pyw: 'python', js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript', vue: 'javascript', svelte: 'javascript',
  ts: 'typescript', tsx: 'typescript', mts: 'typescript', cts: 'typescript',
  java: 'java', go: 'go', c: 'c', h: 'c', cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp', hh: 'cpp', hxx: 'cpp', ino: 'cpp',
  cs: 'csharp', php: 'php', rb: 'ruby', sh: 'shell', bash: 'shell', zsh: 'shell', ps1: 'powershell', psm1: 'powershell',
  kt: 'kotlin', swift: 'swift', rs: 'rust', scala: 'scala', sql: 'sql', yaml: 'yaml', yml: 'yaml', json: 'json', tf: 'terraform',
  html: 'html', htm: 'html', css: 'css', lua: 'lua', pl: 'perl', r: 'r', dart: 'dart', bat: 'batch', cmd: 'batch', ipynb: 'python',
};
// file extension Semgrep needs to pick the right parser
const LANG_EXT = {
  python: 'py', javascript: 'js', typescript: 'ts', java: 'java', go: 'go', c: 'c', cpp: 'cpp', csharp: 'cs', php: 'php', ruby: 'rb',
  shell: 'sh', kotlin: 'kt', swift: 'swift', rust: 'rs', scala: 'scala', yaml: 'yaml', json: 'json', terraform: 'tf', html: 'html',
  lua: 'lua', dart: 'dart', sql: 'sql', powershell: 'ps1', batch: 'bat', css: 'css',
};
const NOT_CODE = new Set(['text', 'txt', 'plaintext', 'plain', 'output', 'log', 'logs', 'markdown', 'md', 'mermaid', 'csv', 'tree', 'ascii', 'diff', 'patch', 'http', 'console', 'terminal', 'stdout', 'stderr', 'math', 'latex', 'tex']);

export function normaliseLang(tag) {
  const t = String(tag || '').trim().toLowerCase();
  return LANG_ALIASES[t] || t;
}

export function langFromPath(p) {
  const base = String(p || '').replace(/\\/g, '/').split('/').pop().toLowerCase();
  if (/^dockerfile/.test(base)) return { lang: 'dockerfile', ext: '' };
  const ext = /\.([a-z0-9]+)$/.exec(base)?.[1] || '';
  return { lang: EXT_LANG[ext] || (ext ? ext : 'unknown'), ext };
}

function guessLang(code) {
  const head = code.slice(0, 1500);
  if (/^#!.*\b(?:ba|z|k)?sh\b/.test(head)) return 'shell';
  if (/^#!.*\bpython/.test(head)) return 'python';
  if (/^#!.*\bnode\b/.test(head)) return 'javascript';
  if (/^\s*<\?php/.test(head)) return 'php';
  if (/^\s*(?:package\s+\w+\s*$|func\s+\w+\s*\()/m.test(head) && /\bfunc\b/.test(head)) return 'go';
  if (/^\s*#include\s*[<"]/m.test(head)) return /\b(?:std::|class\s+\w+|template\s*<|namespace\s+\w+)/.test(code) ? 'cpp' : 'c';
  if (/^\s*(?:public\s+|private\s+)?(?:final\s+)?class\s+\w+/m.test(head) && /\b(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+\w+\s*\(/.test(code)) return /\busing\s+System\b|\bnamespace\s+\w+/.test(code) ? 'csharp' : 'java';
  if (/^\s*(?:def\s+\w+\s*\(|import\s+\w+|from\s+[\w.]+\s+import\s)/m.test(head) && !/[{};]\s*$/m.test(head.split('\n')[0])) return 'python';
  if (/\b(?:const|let|var)\s+\w+\s*=|=>\s*[{(]|\bfunction\s+\w*\s*\(|\brequire\s*\(|^\s*import\s.+\sfrom\s+['"]/m.test(head)) return /:\s*(?:string|number|boolean)\b|\binterface\s+\w+\s*\{/.test(code) ? 'typescript' : 'javascript';
  if (/^\s*(?:\$\w+\s*=|Get-|Set-|New-|Write-Host|param\s*\()/mi.test(head)) return 'powershell';
  if (/^\s*(?:sudo\s|apt(?:-get)?\s|npm\s|pip3?\s|git\s|cd\s|curl\s|wget\s|echo\s|export\s|chmod\s|mkdir\s|docker\s|kubectl\s)/m.test(head)) return 'shell';
  if (/^\s*(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|CREATE\s+TABLE|ALTER\s+TABLE)\b/mi.test(head)) return 'sql';
  return 'unknown';
}

const FENCE = /(^|\n)([ \t]{0,3})(`{3,}|~{3,})[ \t]*([^\n`]*)\n([\s\S]*?)\n?\2\3[ \t]*(?=\n|$)/g;

/** Fenced code blocks in assistant text. `start`/`end` are offsets of the code body within `text`. */
export function extractCodeBlocks(text) {
  const out = [];
  if (typeof text !== 'string' || text.indexOf('```') < 0 && text.indexOf('~~~') < 0) return out;
  FENCE.lastIndex = 0;
  let m;
  while ((m = FENCE.exec(text))) {
    const info = m[4].trim();
    const tag = info.split(/[\s:{,]/)[0];
    const code = m[5];
    if (!code.trim()) continue;
    const bodyStart = m.index + m[0].indexOf('\n', m[1].length) + 1;   // first char after the opening fence line
    let lang = normaliseLang(tag);
    if (NOT_CODE.has(lang)) continue;
    if (!lang) lang = guessLang(code);
    const pathHint = /(?:^|[\s:=])((?:[\w.@~-]+[\\/])*[\w.@-]+\.[A-Za-z0-9]{1,6})\s*$/.exec(info)?.[1] || null;
    out.push({ origin: 'block', lang, ext: LANG_EXT[lang] || '', path: pathHint, code, start: bodyStart, end: bodyStart + code.length, fenceTag: tag });
  }
  return out;
}

const CONTENT_FIELDS = ['content', 'contents', 'file_text', 'new_string', 'new_str', 'newString', 'code', 'new_content', 'replacement', 'code_edit', 'new_source', 'insert_text', 'new_text', 'newText', 'text'];
const EDIT_FIELDS = ['new_string', 'newString', 'new_str', 'new_text', 'newText', 'replacement', 'content', 'text'];

/** Code carried by one file-writing tool call. */
export function extractFromToolCall(call) {
  const a = call.args;
  const out = [];
  if (!a || typeof a !== 'object') {
    if (typeof a === 'string' && a.includes('*** Begin Patch')) return fromApplyPatch(a, call);
    return out;
  }
  const filePath = extractPathArgs(a)[0] || null;
  const { lang, ext } = filePath ? langFromPath(filePath) : { lang: 'unknown', ext: '' };
  const push = (code, partial, p = filePath, l = lang, e = ext) => {
    if (typeof code !== 'string' || !code.trim()) return;
    out.push({ origin: 'tool', toolCallId: call.id, toolName: call.name, path: p, lang: l === 'unknown' ? guessLang(code) : l, ext: e || LANG_EXT[l] || '', code, partial });
  };

  for (const k of ['input', 'patch']) {
    if (typeof a[k] === 'string' && a[k].includes('*** Begin Patch')) return fromApplyPatch(a[k], call);
  }
  if (typeof a.diff === 'string') {
    const parts = [...a.diff.matchAll(/^={7}[ \t]*\r?\n([\s\S]*?)\r?\n?^(?:>{7}[^\n]*|\+{7} REPLACE)[ \t]*$/gm)].map((m) => m[1]);
    if (parts.length) parts.forEach((p) => push(p, true));
    else push(a.diff.split('\n').filter((l) => l.startsWith('+') && !l.startsWith('+++')).map((l) => l.slice(1)).join('\n'), true);
  }
  for (const k of CONTENT_FIELDS) {
    if (typeof a[k] !== 'string') continue;
    const partial = !/^(?:content|contents|file_text|new_content|new_source|code)$/.test(k) || 'old_string' in a || 'old_str' in a;
    push(a[k], partial);
  }
  for (const listKey of ['edits', 'replacements', 'changes', 'operations']) {
    if (!Array.isArray(a[listKey])) continue;
    for (const e of a[listKey]) {
      if (!e || typeof e !== 'object') continue;
      const p = extractPathArgs(e)[0];
      const meta = p ? langFromPath(p) : { lang, ext };
      for (const k of EDIT_FIELDS) if (typeof e[k] === 'string') { push(e[k], true, p || filePath, meta.lang, meta.ext); break; }
    }
  }
  return out;
}

function fromApplyPatch(patch, call) {
  const out = [];
  let cur = null;
  const flush = () => {
    if (cur && cur.lines.length) {
      const { lang, ext } = langFromPath(cur.path);
      out.push({ origin: 'tool', toolCallId: call.id, toolName: call.name, path: cur.path, lang, ext, code: cur.lines.join('\n'), partial: !cur.add });
    }
  };
  for (const line of patch.split(/\r?\n/)) {
    const m = /^\*\*\* (Add|Update) File: (.+)$/.exec(line);
    if (m) { flush(); cur = { path: m[2].trim(), add: m[1] === 'Add', lines: [] }; continue; }
    if (/^\*\*\* /.test(line)) { if (/^\*\*\* (?:Delete File|End Patch)/.test(line)) { flush(); cur = null; } continue; }
    if (cur && line.startsWith('+')) cur.lines.push(line.slice(1));
  }
  flush();
  return out;
}

/**
 * All code in a (canonical) model response.
 * @param {{blocks: Array}} message   blocks: {type:'text', text} | {type:'tool', id, name, args, semantic}
 */
export function extractSnippets(message, { codeBlocks = true, toolWrites = true } = {}) {
  const snippets = [];
  message.blocks.forEach((b, blockIndex) => {
    if (b.type === 'text' && codeBlocks) {
      for (const s of extractCodeBlocks(b.text)) snippets.push({ ...s, blockIndex });
    } else if (b.type === 'tool' && toolWrites && b.semantic === 'write') {
      for (const s of extractFromToolCall(b)) snippets.push({ ...s, blockIndex });
    }
  });
  snippets.forEach((s, i) => { s.id = `s${i}`; });
  return snippets.filter((s) => s.code.length <= 400_000);
}

export { LANG_EXT };
