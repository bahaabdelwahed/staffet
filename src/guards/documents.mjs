// Document guard: classified documents are never sent to the model, and the harness is told
// (through a rule file it loads on every session) never to open them again.
import fs from 'node:fs';
import path from 'node:path';
import { BRAND } from '../brand.mjs';
import { shortHash, LRU, sha1 } from '../util.mjs';
import { normalisePath } from './paths.mjs';
import { RULE_TARGETS, pickWriteTool, joinWorkspace } from '../proxy/harness.mjs';

let scannersPromise = null;
/** Lazy import so the proxy still starts if the scanners folder is missing. */
export function loadScanners() {
  scannersPromise ??= import('../../scanners/index.mjs').catch((e) => ({ error: e }));
  return scannersPromise;
}

export function isDocumentPath(p, extensions) {
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(String(p).replace(/["'`]+$/, ''));
  return Boolean(m && extensions.includes(m[1].toLowerCase()));
}

/** Persistent list of documents the firewall has classified as restricted. */
export class DocRegistry {
  constructor(file) {
    this.file = file;
    this.entries = new Map();
    try {
      for (const e of JSON.parse(fs.readFileSync(file, 'utf8'))) this.entries.set(e.key, e);
    } catch { /* first run */ }
  }
  static key(client, cwd, docPath) {
    const abs = /^(?:\/|~|[a-z]:)/i.test(normalisePath(docPath));
    return shortHash(`${client || ''}|${abs ? '' : normalisePath(cwd || '')}|${normalisePath(docPath)}`, 16);
  }
  get(key) { return this.entries.get(key); }
  has(key) { return this.entries.has(key); }
  list() { return [...this.entries.values()].sort((a, b) => b.at - a.at); }
  add(entry) {
    const e = { at: Date.now(), ...entry };
    this.entries.set(e.key, e);
    this._save();
    return e;
  }
  update(key, patch) {
    const e = this.entries.get(key);
    if (e) { Object.assign(e, patch); this._save(); }
  }
  remove(key) {
    const ok = this.entries.delete(key);
    if (ok) this._save();
    return ok;
  }
  _save() {
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.writeFileSync(this.file, JSON.stringify([...this.entries.values()], null, 2));
    } catch { /* registry is best-effort persistence */ }
  }
}

const verdictCache = new LRU(500);

/** Scan a file on disk (when the proxy can see it). Returns a scanner verdict or null. */
export async function scanLocalFile(filePath, opts) {
  let st;
  try { st = fs.statSync(filePath); } catch { return null; }
  if (!st.isFile()) return null;
  const key = `${filePath}|${st.size}|${st.mtimeMs}|${opts.rulesVersion}`;
  const cached = verdictCache.get(key);
  if (cached) return cached;
  const mod = await loadScanners();
  if (mod.error) return { ok: false, error: `scanners unavailable: ${mod.error.message}` };
  const verdict = await mod.scanDocument(filePath, opts);
  verdictCache.set(key, verdict);
  return verdict;
}

/** Scan document content that came back from the harness (text, or raw bytes of a PDF/Office file). */
export async function scanContent(content, opts) {
  const isBuf = Buffer.isBuffer(content);
  const key = `c|${opts.filename || ''}|${opts.rulesVersion}|${sha1(isBuf ? content : String(content))}`;
  const cached = verdictCache.get(key);
  if (cached) return cached;
  const mod = await loadScanners();
  if (mod.error) return { ok: false, error: `scanners unavailable: ${mod.error.message}` };
  const verdict = isBuf
    ? await mod.scanDocument({ buffer: content, filename: opts.filename || 'document' }, opts)
    : await mod.scanText(String(content), opts);
  verdictCache.set(key, verdict);
  return verdict;
}

export function verdictReason(verdict) {
  if (!verdict) return 'classified as restricted';
  const first = verdict.reasons?.[0];
  const label = verdict.classification ? `classified ${verdict.classification}` : 'classified as restricted';
  return first ? `${label} — ${first}` : label;
}

/** Text that replaces the content of a withheld document in the conversation. */
export function withheldNotice(docPath, verdict, token = BRAND.redactionToken) {
  return `${token}\n[${BRAND.name} firewall] The content of "${docPath}" was withheld: the document is ${verdictReason(verdict)}. ` +
    'Do not open, read, search, summarise or reference this document, and do not try to reach it through other tools or commands. ' +
    'Continue the task without it; if it is essential, tell the user it is restricted by company policy.';
}

export function ruleFileContent({ docPath, verdict, target }) {
  const date = new Date().toISOString().slice(0, 10);
  const body = [
    `# ${BRAND.name} firewall — restricted document`,
    '',
    `The document below is **${verdict?.classification || 'RESTRICTED'}** and must never be sent to an AI model.`,
    '',
    `- NEVER read, open, search, summarise, convert, copy or quote: \`${docPath}\``,
    '- Do not reach it indirectly (shell commands, scripts, archives, MCP tools, sub-agents).',
    '- If the user asks about it, answer that it is restricted by company policy and ask them to provide non-confidential input instead.',
    '',
    `_Written automatically by the ${BRAND.name} LLM firewall on ${date}. Reason: ${verdictReason(verdict)}._`,
    '',
  ].join('\n');
  return target?.frontmatter ? `---\n${target.frontmatter}\n---\n\n${body}` : body;
}

/**
 * Build the tool call that makes the harness persist a "never open this document" rule.
 * Returns null when this harness has no known rule location or no file-creating tool.
 * @returns {{name: string, args: object, ruleFile: string}|null}
 */
export function buildRuleWrite({ harness, tools, docPath, verdict, targets }) {
  const target = { ...RULE_TARGETS, ...(targets || {}) }[harness?.id];
  if (!target) return null;
  const rel = `${target.dir}/${BRAND.slug}-restricted-${shortHash(normalisePath(docPath), 8)}${target.ext}`;
  const content = ruleFileContent({ docPath, verdict, target });

  if (harness.xmlTools) {
    return { name: 'write_to_file', args: { path: rel, content }, ruleFile: rel, xml: true };
  }
  const tool = pickWriteTool(tools);
  if (!tool) return null;
  let filePath = rel;
  if (target.absolute || tool.needsAbsolute) {
    if (!harness.cwd) return null;
    filePath = joinWorkspace(harness.cwd, rel);
  }
  return { name: tool.name, args: tool.build(filePath, content), ruleFile: filePath };
}
