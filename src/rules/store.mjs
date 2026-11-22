import fs from 'node:fs';
import path from 'node:path';
import { EventEmitter } from 'node:events';
import YAML from 'yaml';
import { PKG_ROOT } from '../brand.mjs';
import { escapeRegExp, globToRegExp, wildcardToRegExp } from '../util.mjs';

export const RULE_TYPES = ['redact', 'domain', 'path', 'command', 'document', 'code', 'quality'];
const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical', 'warning', 'error'];

const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48) || 'rule';

function compileRe(pattern, flags, { forceGlobal = false, defaults = '' } = {}) {
  let f = flags == null ? defaults : String(flags);
  if (forceGlobal && !f.includes('g')) f += 'g';
  return new RegExp(pattern, f);
}

/** Validate + normalise a raw rule. Throws Error with a readable message. */
export function normaliseRule(raw, source = 'custom') {
  if (!raw || typeof raw !== 'object') throw new Error('rule must be an object');
  const r = { ...raw };
  if (!RULE_TYPES.includes(r.type)) throw new Error(`rule type must be one of: ${RULE_TYPES.join(', ')}`);
  r.name = String(r.name || r.id || 'Unnamed rule');
  r.id = String(r.id || `custom.${r.type}.${slug(r.name)}`);
  if (!/^[\w.-]+$/.test(r.id)) throw new Error(`rule id "${r.id}" may only contain letters, digits, dot, dash, underscore`);
  r.enabled = r.enabled !== false;
  r.source = source;
  if (r.severity && !SEVERITIES.includes(r.severity)) throw new Error(`rule ${r.id}: unknown severity "${r.severity}"`);

  const needPattern = () => {
    if (!r.pattern || typeof r.pattern !== 'string') throw new Error(`rule ${r.id}: "pattern" (a regular expression) is required`);
    try { compileRe(r.pattern, r.flags, { defaults: 'g' }); } catch (e) { throw new Error(`rule ${r.id}: invalid regular expression — ${e.message}`); }
  };
  switch (r.type) {
    case 'redact':
      needPattern();
      r.severity ||= 'high';
      r.category ||= 'custom';
      for (const a of r.allow || []) { try { new RegExp(a, 'i'); } catch (e) { throw new Error(`rule ${r.id}: invalid allow pattern — ${e.message}`); } }
      break;
    case 'domain':
      r.action ||= 'block';
      if (!['block', 'allow', 'warn'].includes(r.action)) throw new Error(`rule ${r.id}: action must be block, allow or warn`);
      if (!r.heuristic && !(Array.isArray(r.domains) && r.domains.length)) throw new Error(`rule ${r.id}: "domains" (list) is required`);
      r.severity ||= r.action === 'block' ? 'high' : 'info';
      break;
    case 'path':
      r.action ||= 'block';
      if (!['block', 'warn'].includes(r.action)) throw new Error(`rule ${r.id}: action must be block or warn`);
      if (!(Array.isArray(r.paths) && r.paths.length)) throw new Error(`rule ${r.id}: "paths" (list of globs) is required`);
      r.operations = Array.isArray(r.operations) && r.operations.length ? r.operations : ['any'];
      r.severity ||= 'high';
      break;
    case 'command':
      needPattern();
      r.action ||= 'block';
      if (!['block', 'warn'].includes(r.action)) throw new Error(`rule ${r.id}: action must be block or warn`);
      r.severity ||= 'high';
      break;
    case 'document':
      needPattern();
      r.strength ||= 'strong';
      if (!['strong', 'medium', 'weak'].includes(r.strength)) throw new Error(`rule ${r.id}: strength must be strong, medium or weak`);
      r.severity ||= 'high';
      break;
    case 'code':
    case 'quality':
      needPattern();
      r.languages = Array.isArray(r.languages) && r.languages.length ? r.languages.map((l) => String(l).toLowerCase()) : ['*'];
      r.severity ||= 'warning';
      if (!['info', 'warning', 'error'].includes(r.severity)) throw new Error(`rule ${r.id}: severity must be info, warning or error`);
      r.message ||= r.name;
      if (r.exclude) { try { new RegExp(r.exclude, 'i'); } catch (e) { throw new Error(`rule ${r.id}: invalid exclude pattern — ${e.message}`); } }
      break;
  }
  return r;
}

function readRuleFile(file, source, problems) {
  const out = [];
  let doc;
  try { doc = YAML.parse(fs.readFileSync(file, 'utf8')); } catch (e) {
    problems.push(`${path.basename(file)}: ${e.message}`);
    return out;
  }
  const list = Array.isArray(doc) ? doc : doc?.rules;
  if (!Array.isArray(list)) return out;
  for (const raw of list) {
    try { out.push({ ...normaliseRule(raw, source), file }); } catch (e) { problems.push(`${path.basename(file)}: ${e.message}`); }
  }
  return out;
}

export class RuleStore extends EventEmitter {
  /**
   * @param {{config: object}} opts  config.rulesDir holds user rules (custom/), config.dataDir the enable/disable state
   */
  constructor({ config }) {
    super();
    this.config = config;
    this.defaultDir = path.join(PKG_ROOT, 'rules', 'default');
    this.customDir = path.join(config.rulesDir, 'custom');
    this.managedFile = path.join(this.customDir, 'custom.yaml');
    this.stateFile = path.join(config.dataDir, 'rule-state.json');
    this.rules = new Map();
    this.problems = [];
    this.version = 0;
    this._views = new Map();
    this._watcher = null;
  }

  /** Semgrep rule directories (bundled + user). */
  semgrepDirs() {
    const dirs = { security: [], quality: [] };
    for (const base of [path.join(PKG_ROOT, 'rules', 'semgrep'), path.join(this.customDir, 'semgrep')]) {
      for (const kind of ['security', 'quality']) {
        const d = path.join(base, kind);
        if (fs.existsSync(d) && fs.readdirSync(d).some((f) => /\.ya?ml$/.test(f))) dirs[kind].push(d);
      }
    }
    return dirs;
  }

  async load() {
    const problems = [];
    const rules = new Map();
    const add = (r) => {
      if (rules.has(r.id) && r.source !== 'custom') problems.push(`duplicate rule id ${r.id}`);
      rules.set(r.id, r);          // custom rules may deliberately override a default by reusing its id
    };

    if (fs.existsSync(this.defaultDir)) {
      for (const f of fs.readdirSync(this.defaultDir).filter((f) => /\.ya?ml$/.test(f)).sort()) {
        readRuleFile(path.join(this.defaultDir, f), 'default', problems).forEach(add);
      }
    }

    // Built-in document classification markers live with the standalone scanners.
    try {
      const { DEFAULT_MARKERS } = await import('../../scanners/lib/markers.mjs');
      for (const m of DEFAULT_MARKERS || []) {
        add({ id: m.id, type: 'document', name: m.label || m.id, pattern: m.pattern, flags: m.flags, strength: m.strength, lang: m.lang, severity: m.strength === 'strong' ? 'high' : m.strength === 'medium' ? 'medium' : 'low', enabled: true, source: 'default', builtinMarker: true });
      }
    } catch (e) { problems.push(`document markers unavailable: ${e.message}`); }

    for (const r of this._configRules()) add(r);

    if (fs.existsSync(this.customDir)) {
      for (const f of fs.readdirSync(this.customDir).filter((f) => /\.ya?ml$/.test(f)).sort()) {
        readRuleFile(path.join(this.customDir, f), 'custom', problems).forEach(add);
      }
    }

    // enable/disable overrides
    let state = {};
    try { state = JSON.parse(fs.readFileSync(this.stateFile, 'utf8')); } catch { /* none yet */ }
    for (const [id, enabled] of Object.entries(state.enabled || {})) {
      const r = rules.get(id);
      if (r) r.enabled = Boolean(enabled);
    }

    this.rules = rules;
    this.problems = problems;
    this.version++;
    this._views.clear();
    this.emit('reload', { count: rules.size, problems });
    return this;
  }

  /** Rules generated from staffet.config.yaml (enterprise block, protected folders). */
  _configRules() {
    const out = [];
    const ent = this.config.enterprise || {};
    const dom = (d) => escapeRegExp(String(d).replace(/^\*?\.?/, ''));
    if (ent.internalDomains?.length) {
      out.push({ id: 'redact.enterprise.internal-hostnames', type: 'redact', name: 'Enterprise internal hostnames', category: 'enterprise', severity: 'high', enabled: true, source: 'config',
        pattern: `(?<![\\w.-])(?:[a-z0-9-]+\\.)*(?:${ent.internalDomains.map(dom).join('|')})(?![\\w-]|\\.[a-z])`, flags: 'gi' });
    }
    if (ent.emailDomains?.length) {
      out.push({ id: 'redact.enterprise.email', type: 'redact', name: 'Enterprise email addresses', category: 'enterprise', severity: 'high', enabled: true, source: 'config',
        pattern: `\\b[A-Za-z0-9._%+-]+@(?:[a-z0-9-]+\\.)*(?:${ent.emailDomains.map(dom).join('|')})\\b`, flags: 'gi' });
    }
    if (ent.confidentialTerms?.length) {
      out.push({ id: 'redact.enterprise.terms', type: 'redact', name: 'Enterprise confidential terms', category: 'enterprise', severity: 'high', enabled: true, source: 'config',
        pattern: `(?<![\\w])(?:${ent.confidentialTerms.map((t) => escapeRegExp(String(t).trim()).replace(/\s+/g, '\\s+')).filter(Boolean).join('|')})(?![\\w])`, flags: 'gi' });
    }
    const prot = this.config.policy?.toolCalls?.paths?.protected;
    if (prot?.length) {
      out.push({ id: 'path.protected-folders', type: 'path', name: 'Protected folders (config)', severity: 'critical', action: 'block', paths: prot, operations: ['any'], enabled: true, source: 'config' });
    }
    return out;
  }

  list() { return [...this.rules.values()].map(publicRule); }
  get(id) { const r = this.rules.get(id); return r ? publicRule(r) : null; }

  _saveState(mutator) {
    let state = {};
    try { state = JSON.parse(fs.readFileSync(this.stateFile, 'utf8')); } catch { /* new */ }
    state.enabled ||= {};
    mutator(state);
    fs.mkdirSync(path.dirname(this.stateFile), { recursive: true });
    fs.writeFileSync(this.stateFile, JSON.stringify(state, null, 2));
  }

  async setEnabled(id, enabled) {
    if (!this.rules.has(id)) throw new Error(`unknown rule "${id}"`);
    this._saveState((s) => { s.enabled[id] = Boolean(enabled); });
    await this.load();
    return this.get(id);
  }

  _readManaged() {
    try {
      const doc = YAML.parse(fs.readFileSync(this.managedFile, 'utf8'));
      return Array.isArray(doc?.rules) ? doc.rules : [];
    } catch { return []; }
  }

  _writeManaged(list) {
    fs.mkdirSync(this.customDir, { recursive: true });
    const header = '# Custom rules managed by the dashboard / CLI. You can also edit this file by hand\n# or drop additional *.yaml files next to it — they are picked up automatically.\n';
    fs.writeFileSync(this.managedFile, header + YAML.stringify({ version: 1, rules: list }, { lineWidth: 0 }));
  }

  async addCustom(raw) {
    const r = normaliseRule(raw, 'custom');
    const existing = this.rules.get(r.id);
    if (existing && existing.source !== 'custom') throw new Error(`rule id "${r.id}" is already used by a built-in rule`);
    const list = this._readManaged().filter((x) => x.id !== r.id);
    const { source, ...toStore } = r;
    list.push(toStore);
    this._writeManaged(list);
    this._saveState((s) => { delete s.enabled[r.id]; });
    await this.load();
    return this.get(r.id);
  }

  async removeCustom(id) {
    const r = this.rules.get(id);
    if (!r) throw new Error(`unknown rule "${id}"`);
    if (r.source !== 'custom') throw new Error('only custom rules can be deleted — disable built-in rules instead');
    const list = this._readManaged();
    if (!list.some((x) => x.id === id)) throw new Error(`rule "${id}" lives in ${path.basename(r.file)}; edit that file to remove it`);
    this._writeManaged(list.filter((x) => x.id !== id));
    this._saveState((s) => { delete s.enabled[id]; });
    await this.load();
  }

  /** Watch the custom rule folder and reload on change. */
  watch() {
    try {
      fs.mkdirSync(this.customDir, { recursive: true });
      let timer = null;
      this._watcher = fs.watch(this.customDir, { recursive: false }, () => {
        clearTimeout(timer);
        timer = setTimeout(() => this.load().catch(() => {}), 250);
      });
      this._watcher.on('error', () => {});
    } catch { /* watching is best effort */ }
  }

  close() { this._watcher?.close(); }

  /** Compiled, filtered rule set for a policy profile. */
  view(profileName = '') {
    const key = profileName || '';
    if (this._views.has(key)) return this._views.get(key);
    const prof = (profileName && this.config.profiles?.[profileName]?.rules) || {};
    const mk = (list) => (list || []).map((p) => wildcardToRegExp(p));
    const dis = mk(prof.disable), en = mk(prof.enable);
    const isEnabled = (r) => {
      if (en.some((re) => re.test(r.id))) return true;
      if (dis.some((re) => re.test(r.id))) return false;
      return r.enabled;
    };
    const all = [...this.rules.values()];
    const v = compileView(all.filter(isEnabled), this.version);
    // built-in document markers are toggled like any rule; scanners get the disabled ids
    v.document.disabledMarkers = all.filter((r) => r.builtinMarker && !isEnabled(r)).map((r) => r.id);
    this._views.set(key, v);
    return v;
  }
}

function publicRule(r) {
  const { file, ...rest } = r;
  return { ...rest, file: file ? path.basename(file) : undefined };
}

const SEV_RANK = { critical: 0, error: 0, high: 1, warning: 2, medium: 2, low: 3, info: 4 };

export function compileView(rules, version = 0) {
  const view = {
    version,
    redact: [],
    domain: { custom: [], blocks: [], heuristics: [], allows: [] },
    path: [],
    command: [],
    document: { extraMarkers: [], disabledMarkers: [] },
    code: [],
    quality: [],
    ids: new Set(rules.map((r) => r.id)),
  };
  for (const r of rules) {
    try {
      switch (r.type) {
        case 'redact':
          view.redact.push({
            id: r.id, name: r.name, category: r.category, severity: r.severity,
            re: compileRe(r.pattern, r.flags, { forceGlobal: true, defaults: 'g' }),
            group: Number(r.group) || 0,
            validator: r.validator || null,
            allow: (r.allow || []).map((a) => new RegExp(a, 'i')),
            keywords: r.keywords?.length ? r.keywords.map((k) => String(k).toLowerCase()) : null,
            replacement: r.replacement || null,
          });
          break;
        case 'domain': {
          const c = {
            id: r.id, name: r.name, action: r.action, severity: r.severity, heuristic: r.heuristic || null,
            matchers: (r.domains || []).flatMap((d) => {
              d = String(d).trim().toLowerCase();
              // "*.example.com" also covers the apex "example.com"
              return d.startsWith('*.') ? [wildcardToRegExp(d), wildcardToRegExp(d.slice(2))] : [wildcardToRegExp(d)];
            }),
            tlds: new Set((r.tlds || []).map((t) => String(t).toLowerCase())),
            schemes: new Set((r.schemes || []).map((t) => String(t).toLowerCase())),
          };
          if (r.source === 'custom' || r.source === 'config') view.domain.custom.push(c);
          else if (c.heuristic) view.domain.heuristics.push(c);
          else if (c.action === 'allow') view.domain.allows.push(c);
          else view.domain.blocks.push(c);
          break;
        }
        case 'path':
          view.path.push({
            id: r.id, name: r.name, action: r.action, severity: r.severity,
            res: r.paths.map(globToRegExp), except: (r.except || []).map(globToRegExp),
            operations: new Set(r.operations || ['any']), globs: r.paths,
          });
          break;
        case 'command':
          view.command.push({ id: r.id, name: r.name, action: r.action, severity: r.severity, re: compileRe(r.pattern, r.flags, { defaults: 'i' }) });
          break;
        case 'document':
          if (!r.builtinMarker) view.document.extraMarkers.push({ id: r.id, label: r.name, pattern: r.pattern, flags: r.flags || 'gi', strength: r.strength });
          break;
        case 'code':
        case 'quality':
          view[r.type].push({
            id: r.id, name: r.name, category: r.type === 'code' ? 'security' : 'quality', severity: r.severity,
            languages: r.languages.includes('*') ? null : new Set(r.languages),
            re: compileRe(r.pattern, r.flags, { forceGlobal: true, defaults: 'g' }),
            exclude: r.exclude ? new RegExp(r.exclude, 'i') : null,
            matchComments: Boolean(r.matchComments),
            message: r.message, cwe: r.cwe || null, fix: r.fix || null,
          });
          break;
      }
    } catch { /* a rule that fails to compile is skipped; load() already reported it */ }
  }
  view.redact.sort((a, b) => (SEV_RANK[a.severity] ?? 5) - (SEV_RANK[b.severity] ?? 5));
  return view;
}
