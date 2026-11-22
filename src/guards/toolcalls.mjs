// Tool-call guard: every tool call the model emits is evaluated before the harness sees it.
import path from 'node:path';
import { truncate } from '../util.mjs';
import { classifyTool, extractPathArgs, extractCommand } from './toolsem.mjs';
import { extractTargets, evaluateTarget } from './domains.mjs';
import { checkPath, extractShellPaths } from './paths.mjs';
import { checkCommand } from './commands.mjs';
import { DocRegistry, isDocumentPath, scanLocalFile, verdictReason } from './documents.mjs';

/** One-line description of a tool call for logs and the dashboard. */
export function describeCall(call, semantic) {
  const a = call.args;
  let detail = '';
  if (semantic === 'shell') detail = extractCommand(a) || '';
  else if (a && typeof a === 'object') detail = extractPathArgs(a)[0] || a.url || a.query || a.pattern || '';
  else if (typeof a === 'string') detail = a;
  return truncate(`${call.name}${detail ? ': ' + String(detail).replace(/\s+/g, ' ') : ''}`, 160);
}

/**
 * @param {{id, name, args}} call
 * @param {object} env  { view, policy, harness:{id,cwd}, client:{id,isLocal}, registry, rulesVersion }
 * @returns {Promise<{id, name, semantic, summary, action:'allow'|'block'|'rewrite', reasons:Array, warnings:Array, doc?:object}>}
 */
export async function evaluateToolCall(call, env) {
  const { view, policy, harness } = env;
  const tc = policy.toolCalls || {};
  const semantic = classifyTool(call.name, call.args);
  const result = { id: call.id, name: call.name, semantic, summary: describeCall(call, semantic), action: 'allow', reasons: [], warnings: [] };
  if (tc.enabled === false) return result;
  const block = (r) => { result.action = 'block'; result.reasons.push(r); };
  const note = (r) => result.warnings.push(r);

  const command = semantic === 'shell' ? extractCommand(call.args) : null;

  // 1 ─ dangerous commands
  if (command && tc.commands?.enabled !== false) {
    for (const h of checkCommand(command, view)) {
      const r = { kind: 'command', ruleId: h.ruleId, severity: h.severity, message: h.reason, target: truncate(command, 200) };
      h.action === 'block' ? block(r) : note(r);
    }
  }

  // 2 ─ protected paths
  const paths = [];
  if (semantic === 'shell') { if (command) paths.push(...extractShellPaths(command)); }
  else if (call.args && typeof call.args === 'object') {
    const op = semantic === 'write' ? 'write' : semantic === 'read' || semantic === 'search' ? 'read' : 'any';
    for (const p of extractPathArgs(call.args)) paths.push({ path: p, op });
  }
  if (tc.paths?.enabled !== false) {
    const seen = new Set();
    for (const { path: p, op } of paths) {
      const hit = checkPath(p, op, view, tc.paths, harness?.cwd);
      if (!hit || seen.has(hit.ruleId + p)) continue;
      seen.add(hit.ruleId + p);
      const r = { kind: 'path', ruleId: hit.ruleId, severity: hit.severity, message: hit.reason, target: p };
      hit.action === 'block' ? block(r) : note(r);
    }
  }

  // 3 ─ network destinations
  if (tc.domains?.enabled !== false) {
    for (const t of extractTargets(call, semantic)) {
      const v = evaluateTarget(t, view, tc.domains?.mode);
      for (const w of v.warnings) note({ kind: 'domain', ruleId: w.ruleId, severity: 'low', message: w.reason, target: t.host });
      if (v.action === 'block') block({ kind: 'domain', ruleId: v.ruleId, severity: 'high', message: v.reason, target: t.host });
    }
  }

  // 4 ─ classified documents
  const docs = policy.documents || {};
  if (docs.enabled !== false && result.action !== 'block') {
    for (const { path: p } of paths) {
      const key = DocRegistry.key(env.client?.id, harness?.cwd, p);
      const known = env.registry?.get(key);
      if (known) {
        block({ kind: 'document', ruleId: 'doc.restricted', severity: 'high', message: `document is restricted (${known.classification || 'classified'}); a rule forbidding access already exists`, target: p });
        continue;
      }
      if (semantic === 'write' || !isDocumentPath(p, docs.extensions || [])) continue;
      const canScanLocally = docs.localScan === true || (docs.localScan !== false && env.client?.isLocal);
      if (!canScanLocally) continue;
      const abs = path.isAbsolute(p) ? p : harness?.cwd ? path.resolve(harness.cwd, p) : null;
      if (!abs) continue;
      const verdict = await scanLocalFile(abs, env.scanOpts);
      if (!verdict) continue;                         // file not visible from the proxy → content is scanned when it comes back
      if (verdict.ok === false) {
        if (docs.onScanError === 'block') block({ kind: 'document', ruleId: 'doc.scan-error', severity: 'medium', message: `document could not be scanned (${verdict.error})`, target: p });
        else note({ kind: 'document', ruleId: 'doc.scan-error', severity: 'low', message: `document could not be scanned (${verdict.error})`, target: p });
        continue;
      }
      if (verdict.confidential) {
        result.action = 'rewrite';
        result.doc = { path: p, key, verdict, via: 'file-scan' };
        result.reasons.push({ kind: 'document', ruleId: verdict.findings?.[0]?.markerId || 'doc.classified', severity: 'high', message: verdictReason(verdict), target: p });
        break;
      }
    }
  }
  return result;
}

/** Feedback text returned to the model in place of a blocked tool call's result. */
export function blockFeedback(result, brand) {
  const lines = result.reasons.map((r) => `- [${r.kind}] ${r.message}${r.target ? ` → ${truncate(r.target, 120)}` : ''} (rule ${r.ruleId})`);
  return `[${brand} firewall] BLOCKED — this tool call was NOT executed.\n${lines.join('\n')}\n` +
    'Do not retry the same call or try to work around the rule. Choose a compliant alternative, or explain to the user that company policy prevents this action.';
}
