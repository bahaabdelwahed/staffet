// Turn scan findings into the report that is injected back to the model.
import { BRAND } from '../brand.mjs';

function snippetLabel(s) {
  if (!s) return 'code';
  if (s.origin === 'tool') return `${s.path ? `file ${s.path}` : 'code'} (tool call ${s.toolName})`;
  return `code block${s.path ? ` ${s.path}` : ''} (${s.lang})`;
}

/** Human/model readable list of findings grouped by snippet. */
export function formatFindings(findings, snippets) {
  const byId = new Map(snippets.map((s) => [s.id, s]));
  const groups = new Map();
  for (const f of findings) {
    if (!groups.has(f.snippetId)) groups.set(f.snippetId, []);
    groups.get(f.snippetId).push(f);
  }
  const out = [];
  let n = 0;
  for (const [sid, list] of groups) {
    out.push(`▸ In ${snippetLabel(byId.get(sid))}:`);
    for (const f of list) {
      n++;
      out.push(`  ${n}. [${f.severity.toUpperCase()}][${f.category}] ${f.ruleId}${f.cwe ? ` · ${f.cwe}` : ''} · line ${f.line}`);
      out.push(`     ${f.message}`);
      if (f.excerpt) out.push(`       ${String(f.line).padStart(4)} | ${f.excerpt}`);
      if (f.fix) out.push(`     Fix: ${f.fix}`);
    }
  }
  return out.join('\n');
}

/** Feedback sent to the model when its code fails the scan. */
export function scanFeedback(findings, snippets, { iteration, maxIterations, engines }) {
  const sec = findings.filter((f) => f.category === 'security').length;
  const qual = findings.length - sec;
  const what = [sec && `${sec} security issue${sec > 1 ? 's' : ''}`, qual && `${qual} code-quality issue${qual > 1 ? 's' : ''}`].filter(Boolean).join(' and ');
  return [
    `[${BRAND.name} firewall — automated code review, pass ${iteration}/${maxIterations}]`,
    `Your previous output was NOT delivered and nothing was executed. The scanner (${engines.join(' + ')}) found ${what} in the code you produced:`,
    '',
    formatFindings(findings, snippets),
    '',
    'Fix every issue above and send your complete response again — same content and the same tool calls, with corrected code.',
    'Do not weaken, comment out or work around the checks, and do not mention this review in your answer.',
  ].join('\n');
}

/** Short tool-result text for one write call whose code failed. */
export function toolScanFeedback(findings, snippets, meta) {
  return scanFeedback(findings, snippets, meta) + '\nRe-issue this tool call with the corrected code.';
}

export const SIBLING_NOT_EXECUTED = `[${BRAND.name} firewall] This tool call was NOT executed: another call in the same turn was rejected, so the whole turn was held back. Re-issue this call unchanged if it is still needed.`;

/** Note appended to the visible answer when the firewall had to intervene and could not fully resolve it. */
export function inlineNotice(lines) {
  return `\n\n> 🛡 **${BRAND.name} firewall**\n${lines.map((l) => `> - ${l}`).join('\n')}\n`;
}
