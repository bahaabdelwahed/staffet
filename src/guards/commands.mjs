// Command guard: dangerous shell commands.

/**
 * @returns {Array<{action:'block'|'warn', ruleId, reason, severity}>}  block hits first
 */
export function checkCommand(command, view) {
  if (typeof command !== 'string' || !command.trim()) return [];
  const text = command.replace(/\\\r?\n/g, ' ').replace(/`\r?\n/g, ' ');
  const hits = [];
  for (const r of view.command) {
    r.re.lastIndex = 0;
    if (r.re.test(text)) hits.push({ action: r.action, ruleId: r.id, reason: r.name, severity: r.severity });
  }
  return hits.sort((a, b) => (a.action === 'block' ? 0 : 1) - (b.action === 'block' ? 0 : 1));
}
