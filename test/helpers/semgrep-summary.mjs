// Dev helper: print a Semgrep JSON result grouped by file.  node test/helpers/semgrep-summary.mjs out.json
import fs from 'node:fs';
import path from 'node:path';

const j = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const by = {};
for (const r of j.results) (by[path.basename(r.path)] ??= []).push(`${String(r.start.line).padStart(3)}  ${r.check_id.split('staffet.').pop()}`);
for (const f of Object.keys(by).sort()) console.log(`${f} (${by[f].length})\n   ${by[f].sort().join('\n   ')}`);
console.log('errors:', j.errors.length, j.errors.slice(0, 5).map((e) => String(e.message || e.long_msg || JSON.stringify(e)).slice(0, 300)));
