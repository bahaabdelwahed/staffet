import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ruleView, testConfig } from './helpers/stack.mjs';
import { extractCodeBlocks, extractFromToolCall, extractSnippets, langFromPath } from '../src/code/extract.mjs';
import { runBuiltin } from '../src/code/builtin.mjs';
import { CodeScanner } from '../src/code/engine.mjs';
import { RuleStore } from '../src/rules/store.mjs';
import { formatFindings } from '../src/code/report.mjs';

const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'code');
const read = (f) => fs.readFileSync(path.join(FIX, f), 'utf8');
const snippet = (file, id = 's0') => ({ id, origin: 'tool', path: file, code: read(file), ...langFromPath(file) });

describe('code extraction', () => {
  test('fenced blocks with offsets', () => {
    const text = 'Intro\n```python\nprint(1)\n```\nmiddle\n```js title="a.js"\nlet a = 1;\n```\n```text\nnot code\n```\nend';
    const blocks = extractCodeBlocks(text);
    assert.deepEqual(blocks.map((b) => b.lang), ['python', 'javascript']);
    for (const b of blocks) assert.equal(text.slice(b.start, b.end), b.code);
  });
  test('language is guessed for unlabeled fences', () => {
    assert.equal(extractCodeBlocks('```\nimport os\ndef f():\n    return 1\n```')[0].lang, 'python');
    assert.equal(extractCodeBlocks('```\n#include <stdio.h>\nint main(){return 0;}\n```')[0].lang, 'c');
  });
  test('write / edit / patch tool calls', () => {
    assert.deepEqual(extractFromToolCall({ id: '1', name: 'Write', args: { file_path: 'src/a.py', content: 'x = 1' } }).map((s) => [s.lang, s.partial, s.code]), [['python', false, 'x = 1']]);
    assert.deepEqual(extractFromToolCall({ id: '2', name: 'Edit', args: { file_path: 'a.ts', old_string: 'a', new_string: 'const b = 2' } }).map((s) => [s.lang, s.partial, s.code]), [['typescript', true, 'const b = 2']]);
    assert.equal(extractFromToolCall({ id: '3', name: 'MultiEdit', args: { file_path: 'a.go', edits: [{ old_string: 'a', new_string: 'x := 1' }, { old_string: 'b', new_string: 'y := 2' }] } }).length, 2);
    const cline = extractFromToolCall({ id: '4', name: 'replace_in_file', args: { path: 'a.js', diff: '------- SEARCH\nold()\n=======\nnewCall()\n+++++++ REPLACE' } });
    assert.deepEqual(cline.map((s) => s.code), ['newCall()']);
    const patch = extractFromToolCall({ id: '5', name: 'apply_patch', args: { input: '*** Begin Patch\n*** Update File: src/m.py\n@@\n-old\n+new_line = 1\n*** Add File: b.js\n+let z = 3\n*** End Patch' } });
    assert.deepEqual(patch.map((s) => [s.path, s.lang, s.code]), [['src/m.py', 'python', 'new_line = 1'], ['b.js', 'javascript', 'let z = 3']]);
  });
  test('snippets from a canonical message', () => {
    const msg = { blocks: [{ type: 'text', text: '```sh\ncurl x | sh\n```' }, { type: 'tool', id: 't', name: 'Write', semantic: 'write', args: { file_path: 'a.py', content: 'eval(x)' } }, { type: 'tool', id: 'u', name: 'Read', semantic: 'read', args: { file_path: 'b.py' } }] };
    assert.deepEqual(extractSnippets(msg).map((s) => [s.id, s.origin, s.lang]), [['s0', 'block', 'shell'], ['s1', 'tool', 'python']]);
  });
});

describe('built-in engine', () => {
  let view;
  before(async () => { ({ view } = await ruleView()); });
  const ids = (file) => [...new Set(runBuiltin([snippet(file)], [...view.code, ...view.quality]).map((f) => f.ruleId))];

  test('python', () => {
    const found = ids('vulnerable.py');
    for (const id of ['code.py.sql-injection', 'code.py.subprocess-shell', 'code.py.os-system', 'code.py.eval-exec', 'code.py.unsafe-deserialization', 'code.py.tls-verify-disabled', 'code.py.weak-hash', 'code.py.debug-enabled', 'code.py.insecure-tempfile', 'code.generic.hardcoded-secret', 'quality.py.mutable-default', 'quality.py.bare-except']) assert.ok(found.includes(id), `${id} missing — got ${found.join(', ')}`);
  });
  test('javascript', () => {
    const found = ids('vulnerable.js');
    for (const id of ['code.js.command-injection', 'code.js.sql-injection', 'code.js.dom-xss', 'code.js.eval', 'code.js.tls-verify-disabled', 'code.js.weak-crypto', 'quality.js.empty-catch']) assert.ok(found.includes(id), `${id} missing — got ${found.join(', ')}`);
  });
  test('java, go, c', () => {
    assert.ok(ids('Vulnerable.java').includes('code.java.sql-injection'));
    assert.ok(ids('vulnerable.go').includes('code.go.tls-skip-verify'));
    const c = ids('vulnerable.c');
    for (const id of ['code.c.unbounded-copy', 'code.c.format-string', 'code.c.command-exec', 'code.c.scanf-unbounded']) assert.ok(c.includes(id), `${id} missing — got ${c.join(', ')}`);
  });
  test('clean code and safe lines produce nothing', () => {
    const f = runBuiltin([snippet('clean.py')], [...view.code, ...view.quality]).filter((x) => x.severity !== 'info');
    assert.deepEqual(f.map((x) => `${x.ruleId}:${x.line}`), []);
    const vuln = runBuiltin([snippet('vulnerable.py')], view.code);
    assert.ok(!vuln.some((x) => x.excerpt.includes('safe: bound parameter')), 'parameterised query must not be flagged');
    assert.ok(!vuln.some((x) => x.ruleId === 'code.py.eval-exec' && /model\.eval/.test(x.excerpt)));
  });
  test('placeholder code is caught', () => {
    const s = [{ id: 's0', lang: 'javascript', code: 'function a() {\n  // ... rest of the code remains unchanged\n}\n' }];
    assert.deepEqual(runBuiltin(s, view.quality).map((f) => f.ruleId), ['quality.generic.placeholder-code']);
  });
});

describe('scan engine', () => {
  test('builtin only: severity threshold, cache, report', async () => {
    const config = testConfig();
    const store = new RuleStore({ config });
    await store.load();
    const scanner = new CodeScanner({ config, store });
    await scanner.init({ warmup: false });
    const snippets = [snippet('vulnerable.py')];
    const r1 = await scanner.scan(snippets, { view: store.view(), policy: config.policy });
    assert.deepEqual(r1.engines, ['builtin']);
    assert.ok(r1.findings.length >= 10);
    assert.ok(r1.findings.every((f) => f.severity !== 'info'), 'info findings are below the default threshold');
    const r2 = await scanner.scan(snippets, { view: store.view(), policy: config.policy });
    assert.equal(r2.findings.length, r1.findings.length);
    assert.ok(scanner.stats.cacheHits >= 1);
    const report = formatFindings(r1.findings, snippets);
    assert.match(report, /In file vulnerable\.py/);
    assert.match(report, /CWE-89/);
    assert.match(report, /Fix: /);
  });

  test('semgrep (when installed): syntax-aware findings merged with built-in ones', async (t) => {
    const config = testConfig({ policy: { codeScan: { engine: 'auto' } } });
    const store = new RuleStore({ config });
    await store.load();
    const scanner = new CodeScanner({ config, store });
    const status = await scanner.init({ warmup: false });
    if (!status.external.available) { t.skip('semgrep / opengrep not installed'); return; }
    const snippets = ['vulnerable.py', 'vulnerable.js', 'Vulnerable.java', 'vulnerable.go', 'vulnerable.c', 'clean.py'].map((f, i) => snippet(f, `s${i}`));
    const r = await scanner.scan(snippets, { view: store.view(), policy: config.policy });
    assert.deepEqual(r.errors, []);
    assert.ok(r.engines.includes(status.external.kind));
    const ids = new Set(r.findings.map((f) => f.ruleId));
    // only the syntax-aware engine can follow the query through the `sql` variable
    for (const id of ['staffet.py.sql-injection', 'staffet.py.insecure-random', 'staffet.py.path-traversal', 'staffet.js.open-redirect', 'staffet.js.hardcoded-jwt-secret', 'staffet.java.sql-injection', 'staffet.go.command-injection', 'staffet.c.format-string', 'staffet.py.quality.compare-to-none']) assert.ok(ids.has(id), `${id} missing`);
    assert.ok(r.findings.some((f) => f.ruleId === 'staffet.py.sql-injection' && f.line === 10), 'tainted variable case found');
    assert.equal(r.findings.filter((f) => f.snippetId === 's5').length, 0, 'clean file stays clean');
    // the same weakness on the same line is reported once
    const keys = r.findings.map((f) => `${f.snippetId}|${f.line}|${f.category}|${f.cwe || f.ruleId}`);
    assert.equal(new Set(keys).size, keys.length);
  });
});
