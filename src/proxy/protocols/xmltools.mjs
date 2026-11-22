// XML tool protocol (Cline / Roo / Kilo without native tool calling): tool calls are XML blocks
// inside the assistant text, tool results come back as user text "[tool for 'x'] Result: ...".

const TOOLS = ['execute_command', 'read_file', 'write_to_file', 'replace_in_file', 'apply_diff', 'insert_content', 'search_and_replace', 'search_files', 'list_files', 'list_code_definition_names', 'codebase_search', 'browser_action', 'web_fetch', 'use_mcp_tool', 'access_mcp_resource', 'ask_followup_question', 'attempt_completion', 'new_task', 'plan_mode_respond', 'switch_mode', 'fetch_instructions', 'update_todo_list', 'load_mcp_documentation', 'run_slash_command'];
const PARAMS = ['command', 'requires_approval', 'path', 'content', 'diff', 'regex', 'file_pattern', 'recursive', 'action', 'url', 'coordinate', 'text', 'server_name', 'tool_name', 'arguments', 'uri', 'question', 'options', 'result', 'context', 'response', 'task_progress', 'line_count', 'start_line', 'end_line', 'line', 'query', 'mode', 'mode_slug', 'message', 'todos', 'args', 'search', 'replace', 'use_regex', 'ignore_case', 'cwd', 'timeout', 'size', 'task', 'reason', 'follow_up'];
const GREEDY = new Set(['content', 'diff', 'arguments', 'result', 'response']);   // may themselves contain tags

const TOOL_RE = new RegExp(`<(${TOOLS.join('|')})>([\\s\\S]*?)</\\1>`, 'g');
export const XML_RESULT_RE = /^\s*\[(\w+)(?: for '([^']*)')?\] Result:/;

function parseParams(inner) {
  const args = {};
  for (const p of PARAMS) {
    const open = inner.indexOf(`<${p}>`);
    if (open < 0) continue;
    const close = GREEDY.has(p) ? inner.lastIndexOf(`</${p}>`) : inner.indexOf(`</${p}>`, open);
    if (close < open) continue;
    let v = inner.slice(open + p.length + 2, close);
    if (v.startsWith('\n')) v = v.slice(1);
    if (v.endsWith('\n')) v = v.slice(0, -1);
    args[p] = v;
  }
  return args;
}

/** Text → [ {type:'text'} | {type:'tool', transport:'xml'} ... ] */
export function splitXmlTools(text, idBase = 0) {
  const out = [];
  let last = 0, n = 0, m;
  TOOL_RE.lastIndex = 0;
  while ((m = TOOL_RE.exec(text))) {
    if (m.index > last) out.push({ type: 'text', text: text.slice(last, m.index) });
    out.push({ type: 'tool', transport: 'xml', id: `xml_${idBase + n++}`, name: m[1], args: parseParams(m[2]), raw: m[0] });
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push({ type: 'text', text: text.slice(last) });
  return out.some((b) => b.type === 'tool') ? out : [{ type: 'text', text }];
}

export function serializeXmlTool(block) {
  if (block.raw && !block.dirty) return block.raw;
  const body = Object.entries(block.args || {}).map(([k, v]) => `<${k}>${GREEDY.has(k) ? '\n' : ''}${typeof v === 'string' ? v : JSON.stringify(v)}${GREEDY.has(k) ? '\n' : ''}</${k}>`).join('\n');
  return `<${block.name}>\n${body}\n</${block.name}>`;
}

/** Expand text blocks of a canonical message into text + XML tool blocks. */
export function expandXml(message) {
  const blocks = [];
  let n = 0;
  for (const b of message.blocks) {
    if (b.type !== 'text') { blocks.push(b); continue; }
    for (const part of splitXmlTools(b.text, n)) {
      if (part.type === 'tool') n++;
      blocks.push(part);
    }
  }
  message.blocks = blocks;
  return message;
}

/** Fold XML tool blocks back into plain text blocks before encoding to the wire. */
export function collapseXml(message) {
  const blocks = [];
  for (const b of message.blocks) {
    const text = b.type === 'tool' && b.transport === 'xml' ? serializeXmlTool(b) : b.type === 'text' ? b.text : null;
    if (text === null) { blocks.push(b); continue; }
    const prev = blocks[blocks.length - 1];
    if (prev && prev.type === 'text') {
      // untouched blocks are re-joined byte-for-byte; only a new / rewritten tool call gets a separator
      const sep = b.type === 'tool' && (b.dirty || !b.raw) && prev.text && !prev.text.endsWith('\n') ? '\n\n' : '';
      prev.text += sep + text;
      prev.dirty = true;
    }
    else blocks.push({ type: 'text', text, dirty: true });
  }
  message.blocks = blocks;
  return message;
}
