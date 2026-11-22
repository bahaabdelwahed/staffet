// Tool semantics: what a tool call *does*, independent of which harness named it.
import { isPlainObject } from '../util.mjs';

const SHELL = /^(?:bash|shell|sh|zsh|powershell|pwsh|cmd|execute_command|run_in_terminal|run_terminal_cmd|run_terminal_command|run_command|runcommand|run_shell_command|terminal|exec|execute|execute_bash|local_shell|container\.exec|shell_command|bash_command|run_bash)$/i;
const READ = /^(?:read|read_file|readfile|view|view_file|open_file|cat|read_many_files|read_multiple_files|read_text_file|read_media_file|get_file_contents|notebookread|read_notebook|fs_read|file_read|view_image|read_pdf|read_document|open)$/i;
const WRITE = /^(?:write|write_file|writefile|write_to_file|create_file|createfile|new_file|edit|edit_file|editfile|multiedit|multi_edit|replace_in_file|apply_patch|apply_diff|insert_edit_into_file|replace_string_in_file|multi_replace_string_in_file|notebookedit|edit_notebook_file|insert_content|search_and_replace|fs_write|file_write|create|patch|update_file|str_replace|insert|append_to_file|write_notebook)$/i;
const TEXT_EDITOR = /^(?:str_replace_editor|str_replace_based_edit_tool|text_editor)$/i;
const FETCH = /^(?:webfetch|web_fetch|fetch|fetch_webpage|fetch_url|get_url|read_url|open_url|url_fetch|browser_action|browser_navigate|navigate|browse|web_browse|http_request|open_simple_browser|curl|download|download_file)$/i;
const SEARCH = /^(?:glob|grep|ls|list_files|list_dir|list_directory|search_files|file_search|grep_search|find|find_files|codebase_search|semantic_search|list_code_definition_names|search|directory_tree|rg)$/i;

export const PATH_KEYS = new Set(['file_path', 'filepath', 'path', 'paths', 'filename', 'file', 'files', 'target_file', 'targetfile', 'absolutepath', 'absolute_path', 'notebook_path', 'uri', 'directory', 'dir', 'cwd', 'relative_path', 'relativepath', 'relative_workspace_path', 'target', 'destination', 'old_path', 'new_path', 'file_paths', 'filepaths', 'directory_path', 'dirpath', 'folder', 'rootpath', 'root', 'target_directory', 'source_path', 'destination_path', 'working_directory', 'workdir']);
const COMMAND_KEYS = ['command', 'cmd', 'script', 'commandline', 'command_line', 'bash_command', 'shell_command', 'input'];
export const CONTENT_KEYS = new Set(['content', 'contents', 'file_text', 'new_string', 'new_str', 'newstring', 'code', 'new_content', 'replacement', 'code_edit', 'new_source', 'text', 'insert_text', 'new_text', 'newtext', 'diff', 'patch', 'old_string', 'old_str', 'oldstring', 'old_text', 'oldtext', 'search', 'replace']);

/** Strip MCP-style namespaces: mcp__server__tool, server.tool, server-tool. */
function baseName(name) {
  const s = String(name || '');
  const parts = s.split(/__|\./);
  return parts[parts.length - 1];
}

/** shell | read | write | fetch | search | other */
export function classifyTool(name, args) {
  const n = baseName(name);
  if (TEXT_EDITOR.test(n)) return args?.command === 'view' ? 'read' : 'write';
  if (SHELL.test(n)) return 'shell';
  if (READ.test(n)) return 'read';
  if (WRITE.test(n)) return 'write';
  if (FETCH.test(n)) return 'fetch';
  if (SEARCH.test(n)) return 'search';
  // unknown tool: infer from argument shape
  if (isPlainObject(args)) {
    const lower = Object.fromEntries(Object.entries(args).map(([k, v]) => [k.toLowerCase(), v]));
    const hasPath = 'path' in lower || 'file_path' in lower || 'filepath' in lower;
    if (!hasPath && COMMAND_KEYS.slice(0, 7).some((k) => typeof lower[k] === 'string')) return 'shell';
    if (typeof lower.url === 'string' && !Object.keys(lower).some((k) => CONTENT_KEYS.has(k))) return 'fetch';
  }
  return 'other';
}

/** Path-like argument values of a tool call (by key name). */
export function extractPathArgs(args) {
  const out = [];
  const visit = (v, key, depth) => {
    if (depth > 4 || v == null) return;
    const isPathKey = key != null && PATH_KEYS.has(String(key).toLowerCase());
    if (typeof v === 'string') { if (isPathKey && v.length && v.length < 2048) out.push(v); }
    else if (Array.isArray(v)) v.forEach((x) => visit(x, isPathKey ? key : null, depth + 1));
    else if (isPlainObject(v)) for (const [k, x] of Object.entries(v)) visit(x, k, depth + 1);
  };
  visit(args, null, 0);
  return [...new Set(out)];
}

/** The command line of a shell-type tool call, or null. */
export function extractCommand(args) {
  if (typeof args === 'string') return args;
  if (!isPlainObject(args)) return null;
  for (const [k, v] of Object.entries(args)) {
    if (!COMMAND_KEYS.includes(k.toLowerCase())) continue;
    if (typeof v === 'string') return v;
    if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v.join(' ');
  }
  if (Array.isArray(args.args) && typeof args.program === 'string') return [args.program, ...args.args].join(' ');
  return null;
}

/** Split a command line into simple commands (on ; && || | newline), respecting quotes. */
export function splitCommands(cmd) {
  const out = [];
  let cur = '', q = null;
  const s = String(cmd).replace(/\\\r?\n/g, ' ').replace(/`\r?\n/g, ' ');
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === q && s[i - 1] !== '\\') q = null; cur += c; continue; }
    if (c === '"' || c === "'") { q = c; cur += c; continue; }
    if (c === '\n' || c === ';' || c === '|' || (c === '&' && s[i + 1] === '&')) {
      if (cur.trim()) out.push(cur.trim());
      cur = '';
      if ((c === '|' && s[i + 1] === '|') || c === '&') i++;
      continue;
    }
    cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  // $(...) and backtick substitutions are commands too
  for (const m of s.matchAll(/\$\(([^()]{2,})\)|`([^`]{2,})`/g)) out.push((m[1] || m[2]).trim());
  return out;
}

/** Whitespace tokenizer that honours single and double quotes (quotes removed). */
export function tokenize(s) {
  const out = [];
  let cur = '', q = null, has = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === q) q = null; else cur += c; continue; }
    if (c === '"' || c === "'") { q = c; has = true; continue; }
    if (/\s/.test(c)) { if (cur || has) out.push(cur); cur = ''; has = false; continue; }
    cur += c;
  }
  if (cur || has) out.push(cur);
  return out;
}

/** First real word of a simple command (skips sudo, env assignments, wrappers). */
export function commandVerb(tokens) {
  let i = 0;
  while (i < tokens.length && (/^(?:sudo|doas|env|nohup|time|command|exec|call|start|&)$/i.test(tokens[i]) || /^[A-Za-z_]\w*=/.test(tokens[i]) || (tokens[i].startsWith('-') && i > 0))) i++;
  const verb = (tokens[i] || '').replace(/^.*[\\/]/, '').replace(/\.(?:exe|cmd|bat|com)$/i, '').toLowerCase();
  return { verb, rest: tokens.slice(i + 1) };
}
