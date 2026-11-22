// Path guard: protected files/folders and (optionally) workspace confinement.
import { globToRegExp } from '../util.mjs';
import { splitCommands, tokenize, commandVerb } from './toolsem.mjs';

const HOME_VARS = /^(?:\$HOME|\$\{HOME\}|%USERPROFILE%|%HOMEPATH%|\$env:USERPROFILE|\$env:HOME|\$USERPROFILE|\$\{env:USERPROFILE\})(?=[\\/]|$)/i;
const WRITE_VERBS = new Set(['rm', 'mv', 'cp', 'tee', 'touch', 'mkdir', 'rmdir', 'chmod', 'chown', 'chgrp', 'dd', 'truncate', 'ln', 'install', 'shred', 'del', 'erase', 'copy', 'xcopy', 'robocopy', 'move', 'ren', 'rename', 'rd', 'set-content', 'add-content', 'out-file', 'new-item', 'remove-item', 'copy-item', 'move-item', 'rename-item', 'clear-content', 'ni', 'ri', 'sc', 'ac', 'mklink', 'unlink', 'patch', 'sponge']);

function collapse(p) {
  const drive = /^[a-z]:/.exec(p)?.[0] || '';
  let rest = drive ? p.slice(2) : p;
  const home = rest.startsWith('~');
  if (home) rest = rest.slice(1);
  const abs = rest.startsWith('/');
  const out = [];
  for (const seg of rest.split('/')) {
    if (!seg || seg === '.') continue;
    if (seg === '..') { if (out.length && out[out.length - 1] !== '..') out.pop(); else if (!abs && !home && !drive) out.push('..'); continue; }
    out.push(seg);
  }
  return drive + (home ? '~' : '') + (abs || ((home || drive) && out.length) ? '/' : '') + out.join('/');
}

/** Canonical lower-case, forward-slash form used for matching. */
export function normalisePath(p) {
  let s = String(p).trim().replace(/^["'`]+|["'`]+$/g, '');
  s = s.replace(/^file:\/\/\/?(?=[a-z]:)/i, '').replace(/^file:\/\//i, '');
  s = s.replace(/\\/g, '/');
  s = s.replace(HOME_VARS, '~');
  s = s.replace(/^(?:%APPDATA%|\$env:APPDATA)/i, '~/appdata/roaming').replace(/^(?:%LOCALAPPDATA%|\$env:LOCALAPPDATA)/i, '~/appdata/local');
  s = s.replace(/^(?:%SYSTEMROOT%|%WINDIR%|\$env:SystemRoot|\$env:windir)/i, 'c:/windows').replace(/^(?:%SYSTEMDRIVE%|\$env:SystemDrive)/i, 'c:');
  s = s.replace(/^(?:%PROGRAMFILES%|\$env:ProgramFiles)/i, 'c:/program files');
  s = s.toLowerCase();
  s = s.replace(/^\/mnt\/([a-z])(?=\/|$)/, '$1:').replace(/^\/([a-z])\/(?=users\/|windows\/|program)/, '$1:/');   // WSL, Git Bash
  return collapse(s);
}

/** All forms of a path worth matching: as written, resolved against cwd, and home-relative. */
export function pathVariants(p, cwd) {
  const n = normalisePath(p);
  const vars = new Set([n]);
  const isAbs = /^(?:\/|~|[a-z]:)/.test(n);
  if (!isAbs && cwd) vars.add(collapse(`${normalisePath(cwd)}/${n}`));
  for (const v of [...vars]) {
    const m = /^(?:[a-z]:)?\/(?:users|home)\/[^/]+(\/.*)?$/.exec(v) || /^\/root(\/.*)?$/.exec(v);
    if (m) vars.add('~' + (m[1] || ''));
  }
  return [...vars];
}

const TEMP_ROOTS = ['/tmp', '/var/tmp', '/private/tmp', '~/appdata/local/temp', '/dev/null', 'nul'];

/**
 * @param {string} p     path as written by the model
 * @param {'read'|'write'|'any'} op
 * @returns {{action:'block'|'warn', ruleId, reason}|null}
 */
export function checkPath(p, op, view, policy = {}, cwd = null) {
  const variants = pathVariants(p, cwd);
  let warn = null;
  for (const r of view.path) {
    if (!(r.operations.has('any') || op === 'any' || r.operations.has(op))) continue;
    if (!variants.some((v) => r.res.some((re) => re.test(v)))) continue;
    if (r.except.length && variants.some((v) => r.except.some((re) => re.test(v)))) continue;
    const hit = { action: r.action, ruleId: r.id, reason: r.name, severity: r.severity };
    if (r.action === 'block') return hit;
    warn ??= hit;
  }
  if (policy.confineToWorkspace && cwd) {
    const root = normalisePath(cwd);
    const abs = variants.filter((v) => /^(?:\/|~|[a-z]:)/.test(v));
    if (abs.length) {
      const allowed = [root, ...TEMP_ROOTS, ...(policy.allowedRoots || []).map(normalisePath)];
      const inside = abs.some((v) => allowed.some((a) => v === a || v.startsWith(a.replace(/\/$/, '') + '/')));
      const extra = (policy.allowedRoots || []).some((g) => { const re = globToRegExp(g); return abs.some((v) => re.test(v)); });
      if (!inside && !extra) return { action: 'block', ruleId: 'path.outside-workspace', reason: 'path is outside the workspace', severity: 'high' };
    }
  }
  return warn;
}

const LOOKS_LIKE_PATH = /^(?:~|\.{1,2}[\\/]|[\\/]|[A-Za-z]:[\\/]|%[A-Za-z_]+%|\$(?:HOME|USERPROFILE|\{HOME\})|\$env:)/;
const FILE_NAME = /^\.?[\w.@+-]+\.[A-Za-z0-9_]{1,8}$/;
const DOTFILE = /^\.[\w.-]{2,}$/;

/**
 * Path-like tokens in a shell command line, with the operation they are used for.
 * @returns {Array<{path: string, op: 'read'|'write'}>}
 */
export function extractShellPaths(command) {
  const out = new Map();
  const add = (path, op) => {
    path = path.replace(/^["'`(]+|["'`),;]+$/g, '');
    if (!path || path.length > 1024 || path.includes('://')) return;
    const prev = out.get(path);
    if (!prev || (prev === 'read' && op === 'write')) out.set(path, op);
  };
  for (const simple of splitCommands(command)) {
    const tokens = tokenize(simple);
    const { verb } = commandVerb(tokens);
    const writer = WRITE_VERBS.has(verb) || (verb === 'sed' && tokens.some((t) => /^-[a-z]*i/.test(t))) || (verb === 'git' && /^(?:rm|mv|clean)$/.test(tokens[1] || ''));
    for (let i = 0; i < tokens.length; i++) {
      let tok = tokens[i];
      if (!tok) continue;
      // redirections:  > file   >> file   2> file   >file
      const redir = /^(?:\d?>>?|&>>?)(.*)$/.exec(tok);
      if (redir) { const target = redir[1] || tokens[++i]; if (target) add(target, 'write'); continue; }
      if (tok === '<') { if (tokens[i + 1]) add(tokens[++i], 'read'); continue; }
      if (tok.startsWith('-')) {
        const eq = tok.indexOf('=');
        if (eq < 0) continue;
        tok = tok.slice(eq + 1);            // --output=path
      } else if (/^[A-Za-z_]\w*=/.test(tok) && i === 0) continue;   // VAR=value prefix
      if (/^@/.test(tok)) tok = tok.slice(1);                          // curl -d @file
      const t = tok.replace(/^["'`]+|["'`]+$/g, '');
      if (LOOKS_LIKE_PATH.test(t) || /[\\/]/.test(t) || FILE_NAME.test(t) || DOTFILE.test(t)) {
        if (/^\/[a-zA-Z?]{1,2}$/.test(t)) continue;                    // cmd.exe switches: /s /q
        if (/^s?\/.*\/.*\/[gimsx]*$/.test(t)) continue;                // sed / regex literals
        add(t, writer ? 'write' : 'read');
      }
    }
  }
  return [...out].map(([path, op]) => ({ path, op }));
}
