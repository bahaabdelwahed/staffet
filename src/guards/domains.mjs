// Domain guard: which hosts would a tool call reach, and are they allowed?
import net from 'node:net';
import { walkStrings } from '../util.mjs';
import { splitCommands, tokenize, commandVerb } from './toolsem.mjs';

const URL_RE = /\b((?:https?|wss?|ftps?|sftp|ssh|git|file|gopher|dict|ldaps?|smb|tftp|jar|netdoc):\/\/[^\s'"<>`\\)\]}|]+)/gi;
const SCP_RE = /(?:^|[\s'"=])(?:[\w.-]+@)((?:[a-z0-9-]+\.)+[a-z]{2,24}):(?!\d+(?:\/|\s|$))[\w./~-]+/gi;
const BARE_HOST = /^((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\])(?::\d{1,5})?(?:[/?#].*)?$/i;
const NET_COMMANDS = new Set(['curl', 'wget', 'http', 'https', 'httpie', 'xh', 'aria2c', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod', 'start-bitstransfer', 'ssh', 'scp', 'sftp', 'telnet', 'nc', 'ncat', 'netcat', 'ftp', 'ping', 'nslookup', 'dig', 'host', 'nmap', 'rsync', 'socat', 'test-netconnection', 'tnc', 'wscat', 'websocat', 'traceroute', 'tracert']);
// last labels that are far more often a file extension than a TLD on a command line
const FILE_EXT = new Set(['txt', 'json', 'html', 'htm', 'xml', 'yaml', 'yml', 'md', 'js', 'mjs', 'cjs', 'ts', 'tsx', 'jsx', 'py', 'sh', 'zip', 'gz', 'tar', 'tgz', 'log', 'csv', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'exe', 'dll', 'bin', 'out', 'tmp', 'conf', 'cfg', 'ini', 'lock', 'pem', 'key', 'crt', 'sql', 'db', 'bak', 'php', 'rb', 'go', 'rs', 'java', 'c', 'h', 'cpp', 'css', 'ps', 'bat', 'cmd', 'so', 'pl', 'toml', 'env', 'iso', 'img', 'deb', 'rpm', 'msi', 'jar', 'war', 'whl', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx']);

export function isIpLiteral(host) {
  return net.isIP(host.replace(/^\[|\]$/g, '')) !== 0;
}

export function isPrivateHost(host) {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h === 'host.docker.internal') return true;
  if (net.isIPv4(h)) {
    const [a, b] = h.split('.').map(Number);
    return a === 127 || a === 10 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127);
  }
  if (net.isIPv6(h)) return h === '::1' || h === '::' || /^f[cd]/.test(h) || /^fe[89ab]/.test(h);
  return !h.includes('.');            // single-label intranet names
}

function parseUrl(raw) {
  let s = raw.replace(/[.,;:!?'")\]]+$/, '');
  try {
    const u = new URL(s);
    return { url: s, scheme: u.protocol.replace(':', '').toLowerCase(), host: u.hostname.replace(/^\[|\]$/g, '').toLowerCase(), userinfo: Boolean(u.username || u.password), password: Boolean(u.password), port: u.port };
  } catch {
    return null;
  }
}

/**
 * Network targets referenced by a tool call.
 * @returns {Array<{host, scheme, url, userinfo, password, source}>}
 */
export function extractTargets(call, semantic) {
  const found = new Map();
  const add = (t) => { if (t && t.host !== undefined) { const k = `${t.scheme}|${t.host}`; if (!found.has(k)) found.set(k, t); } };

  const scanText = (text, isCommand) => {
    const urlHosts = new Set();
    for (const m of text.matchAll(URL_RE)) {
      const t = parseUrl(m[1]);
      if (t) { add({ ...t, source: 'url' }); urlHosts.add(t.host); }
    }
    for (const m of text.matchAll(SCP_RE)) add({ host: m[1].toLowerCase(), scheme: 'ssh', url: m[0].trim(), userinfo: false, password: false, source: 'scp' });
    if (!isCommand) return;
    for (const simple of splitCommands(text)) {
      const { verb, rest } = commandVerb(tokenize(simple));
      if (!NET_COMMANDS.has(verb)) continue;
      for (let tok of rest) {
        if (!tok || tok.startsWith('-') || tok.includes('://')) continue;
        tok = tok.replace(/^[\w.-]+@/, '');
        const m = BARE_HOST.exec(tok);
        if (!m) continue;
        const host = m[1].replace(/^\[|\]$/g, '').toLowerCase();
        const last = host.split('.').pop();
        if (!isIpLiteral(host) && FILE_EXT.has(last)) continue;
        if (urlHosts.has(host)) continue;
        const scheme = ['ssh', 'scp', 'sftp', 'rsync'].includes(verb) ? 'ssh' : ['curl', 'wget', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod', 'http', 'xh', 'httpie', 'aria2c'].includes(verb) ? 'http' : 'tcp';
        add({ host, scheme, url: tok, userinfo: false, password: false, source: 'command' });
      }
    }
  };

  // reading, searching and writing files are not network calls (file content is data)
  if (semantic === 'read' || semantic === 'search' || semantic === 'write') return [];
  const args = call.args;
  if (typeof args === 'string') { scanText(args, semantic === 'shell'); return [...found.values()]; }
  walkStrings(args, (value, keyPath) => {
    const key = String(keyPath[keyPath.length - 1] ?? '').toLowerCase();
    if (value.length > 200000) return;
    scanText(value, semantic === 'shell');
    // a bare "url"/"host" style argument without a scheme
    if (['url', 'uri', 'host', 'hostname', 'domain', 'endpoint', 'server', 'address'].includes(key) && !value.includes('://')) {
      const m = BARE_HOST.exec(value.trim());
      if (m) add({ host: m[1].replace(/^\[|\]$/g, '').toLowerCase(), scheme: 'https', url: value.trim(), userinfo: false, password: false, source: 'argument' });
    }
  });
  return [...found.values()];
}

const matches = (rule, host) => rule.matchers.some((re) => re.test(host));

function heuristicHit(rule, t) {
  switch (rule.heuristic) {
    case 'ip-literal': return isIpLiteral(t.host) && !isPrivateHost(t.host) && 'raw public IP address';
    case 'punycode': return (t.host.split('.').some((l) => l.startsWith('xn--')) || /[^\x00-\x7f]/.test(t.host)) && 'punycode / internationalised look-alike hostname';
    case 'userinfo': return t.userinfo && ['http', 'https', 'ws', 'wss', 'ftp', 'ftps'].includes(t.scheme) && (t.password ? 'credentials embedded in the URL' : 'user-info in the URL can disguise the real host');
    case 'scheme': return rule.schemes.has(t.scheme) && `"${t.scheme}://" scheme`;
    case 'tld': return rule.tlds.has(t.host.split('.').pop()) && `".${t.host.split('.').pop()}" top-level domain`;
    case 'plain-http': return t.scheme === 'http' && t.source !== 'command' && !isPrivateHost(t.host) && 'unencrypted http://';
    default: return false;
  }
}

/**
 * Decide what to do with one target.
 * @returns {{ action: 'allow'|'block', ruleId?, reason?, warnings: Array<{ruleId, reason}> }}
 */
export function evaluateTarget(t, view, mode = 'denylist') {
  const d = view.domain;
  const warnings = [];
  const label = (r) => r.name || r.id;

  for (const r of d.custom) {
    const hit = r.heuristic ? heuristicHit(r, t) : matches(r, t.host);
    if (!hit) continue;
    if (r.action === 'warn') { warnings.push({ ruleId: r.id, reason: label(r) }); continue; }
    return { action: r.action, ruleId: r.id, reason: label(r), warnings };
  }
  for (const r of d.blocks) {
    if (!matches(r, t.host)) continue;
    if (r.action === 'warn') { warnings.push({ ruleId: r.id, reason: label(r) }); continue; }
    return { action: 'block', ruleId: r.id, reason: label(r), warnings };
  }
  for (const r of d.heuristics) {
    const why = heuristicHit(r, t);
    if (!why) continue;
    if (r.action === 'warn') { warnings.push({ ruleId: r.id, reason: why }); continue; }
    return { action: 'block', ruleId: r.id, reason: why, warnings };
  }
  for (const r of d.allows) {
    if (matches(r, t.host)) return { action: 'allow', ruleId: r.id, warnings };
  }
  if (mode === 'allowlist' && !isPrivateHost(t.host)) {
    return { action: 'block', ruleId: 'domain.allowlist-mode', reason: 'domain is not on the allow list', warnings };
  }
  return { action: 'allow', warnings };
}

/** Convenience for the CLI / playground: check a single URL or host string. */
export function checkUrl(input, view, mode) {
  let t = parseUrl(input.includes('://') ? input : `https://${input}`);
  if (!t) return { action: 'block', ruleId: 'domain.unparseable', reason: 'not a valid URL', warnings: [], host: input };
  return { ...evaluateTarget({ ...t, source: 'url' }, view, mode), host: t.host };
}
