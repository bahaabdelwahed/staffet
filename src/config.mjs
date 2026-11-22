import fs from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import { BRAND } from './brand.mjs';
import { deepMerge, clone } from './util.mjs';

export const DEFAULTS = Object.freeze({
  server: {
    host: '127.0.0.1',
    port: 8787,
    adminToken: '',          // required for dashboard + admin API when not bound to loopback
    maxBodyMb: 64,
  },
  auth: {
    mode: 'passthrough',     // passthrough: forward the caller's own provider key | keys: callers use Staffet keys
  },
  upstreams: [
    { name: 'openai', protocol: 'openai', baseUrl: 'https://api.openai.com/v1', apiKeyEnv: 'OPENAI_API_KEY', models: ['gpt-*', 'o1*', 'o3*', 'o4*', 'chatgpt-*'] },
    { name: 'anthropic', protocol: 'anthropic', baseUrl: 'https://api.anthropic.com/v1', apiKeyEnv: 'ANTHROPIC_API_KEY', models: ['claude-*'] },
  ],
  network: {
    proxy: '',               // outbound HTTP(S) proxy; empty = use HTTPS_PROXY / HTTP_PROXY env if set
    timeoutMs: 600000,
  },
  enterprise: {
    name: '',
    emailDomains: [],        // informational + used by the "enterprise email" rule
    internalDomains: [],     // hostnames ending with these are always redacted
    confidentialTerms: [],   // project code names etc. — always redacted
  },
  policy: {
    redaction: {
      enabled: true,
      token: BRAND.redactionToken,
      scopes: ['tool_output'],          // tool_output | user | system
    },
    toolCalls: {
      enabled: true,
      domains: { enabled: true, mode: 'denylist' },   // denylist | allowlist
      paths: { enabled: true, protected: [], confineToWorkspace: false, allowedRoots: [] },
      commands: { enabled: true },
    },
    documents: {
      enabled: true,
      localScan: true,                  // scan the file itself when the proxy can read the path
      scanToolOutputs: true,            // scan document content coming back in tool results
      writeHarnessRule: true,           // overwrite the tool call with one that writes a "never open" rule
      piiThreshold: 5,
      threshold: 1.0,
      extensions: ['txt', 'md', 'markdown', 'rst', 'pdf', 'doc', 'docx', 'docm', 'dotx', 'rtf', 'odt', 'ppt', 'pptx', 'pptm', 'odp', 'xls', 'xlsx', 'xlsm', 'ods', 'csv', 'tsv', 'xml', 'html', 'htm', 'eml', 'msg'],
      onScanError: 'allow',             // allow | block
    },
    codeScan: {
      enabled: true,
      engine: 'auto',                   // auto | semgrep | opengrep | builtin
      binary: '',                       // explicit path to semgrep / opengrep
      extraConfigs: [],                 // extra Semgrep --config values (dirs, files, or registry packs)
      scanCodeBlocks: true,             // ``` fenced code in assistant text
      scanToolWrites: true,             // code inside file-writing tool calls
      minSeverity: 'warning',           // info | warning | error
      onUnresolved: 'block',            // block | annotate | allow
      timeoutMs: 30000,
      maxConcurrent: 4,
    },
    quality: {
      enabled: true,
      minSeverity: 'warning',
      maxIterations: 2,
      onUnresolved: 'annotate',
    },
    loop: {
      maxIterations: 3,                 // model round-trips the firewall may spend fixing one response
    },
    notifyInline: true,                 // add a short visible note when the firewall intervenes
    uninspectedEndpoints: 'block',      // block | allow  (e.g. /v1/responses, /v1/completions)
  },
  profiles: {},                         // name -> { policy: {...partial}, rules: { disable: [], enable: [] } }
  logging: {
    capture: 'preview',                 // none | preview | full
    retentionDays: 30,
    console: true,
  },
  dataDir: './data',
  rulesDir: './rules',
});

export function findConfigPath(explicit) {
  if (explicit) return path.resolve(explicit);
  if (process.env.STAFFET_CONFIG) return path.resolve(process.env.STAFFET_CONFIG);
  return path.resolve(process.cwd(), BRAND.configFile);
}

/**
 * Load configuration. Missing file is fine — defaults apply.
 * Returns { config, path, exists, baseDir }.
 */
export function loadConfig(explicitPath, overrides = {}) {
  const file = findConfigPath(explicitPath);
  let user = {};
  const exists = fs.existsSync(file);
  if (exists) {
    const doc = YAML.parse(fs.readFileSync(file, 'utf8'));
    if (doc && typeof doc === 'object') user = doc;
  }
  let config = deepMerge(clone(DEFAULTS), user);
  config = deepMerge(config, overrides);

  const env = process.env;
  if (env.STAFFET_PORT) config.server.port = Number(env.STAFFET_PORT);
  if (env.STAFFET_HOST) config.server.host = env.STAFFET_HOST;
  if (env.STAFFET_ADMIN_TOKEN) config.server.adminToken = env.STAFFET_ADMIN_TOKEN;

  const baseDir = path.dirname(file);
  config.dataDir = path.resolve(baseDir, config.dataDir);
  config.rulesDir = path.resolve(baseDir, config.rulesDir);
  validateConfig(config);
  return { config, path: file, exists, baseDir };
}

export function validateConfig(c) {
  const errs = [];
  if (!Number.isInteger(c.server.port) || c.server.port < 0 || c.server.port > 65535) errs.push('server.port must be a port number');
  if (!Array.isArray(c.upstreams) || !c.upstreams.length) errs.push('at least one upstream is required');
  const names = new Set();
  for (const u of c.upstreams || []) {
    if (!u.name) errs.push('every upstream needs a name');
    if (names.has(u.name)) errs.push(`duplicate upstream name "${u.name}"`);
    names.add(u.name);
    if (!['openai', 'anthropic'].includes(u.protocol)) errs.push(`upstream "${u.name}": protocol must be openai or anthropic`);
    try { new URL(u.baseUrl); } catch { errs.push(`upstream "${u.name}": baseUrl is not a valid URL`); }
  }
  if (!['passthrough', 'keys'].includes(c.auth.mode)) errs.push('auth.mode must be passthrough or keys');
  if (!['denylist', 'allowlist'].includes(c.policy.toolCalls.domains.mode)) errs.push('policy.toolCalls.domains.mode must be denylist or allowlist');
  if (errs.length) {
    const e = new Error('Invalid configuration:\n  - ' + errs.join('\n  - '));
    e.code = 'CONFIG_INVALID';
    throw e;
  }
}

/** Effective policy for a profile (profile.policy overlays the base policy). */
export function resolvePolicy(config, profileName) {
  const p = profileName && config.profiles?.[profileName];
  return p?.policy ? deepMerge(clone(config.policy), p.policy) : config.policy;
}

/** Config safe to show in the dashboard (no secrets). */
export function publicConfig(config) {
  const c = clone(config);
  if (c.server.adminToken) c.server.adminToken = '••••';
  for (const u of c.upstreams) {
    u.hasKey = Boolean(u.apiKey || (u.apiKeyEnv && process.env[u.apiKeyEnv]));
    delete u.apiKey;
  }
  if (c.network?.proxy) c.network.proxy = c.network.proxy.replace(/\/\/[^@/]*@/, '//••••@');
  return c;
}

export const SAMPLE_CONFIG = `# ${BRAND.name} — ${BRAND.tagline}
# Docs: README.md. Everything here is optional; defaults are shown.

server:
  host: 127.0.0.1          # use 0.0.0.0 to serve the whole network (set adminToken!)
  port: 8787
  adminToken: "__ADMIN_TOKEN__"   # dashboard + admin API + CLI

auth:
  mode: passthrough        # passthrough = callers send their own provider key
                           # keys        = callers use ${BRAND.name} keys ("${BRAND.cli} keys create")

# Where traffic goes. The model name picks the upstream (first match wins);
# "name/model" (e.g. local/llama3.1) forces an upstream explicitly.
upstreams:
  - name: openai
    protocol: openai                       # speaks /v1/chat/completions
    baseUrl: https://api.openai.com/v1
    apiKeyEnv: OPENAI_API_KEY              # optional: replace the caller's key with this one
    models: ["gpt-*", "o1*", "o3*", "o4*", "chatgpt-*"]
  - name: anthropic
    protocol: anthropic                    # speaks /v1/messages (Claude Code)
    baseUrl: https://api.anthropic.com/v1
    apiKeyEnv: ANTHROPIC_API_KEY
    models: ["claude-*"]
  # - name: local
  #   protocol: openai
  #   baseUrl: http://localhost:11434/v1   # Ollama, vLLM, LM Studio, LiteLLM, OpenRouter ...
  #   models: ["*"]

enterprise:
  name: ""
  emailDomains: []          # e.g. [acme.com]
  internalDomains: []       # e.g. [corp.acme.com, acme.lan]  -> hostnames always redacted
  confidentialTerms: []     # e.g. ["Project Falcon"]         -> always redacted

policy:
  redaction:
    enabled: true
    scopes: [tool_output]   # add "user" / "system" to scrub prompts too
  toolCalls:
    domains: { enabled: true, mode: denylist }   # allowlist = block every domain not explicitly allowed
    paths:
      enabled: true
      protected: []         # folders/files no tool call may touch, e.g. ["D:/Finance", "**/customer-data/**"]
      confineToWorkspace: false
    commands: { enabled: true }
  documents:
    enabled: true
    writeHarnessRule: true  # overwrite the tool call with one writing a "never open this" rule
    piiThreshold: 5
  codeScan:
    enabled: true
    engine: auto            # auto | semgrep | opengrep | builtin
    onUnresolved: block     # block | annotate | allow
  quality:
    enabled: true
    onUnresolved: annotate
  loop:
    maxIterations: 3

# Different rules for different teams: attach a profile to a key
# ("${BRAND.cli} keys create --name ci --profile strict").
profiles:
  strict:
    policy:
      toolCalls: { domains: { mode: allowlist } }
      codeScan: { minSeverity: info }
    rules:
      disable: []           # rule ids or prefixes ending with *
      enable: []

logging:
  capture: preview          # none | preview | full
  retentionDays: 30
`;
