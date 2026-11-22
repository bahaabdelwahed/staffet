// Upstream providers: routing by model name, auth, outbound proxy support.
import { Agent, ProxyAgent, EnvHttpProxyAgent, fetch as undiciFetch } from 'undici';
import { wildcardToRegExp } from '../util.mjs';

const HOP_BY_HOP = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'accept-encoding', 'keep-alive', 'proxy-authorization', 'proxy-connection', 'upgrade', 'te', 'trailer', 'expect', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'forwarded']);
const PASS_RESPONSE = /^(?:content-type|retry-after|request-id|x-request-id|x-ratelimit-.*|anthropic-.*|openai-.*|x-should-retry|cf-ray)$/i;

export class Upstreams {
  constructor(config) {
    this.config = config;
    this.list = config.upstreams.map((u) => ({
      ...u,
      baseUrl: String(u.baseUrl).replace(/\/+$/, ''),
      patterns: (u.models?.length ? u.models : ['*']).map(wildcardToRegExp),
      key: u.apiKey || (u.apiKeyEnv ? process.env[u.apiKeyEnv] : '') || '',
    }));
    const t = config.network?.timeoutMs || 600000;
    const opts = { headersTimeout: t, bodyTimeout: t, connect: { timeout: 30000 } };
    const env = process.env;
    if (config.network?.proxy) this.dispatcher = new ProxyAgent({ uri: config.network.proxy, ...opts });
    else if (env.HTTPS_PROXY || env.https_proxy || env.HTTP_PROXY || env.http_proxy) this.dispatcher = new EnvHttpProxyAgent(opts);
    else this.dispatcher = new Agent(opts);
  }

  /**
   * Choose the upstream for a model. "name/model" forces an upstream; otherwise the first
   * upstream of the right protocol whose model patterns match, else the first of that protocol.
   * @returns {{upstream: object, model: string}|null}
   */
  pick(protocol, model = '') {
    const candidates = this.list.filter((u) => u.protocol === protocol);
    if (!candidates.length) return null;
    const slash = model.indexOf('/');
    if (slash > 0) {
      const forced = candidates.find((u) => u.name === model.slice(0, slash));
      if (forced) return { upstream: forced, model: model.slice(slash + 1) };
    }
    const match = candidates.find((u) => u.patterns.some((re) => re.test(model)));
    return { upstream: match || candidates[0], model };
  }

  byProtocol(protocol) {
    return this.list.filter((u) => u.protocol === protocol);
  }

  /** Headers to send upstream: the caller's own, minus hop-by-hop, with auth swapped when the upstream has a key. */
  headers(incoming, upstream, { requireKey = false } = {}) {
    const h = {};
    for (const [k, v] of Object.entries(incoming || {})) {
      const key = k.toLowerCase();
      if (HOP_BY_HOP.has(key) || key.startsWith('x-staffet-') || v == null) continue;
      h[key] = Array.isArray(v) ? v.join(', ') : String(v);
    }
    if (upstream.key) {
      if (upstream.protocol === 'anthropic') { h['x-api-key'] = upstream.key; delete h.authorization; }
      else { h.authorization = `Bearer ${upstream.key}`; delete h['x-api-key']; }
    } else if (requireKey) {
      const e = new Error(`upstream "${upstream.name}" has no API key configured (set ${upstream.apiKeyEnv || 'apiKey'})`);
      e.status = 500;
      throw e;
    }
    if (upstream.protocol === 'anthropic' && !h['anthropic-version']) h['anthropic-version'] = '2023-06-01';
    for (const [k, v] of Object.entries(upstream.headers || {})) h[k.toLowerCase()] = String(v);
    h['content-type'] ||= 'application/json';
    return h;
  }

  async fetch(upstream, suffix, { method = 'POST', headers, body, signal, search = '' } = {}) {
    return undiciFetch(`${upstream.baseUrl}${suffix}${search}`, { method, headers, body, signal, dispatcher: this.dispatcher });
  }

  /** Response headers worth relaying to the client (rate limits, request ids, content type). */
  static relayHeaders(res) {
    const out = {};
    for (const [k, v] of res.headers) if (PASS_RESPONSE.test(k)) out[k] = v;
    return out;
  }
}
