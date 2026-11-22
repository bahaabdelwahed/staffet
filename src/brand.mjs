// Single place to rename the product. Everything user-visible reads from here.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

let version = '0.0.0';
try {
  version = JSON.parse(readFileSync(path.join(PKG_ROOT, 'package.json'), 'utf8')).version;
} catch { /* running from an unusual layout */ }

export const BRAND = Object.freeze({
  name: 'Staffet',
  cli: 'staffet',
  tagline: 'LLM firewall proxy',
  version,
  /** Replacement written over every redacted value (per product spec). */
  redactionToken: '[CONFIDENTIAL_NEVER_ASK]',
  /** Prefix used for synthetic tool-call ids, rule files and headers. */
  slug: 'staffet',
  configFile: 'staffet.config.yaml',
});
