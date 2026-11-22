// Client API keys ("auth.mode: keys"): developers use a Staffet key, the provider key stays on the server.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { sha256 } from './util.mjs';

export class KeyStore {
  constructor(file) {
    this.file = file;
    this.keys = [];
    this.reload();
  }

  reload() {
    try {
      this.keys = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      this.mtime = fs.statSync(this.file).mtimeMs;
    } catch { this.keys = []; this.mtime = 0; }
  }

  /** Pick up keys created or revoked by another process (e.g. the CLI while the proxy runs). */
  _refresh() {
    try { if (fs.statSync(this.file).mtimeMs !== this.mtime) this.reload(); } catch { /* no key file yet */ }
  }

  _save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify(this.keys, null, 2));
    this.mtime = fs.statSync(this.file).mtimeMs;
  }

  /** Returns the plaintext key once; only its hash is stored. */
  create({ name, profile = '' }) {
    if (!name || !/^[\w .@-]{1,64}$/.test(name)) throw new Error('key name is required (letters, digits, space, . _ @ -)');
    const key = `rk_${randomBytes(24).toString('hex')}`;
    const hash = sha256(key);
    const rec = { id: hash.slice(0, 10), name, profile, hash, prefix: key.slice(0, 7), createdAt: Date.now(), lastUsedAt: null, revoked: false };
    this.keys.push(rec);
    this._save();
    return { key, record: publicKey(rec) };
  }

  list() { return this.keys.map(publicKey); }

  revoke(idOrName) {
    const rec = this.keys.find((k) => k.id === idOrName || k.name === idOrName);
    if (!rec) throw new Error(`no key "${idOrName}"`);
    rec.revoked = true;
    this._save();
    return publicKey(rec);
  }

  verify(token) {
    if (!token || !token.startsWith('rk_')) return null;
    this._refresh();
    const hash = Buffer.from(sha256(token));
    for (const k of this.keys) {
      if (k.revoked) continue;
      const other = Buffer.from(k.hash);
      if (other.length === hash.length && timingSafeEqual(other, hash)) {
        if (!k.lastUsedAt || Date.now() - k.lastUsedAt > 60_000) { k.lastUsedAt = Date.now(); try { this._save(); } catch { /* non fatal */ } }
        return publicKey(k);
      }
    }
    return null;
  }
}

function publicKey(k) {
  const { hash, ...rest } = k;
  return rest;
}
