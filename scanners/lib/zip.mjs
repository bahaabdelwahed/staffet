// Dependency-free ZIP reader (central directory + raw inflate).
// Used by the OOXML / ODF scanners. Read-only, bounded (zip-bomb guard), no CRC check.
import zlib from 'node:zlib';

export const ZIP_LIMITS = Object.freeze({
  maxEntryBytes: 50 * 1024 * 1024, // per-entry inflated size
  maxTotalBytes: 200 * 1024 * 1024, // total inflated across all reads of one archive
  maxEntries: 20000,
});

export class ZipError extends Error {
  constructor(message, code = 'EZIP') {
    super(message);
    this.name = 'ZipError';
    this.code = code;
  }
}

const SIG_EOCD = 0x06054b50;
const SIG_EOCD64_LOCATOR = 0x07064b50;
const SIG_EOCD64 = 0x06064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

/**
 * Parse a ZIP archive held in memory.
 * @param {Buffer|Uint8Array} input
 * @param {{maxEntryBytes?: number, maxTotalBytes?: number, maxEntries?: number}} [limits]
 * @returns {{names: string[], entries: Map<string, object>, has(name: string): boolean,
 *            read(name: string): Buffer, text(name: string): string|null, match(re: RegExp): string[]}}
 */
export function readZip(input, limits = {}) {
  const lim = { ...ZIP_LIMITS, ...limits };
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(input.buffer ?? input, input.byteOffset ?? 0, input.byteLength);
  if (buffer.length < 22) throw new ZipError('not a ZIP archive (too small)', 'ENOTZIP');

  // End-of-central-directory record: scan backwards (it may be followed by a comment).
  let eocd = -1;
  const lowest = Math.max(0, buffer.length - 22 - 0xffff);
  for (let i = buffer.length - 22; i >= lowest; i--) {
    if (buffer.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new ZipError('not a ZIP archive (no end-of-central-directory record)', 'ENOTZIP');

  let count = buffer.readUInt16LE(eocd + 10);
  let cdOffset = buffer.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdOffset === 0xffffffff) {
    const loc = eocd - 20;
    if (loc >= 0 && buffer.readUInt32LE(loc) === SIG_EOCD64_LOCATOR) {
      const off64 = Number(buffer.readBigUInt64LE(loc + 8));
      if (off64 >= 0 && off64 + 56 <= buffer.length && buffer.readUInt32LE(off64) === SIG_EOCD64) {
        count = Number(buffer.readBigUInt64LE(off64 + 32));
        cdOffset = Number(buffer.readBigUInt64LE(off64 + 48));
      }
    }
  }
  if (count > lim.maxEntries) throw new ZipError(`too many entries (${count})`, 'EBOMB');

  const entries = new Map();
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (p + 46 > buffer.length || buffer.readUInt32LE(p) !== SIG_CENTRAL) break;
    const flags = buffer.readUInt16LE(p + 8);
    const method = buffer.readUInt16LE(p + 10);
    let compressedSize = buffer.readUInt32LE(p + 20);
    let size = buffer.readUInt32LE(p + 24);
    const nameLen = buffer.readUInt16LE(p + 28);
    const extraLen = buffer.readUInt16LE(p + 30);
    const commentLen = buffer.readUInt16LE(p + 32);
    let localOffset = buffer.readUInt32LE(p + 42);
    const rawName = buffer.subarray(p + 46, p + 46 + nameLen);
    const name = (flags & 0x800 ? rawName.toString('utf8') : rawName.toString('latin1')).replace(/\\/g, '/');

    // ZIP64 extended information extra field
    if (size === 0xffffffff || compressedSize === 0xffffffff || localOffset === 0xffffffff) {
      let e = p + 46 + nameLen;
      const eEnd = e + extraLen;
      while (e + 4 <= eEnd) {
        const id = buffer.readUInt16LE(e);
        const len = buffer.readUInt16LE(e + 2);
        if (id === 0x0001) {
          let q = e + 4;
          if (size === 0xffffffff && q + 8 <= eEnd) { size = Number(buffer.readBigUInt64LE(q)); q += 8; }
          if (compressedSize === 0xffffffff && q + 8 <= eEnd) { compressedSize = Number(buffer.readBigUInt64LE(q)); q += 8; }
          if (localOffset === 0xffffffff && q + 8 <= eEnd) { localOffset = Number(buffer.readBigUInt64LE(q)); }
          break;
        }
        e += 4 + len;
      }
    }

    if (!name.endsWith('/')) {
      entries.set(name, { name, method, size, compressedSize, localOffset, encrypted: (flags & 0x1) !== 0 });
    }
    p += 46 + nameLen + extraLen + commentLen;
  }

  let totalInflated = 0;

  function read(name) {
    const entry = entries.get(name);
    if (!entry) throw new ZipError(`entry not found: ${name}`, 'ENOENT');
    if (entry.encrypted) throw new ZipError(`entry is encrypted: ${name}`, 'EENCRYPTED');
    if (entry.size > lim.maxEntryBytes) throw new ZipError(`entry too large: ${name} (${entry.size} bytes)`, 'EBOMB');
    const lo = entry.localOffset;
    if (lo + 30 > buffer.length || buffer.readUInt32LE(lo) !== SIG_LOCAL) {
      throw new ZipError(`corrupt local header for ${name}`, 'ECORRUPT');
    }
    const start = lo + 30 + buffer.readUInt16LE(lo + 26) + buffer.readUInt16LE(lo + 28);
    const end = start + entry.compressedSize;
    if (end > buffer.length) throw new ZipError(`truncated entry: ${name}`, 'ECORRUPT');
    const data = buffer.subarray(start, end);
    let out;
    if (entry.method === 0) {
      out = Buffer.from(data);
    } else if (entry.method === 8) {
      try {
        out = zlib.inflateRawSync(data, { maxOutputLength: lim.maxEntryBytes });
      } catch (err) {
        if (err && err.code === 'ERR_BUFFER_TOO_LARGE') throw new ZipError(`entry too large: ${name}`, 'EBOMB');
        throw new ZipError(`cannot inflate ${name}: ${err.message}`, 'ECORRUPT');
      }
    } else {
      throw new ZipError(`unsupported compression method ${entry.method} for ${name}`, 'EUNSUPPORTED');
    }
    totalInflated += out.length;
    if (totalInflated > lim.maxTotalBytes) throw new ZipError('archive inflates beyond the allowed total size', 'EBOMB');
    return out;
  }

  const names = [...entries.keys()];
  return {
    names,
    entries,
    has: (name) => entries.has(name),
    read,
    /** UTF-8 text of an entry, or null when the entry does not exist. */
    text(name) {
      if (!entries.has(name)) return null;
      const buf = read(name);
      if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return buf.subarray(2).toString('utf16le');
      const s = buf.toString('utf8');
      return s.charCodeAt(0) === 0xfeff ? s.slice(1) : s;
    },
    /** Entry names matching a regex, in natural (numeric-aware) order. */
    match(re) {
      return names
        .filter((n) => re.test(n))
        .sort((a, b) => a.localeCompare(b, 'en', { numeric: true }));
    },
  };
}
