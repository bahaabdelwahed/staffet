#!/usr/bin/env node
// Markdown scanner: md, markdown, mdx.
//   YAML / TOML front matter -> metadata      HTML comments -> comments
//   H1 / H2 headings         -> title         everything else -> body (banner lines are detected there)
import { makeScanner, decodeText, runCli, isMain } from './lib/common.mjs';

export const TYPE = 'markdown';
export const SCANNER = 'scan-markdown';
export const EXTENSIONS = ['md', 'markdown', 'mdx'];

const unquote = (v) => v.trim().replace(/^(['"])(.*)\1$/, '$2');

/** Minimal front-matter reader: scalars, inline lists and block lists. No YAML dependency on purpose. */
function parseFrontMatter(block, toml) {
  const out = [];
  let current = null;
  for (const raw of block.split(/\r?\n/)) {
    if (!raw.trim() || /^\s*#/.test(raw)) continue;
    const item = /^\s*-\s+(.*)$/.exec(raw);
    if (item && current) {
      current.value = current.value ? `${current.value}, ${unquote(item[1])}` : unquote(item[1]);
      continue;
    }
    const kv = toml ? /^\s*([A-Za-z_][\w.-]*)\s*=\s*(.*)$/.exec(raw) : /^\s*([A-Za-z_][\w .-]*?)\s*:\s*(.*)$/.exec(raw);
    if (!kv) continue;
    let value = kv[2].trim();
    if (/^\[.*\]$/.test(value)) value = value.slice(1, -1).split(',').map(unquote).join(', ');
    else value = unquote(value.replace(/\s+#.*$/, ''));
    current = { name: kv[1].trim(), value };
    out.push(current);
  }
  return out.filter((e) => e.value !== '');
}

export function extractFromMarkdown(text) {
  let rest = text.replace(/^﻿/, '');
  let metadata = [];

  const yaml = /^---[ \t]*\r?\n([\s\S]*?)\r?\n(?:---|\.\.\.)[ \t]*(?:\r?\n|$)/.exec(rest);
  const toml = !yaml && /^\+\+\+[ \t]*\r?\n([\s\S]*?)\r?\n\+\+\+[ \t]*(?:\r?\n|$)/.exec(rest);
  const fm = yaml || toml;
  if (fm) {
    metadata = parseFrontMatter(fm[1], Boolean(toml));
    rest = rest.slice(fm[0].length);
  }

  const comments = [];
  rest = rest.replace(/<!--([\s\S]*?)-->/g, (m, c) => {
    const t = c.trim();
    if (t) comments.push(t.slice(0, 2000));
    return '';
  });

  const title = [];
  const body = [];
  const lines = rest.split(/\r\n|\r|\n/);
  let inFence = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*(```|~~~)/.test(line)) {
      inFence = !inFence;
      body.push(line);
      continue;
    }
    if (!inFence) {
      const atx = /^\s{0,3}(#{1,2})\s+(.+?)\s*#*\s*$/.exec(line);
      if (atx) {
        title.push({ text: atx[2], where: `heading, line ${i + 1}` });
        continue;
      }
      const next = lines[i + 1];
      if (line.trim() && next != null && /^\s{0,3}(=+|-{2,})\s*$/.test(next) && !/^\s*[-*+]\s/.test(line)) {
        title.push({ text: line.trim(), where: `heading, line ${i + 1}` });
        i++; // skip the underline
        continue;
      }
    }
    body.push(line);
  }

  return { zones: { metadata, title, comments, body: body.join('\n') }, stats: { lines: lines.length } };
}

export const scan = makeScanner({
  type: TYPE,
  scanner: SCANNER,
  extract: (src) => extractFromMarkdown(decodeText(src.buffer)),
});

if (isMain(import.meta.url)) {
  runCli({ name: SCANNER, description: 'confidentiality scanner for Markdown documents', extensions: EXTENSIONS.join(', ') }, scan);
}
