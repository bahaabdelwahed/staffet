// Server-sent events: parse an upstream stream, format events for the client.

/**
 * @param {AsyncIterable<Uint8Array>} body
 * @yields {{event: string|null, data: string}}
 */
export async function* parseSSE(body) {
  const decoder = new TextDecoder();
  let buf = '';
  const flush = function* (block) {
    let event = null;
    const data = [];
    for (const line of block.split(/\r?\n/)) {
      if (!line || line.startsWith(':')) continue;
      const i = line.indexOf(':');
      const field = i < 0 ? line : line.slice(0, i);
      let value = i < 0 ? '' : line.slice(i + 1);
      if (value.startsWith(' ')) value = value.slice(1);
      if (field === 'event') event = value;
      else if (field === 'data') data.push(value);
    }
    if (data.length || event) yield { event, data: data.join('\n') };
  };
  for await (const chunk of body) {
    buf += decoder.decode(chunk, { stream: true });
    let m;
    while ((m = /\r?\n\r?\n/.exec(buf))) {
      const block = buf.slice(0, m.index);
      buf = buf.slice(m.index + m[0].length);
      yield* flush(block);
    }
  }
  buf += decoder.decode();
  if (buf.trim()) yield* flush(buf);
}

export const sseData = (obj) => `data: ${typeof obj === 'string' ? obj : JSON.stringify(obj)}\n\n`;
export const sseEvent = (event, obj) => `event: ${event}\ndata: ${JSON.stringify(obj)}\n\n`;

/** Split text into chunks so a re-streamed answer arrives progressively instead of as one giant frame. */
export function chunkText(text, size = 160) {
  const out = [];
  for (let i = 0; i < text.length; i += size) out.push(text.slice(i, i + size));
  return out;
}
