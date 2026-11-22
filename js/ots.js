// Minimal OpenTimestamps client: submit a hash to public calendars and
// build a standard .ots receipt that opentimestamps.org and the official
// `ots` tool can read, upgrade (to a Bitcoin proof) and verify.
//
// The file never leaves the browser. Calendars receive only a salted hash.
// Note: the .ots receipt itself contains the file's plain SHA-256 (that's
// how the format works), so whoever holds the receipt can match it to a copy.

import { sha256 } from './sha256.js';

export const CALENDARS = [
  'https://a.pool.opentimestamps.org',
  'https://b.pool.opentimestamps.org',
  'https://a.pool.eternitywall.com',
  'https://ots.btc.catallaxy.com',
];

export const MAGIC = new Uint8Array([
  0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
  0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
]); // "\0OpenTimestamps\0\0Proof\0" + 8 magic bytes
const VERSION = 1;
const OP_SHA256 = 0x08;
const OP_APPEND = 0xf0;
const OP_PREPEND = 0xf1;
const FORK = 0xff;
const ATTESTATION = 0x00;
// Unary ops defined by OpenTimestamps: sha1, ripemd160, sha256, keccak256, reverse, hexlify.
const UNARY_OPS = new Set([0x02, 0x03, 0x08, 0x67, 0xf2, 0xf3]);
const TAG_PENDING = '83dfe30d2ef90c8e';
const TAG_BITCOIN = '0588960d73d71901';

export const MAX_RECEIPT_BYTES = 1024 * 1024; // receipts are normally a few KB
export const MAX_CALENDAR_RESPONSE_BYTES = 64 * 1024;
const MAX_OP_ARG = 4096;
const MAX_ATTESTATION_PAYLOAD = 8192;
const MAX_DEPTH = 256;

export function varuint(n) {
  const out = [];
  do {
    let b = n & 0x7f;
    n = Math.floor(n / 128);
    if (n > 0) b |= 0x80;
    out.push(b);
  } while (n > 0);
  return out;
}

function concat(parts) {
  const len = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

// The message we send to calendars: sha256(fileDigest || nonce).
export function commitment(fileDigest, nonce) {
  return sha256(concat([fileDigest, nonce]));
}

// ---------- parsing ----------
//
// A timestamp is a tree. Each node holds attestations (proof endpoints) and
// operations, each leading to a child node. We parse strictly: anything
// malformed throws, so a broken calendar answer can never slip into a receipt.

class Reader {
  constructor(bytes, offset = 0) { this.b = bytes; this.o = offset; }
  byte() {
    if (this.o >= this.b.length) throw new Error('receipt is cut off');
    return this.b[this.o++];
  }
  bytes(n) {
    if (this.o + n > this.b.length) throw new Error('receipt is cut off');
    const out = this.b.slice(this.o, this.o + n);
    this.o += n;
    return out;
  }
  varuint() {
    let n = 0, shift = 0, b;
    do {
      b = this.byte();
      n += (b & 0x7f) * 2 ** shift;
      shift += 7;
      if (shift > 49) throw new Error('number too large');
    } while (b & 0x80);
    return n;
  }
  varbytes(max) {
    const n = this.varuint();
    if (n > max) throw new Error('field too large');
    return this.bytes(n);
  }
}

function newNode() { return { atts: new Map(), ops: new Map() }; }

function readItem(r, tag, node, depth) {
  if (tag === ATTESTATION) {
    const t = r.bytes(8);
    const payload = r.varbytes(MAX_ATTESTATION_PAYLOAD);
    const raw = concat([Uint8Array.of(ATTESTATION), t, Uint8Array.from(varuint(payload.length)), payload]);
    node.atts.set(hex(raw), { tag: hex(t), payload, raw });
    return;
  }
  let opBytes;
  if (tag === OP_APPEND || tag === OP_PREPEND) {
    const arg = r.varbytes(MAX_OP_ARG);
    if (arg.length === 0) throw new Error('empty append/prepend');
    opBytes = concat([Uint8Array.of(tag), Uint8Array.from(varuint(arg.length)), arg]);
  } else if (UNARY_OPS.has(tag)) {
    opBytes = Uint8Array.of(tag);
  } else {
    throw new Error('unknown operation 0x' + tag.toString(16));
  }
  const key = hex(opBytes);
  if (node.ops.has(key)) throw new Error('operation repeated');
  node.ops.set(key, { opBytes, child: parseNode(r, depth + 1) });
}

function parseNode(r, depth = 0) {
  if (depth > MAX_DEPTH) throw new Error('receipt nested too deep');
  const node = newNode();
  let tag = r.byte();
  while (tag === FORK) {
    readItem(r, r.byte(), node, depth);
    tag = r.byte();
  }
  readItem(r, tag, node, depth);
  return node;
}

// Parse a calendar's answer. Throws unless it is one complete, well-formed timestamp.
export function parseTimestamp(bytes) {
  const r = new Reader(bytes);
  const node = parseNode(r);
  if (r.o !== bytes.length) throw new Error('unexpected bytes after timestamp');
  return node;
}

// Merge b into a. Safe because both describe the same starting message.
export function mergeNodes(a, b) {
  for (const [k, v] of b.atts) a.atts.set(k, v);
  for (const [k, v] of b.ops) {
    if (a.ops.has(k)) mergeNodes(a.ops.get(k).child, v.child);
    else a.ops.set(k, v);
  }
  return a;
}

export function serializeNode(node) {
  const items = [
    ...[...node.atts.values()].map((a) => [a.raw]),
    ...[...node.ops.values()].map((o) => [o.opBytes, serializeNode(o.child)]),
  ];
  const parts = [];
  items.forEach((item, i) => {
    if (i < items.length - 1) parts.push(Uint8Array.of(FORK));
    parts.push(...item);
  });
  return concat(parts);
}

export function summarize(node, out = { pending: [], bitcoin: [], other: 0 }) {
  for (const a of node.atts.values()) {
    if (a.tag === TAG_PENDING) {
      out.pending.push(new TextDecoder().decode(new Reader(a.payload).varbytes(1000)));
    } else if (a.tag === TAG_BITCOIN) {
      out.bitcoin.push(new Reader(a.payload).varuint());
    } else {
      out.other++;
    }
  }
  for (const o of node.ops.values()) summarize(o.child, out);
  return out;
}

// ---------- building ----------

// Build a detached .ots file.
// calendarResponses: parsed timestamps (from parseTimestamp), each for commitment(fileDigest, nonce).
export function buildOts(fileDigest, nonce, calendarResponses) {
  if (fileDigest.length !== 32) throw new Error('need a 32-byte sha256 digest');
  if (!calendarResponses.length) throw new Error('need at least one calendar response');
  const merged = calendarResponses.reduce((acc, n) => mergeNodes(acc, n), newNode());
  return concat([
    MAGIC, Uint8Array.from(varuint(VERSION)), Uint8Array.of(OP_SHA256), fileDigest,
    // file digest --append(nonce)--> --sha256--> commitment, then the merged calendar proofs
    Uint8Array.of(OP_APPEND), Uint8Array.from(varuint(nonce.length)), nonce,
    Uint8Array.of(OP_SHA256),
    serializeNode(merged),
  ]);
}

// ---------- reading a receipt ----------

// Fully parse a .ots receipt. Returns the file digest and what proofs it holds.
// This checks the receipt is well formed. It does NOT check against Bitcoin;
// that needs block data (opentimestamps.org or the official client do it).
export function readOts(bytes) {
  if (bytes.length > MAX_RECEIPT_BYTES) throw new Error('file is too large to be a receipt');
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) throw new Error('not an OpenTimestamps receipt');
  }
  const r = new Reader(bytes, MAGIC.length);
  if (r.varuint() !== VERSION) throw new Error('unsupported receipt version');
  if (r.byte() !== OP_SHA256) throw new Error('receipt is not for a SHA-256 hash');
  const digest = r.bytes(32);
  const tree = parseNode(r);
  if (r.o !== bytes.length) throw new Error('unexpected bytes after the proof');
  return { digest, proofs: summarize(tree) };
}

// Kept for callers that only need the digest.
export function readOtsDigest(bytes) {
  return readOts(bytes).digest;
}

// ---------- network ----------

// Read a response body, refusing to hold more than `max` bytes.
export async function readCapped(response, max) {
  const len = Number(response.headers?.get?.('content-length'));
  if (len > max) throw new Error('response too large');
  if (!response.body?.getReader) {
    const buf = new Uint8Array(await response.arrayBuffer());
    if (buf.length > max) throw new Error('response too large');
    return buf;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > max) { reader.cancel(); throw new Error('response too large'); }
    chunks.push(value);
  }
  return concat(chunks);
}

export async function submitToCalendars(fileDigest, { calendars = CALENDARS, timeoutMs = 10000, fetchFn = fetch } = {}) {
  const nonce = crypto.getRandomValues(new Uint8Array(16));
  const msg = commitment(fileDigest, nonce);
  const results = await Promise.allSettled(calendars.map(async (url) => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const r = await fetchFn(url + '/digest', {
        method: 'POST',
        headers: { Accept: 'application/vnd.opentimestamps.v1' },
        body: msg,
        signal: ctrl.signal,
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      const node = parseTimestamp(await readCapped(r, MAX_CALENDAR_RESPONSE_BYTES));
      if (!summarize(node).pending.length && !summarize(node).bitcoin.length) {
        throw new Error('no usable proof in response');
      }
      return { url, node };
    } finally {
      clearTimeout(t);
    }
  }));
  const ok = results.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  const failed = calendars.filter((_, i) => results[i].status === 'rejected');
  if (!ok.length) throw new Error('No timestamp server gave a usable answer. Check your connection and try again.');
  return { ots: buildOts(fileDigest, nonce, ok.map((o) => o.node)), calendars: ok.map((o) => o.url), failed };
}
