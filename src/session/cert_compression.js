/**
 * TLS Certificate Compression (RFC 8879), TLS 1.3 and DTLS 1.3.
 *
 * A certificate chain is most of what a server sends in its handshake —
 * 3-5 KB for a public CA's chain, against a few hundred bytes for the rest.
 * Compressed it is often half that or less: the certificates repeat names,
 * extensions and OIDs. Over QUIC it decides how many round trips the
 * handshake takes: before the client's address is validated a server may
 * send three times what it received (RFC 9000 §8.1), ~3.6 KB for a 1200-byte
 * Initial, and a chain that does not fit waits a round trip for the
 * client's next packet. Browsers offer it (Chrome: brotli; Firefox: zlib,
 * brotli, zstd).
 *
 * The client lists the algorithms it can decompress (compress_certificate,
 * extension 27); the server, holding one it can compress with, sends
 * CompressedCertificate (handshake type 25) in place of Certificate. The
 * same works the other way for a client certificate, when the server's
 * CertificateRequest carries the extension.
 */

import zlib from 'node:zlib';
import crypto from 'node:crypto';

function brotliOptions(b) {
  return { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11, [zlib.constants.BROTLI_PARAM_SIZE_HINT]: b.length } };
}

// RFC 8879 §3, and the IANA registry: zlib 1, brotli 2, zstd 3.
const ALGORITHMS = {
  1: { name: 'zlib',
       compress: (b) => zlib.deflateSync(b, { level: 9 }),
       compressAsync: (b, cb) => zlib.deflate(b, { level: 9 }, cb),
       decompress: (b, max) => zlib.inflateSync(b, { maxOutputLength: max }) },
  2: { name: 'brotli',
       compress: (b) => zlib.brotliCompressSync(b, brotliOptions(b)),
       compressAsync: (b, cb) => zlib.brotliCompress(b, brotliOptions(b), cb),
       decompress: (b, max) => zlib.brotliDecompressSync(b, { maxOutputLength: max }) },
};
// zstd where node:zlib has it (Node 22.15+, 23.8+).
if (typeof zlib.zstdCompressSync === 'function' && typeof zlib.zstdDecompressSync === 'function') {
  ALGORITHMS[3] = { name: 'zstd',
    compress: (b) => zlib.zstdCompressSync(b),
    compressAsync: (b, cb) => zlib.zstdCompress(b, cb),
    decompress: (b, max) => zlib.zstdDecompressSync(b, { maxOutputLength: max }) };
}

const BY_NAME = {};
for (const code in ALGORITHMS) BY_NAME[ALGORITHMS[code].name] = Number(code);

/** The algorithms this build can use, in its preference (best ratio first). */
function supported_cert_compression() {
  return [2, 3, 1].filter((c) => !!ALGORITHMS[c]);
}

/**
 * An option naming algorithms — ['brotli', 'zlib'], codes, or true (all) /
 * false (none) — as codes this build supports. Throws on a name it does not
 * know; one it knows but cannot run here (zstd on an older Node) is left out.
 */
function parse_cert_compression(value, what) {
  if (value === undefined || value === null) return null;
  if (value === false) return [];
  if (value === true) return supported_cert_compression();
  if (!Array.isArray(value)) throw new TypeError((what || 'certificateCompression') + ' must be an array of algorithms (brotli, zlib, zstd), true or false');
  const out = [];
  for (const v of value) {
    let code = typeof v === 'number' ? v : BY_NAME[String(v).toLowerCase()];
    if (code === undefined && String(v).toLowerCase() === 'zstd') continue;   // not in this Node
    if (code === undefined || (code !== 1 && code !== 2 && code !== 3)) throw new TypeError((what || 'certificateCompression') + ': unknown algorithm ' + JSON.stringify(v));
    if (ALGORITHMS[code] && out.indexOf(code) < 0) out.push(code);
  }
  return out;
}

// A chain is compressed once per algorithm: the server sends the same bytes
// on every handshake, and brotli at quality 11 is not cheap. Keyed by a hash
// of the uncompressed message; bounded.
const cache = new Map();
const CACHE_MAX = 64;

function cache_key(body, alg) {
  return alg + ':' + crypto.createHash('sha256').update(body).digest('hex');
}
function cache_put(key, out) {
  cache.set(key, out);
  if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
}

/** `body` (an encoded Certificate message body) compressed with `alg`. */
function compress_certificate_body(body, alg) {
  const a = ALGORITHMS[alg];
  if (!a) return null;
  const key = cache_key(body, alg);
  let out = cache.get(key);
  if (out) return out;
  out = new Uint8Array(a.compress(Buffer.from(body)));
  cache_put(key, out);
  return out;
}

// The same, ahead of the first handshake and off the event loop (zlib's
// thread pool): what that handshake would have done synchronously — brotli
// at quality 11 is 4 ms for a 400-byte chain and 18 ms for a 9 KB one, the
// first time a server sends it, while that client waits — is in the cache
// when it comes. A chain already there, or on its way, is not done twice.
// callback() when every algorithm's is in; a failure leaves that one to
// the handshake, as before.
const pending = new Map();   // key → callbacks waiting on it
function precompress_certificate_body(body, algs, callback) {
  let left = 1;
  const done = () => { if (--left === 0 && callback) callback(); };
  for (const alg of algs) {
    const a = ALGORITHMS[alg];
    if (!a || !a.compressAsync) continue;
    const key = cache_key(body, alg);
    if (cache.has(key)) continue;
    left++;
    if (pending.has(key)) { pending.get(key).push(done); continue; }
    pending.set(key, [done]);
    a.compressAsync(Buffer.from(body), (err, out) => {
      if (!err && !cache.has(key)) cache_put(key, new Uint8Array(out));
      const waiters = pending.get(key) || []; pending.delete(key);
      for (const w of waiters) w();
    });
  }
  done();
}

/**
 * A CompressedCertificate's contents back to the Certificate message body,
 * or null: an algorithm not ours, data that does not decompress, or a
 * length other than the one declared (RFC 8879 §4: bad_certificate). Never
 * more than the declared length is produced — nor more than `limit`.
 */
function decompress_certificate_body(alg, data, uncompressedLength, limit) {
  const a = ALGORITHMS[alg];
  if (!a) return null;
  if (!(uncompressedLength > 0) || (limit && uncompressedLength > limit)) return null;
  let out;
  try { out = a.decompress(Buffer.from(data), uncompressedLength); }
  catch (e) { return null; }
  if (out.length !== uncompressedLength) return null;
  return new Uint8Array(out);
}

function cert_compression_name(alg) {
  return ALGORITHMS[alg] ? ALGORITHMS[alg].name : String(alg);
}

export {
  supported_cert_compression,
  parse_cert_compression,
  compress_certificate_body,
  precompress_certificate_body,
  decompress_certificate_body,
  cert_compression_name,
};
