/**
 * record.js — Record-layer primitives for TLS 1.2, TLS 1.3, DTLS 1.2, and DTLS 1.3.
 *
 * Used by TLSSocket, DTLSSession, DTLSSocket, and test harnesses.
 * Handles AEAD encryption/decryption, nonce construction, key derivation,
 * raw record framing, and DTLS-specific record number encryption.
 */

import crypto from 'node:crypto';
import {
  TLS_CIPHER_SUITES,
  hkdf_expand_label,
  tls_derive_from_master_secret_tls12
} from './crypto.js';
import {
  w_u8,
  w_u16,
  w_u48,
} from './wire.js';

// ===================== AEAD algorithm resolution =====================

/** Resolve node:crypto cipher name from a TLS cipher suite code. */
function getAeadAlgo(cipherSuite) {
  if (cipherSuite != null) {
    let info = TLS_CIPHER_SUITES[cipherSuite];
    if (info && info.cipher === 'CHACHA20_POLY1305') return 'chacha20-poly1305';
    if (info && info.keylen === 32) return 'aes-256-gcm';
  }
  return 'aes-128-gcm';
}

// ===================== TLS 1.3 primitives =====================

/** Derive write key + IV from a TLS 1.3 traffic secret. */
function deriveKeys(trafficSecret, cipherSuite) {
  const empty = new Uint8Array(0);
  let cs = TLS_CIPHER_SUITES[cipherSuite];
  return {
    key: hkdf_expand_label(cs.hash, trafficSecret, 'key', empty, cs.keylen),
    iv:  hkdf_expand_label(cs.hash, trafficSecret, 'iv',  empty, 12)
  };
}

/**
 * TLS 1.3 nonce: IV XOR zero-padded 64-bit sequence number.
 *
 * Perf-critical: called on every encrypted record. Uses Number arithmetic
 * (safe for seq < 2^53, vastly exceeds practical TLS limits) instead of BigInt,
 * which is ~20x slower in V8. Single allocation, unrolled XOR loop.
 */
function getNonce(iv, seq) {
  const nonce = new Uint8Array(12);
  // High 4 bytes of IV are XOR'd with zeros (seq top bits) — just copy
  nonce[0] = iv[0]; nonce[1] = iv[1]; nonce[2] = iv[2]; nonce[3] = iv[3];
  // Split seq into hi/lo 32-bit halves (seq < 2^53 is safe)
  const hi = (seq / 0x100000000) | 0;
  const lo = seq >>> 0;
  nonce[4]  = iv[4]  ^ ((hi >>> 24) & 0xff);
  nonce[5]  = iv[5]  ^ ((hi >>> 16) & 0xff);
  nonce[6]  = iv[6]  ^ ((hi >>> 8)  & 0xff);
  nonce[7]  = iv[7]  ^ ( hi         & 0xff);
  nonce[8]  = iv[8]  ^ ((lo >>> 24) & 0xff);
  nonce[9]  = iv[9]  ^ ((lo >>> 16) & 0xff);
  nonce[10] = iv[10] ^ ((lo >>> 8)  & 0xff);
  nonce[11] = iv[11] ^ ( lo         & 0xff);
  return nonce;
}

/**
 * Same as getNonce but writes into a provided output buffer instead of
 * allocating a fresh one. Returns the same buffer for chaining.
 *
 * Use this when you have a per-connection reusable nonce scratch buffer —
 * TLS processing is synchronous per connection, and Node's crypto.createCipheriv
 * copies the nonce into OpenSSL state, so we can safely reuse the same buffer
 * across records.
 *
 * Saves 12 bytes × records of allocations. For a 10MB transfer (640 records)
 * that's ~7.7KB of garbage eliminated.
 */
function getNonceInto(out, iv, seq) {
  out[0] = iv[0]; out[1] = iv[1]; out[2] = iv[2]; out[3] = iv[3];
  const hi = (seq / 0x100000000) | 0;
  const lo = seq >>> 0;
  out[4]  = iv[4]  ^ ((hi >>> 24) & 0xff);
  out[5]  = iv[5]  ^ ((hi >>> 16) & 0xff);
  out[6]  = iv[6]  ^ ((hi >>> 8)  & 0xff);
  out[7]  = iv[7]  ^ ( hi         & 0xff);
  out[8]  = iv[8]  ^ ((lo >>> 24) & 0xff);
  out[9]  = iv[9]  ^ ((lo >>> 16) & 0xff);
  out[10] = iv[10] ^ ((lo >>> 8)  & 0xff);
  out[11] = iv[11] ^ ( lo         & 0xff);
  return out;
}

/**
 * Encrypt a TLS 1.3 record (TLSInnerPlaintext = plaintext || inner_content_type).
 * Returns ciphertext || tag (without record header).
 *
 * Perf: uses two cipher.update() calls (plaintext, then 1-byte inner type) instead
 * of allocating and copying a +1-byte buffer. For 16KB records this saves ~16KB
 * of allocation and copy per encrypted record.
 */
function encryptRecord(innerType, plaintext, key, nonce, algo) {
  const ptLen = plaintext.length;
  const recLen = ptLen + 1 + 16; // plaintext + inner_type + tag
  const aad = new Uint8Array(5);
  aad[0] = 0x17; aad[1] = 0x03; aad[2] = 0x03;
  aad[3] = (recLen >>> 8) & 0xff;
  aad[4] = recLen & 0xff;

  if (!algo) algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const isChaCha = algo === 'chacha20-poly1305';
  const cipher = crypto.createCipheriv(algo, key, nonce, isChaCha ? { authTagLength: 16 } : undefined);
  cipher.setAAD(aad, isChaCha ? { plaintextLength: ptLen + 1 } : undefined);

  // Stream: plaintext first, then the 1-byte inner content type
  const ct1 = cipher.update(plaintext);
  // Reuse a single-byte scratch for inner type — tiny allocation, unavoidable
  const innerBuf = new Uint8Array(1);
  innerBuf[0] = innerType;
  const ct2 = cipher.update(innerBuf);
  cipher.final();
  const tag = cipher.getAuthTag();

  // AES-GCM and ChaCha20-Poly1305 are stream ciphers → ct1.length + ct2.length === ptLen + 1
  const out = new Uint8Array(ct1.length + ct2.length + tag.length);
  out.set(ct1, 0);
  if (ct2.length > 0) out.set(ct2, ct1.length);
  out.set(tag, ct1.length + ct2.length);
  return out;
}

// Pre-allocated single-byte buffers for inner content type. Avoids allocating a
// new 1-byte Uint8Array for every encrypted record (25 bytes × records adds up
// in garbage — 640 records for 10MB = 16KB of pointless allocations).
const _INNER_TYPE_BUFS = new Array(256);
for (let i = 0; i < 256; i++) {
  const b = new Uint8Array(1);
  b[0] = i;
  _INNER_TYPE_BUFS[i] = b;
}

/**
 * Encrypt a TLS 1.3 record directly into a complete TLS record buffer (5-byte
 * header + ciphertext + inner type + tag), ready to hand to transport.write().
 *
 * Single-allocation + single-update hot-path version — the biggest throughput
 * optimization we have for TLS 1.3 bulk data.
 *
 * Strategy:
 *   1. Allocate rec of the full final size upfront.
 *   2. Write record header (5 bytes) — also serves as AAD (TLS 1.3 AAD == header).
 *   3. Stage plaintext + inner_type byte into rec[5 .. 5+ptLen+1]. This is a
 *      16KB copy we pay for up front but it lets us call cipher.update ONCE
 *      with a single contiguous input.
 *   4. cipher.setAAD(rec.subarray(0, 5)) — view, no alloc.
 *   5. cipher.update(rec.subarray(5, 5+ptLen+1)) — one call, returns ct of
 *      same size (AES-GCM is a stream cipher). We then copy ct back into rec,
 *      overwriting the staged plaintext with ciphertext.
 *   6. Write the 16-byte auth tag at the end.
 *
 * Why single-update beats two updates (plaintext then [inner_type]):
 *   - Each cipher.update call crosses the JS↔C boundary (~1-3μs overhead).
 *     For 640 records per 10MB transfer, skipping one call per record saves
 *     ~0.6-2ms per transfer.
 *   - Avoids the small Buffer object wrapper Node creates for the 1-byte ct2.
 *
 * Why the extra plaintext→rec copy is cheap:
 *   - memcpy throughput is ~20GB/s → a 16KB copy is ~800ns.
 *   - For 640 records, total extra copy time is ~500μs, dominated by the
 *     2-4ms of cipher.update overhead we avoid.
 *
 * Net savings per record: ~1-2μs. Per 10MB transfer: ~1-2ms on encryption
 * hot path — meaningful on top of the ~25ms actual AES work.
 *
 * Note: outer record type for encrypted TLS 1.3 records is ALWAYS 0x17
 * (application_data) regardless of inner type — the real type is encrypted
 * in the inner byte.
 */
function encryptCompleteRecord13(innerType, plaintext, key, nonce, algo, version) {
  const ptLen = plaintext.length;
  const payloadLen = ptLen + 1 + 16; // inner_type + tag
  const ver = version || 0x0303;

  const rec = Buffer.allocUnsafe(5 + payloadLen);
  // Record header (also used as AAD)
  rec[0] = 0x17; // outer type always application_data for encrypted records
  rec[1] = (ver >>> 8) & 0xff;
  rec[2] = ver & 0xff;
  rec[3] = (payloadLen >>> 8) & 0xff;
  rec[4] = payloadLen & 0xff;

  // Stage plaintext + inner_type byte at rec[5 .. 5+ptLen+1].
  // cipher.update will read from this view, and we'll overwrite it with
  // ciphertext immediately after.
  if (plaintext.length > 0) {
    // Buffer.prototype.copy and Uint8Array.set both work; .set is faster for Uint8Array src.
    if (plaintext.copy) plaintext.copy(rec, 5);
    else rec.set(plaintext, 5);
  }
  rec[5 + ptLen] = innerType & 0xff;

  if (!algo) algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const isChaCha = algo === 'chacha20-poly1305';
  const cipher = crypto.createCipheriv(algo, key, nonce, isChaCha ? { authTagLength: 16 } : undefined);
  cipher.setAAD(rec.subarray(0, 5), isChaCha ? { plaintextLength: ptLen + 1 } : undefined);

  // Single update reading plaintext+innerType from rec, writing ciphertext
  // back into rec (overwriting the staged plaintext). ct.length === ptLen + 1.
  const ct = cipher.update(rec.subarray(5, 5 + ptLen + 1));
  ct.copy(rec, 5);

  cipher.final();
  cipher.getAuthTag().copy(rec, 5 + ct.length);

  return rec;
}

/**
 * Decrypt a TLS 1.3 record.
 * Input: raw ciphertext || tag (without record header).
 * Returns full TLSInnerPlaintext (content || content_type || padding).
 *
 * Perf: returns Node Buffer directly (which IS a Uint8Array subclass) — avoids
 * a redundant copy into a plain Uint8Array.
 */
function decryptRecord(ciphertext, key, nonce, algo) {
  const aad = new Uint8Array(5);
  aad[0] = 0x17; aad[1] = 0x03; aad[2] = 0x03;
  aad[3] = (ciphertext.length >> 8) & 0xff;
  aad[4] = ciphertext.length & 0xff;

  const ct  = ciphertext.subarray(0, ciphertext.length - 16);
  const tag = ciphertext.subarray(ciphertext.length - 16);

  if (!algo) algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const isChaCha = algo === 'chacha20-poly1305';
  const decipher = crypto.createDecipheriv(algo, key, nonce, isChaCha ? { authTagLength: 16 } : undefined);
  decipher.setAAD(aad, isChaCha ? { plaintextLength: ct.length } : undefined);
  decipher.setAuthTag(tag);
  const pt = decipher.update(ct);
  decipher.final();
  return pt;
}

/**
 * Decrypt a TLS 1.3 record using an AAD view taken directly from the record
 * buffer's header — no fresh AAD allocation. Use this when the caller has
 * access to the original record header bytes (e.g., parseRecordsAndDispatch
 * has the full readBuffer and knows the offset of the record).
 *
 * aadView must be the 5 bytes that precede `ciphertext` in the original record:
 *   [type, version_hi, version_lo, length_hi, length_lo]
 *
 * Saves a 5-byte allocation per decrypt. For 640 records in a 10MB transfer,
 * that's 3.2KB of avoided allocations — small on its own but part of the
 * ongoing effort to reduce per-record GC pressure.
 */
function decryptRecordWithAadView(aadView, ciphertext, key, nonce, algo) {
  const ct  = ciphertext.subarray(0, ciphertext.length - 16);
  const tag = ciphertext.subarray(ciphertext.length - 16);

  if (!algo) algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const isChaCha = algo === 'chacha20-poly1305';
  const decipher = crypto.createDecipheriv(algo, key, nonce, isChaCha ? { authTagLength: 16 } : undefined);
  decipher.setAAD(aadView, isChaCha ? { plaintextLength: ct.length } : undefined);
  decipher.setAuthTag(tag);
  const pt = decipher.update(ct);
  decipher.final();
  return pt;
}

/** Strip trailing zeros and extract content_type from TLSInnerPlaintext. */
/**
 * Strip trailing zeros and extract content_type from TLSInnerPlaintext.
 *
 * Perf: returns a `subarray` (zero-copy view) rather than `slice`. When `data` is
 * a Node Buffer these are equivalent, but being explicit makes the behaviour
 * uniform across Buffer / Uint8Array inputs and documents the intent.
 */
function parseInnerPlaintext(data) {
  let j = data.length - 1;
  while (j >= 0 && data[j] === 0) j--;
  if (j < 0) throw new Error('Malformed TLSInnerPlaintext');
  return { type: data[j], content: data.subarray(0, j) };
}

// ===================== TLS 1.2 primitives =====================

/** TLS 1.2 GCM nonce: fixed_salt(4) || explicit_nonce(8). */
function getNonce12(salt4, explicit8) {
  const out = new Uint8Array(12);
  out.set(salt4, 0);
  out.set(explicit8, 4);
  return out;
}

/**
 * Encode sequence number as 8-byte big-endian.
 * Perf: uses Number arithmetic (seq < 2^53 is always safe for TLS).
 */
function seqToBytes(seq) {
  const buf = new Uint8Array(8);
  const hi = (seq / 0x100000000) | 0;
  const lo = seq >>> 0;
  buf[0] = (hi >>> 24) & 0xff;
  buf[1] = (hi >>> 16) & 0xff;
  buf[2] = (hi >>> 8)  & 0xff;
  buf[3] =  hi         & 0xff;
  buf[4] = (lo >>> 24) & 0xff;
  buf[5] = (lo >>> 16) & 0xff;
  buf[6] = (lo >>> 8)  & 0xff;
  buf[7] =  lo         & 0xff;
  return buf;
}

/**
 * TLS 1.2 AAD: seq(8) || type(1) || version(2) || length(2).
 * Perf: inlines seqToBytes to avoid an extra allocation + copy.
 */
function buildAad12(seqNum, recordType, plaintextLen) {
  const aad = new Uint8Array(13);
  const hi = (seqNum / 0x100000000) | 0;
  const lo = seqNum >>> 0;
  aad[0] = (hi >>> 24) & 0xff;
  aad[1] = (hi >>> 16) & 0xff;
  aad[2] = (hi >>> 8)  & 0xff;
  aad[3] =  hi         & 0xff;
  aad[4] = (lo >>> 24) & 0xff;
  aad[5] = (lo >>> 16) & 0xff;
  aad[6] = (lo >>> 8)  & 0xff;
  aad[7] =  lo         & 0xff;
  aad[8]  = recordType & 0xff;
  aad[9]  = 0x03;
  aad[10] = 0x03;
  aad[11] = (plaintextLen >>> 8) & 0xff;
  aad[12] = plaintextLen & 0xff;
  return aad;
}

/**
 * Encrypt a TLS 1.2 GCM record fragment. Returns explicit_nonce(8) || ciphertext || tag(16).
 * Perf: computes seq-bytes once for both explicit nonce and AAD (was computed twice).
 */
function encrypt12(pt, key, salt4, seqNum, recordType) {
  // Shared big-endian seq encoding (used as both explicit_nonce and AAD[0..8])
  const hi = (seqNum / 0x100000000) | 0;
  const lo = seqNum >>> 0;

  // Nonce = salt4(4) || seq(8)
  const nonce = new Uint8Array(12);
  nonce[0] = salt4[0]; nonce[1] = salt4[1]; nonce[2] = salt4[2]; nonce[3] = salt4[3];
  nonce[4] = (hi >>> 24) & 0xff;
  nonce[5] = (hi >>> 16) & 0xff;
  nonce[6] = (hi >>> 8)  & 0xff;
  nonce[7] =  hi         & 0xff;
  nonce[8] = (lo >>> 24) & 0xff;
  nonce[9] = (lo >>> 16) & 0xff;
  nonce[10] = (lo >>> 8) & 0xff;
  nonce[11] =  lo        & 0xff;

  // AAD = seq(8) || type(1) || 03 03 || length(2)
  const aad = new Uint8Array(13);
  aad[0] = nonce[4]; aad[1] = nonce[5]; aad[2] = nonce[6]; aad[3] = nonce[7];
  aad[4] = nonce[8]; aad[5] = nonce[9]; aad[6] = nonce[10]; aad[7] = nonce[11];
  aad[8]  = recordType & 0xff;
  aad[9]  = 0x03;
  aad[10] = 0x03;
  aad[11] = (pt.length >>> 8) & 0xff;
  aad[12] = pt.length & 0xff;

  const algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const cipher = crypto.createCipheriv(algo, key, nonce);
  cipher.setAAD(aad);
  const ct = cipher.update(pt);
  cipher.final();
  const tag = cipher.getAuthTag();

  // Output: explicit_nonce(8) || ct || tag(16)
  const out = new Uint8Array(8 + ct.length + tag.length);
  // explicit_nonce = seq bytes (nonce[4..12])
  out[0] = nonce[4]; out[1] = nonce[5]; out[2] = nonce[6]; out[3] = nonce[7];
  out[4] = nonce[8]; out[5] = nonce[9]; out[6] = nonce[10]; out[7] = nonce[11];
  out.set(ct, 8);
  out.set(tag, 8 + ct.length);
  return out;
}

/**
 * Encrypt a TLS 1.2 GCM record directly into a complete TLS record buffer
 * (5-byte header + 8-byte explicit_iv + ciphertext + 16-byte tag).
 *
 * Same "single allocation, single bulk copy" principle as encryptCompleteRecord13,
 * but TLS 1.2 has extra complications:
 *   - AAD is NOT the record header (it's seq || type || version || length)
 *   - Record body has an 8-byte explicit_iv prefix before the ciphertext
 *
 * The seq bytes used in nonce are the SAME bytes written as explicit_iv —
 * so we write them once into rec[5..13] and reference them from there, and
 * we copy them into the nonce inline. Old flow needed a separate 'out' buffer
 * with explicit_iv || ct || tag plus an 8-byte out[0..7] copy; this eliminates
 * both of those.
 */
function encryptCompleteRecord12(pt, key, salt4, seqNum, recordType, version) {
  const ptLen = pt.length;
  // Record body: 8 explicit_iv + ptLen ciphertext + 16 tag
  const bodyLen = 8 + ptLen + 16;
  const ver = version || 0x0303;

  const rec = Buffer.allocUnsafe(5 + bodyLen);
  // Record header
  rec[0] = recordType & 0xff;
  rec[1] = (ver >>> 8) & 0xff;
  rec[2] = ver & 0xff;
  rec[3] = (bodyLen >>> 8) & 0xff;
  rec[4] = bodyLen & 0xff;

  // Write explicit_iv (= seq bytes) into rec[5..13]
  const hi = (seqNum / 0x100000000) | 0;
  const lo = seqNum >>> 0;
  rec[5]  = (hi >>> 24) & 0xff;
  rec[6]  = (hi >>> 16) & 0xff;
  rec[7]  = (hi >>> 8)  & 0xff;
  rec[8]  =  hi         & 0xff;
  rec[9]  = (lo >>> 24) & 0xff;
  rec[10] = (lo >>> 16) & 0xff;
  rec[11] = (lo >>> 8)  & 0xff;
  rec[12] =  lo         & 0xff;

  // Nonce = salt4(4) || seq(8) — use the seq bytes we just wrote
  const nonce = new Uint8Array(12);
  nonce[0] = salt4[0]; nonce[1] = salt4[1]; nonce[2] = salt4[2]; nonce[3] = salt4[3];
  nonce[4] = rec[5]; nonce[5] = rec[6]; nonce[6] = rec[7]; nonce[7] = rec[8];
  nonce[8] = rec[9]; nonce[9] = rec[10]; nonce[10] = rec[11]; nonce[11] = rec[12];

  // AAD = seq(8) || type(1) || 03 03 || plaintextLen(2)
  // Note: AAD uses the PLAINTEXT length, not the record body length.
  const aad = new Uint8Array(13);
  aad[0] = rec[5]; aad[1] = rec[6]; aad[2] = rec[7]; aad[3] = rec[8];
  aad[4] = rec[9]; aad[5] = rec[10]; aad[6] = rec[11]; aad[7] = rec[12];
  aad[8]  = recordType & 0xff;
  aad[9]  = 0x03;
  aad[10] = 0x03;
  aad[11] = (ptLen >>> 8) & 0xff;
  aad[12] = ptLen & 0xff;

  const algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const cipher = crypto.createCipheriv(algo, key, nonce);
  cipher.setAAD(aad);
  const ct = cipher.update(pt);
  cipher.final();

  // Copy ciphertext into rec[13 : 13+ptLen]
  ct.copy(rec, 13);
  // Copy tag into rec[13+ptLen : 13+ptLen+16]
  cipher.getAuthTag().copy(rec, 13 + ct.length);

  return rec;
}

/**
 * Decrypt a TLS 1.2 GCM record fragment. Input: explicit_nonce(8) || ciphertext || tag(16).
 * Perf: subarray (zero-copy views) instead of slice (copies); returns Node Buffer
 * (which IS a Uint8Array subclass) instead of re-copying to a plain Uint8Array.
 */
function decrypt12(fragment, key, salt4, seqNum, recordType) {
  if (fragment.length < 24) throw new Error('TLS 1.2 fragment too short');

  // Zero-copy views over the input
  const explicit = fragment.subarray(0, 8);
  const ct       = fragment.subarray(8, fragment.length - 16);
  const tag      = fragment.subarray(fragment.length - 16);

  // Nonce = salt4 || explicit
  const nonce = new Uint8Array(12);
  nonce[0] = salt4[0]; nonce[1] = salt4[1]; nonce[2] = salt4[2]; nonce[3] = salt4[3];
  nonce[4] = explicit[0]; nonce[5] = explicit[1]; nonce[6] = explicit[2]; nonce[7] = explicit[3];
  nonce[8] = explicit[4]; nonce[9] = explicit[5]; nonce[10] = explicit[6]; nonce[11] = explicit[7];

  // AAD = seq(8) || type(1) || 03 03 || ct.length(2)
  const aad = new Uint8Array(13);
  const hi = (seqNum / 0x100000000) | 0;
  const lo = seqNum >>> 0;
  aad[0] = (hi >>> 24) & 0xff;
  aad[1] = (hi >>> 16) & 0xff;
  aad[2] = (hi >>> 8)  & 0xff;
  aad[3] =  hi         & 0xff;
  aad[4] = (lo >>> 24) & 0xff;
  aad[5] = (lo >>> 16) & 0xff;
  aad[6] = (lo >>> 8)  & 0xff;
  aad[7] =  lo         & 0xff;
  aad[8]  = recordType & 0xff;
  aad[9]  = 0x03;
  aad[10] = 0x03;
  aad[11] = (ct.length >>> 8) & 0xff;
  aad[12] = ct.length & 0xff;

  const algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  const decipher = crypto.createDecipheriv(algo, key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const pt = decipher.update(ct);
  decipher.final();
  // Node Buffer extends Uint8Array, so callers that expect Uint8Array work unmodified.
  return pt;
}

// ===================== Shared: TLS 1.2 key_block =====================

/** Derive TLS 1.2 read/write keys from master_secret. Wraps crypto.js function. */
function deriveKeys12(masterSecret, localRandom, remoteRandom, cipherSuite, isServer) {
  if (isServer) {
    let d = tls_derive_from_master_secret_tls12(masterSecret, localRandom, remoteRandom, cipherSuite);
    return { readKey: d.client_key, readIv: d.client_iv, writeKey: d.server_key, writeIv: d.server_iv };
  } else {
    let d = tls_derive_from_master_secret_tls12(masterSecret, remoteRandom, localRandom, cipherSuite);
    return { readKey: d.server_key, readIv: d.server_iv, writeKey: d.client_key, writeIv: d.client_iv };
  }
}

// ===================== Record framing =====================

/** Content type constants. */
const CT = { CHANGE_CIPHER_SPEC: 20, ALERT: 21, HANDSHAKE: 22, APPLICATION_DATA: 23, ACK: 26 };

/**
 * Write a raw TLS record to a writable stream.
 *
 * Returns the transport's backpressure signal (true = ready for more, false = buffer
 * full, wait for 'drain'). Callers should propagate this through the TLS write chain
 * so user-level sock.write() can apply backpressure correctly.
 *
 * Perf: single-copy from payload into the allocated record buffer, using
 * typed-array `.set()` (fast native memcpy) instead of
 * `Buffer.from(payload).copy(rec, 5)` which allocates an intermediate Buffer
 * and does two copies. Also writes the 5-byte header with direct byte
 * assignments to avoid method call overhead.
 */
function writeRecord(transport, type, payload, version) {
  if (!transport || typeof transport.write !== 'function') return false;
  const ver = version || 0x0303;
  const plen = payload.length;
  const rec = Buffer.allocUnsafe(5 + plen);
  rec[0] = type;
  rec[1] = (ver >>> 8) & 0xff;
  rec[2] = ver & 0xff;
  rec[3] = (plen >>> 8) & 0xff;
  rec[4] = plen & 0xff;
  // Buffer extends Uint8Array → .set() copies in a single pass from any TypedArray/Buffer.
  rec.set(payload, 5);
  return transport.write(rec);
}

// ===================== DTLS binary helpers =====================
// w_u8, w_u16, w_u48 imported from wire.js
// readU16, readU48 return value only (no offset tracking), unlike wire.js r_u16 which returns [value, offset]

function readU16(buf, off) { return ((buf[off] << 8) | buf[off+1]) >>> 0; }
function readU48(buf, off) {
  let hi = ((buf[off] << 8) | buf[off+1]) >>> 0;
  let lo = ((buf[off+2] << 24) | (buf[off+3] << 16) | (buf[off+4] << 8) | buf[off+5]) >>> 0;
  return hi * 0x100000000 + lo;
}

/** AES-ECB encrypt a single 16-byte block (for DTLS 1.3 record number encryption). */
function aesEcbEncrypt(key, block) {
  let algo = key.length === 32 ? 'aes-256-ecb' : 'aes-128-ecb';
  let cipher = crypto.createCipheriv(algo, key, null);
  cipher.setAutoPadding(false);
  let out = cipher.update(block);
  cipher.final();
  return new Uint8Array(out);
}


// ===================== DTLS plaintext record (13-byte header) =====================
//
// Used for: DTLS 1.2 all records, DTLS 1.3 epoch 0 (cleartext handshake).
//
// struct {
//   ContentType type;           // 1 byte
//   ProtocolVersion version;    // 2 bytes (0xFEFD)
//   uint16 epoch;               // 2 bytes
//   uint48 sequence_number;     // 6 bytes
//   uint16 length;              // 2 bytes
//   opaque fragment[length];
// } DTLSPlaintext;

/** Build a plaintext DTLS record (classic 13-byte header). */
function buildDtlsPlaintext(type, epoch, seq, payload) {
  let out = new Uint8Array(13 + payload.length);
  let off = 0;
  off = w_u8(out, off, type);
  off = w_u16(out, off, 0xFEFD);
  off = w_u16(out, off, epoch);
  off = w_u48(out, off, seq);
  off = w_u16(out, off, payload.length);
  out.set(payload, off);
  return out;
}

/** Parse plaintext DTLS records from a datagram. Returns array of { type, version, epoch, seq, payload, total_length }. */
function parseDtlsPlaintext(data) {
  let records = [];
  let off = 0;
  while (off + 13 <= data.length) {
    let type    = data[off];
    let version = readU16(data, off + 1);
    let epoch   = readU16(data, off + 3);
    let seq     = readU48(data, off + 5);
    let length  = readU16(data, off + 11);
    if (off + 13 + length > data.length) break;
    let payload = data.slice(off + 13, off + 13 + length);
    records.push({ type, version, epoch, seq, payload, total_length: 13 + length });
    off += 13 + length;
  }
  return records;
}


// ===================== DTLS 1.2 encrypted records =====================

/** DTLS 1.2 AAD: epoch(2) + seq(6) + type(1) + version(2) + plaintext_length(2). */
function buildDtlsAad12(epoch, seq, type, plaintextLen) {
  let aad = new Uint8Array(13);
  let off = 0;
  off = w_u16(aad, off, epoch);
  off = w_u48(aad, off, seq);
  off = w_u8(aad, off, type);
  off = w_u16(aad, off, 0xFEFD);
  off = w_u16(aad, off, plaintextLen);
  return aad;
}

/** Encrypt DTLS 1.2 record payload. Returns: explicit_nonce(8) || ciphertext || tag(16). */
function encryptDtls12(pt, key, ivSalt, epoch, seq, type) {
  let explicit = seqToBytes(seq);
  let nonce = getNonce12(ivSalt, explicit);
  let aad = buildDtlsAad12(epoch, seq, type, pt.length);
  let algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  let cipher = crypto.createCipheriv(algo, key, nonce);
  cipher.setAAD(aad);
  let ct = cipher.update(pt);
  cipher.final();
  let tag = cipher.getAuthTag();
  let out = new Uint8Array(8 + ct.length + tag.length);
  out.set(explicit, 0);
  out.set(new Uint8Array(ct), 8);
  out.set(new Uint8Array(tag), 8 + ct.length);
  return out;
}

/** Decrypt DTLS 1.2 record fragment. Input: explicit_nonce(8) || ciphertext || tag(16). */
function decryptDtls12(fragment, key, ivSalt, epoch, seq, type) {
  if (fragment.length < 24) throw new Error('DTLS 1.2 fragment too short');
  let explicit = fragment.slice(0, 8);
  let tag = fragment.slice(fragment.length - 16);
  let ct = fragment.slice(8, fragment.length - 16);
  let nonce = getNonce12(ivSalt, explicit);
  let aad = buildDtlsAad12(epoch, seq, type, ct.length);
  let algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  let decipher = crypto.createDecipheriv(algo, key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  let pt = decipher.update(ct);
  decipher.final();
  return new Uint8Array(pt);
}

/** Build complete encrypted DTLS 1.2 record (header + encrypted payload). */
function buildEncryptedDtls12(type, epoch, seq, plaintext, keys) {
  let encrypted = encryptDtls12(plaintext, keys.key, keys.iv, epoch, seq, type);
  return buildDtlsPlaintext(type, epoch, seq, encrypted);
}


// ===================== DTLS 1.3 unified header =====================
//
// struct {
//   uint8 header_info;
//     bits 7-5: 001 (fixed)
//     bit 4:    connection_id present
//     bit 3:    sequence_number_length (0=1byte, 1=2bytes)
//     bit 2:    length_present
//     bits 1-0: epoch (low 2 bits)
//   [ConnectionID cid;]
//   uint8/uint16 record_number;  // 1 or 2 bytes
//   [uint16 length;]
//   opaque encrypted_record[];
// } DTLSCiphertext;

const UNIFIED_HDR_FIXED = 0x20;  // 001xxxxx

/** Build unified header info byte. */
function buildUnifiedHdr(epoch, seqLen2, hasLength, hasCid) {
  let b = UNIFIED_HDR_FIXED;
  if (hasCid)    b |= 0x10;
  if (seqLen2)   b |= 0x08;
  if (hasLength) b |= 0x04;
  b |= (epoch & 0x03);
  return b;
}

/** Parse unified header info byte. */
function parseUnifiedHdr(b) {
  return {
    hasCid:    !!(b & 0x10),
    seqLen2:   !!(b & 0x08),
    hasLength: !!(b & 0x04),
    epoch:      b & 0x03,
  };
}

/** Check if a byte is a DTLS 1.3 unified header (0x20..0x3F). */
function isUnifiedHdr(b) { return (b & 0xE0) === UNIFIED_HDR_FIXED; }


// ===================== DTLS 1.3 record number encryption =====================

/**
 * Encrypt/decrypt record number (XOR with AES-ECB mask — symmetric operation).
 * mask = AES-ECB(snKey, ciphertext[0..15])
 * result = rnBytes XOR mask[0..len-1]
 */
function maskRecordNumber(snKey, rnBytes, ciphertext) {
  let sample = new Uint8Array(16);
  sample.set(ciphertext.subarray(0, Math.min(16, ciphertext.length)), 0);
  let mask = aesEcbEncrypt(snKey, sample);
  let out = new Uint8Array(rnBytes.length);
  for (let i = 0; i < rnBytes.length; i++) out[i] = rnBytes[i] ^ mask[i];
  return out;
}


// ===================== DTLS 1.3 encrypted record build/decrypt =====================

/**
 * Build a DTLS 1.3 encrypted record (unified header).
 *
 * innerType: content type (22=handshake, 23=app_data, 26=ACK)
 * plaintext: content to encrypt
 * seq:       record sequence number
 * epoch:     low 2 bits (2=handshake, 3=application)
 * keys:      { key, iv, snKey, algo? }
 */
function buildEncryptedDtls13(innerType, plaintext, seq, epoch, keys) {
  let algo = keys.algo || (keys.key.length === 32 ? 'aes-256-gcm' : 'aes-128-gcm');
  let isChaCha = algo === 'chacha20-poly1305';

  // Unified header: 2-byte seq, with length, no CID
  let info = buildUnifiedHdr(epoch, true, true, false);

  // Plaintext record number
  let rn = new Uint8Array(2);
  rn[0] = (seq >>> 8) & 0xFF;
  rn[1] = seq & 0xFF;

  // Inner plaintext: content + content_type
  let inner = new Uint8Array(plaintext.length + 1);
  inner.set(plaintext, 0);
  inner[plaintext.length] = innerType;

  let encLen = inner.length + 16;

  // AAD = header with PLAINTEXT record number (before RN encryption)
  let aad = new Uint8Array(5);
  aad[0] = info;
  aad[1] = rn[0];
  aad[2] = rn[1];
  aad[3] = (encLen >>> 8) & 0xFF;
  aad[4] = encLen & 0xFF;

  // Nonce (reuse TLS 1.3 nonce construction)
  let nonce = getNonce(keys.iv, seq);

  // AEAD encrypt
  let cipher = crypto.createCipheriv(algo, keys.key, nonce,
    isChaCha ? { authTagLength: 16 } : undefined);
  cipher.setAAD(aad, isChaCha ? { plaintextLength: inner.length } : undefined);
  let ct = cipher.update(inner);
  cipher.final();
  let tag = cipher.getAuthTag();

  let ciphertext = new Uint8Array(ct.length + tag.length);
  ciphertext.set(new Uint8Array(ct), 0);
  ciphertext.set(new Uint8Array(tag), ct.length);

  // Encrypt record number
  let encRn = maskRecordNumber(keys.snKey, rn, ciphertext);

  // Assemble: info(1) + encrypted_rn(2) + length(2) + ciphertext
  let record = new Uint8Array(5 + ciphertext.length);
  record[0] = info;
  record[1] = encRn[0];
  record[2] = encRn[1];
  record[3] = (ciphertext.length >>> 8) & 0xFF;
  record[4] = ciphertext.length & 0xFF;
  record.set(ciphertext, 5);
  return record;
}

/**
 * Decrypt a DTLS 1.3 encrypted record.
 * data: full record bytes (starting with unified header byte)
 * keys: { key, iv, snKey, algo? }
 * Returns { epoch, seq, type, content } or null on failure.
 */
function decryptEncryptedDtls13(data, keys) {
  if (data.length < 1) return null;

  let hdr = parseUnifiedHdr(data[0]);
  let off = 1;

  if (hdr.hasCid) return null; // CID not supported yet

  let rnLen = hdr.seqLen2 ? 2 : 1;
  if (off + rnLen > data.length) return null;
  let encRn = data.slice(off, off + rnLen);
  off += rnLen;

  let ctLen;
  if (hdr.hasLength) {
    if (off + 2 > data.length) return null;
    ctLen = readU16(data, off);
    off += 2;
  } else {
    ctLen = data.length - off;
  }

  if (off + ctLen > data.length) return null;
  let ciphertext = data.slice(off, off + ctLen);

  // Decrypt record number
  let rn = maskRecordNumber(keys.snKey, encRn, ciphertext);
  let seq = hdr.seqLen2 ? ((rn[0] << 8) | rn[1]) : rn[0];

  // Rebuild AAD with plaintext RN
  let hdrLen = 1 + rnLen + (hdr.hasLength ? 2 : 0);
  let aad = new Uint8Array(hdrLen);
  aad[0] = data[0];
  for (let i = 0; i < rnLen; i++) aad[1 + i] = rn[i];
  if (hdr.hasLength) {
    aad[1 + rnLen]     = (ctLen >>> 8) & 0xFF;
    aad[1 + rnLen + 1] = ctLen & 0xFF;
  }

  let nonce = getNonce(keys.iv, seq);
  let algo = keys.algo || (keys.key.length === 32 ? 'aes-256-gcm' : 'aes-128-gcm');
  let isChaCha = algo === 'chacha20-poly1305';

  if (ciphertext.length < 16) return null;
  let ct = ciphertext.subarray(0, ciphertext.length - 16);
  let tag = ciphertext.subarray(ciphertext.length - 16);

  try {
    let decipher = crypto.createDecipheriv(algo, keys.key, nonce,
      isChaCha ? { authTagLength: 16 } : undefined);
    decipher.setAAD(aad, isChaCha ? { plaintextLength: ct.length } : undefined);
    decipher.setAuthTag(tag);
    let pt = decipher.update(ct);
    decipher.final();

    let inner = parseInnerPlaintext(new Uint8Array(pt));
    return {
      epoch: hdr.epoch,
      seq: seq,
      type: inner.type,
      content: inner.content,
      total_length: off + ctLen,
    };
  } catch (e) {
    return null;
  }
}


// ===================== DTLS datagram parsing =====================

/**
 * Parse a DTLS datagram containing one or more records.
 * Dispatches between plaintext (classic header) and encrypted (unified header).
 *
 * keysByEpoch: { [epoch]: { key, iv, snKey, algo } } — null for plaintext only.
 * Returns array of { type, epoch, seq, content, encrypted }.
 */
function parseDtlsDatagram(data, keysByEpoch) {
  let records = [];
  let off = 0;

  while (off < data.length) {
    let first = data[off];

    if (isUnifiedHdr(first)) {
      let hdr = parseUnifiedHdr(first);
      let keys = keysByEpoch ? keysByEpoch[hdr.epoch] : null;

      if (!keys) {
        // Can't decrypt — try to skip
        let rnLen = hdr.seqLen2 ? 2 : 1;
        let skip = 1 + rnLen;
        if (hdr.hasLength && off + skip + 2 <= data.length) {
          skip += 2 + readU16(data, off + skip);
        } else {
          skip = data.length - off;
        }
        off += skip;
        continue;
      }

      let result = decryptEncryptedDtls13(data.subarray(off), keys);
      if (result) {
        records.push({
          type: result.type,
          epoch: result.epoch,
          seq: result.seq,
          content: result.content,
          encrypted: true,
        });
        off += result.total_length;
      } else {
        break;
      }

    } else if (first <= 63) {
      // Classic DTLS record
      if (off + 13 > data.length) break;
      let type    = data[off];
      let epoch   = readU16(data, off + 3);
      let seq     = readU48(data, off + 5);
      let length  = readU16(data, off + 11);
      if (off + 13 + length > data.length) break;

      let payload = data.slice(off + 13, off + 13 + length);
      let encrypted = false;

      // DTLS 1.2: decrypt if epoch > 0 and keys available
      if (epoch > 0 && keysByEpoch && keysByEpoch[epoch]) {
        let keys = keysByEpoch[epoch];
        try {
          payload = decryptDtls12(payload, keys.key, keys.iv, epoch, seq, type);
          encrypted = true;
        } catch(e) {
          // Decryption failed — return raw
        }
      }

      records.push({
        type: type,
        epoch: epoch,
        seq: seq,
        content: payload,
        encrypted: encrypted,
      });
      off += 13 + length;
    } else {
      break;
    }
  }
  return records;
}


// ===================== DTLS 1.3 ACK (RFC 9147 §7) =====================
//
// struct {
//   RecordNumber record_numbers<0..2^16-1>;
// }
// struct {
//   uint16 epoch;
//   uint48 sequence_number;
// } RecordNumber;  // 8 bytes

/** Build ACK payload. acks: [{ epoch, seq }, ...] */
function buildDtlsAck(acks) {
  let bodyLen = acks.length * 8;
  let out = new Uint8Array(2 + bodyLen);
  let off = 0;
  off = w_u16(out, off, bodyLen);
  for (let i = 0; i < acks.length; i++) {
    off = w_u16(out, off, acks[i].epoch);
    off = w_u48(out, off, acks[i].seq);
  }
  return out;
}

/** Parse ACK payload. Returns [{ epoch, seq }, ...]. */
function parseDtlsAck(data) {
  let bodyLen = readU16(data, 0);
  let off = 2;
  let end = off + bodyLen;
  let acks = [];
  while (off + 8 <= end) {
    let epoch = readU16(data, off); off += 2;
    let seq   = readU48(data, off); off += 6;
    acks.push({ epoch, seq });
  }
  return acks;
}


// ===================== Exports =====================

export {
  // AEAD
  getAeadAlgo,

  // TLS 1.3
  deriveKeys,
  getNonce,
  getNonceInto, // write nonce into a caller-provided buffer (avoid alloc per record)
  encryptRecord,
  encryptCompleteRecord13, // fused encrypt + header → single allocation hot path
  decryptRecord,
  decryptRecordWithAadView, // decrypt using caller-provided header view as AAD (no alloc)
  parseInnerPlaintext,

  // TLS 1.2
  getNonce12,
  seqToBytes,
  buildAad12,
  encrypt12,
  encryptCompleteRecord12, // fused encrypt + header → single allocation hot path
  decrypt12,
  deriveKeys12,

  // Record framing
  CT,
  writeRecord,

  // DTLS helpers
  aesEcbEncrypt,
  isUnifiedHdr,

  // DTLS plaintext records
  buildDtlsPlaintext,
  parseDtlsPlaintext,

  // DTLS 1.2 encrypted records
  buildDtlsAad12,
  encryptDtls12,
  decryptDtls12,
  buildEncryptedDtls12,

  // DTLS 1.3 unified header
  buildUnifiedHdr,
  parseUnifiedHdr,
  maskRecordNumber,

  // DTLS 1.3 encrypted records
  buildEncryptedDtls13,
  decryptEncryptedDtls13,

  // DTLS datagram parsing
  parseDtlsDatagram,

  // DTLS 1.3 ACK
  buildDtlsAck,
  parseDtlsAck,
};
