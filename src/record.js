/**
 * record.js — Shared record-layer primitives for TLS 1.2 and TLS 1.3.
 *
 * Used by TLSSocket, DTLSSocket, and test harnesses.
 * Handles AEAD encryption/decryption, nonce construction, key derivation,
 * and raw record framing.
 */

import crypto from 'node:crypto';
import {
  TLS_CIPHER_SUITES,
  hkdf_expand_label,
  tls_derive_from_master_secret_tls12
} from './crypto.js';

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

/** TLS 1.3 nonce: IV XOR zero-padded 64-bit sequence number. */
function getNonce(iv, seq) {
  const seqBuf = new Uint8Array(12);
  const view = new DataView(seqBuf.buffer);
  view.setBigUint64(4, BigInt(seq));
  const nonce = new Uint8Array(12);
  for (let i = 0; i < 12; i++) nonce[i] = iv[i] ^ seqBuf[i];
  return nonce;
}

/**
 * Encrypt a TLS 1.3 record (TLSInnerPlaintext).
 * Returns ciphertext || tag (without record header).
 */
function encryptRecord(innerType, plaintext, key, nonce, algo) {
  const full = new Uint8Array(plaintext.length + 1);
  full.set(plaintext);
  full[plaintext.length] = innerType;

  const recLen = full.length + 16;
  const aad = new Uint8Array([0x17, 0x03, 0x03, (recLen >>> 8) & 0xff, recLen & 0xff]);

  if (!algo) algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  let isChaCha = algo === 'chacha20-poly1305';
  let cipher = crypto.createCipheriv(algo, key, nonce, isChaCha ? { authTagLength: 16 } : undefined);
  cipher.setAAD(aad, isChaCha ? { plaintextLength: full.length } : undefined);
  let ct = cipher.update(full);
  cipher.final();
  let tag = cipher.getAuthTag();

  let out = new Uint8Array(ct.length + tag.length);
  out.set(ct, 0);
  out.set(tag, ct.length);
  return out;
}

/**
 * Decrypt a TLS 1.3 record.
 * Input: raw ciphertext || tag (without record header).
 * Returns full TLSInnerPlaintext (content || content_type || padding).
 */
function decryptRecord(ciphertext, key, nonce, algo) {
  const aad = new Uint8Array(5);
  aad[0] = 0x17; aad[1] = 0x03; aad[2] = 0x03;
  aad[3] = (ciphertext.length >> 8) & 0xff;
  aad[4] = ciphertext.length & 0xff;

  let ct  = ciphertext.subarray(0, ciphertext.length - 16);
  let tag = ciphertext.subarray(ciphertext.length - 16);

  if (!algo) algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  let isChaCha = algo === 'chacha20-poly1305';
  let decipher = crypto.createDecipheriv(algo, key, nonce, isChaCha ? { authTagLength: 16 } : undefined);
  decipher.setAAD(aad, isChaCha ? { plaintextLength: ct.length } : undefined);
  decipher.setAuthTag(tag);
  let pt = decipher.update(ct);
  decipher.final();
  return new Uint8Array(pt);
}

/** Strip trailing zeros and extract content_type from TLSInnerPlaintext. */
function parseInnerPlaintext(data) {
  let j = data.length - 1;
  while (j >= 0 && data[j] === 0) j--;
  if (j < 0) throw new Error('Malformed TLSInnerPlaintext');
  return { type: data[j], content: data.slice(0, j) };
}

// ===================== TLS 1.2 primitives =====================

/** TLS 1.2 GCM nonce: fixed_salt(4) || explicit_nonce(8). */
function getNonce12(salt4, explicit8) {
  const out = new Uint8Array(12);
  out.set(salt4, 0);
  out.set(explicit8, 4);
  return out;
}

/** Encode sequence number as 8-byte big-endian. */
function seqToBytes(seq) {
  const buf = new Uint8Array(8);
  let bn = BigInt(seq);
  for (let i = 0; i < 8; i++) buf[7 - i] = Number((bn >> BigInt(8 * i)) & 0xffn);
  return buf;
}

/** TLS 1.2 AAD: seq(8) || type(1) || version(2) || length(2). */
function buildAad12(seqNum, recordType, plaintextLen) {
  const aad = new Uint8Array(13);
  aad.set(seqToBytes(seqNum), 0);
  aad[8]  = recordType & 0xff;
  aad[9]  = 0x03;
  aad[10] = 0x03;
  aad[11] = (plaintextLen >>> 8) & 0xff;
  aad[12] = plaintextLen & 0xff;
  return aad;
}

/** Encrypt a TLS 1.2 GCM record fragment. Returns explicit_nonce(8) || ciphertext || tag(16). */
function encrypt12(pt, key, salt4, seqNum, recordType) {
  let explicit = seqToBytes(seqNum);
  let nonce = getNonce12(salt4, explicit);
  let aad = buildAad12(seqNum, recordType, pt.length);

  let algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  let cipher = crypto.createCipheriv(algo, key, nonce);
  cipher.setAAD(aad);
  let ct = cipher.update(pt);
  cipher.final();
  let tag = cipher.getAuthTag();

  let out = new Uint8Array(8 + ct.length + tag.length);
  out.set(explicit, 0);
  out.set(ct, 8);
  out.set(tag, 8 + ct.length);
  return out;
}

/** Decrypt a TLS 1.2 GCM record fragment. Input: explicit_nonce(8) || ciphertext || tag(16). */
function decrypt12(fragment, key, salt4, seqNum, recordType) {
  if (fragment.length < 24) throw new Error('TLS 1.2 fragment too short');

  let explicit = fragment.slice(0, 8);
  let tag      = fragment.slice(fragment.length - 16);
  let ct       = fragment.slice(8, fragment.length - 16);

  let nonce = getNonce12(salt4, explicit);
  let aad = buildAad12(seqNum, recordType, ct.length);

  let algo = key.length === 16 ? 'aes-128-gcm' : 'aes-256-gcm';
  let decipher = crypto.createDecipheriv(algo, key, nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  let pt = decipher.update(ct);
  decipher.final();
  return new Uint8Array(pt);
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
const CT = { CHANGE_CIPHER_SPEC: 20, ALERT: 21, HANDSHAKE: 22, APPLICATION_DATA: 23 };

/** Write a raw TLS record to a writable stream. */
function writeRecord(transport, type, payload, version) {
  if (!transport || typeof transport.write !== 'function') return;
  let ver = version || 0x0303;
  let rec = Buffer.allocUnsafe(5 + payload.length);
  rec.writeUInt8(type, 0);
  rec.writeUInt16BE(ver, 1);
  rec.writeUInt16BE(payload.length, 3);
  Buffer.from(payload).copy(rec, 5);
  transport.write(rec);
}

// ===================== Exports =====================

export {
  // AEAD
  getAeadAlgo,

  // TLS 1.3
  deriveKeys,
  getNonce,
  encryptRecord,
  decryptRecord,
  parseInnerPlaintext,

  // TLS 1.2
  getNonce12,
  seqToBytes,
  buildAad12,
  encrypt12,
  decrypt12,
  deriveKeys12,

  // Record framing
  CT,
  writeRecord,
};
