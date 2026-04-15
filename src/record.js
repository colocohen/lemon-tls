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
const CT = { CHANGE_CIPHER_SPEC: 20, ALERT: 21, HANDSHAKE: 22, APPLICATION_DATA: 23, ACK: 26 };

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
