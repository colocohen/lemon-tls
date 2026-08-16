import {
  concatUint8Arrays
} from './utils.js';

import crypto from 'node:crypto';


// ============================================================
//  Cipher suite registry
// ============================================================

const TLS_CIPHER_SUITES = {
  // ----------------------
  // TLS 1.3 (RFC 8446)
  // ----------------------
  0x1301: { // TLS_AES_128_GCM_SHA256
    name: 'TLS_AES_128_GCM_SHA256', standardName: 'TLS_AES_128_GCM_SHA256',
    tls:    13,
    kex:    'TLS13',
    sig:    'TLS13',
    cipher: 'AES_128_GCM',
    aead:   true,
    keylen: 16,
    ivlen:  12,
    hash:   'sha256'
  },
  0x1302: { // TLS_AES_256_GCM_SHA384
    name: 'TLS_AES_256_GCM_SHA384', standardName: 'TLS_AES_256_GCM_SHA384',
    tls:    13,
    kex:    'TLS13',
    sig:    'TLS13',
    cipher: 'AES_256_GCM',
    aead:   true,
    keylen: 32,
    ivlen:  12,
    hash:   'sha384'
  },
  0x1303: { // TLS_CHACHA20_POLY1305_SHA256
    name: 'TLS_CHACHA20_POLY1305_SHA256', standardName: 'TLS_CHACHA20_POLY1305_SHA256',
    tls:    13,
    kex:    'TLS13',
    sig:    'TLS13',
    cipher: 'CHACHA20_POLY1305',
    aead:   true,
    keylen: 32,
    ivlen:  12,
    hash:   'sha256'
  },

  // ----------------------
  // TLS 1.2 AEAD (GCM / CHACHA20)
  // ----------------------
  0xC02F: { // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    name: 'ECDHE-RSA-AES128-GCM-SHA256', standardName: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    tls:          12,
    kex:          'ECDHE_RSA',
    sig:          'RSA',
    cipher:       'AES_128_GCM',
    aead:         true,
    keylen:       16,
    fixed_ivlen:  4,
    record_ivlen: 8,
    ivlen:        12,
    hash:         'sha256'
  },
  0xC030: { // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    name: 'ECDHE-RSA-AES256-GCM-SHA384', standardName: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    tls:          12,
    kex:          'ECDHE_RSA',
    sig:          'RSA',
    cipher:       'AES_256_GCM',
    aead:         true,
    keylen:       32,
    fixed_ivlen:  4,
    record_ivlen: 8,
    ivlen:        12,
    hash:         'sha384'
  },
  0xC02B: { // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    name: 'ECDHE-ECDSA-AES128-GCM-SHA256', standardName: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    tls:          12,
    kex:          'ECDHE_ECDSA',
    sig:          'ECDSA',
    cipher:       'AES_128_GCM',
    aead:         true,
    keylen:       16,
    fixed_ivlen:  4,
    record_ivlen: 8,
    ivlen:        12,
    hash:         'sha256'
  },
  0xC02C: { // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    name: 'ECDHE-ECDSA-AES256-GCM-SHA384', standardName: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    tls:          12,
    kex:          'ECDHE_ECDSA',
    sig:          'ECDSA',
    cipher:       'AES_256_GCM',
    aead:         true,
    keylen:       32,
    fixed_ivlen:  4,
    record_ivlen: 8,
    ivlen:        12,
    hash:         'sha384'
  },
  0xCCA8: { // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    name: 'ECDHE-RSA-CHACHA20-POLY1305', standardName: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    tls:          12,
    kex:          'ECDHE_RSA',
    sig:          'RSA',
    cipher:       'CHACHA20_POLY1305',
    aead:         true,
    keylen:       32,
    fixed_ivlen:  12,
    record_ivlen: 0,
    ivlen:        12,
    hash:         'sha256'
  },
  0xCCA9: { // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    name: 'ECDHE-ECDSA-CHACHA20-POLY1305', standardName: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    tls:          12,
    kex:          'ECDHE_ECDSA',
    sig:          'ECDSA',
    cipher:       'CHACHA20_POLY1305',
    aead:         true,
    keylen:       32,
    fixed_ivlen:  12,
    record_ivlen: 0,
    ivlen:        12,
    hash:         'sha256'
  },
  0xCCAA: { // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    name: 'DHE-RSA-CHACHA20-POLY1305', standardName: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    tls:          12,
    kex:          'DHE_RSA',
    sig:          'RSA',
    cipher:       'CHACHA20_POLY1305',
    aead:         true,
    keylen:       32,
    fixed_ivlen:  12,  // RFC 7905: ChaCha20 uses a full 12-byte IV, no explicit nonce
    record_ivlen: 0,
    ivlen:        12,
    hash:         'sha256'
  },
  0x009C: { // TLS_RSA_WITH_AES_128_GCM_SHA256
    name: 'AES128-GCM-SHA256', standardName: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    tls:          12,
    kex:          'RSA',
    sig:          'RSA',
    cipher:       'AES_128_GCM',
    aead:         true,
    keylen:       16,
    fixed_ivlen:  4,
    record_ivlen: 8,
    ivlen:        12,
    hash:         'sha256'
  },
  0x009D: { // TLS_RSA_WITH_AES_256_GCM_SHA384
    name: 'AES256-GCM-SHA384', standardName: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    tls:          12,
    kex:          'RSA',
    sig:          'RSA',
    cipher:       'AES_256_GCM',
    aead:         true,
    keylen:       32,
    fixed_ivlen:  4,
    record_ivlen: 8,
    ivlen:        12,
    hash:         'sha384'
  },

  // ----------------------
  // TLS 1.2 CBC (Legacy)
  // ----------------------
  0xC013: { // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    name: 'ECDHE-RSA-AES128-SHA', standardName: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    tls:    12,
    kex:    'ECDHE_RSA',
    sig:    'RSA',
    cipher: 'AES_128_CBC',
    aead:   false,
    keylen: 16,
    ivlen:  16,
    mac:    'sha1',
    maclen: 20,
    hash:   'sha256'
  },
  0xC014: { // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    name: 'ECDHE-RSA-AES256-SHA', standardName: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    tls:    12,
    kex:    'ECDHE_RSA',
    sig:    'RSA',
    cipher: 'AES_256_CBC',
    aead:   false,
    keylen: 32,
    ivlen:  16,
    mac:    'sha1',
    maclen: 20,
    hash:   'sha256'
  },
  0x003C: { // TLS_RSA_WITH_AES_128_CBC_SHA256
    name: 'AES128-SHA256', standardName: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
    tls:    12,
    kex:    'RSA',
    sig:    'RSA',
    cipher: 'AES_128_CBC',
    aead:   false,
    keylen: 16,
    ivlen:  16,
    mac:    'sha256',
    maclen: 32,
    hash:   'sha256'
  },
  0x003D: { // TLS_RSA_WITH_AES_256_CBC_SHA256
    name: 'AES256-SHA256', standardName: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
    tls:    12,
    kex:    'RSA',
    sig:    'RSA',
    cipher: 'AES_256_CBC',
    aead:   false,
    keylen: 32,
    ivlen:  16,
    mac:    'sha256',
    maclen: 32,
    hash:   'sha256'
  }
};


// ============================================================
//  Hash helpers
//  Drop-in for noble: callable as hashFn(data) with .outputLen
// ============================================================

function makeHashFn(algorithm, outputLen) {
  let fn = function (data) {
    return new Uint8Array(crypto.createHash(algorithm).update(data).digest());
  };
  fn.outputLen = outputLen;
  return fn;
}

let sha256 = makeHashFn('sha256', 32);
let sha384 = makeHashFn('sha384', 48);

function getHashFn(hashName) {
  if (hashName === 'sha256') return sha256;
  if (hashName === 'sha384') return sha384;
  throw new Error('Unsupported hash: ' + hashName);
}

function getHashLen(hashName) {
  return getHashFn(hashName).outputLen | 0;
}


// ============================================================
//  HMAC
// ============================================================

function hmac(hashName, keyU8, dataU8) {
  return new Uint8Array(
    crypto.createHmac(hashName, keyU8).update(dataU8).digest()
  );
}


// ============================================================
//  HKDF Extract / Expand (RFC 5869)
// ============================================================

function hkdf_extract(hashName, saltU8, ikmU8) {
  // RFC 5869 section 2.2: if salt not provided, set to HashLen zeros
  let hashLen = getHashLen(hashName);
  let salt = (saltU8.length === 0) ? Buffer.alloc(hashLen) : saltU8;
  return new Uint8Array(
    crypto.createHmac(hashName, salt).update(ikmU8).digest()
  );
}

function hkdf_expand(hashName, prkU8, infoU8, length) {
  let hashLen = getHashLen(hashName);
  let N = Math.ceil(length / hashLen);
  // allocUnsafe is safe here: every byte is overwritten by prev.copy() below.
  let output = Buffer.allocUnsafe(N * hashLen);
  let prev = Buffer.alloc(0);
  let counter = Buffer.allocUnsafe(1);

  for (let i = 1; i <= N; i++) {
    let h = crypto.createHmac(hashName, prkU8);
    h.update(prev);
    h.update(infoU8);
    counter[0] = i;
    h.update(counter);
    prev = h.digest();
    prev.copy(output, (i - 1) * hashLen);
  }

  return new Uint8Array(output.buffer, output.byteOffset, length);
}


// ============================================================
//  TLS 1.3 HKDF-Expand-Label (RFC 8446 section 7.1)
// ============================================================

// Module-level TextEncoder — creating one per hkdf call added significant overhead
// to handshakes (TextEncoder construction is not free in V8).
const _TEXT_ENCODER = new TextEncoder();

// Label prefixes (RFC 8446 §7.1 / RFC 9147 §5.9). Exported so transports pick
// one explicitly instead of spelling the string out at each derivation site.
const LABEL_PREFIX_TLS13  = 'tls13 ';   // trailing space is part of the label
const LABEL_PREFIX_DTLS13 = 'dtls13';   // no trailing space — deliberate

/**
 * RFC 8446 §7.1 HkdfLabel, with the protocol's label prefix.
 *
 * TLS 1.3 uses "tls13 " (trailing space). DTLS 1.3 uses "dtls13" with NO
 * trailing space — RFC 9147 §5.9: "For DTLS 1.3, that label SHALL be
 * 'dtls13'. This ensures key separation between DTLS 1.3 and TLS 1.3. Note
 * that there is no trailing space; this is necessary in order to keep the
 * overall label size inside of one hash iteration."
 *
 * The prefix is threaded as a parameter rather than read from module state
 * because it is a property of ONE session's key schedule; two sessions of
 * different protocols can be live in the same process.
 */
function build_hkdf_label(label, context, length, labelPrefix) {
  const full = _TEXT_ENCODER.encode((labelPrefix || LABEL_PREFIX_TLS13) + label);
  const info = new Uint8Array(2 + 1 + full.length + 1 + context.length);

  info[0] = (length >>> 8) & 0xff;
  info[1] = (length      ) & 0xff;
  info[2] = full.length;
  info.set(full, 3);

  let ofs = 3 + full.length;
  info[ofs] = context.length;
  info.set(context, ofs + 1);

  return info;
}

function hkdf_expand_label(hashName, secret, label, context, length, labelPrefix) {
  let info = build_hkdf_label(label, context, length | 0, labelPrefix);
  return hkdf_expand(hashName, secret, info, length | 0);
}


// ============================================================
//  TLS 1.3: derive handshake traffic secrets
// ============================================================

function derive_handshake_traffic_secrets(hashName, shared_secret, transcript, labelPrefix) {
  let hashFn  = getHashFn(hashName);
  let hashLen = hashFn.outputLen | 0;
  const empty = new Uint8Array(0);
  const zeros = new Uint8Array(hashLen);

  let early_secret = hkdf_extract(hashName, empty, zeros);
  let h_empty = hashFn(empty);
  let derived_secret = hkdf_expand_label(hashName, early_secret, 'derived', h_empty, hashLen, labelPrefix);
  let handshake_secret = hkdf_extract(hashName, derived_secret, shared_secret);
  let transcript_hash = hashFn(transcript);
  let client_handshake_traffic_secret = hkdf_expand_label(hashName, handshake_secret, 'c hs traffic', transcript_hash, hashLen, labelPrefix);
  let server_handshake_traffic_secret = hkdf_expand_label(hashName, handshake_secret, 's hs traffic', transcript_hash, hashLen, labelPrefix);

  return {
    handshake_secret: handshake_secret,
    client_handshake_traffic_secret: client_handshake_traffic_secret,
    server_handshake_traffic_secret: server_handshake_traffic_secret,
  };
}

/**
 * Like derive_handshake_traffic_secrets but accepts a pre-computed transcript
 * hash — skips the hashFn(transcript) step and its allocation. Use this when
 * the caller has already computed the hash via an incremental running hash.
 */
function derive_handshake_traffic_secrets_with_hash(hashName, shared_secret, transcript_hash, labelPrefix) {
  let hashFn  = getHashFn(hashName);
  let hashLen = hashFn.outputLen | 0;
  const empty = new Uint8Array(0);
  const zeros = new Uint8Array(hashLen);

  let early_secret = hkdf_extract(hashName, empty, zeros);
  let h_empty = hashFn(empty);
  let derived_secret = hkdf_expand_label(hashName, early_secret, 'derived', h_empty, hashLen, labelPrefix);
  let handshake_secret = hkdf_extract(hashName, derived_secret, shared_secret);
  let client_handshake_traffic_secret = hkdf_expand_label(hashName, handshake_secret, 'c hs traffic', transcript_hash, hashLen, labelPrefix);
  let server_handshake_traffic_secret = hkdf_expand_label(hashName, handshake_secret, 's hs traffic', transcript_hash, hashLen, labelPrefix);

  return {
    handshake_secret: handshake_secret,
    client_handshake_traffic_secret: client_handshake_traffic_secret,
    server_handshake_traffic_secret: server_handshake_traffic_secret,
  };
}


// ============================================================
//  TLS 1.3: derive application traffic secrets
// ============================================================

function derive_app_traffic_secrets(hashName, handshake_secret, transcript, labelPrefix) {
  let hashFn  = getHashFn(hashName);
  let hashLen = hashFn.outputLen | 0;
  const empty = new Uint8Array(0);
  const zeros = new Uint8Array(hashLen);

  let h_empty = hashFn(empty);
  let derived_secret = hkdf_expand_label(hashName, handshake_secret, 'derived', h_empty, hashLen, labelPrefix);
  let master_secret = hkdf_extract(hashName, derived_secret, zeros);
  let transcript_hash = hashFn(transcript);
  let client_app_traffic_secret = hkdf_expand_label(hashName, master_secret, 'c ap traffic', transcript_hash, hashLen, labelPrefix);
  let server_app_traffic_secret = hkdf_expand_label(hashName, master_secret, 's ap traffic', transcript_hash, hashLen, labelPrefix);

  return {
    client_app_traffic_secret: client_app_traffic_secret,
    server_app_traffic_secret: server_app_traffic_secret,
    master_secret: master_secret
  };
}

/**
 * Like derive_app_traffic_secrets but accepts a pre-computed transcript hash.
 */
function derive_app_traffic_secrets_with_hash(hashName, handshake_secret, transcript_hash, labelPrefix) {
  let hashFn  = getHashFn(hashName);
  let hashLen = hashFn.outputLen | 0;
  const empty = new Uint8Array(0);
  const zeros = new Uint8Array(hashLen);

  let h_empty = hashFn(empty);
  let derived_secret = hkdf_expand_label(hashName, handshake_secret, 'derived', h_empty, hashLen, labelPrefix);
  let master_secret = hkdf_extract(hashName, derived_secret, zeros);
  let client_app_traffic_secret = hkdf_expand_label(hashName, master_secret, 'c ap traffic', transcript_hash, hashLen, labelPrefix);
  let server_app_traffic_secret = hkdf_expand_label(hashName, master_secret, 's ap traffic', transcript_hash, hashLen, labelPrefix);

  return {
    client_app_traffic_secret: client_app_traffic_secret,
    server_app_traffic_secret: server_app_traffic_secret,
    master_secret: master_secret
  };
}


// ============================================================
//  TLS 1.3: resumption master secret (RFC 8446 §7.1)
// ============================================================

/**
 * Derive the resumption_master_secret from the master_secret.
 * transcript = all handshake messages including both Finished.
 */
function derive_resumption_master_secret(hashName, master_secret, transcript, labelPrefix) {
  let hashFn = getHashFn(hashName);
  let hashLen = hashFn.outputLen | 0;
  let transcript_hash = hashFn(transcript);
  return hkdf_expand_label(hashName, master_secret, 'res master', transcript_hash, hashLen, labelPrefix);
}

/**
 * Like derive_resumption_master_secret but accepts a pre-computed transcript hash.
 */
function derive_resumption_master_secret_with_hash(hashName, master_secret, transcript_hash, labelPrefix) {
  let hashLen = getHashLen(hashName);
  return hkdf_expand_label(hashName, master_secret, 'res master', transcript_hash, hashLen, labelPrefix);
}

/**
 * Derive PSK from a resumption_master_secret + ticket_nonce.
 * Used by the server when creating a ticket, and by the client when resuming.
 */
function derive_psk(hashName, resumption_master_secret, ticket_nonce, labelPrefix) {
  let hashLen = getHashFn(hashName).outputLen | 0;
  return hkdf_expand_label(hashName, resumption_master_secret, 'resumption', ticket_nonce, hashLen, labelPrefix);
}

/**
 * Derive the binder_key for PSK binders in ClientHello.
 * For resumption PSK, label is "res binder".
 * For external PSK, label is "ext binder".
 */
function derive_binder_key(hashName, psk, isExternal, labelPrefix) {
  let hashFn = getHashFn(hashName);
  let hashLen = hashFn.outputLen | 0;
  const empty = new Uint8Array(0);
  const zeros = new Uint8Array(hashLen);

  let early_secret = hkdf_extract(hashName, empty, psk);
  let h_empty = hashFn(empty);
  let label = isExternal ? 'ext binder' : 'res binder';
  return hkdf_expand_label(hashName, early_secret, label, h_empty, hashLen, labelPrefix);
}

/**
 * Compute a PSK binder value.
 * binder_key = derive_binder_key(...)
 * transcript = ClientHello up to (but not including) the binders list.
 *
 * Per RFC 8446 §4.1.4: "PskBinderEntry is computed in the same way as the Finished
 * message (Section 4.4.4) but with the BaseKey being the binder_key derived via
 * the key schedule from the corresponding PSK."
 *
 * So we must derive a finished_key from binder_key (as in get_handshake_finished)
 * before the HMAC, NOT use binder_key directly.
 */
function compute_psk_binder(hashName, binder_key, truncated_transcript, labelPrefix) {
  let hashFn = getHashFn(hashName);
  let hashLen = hashFn.outputLen | 0;
  const empty = new Uint8Array(0);
  let finished_key = hkdf_expand_label(hashName, binder_key, 'finished', empty, hashLen, labelPrefix);
  let transcript_hash = hashFn(truncated_transcript);
  return hmac(hashName, finished_key, transcript_hash);
}

/**
 * Derive handshake secrets for a PSK-based handshake (with ECDHE).
 * Uses the PSK as input to early_secret instead of zeros.
 */
function derive_handshake_traffic_secrets_psk(hashName, psk, shared_secret, transcript, labelPrefix) {
  let hashFn = getHashFn(hashName);
  let hashLen = hashFn.outputLen | 0;
  const empty = new Uint8Array(0);

  let early_secret = hkdf_extract(hashName, empty, psk);
  let h_empty = hashFn(empty);
  let derived_secret = hkdf_expand_label(hashName, early_secret, 'derived', h_empty, hashLen, labelPrefix);
  let handshake_secret = hkdf_extract(hashName, derived_secret, shared_secret);
  let transcript_hash = hashFn(transcript);
  let client_handshake_traffic_secret = hkdf_expand_label(hashName, handshake_secret, 'c hs traffic', transcript_hash, hashLen, labelPrefix);
  let server_handshake_traffic_secret = hkdf_expand_label(hashName, handshake_secret, 's hs traffic', transcript_hash, hashLen, labelPrefix);

  return {
    handshake_secret: handshake_secret,
    client_handshake_traffic_secret: client_handshake_traffic_secret,
    server_handshake_traffic_secret: server_handshake_traffic_secret,
  };
}

/**
 * Like derive_handshake_traffic_secrets_psk but accepts a pre-computed transcript hash.
 */
function derive_handshake_traffic_secrets_psk_with_hash(hashName, psk, shared_secret, transcript_hash, labelPrefix) {
  let hashFn = getHashFn(hashName);
  let hashLen = hashFn.outputLen | 0;
  const empty = new Uint8Array(0);

  let early_secret = hkdf_extract(hashName, empty, psk);
  let h_empty = hashFn(empty);
  let derived_secret = hkdf_expand_label(hashName, early_secret, 'derived', h_empty, hashLen, labelPrefix);
  let handshake_secret = hkdf_extract(hashName, derived_secret, shared_secret);
  let client_handshake_traffic_secret = hkdf_expand_label(hashName, handshake_secret, 'c hs traffic', transcript_hash, hashLen, labelPrefix);
  let server_handshake_traffic_secret = hkdf_expand_label(hashName, handshake_secret, 's hs traffic', transcript_hash, hashLen, labelPrefix);

  return {
    handshake_secret: handshake_secret,
    client_handshake_traffic_secret: client_handshake_traffic_secret,
    server_handshake_traffic_secret: server_handshake_traffic_secret,
  };
}


// ============================================================
//  TLS 1.2 PRF (RFC 5246 section 5)
// ============================================================

function tls12_prf(secret, labelStr, seed, outLen, hashName) {
  let label = new TextEncoder().encode(labelStr);
  let fullSeed = concatUint8Arrays([label, seed]);

  let a = fullSeed;
  let out = new Uint8Array(0);

  while (out.length < outLen) {
    a = hmac(hashName, secret, a);
    let block = hmac(hashName, secret, concatUint8Arrays([a, fullSeed]));
    const tmp = new Uint8Array(out.length + block.length);
    tmp.set(out, 0);
    tmp.set(block, out.length);
    out = tmp;
  }

  return out.slice(0, outLen);
}


// ============================================================
//  TLS 1.2: key_block from master_secret
// ============================================================

function tls_derive_from_master_secret_tls12(master_secret, server_random, client_random, cipher_suite) {
  let p = TLS_CIPHER_SUITES[cipher_suite];
  if (!p || p.tls !== 12) throw new Error('cipher suite not TLS 1.2 or not mapped');

  let hashName = p.hash;
  let macLen       = p.aead ? 0 : (p.maclen || 0);
  let ivFromKbLen  = p.aead ? (p.fixed_ivlen || 0) : 0;
  let need = (2 * macLen) + (2 * p.keylen) + (2 * ivFromKbLen);

  let key_block = tls12_prf(
    master_secret,
    "key expansion",
    concatUint8Arrays([server_random, client_random]),
    need,
    hashName
  );

  let off = 0;
  let c_mac = null, s_mac = null;

  if (!p.aead && macLen > 0) {
    c_mac = key_block.slice(off, off + macLen); off += macLen;
    s_mac = key_block.slice(off, off + macLen); off += macLen;
  }

  let c_key = key_block.slice(off, off + p.keylen); off += p.keylen;
  let s_key = key_block.slice(off, off + p.keylen); off += p.keylen;

  let c_iv_salt = ivFromKbLen ? key_block.slice(off, off + ivFromKbLen) : null; off += ivFromKbLen;
  let s_iv_salt = ivFromKbLen ? key_block.slice(off, off + ivFromKbLen) : null; off += ivFromKbLen;

  return {
    client_mac: c_mac,
    server_mac: s_mac,
    client_key: c_key,
    server_key: s_key,
    client_iv: c_iv_salt,
    server_iv: s_iv_salt,
    aead:        !!p.aead,
    cipher:      p.cipher,
    prf_hash:    hashName,
    key_len:     p.keylen,
    fixed_ivlen: ivFromKbLen,
    record_ivlen: p.aead ? (p.record_ivlen || 0) : 16
  };
}


// ============================================================
//  TLS 1.3 CertificateVerify — to-be-signed construction
// ============================================================

function build_cert_verify_tbs(hashName, isServer, transcript) {
  let label = new TextEncoder().encode(
    isServer ? "TLS 1.3, server CertificateVerify" : "TLS 1.3, client CertificateVerify"
  );
  const separator = new Uint8Array([0x00]);
  const padding = new Uint8Array(64).fill(0x20);
  let transcript_hash = getHashFn(hashName)(transcript);

  return concatUint8Arrays([padding, label, separator, transcript_hash]);
}

/**
 * Like build_cert_verify_tbs but accepts a pre-computed transcript hash.
 */
function build_cert_verify_tbs_with_hash(hashName, isServer, transcript_hash) {
  let label = new TextEncoder().encode(
    isServer ? "TLS 1.3, server CertificateVerify" : "TLS 1.3, client CertificateVerify"
  );
  const separator = new Uint8Array([0x00]);
  const padding = new Uint8Array(64).fill(0x20);
  return concatUint8Arrays([padding, label, separator, transcript_hash]);
}


// ============================================================
//  TLS 1.3 Finished verify_data
// ============================================================

function get_handshake_finished(hashName, traffic_secret, transcript, labelPrefix) {
  let hashLen = getHashLen(hashName);
  const empty = new Uint8Array(0);
  let finished_key = hkdf_expand_label(hashName, traffic_secret, 'finished', empty, hashLen, labelPrefix);
  let transcript_hash = getHashFn(hashName)(transcript);
  return hmac(hashName, finished_key, transcript_hash);
}

/**
 * Like get_handshake_finished but accepts a pre-computed transcript hash.
 */
function get_handshake_finished_with_hash(hashName, traffic_secret, transcript_hash, labelPrefix) {
  let hashLen = getHashLen(hashName);
  const empty = new Uint8Array(0);
  let finished_key = hkdf_expand_label(hashName, traffic_secret, 'finished', empty, hashLen, labelPrefix);
  return hmac(hashName, finished_key, transcript_hash);
}


// ============================================================
//  DTLS 1.3: record number encryption key (RFC 9147 §5.9)
// ============================================================



// ============================================================
//  Keying-material exporters (RFC 5705 / RFC 8446 §7.5)
// ============================================================

/**
 * TLS 1.3: derive the exporter_master_secret (RFC 8446 §7.1).
 *
 *   exporter_master_secret = Derive-Secret(Master Secret, "exp master",
 *                                          ClientHello...server Finished)
 *
 * Called at the same point (and with the same transcript hash) as the
 * application traffic secrets.
 */
function derive_exporter_master_secret_with_hash(hashName, master_secret, transcript_hash, labelPrefix) {
  let hashLen = getHashLen(hashName);
  return hkdf_expand_label(hashName, master_secret, 'exp master', transcript_hash, hashLen, labelPrefix);
}

/**
 * TLS 1.3 exporter (RFC 8446 §7.5) — two-stage derivation:
 *
 *   TLS-Exporter(label, context_value, key_length) =
 *     HKDF-Expand-Label(
 *       Derive-Secret(exporter_master_secret, label, ""),
 *       "exporter", Hash(context_value), key_length)
 *
 * Note the FIRST stage uses Hash("") as its context (Derive-Secret over an
 * empty transcript), and only the SECOND stage hashes the caller's context.
 * A single-stage HKDF-Expand-Label(secret, label, ...) is NOT conformant
 * and will not interoperate with OpenSSL/BoringSSL exporters.
 *
 * @param {string}      hashName                 'sha256' | 'sha384'
 * @param {Uint8Array}  exporter_master_secret
 * @param {string}      label
 * @param {Uint8Array|null} context_value        null/undefined ≡ empty (per RFC 8446)
 * @param {number}      length
 * @returns {Uint8Array}
 */
function tls13_exporter(hashName, exporter_master_secret, label, context_value, length, labelPrefix) {
  let hashFn  = getHashFn(hashName);
  let hashLen = getHashLen(hashName);
  let h_empty = hashFn(new Uint8Array(0));
  let derived = hkdf_expand_label(hashName, exporter_master_secret, label, h_empty, hashLen, labelPrefix);
  let h_ctx   = hashFn(context_value || new Uint8Array(0));
  // BOTH expansions carry the prefix. RFC 8446 §7.5 defines the exporter
  // as two HKDF-Expand-Label steps, and in DTLS 1.3 both use "dtls13"
  // (RFC 9147 §5.9) — this second one was omitting it and falling back
  // to "tls13 ", so the exported key differed from a conforming peer's.
  // For WebRTC that key IS the DTLS-SRTP keying material: the handshake
  // completes, SRTP reports ready, packets flow in both directions, and
  // NOTHING decrypts. Two peers running this library derive the same
  // wrong key and interoperate perfectly with each other, which is why
  // it only appears against Chrome — and appears as "media does not
  // flow" rather than as a crypto error, since a failed unprotect is
  // just a dropped packet.
  return hkdf_expand(hashName, derived,
    build_hkdf_label('exporter', h_ctx, length, labelPrefix), length);
}

/**
 * TLS 1.2 exporter (RFC 5705).
 *
 *   If no context:   PRF(master_secret, label, client_random + server_random)
 *   With context:    PRF(master_secret, label,
 *                        client_random + server_random +
 *                        uint16(len(context)) + context)
 *
 * "No context" and "empty context" produce DIFFERENT output in TLS 1.2
 * (unlike 1.3) — pass context_value === null/undefined for the no-context
 * form. DTLS-SRTP (RFC 5764) uses the no-context form with label
 * 'EXTRACTOR-dtls_srtp'.
 *
 * The PRF hash follows the negotiated cipher suite (RFC 5246 §5 /
 * RFC 5289): SHA-256 for *_SHA256 suites, SHA-384 for *_SHA384 suites.
 *
 * @param {string}      hashName        cipher suite's PRF hash
 * @param {Uint8Array}  master_secret
 * @param {string}      label
 * @param {Uint8Array}  client_random   32 bytes
 * @param {Uint8Array}  server_random   32 bytes
 * @param {Uint8Array|null} context_value
 * @param {number}      length
 * @returns {Uint8Array}
 */
function tls12_exporter(hashName, master_secret, label, client_random, server_random, context_value, length) {
  let seedLen = 64 + (context_value != null ? 2 + context_value.length : 0);
  let seed = new Uint8Array(seedLen);
  seed.set(client_random, 0);
  seed.set(server_random, 32);
  if (context_value != null) {
    seed[64] = (context_value.length >>> 8) & 0xFF;
    seed[65] =  context_value.length        & 0xFF;
    seed.set(context_value, 66);
  }
  return tls12_prf(master_secret, label, seed, length, hashName);
}

function derive_sn_key(hashName, traffic_secret, cipher_suite, labelPrefix) {
  let keylen = TLS_CIPHER_SUITES[cipher_suite].keylen;
  return hkdf_expand_label(hashName, traffic_secret, 'sn', new Uint8Array(0), keylen, labelPrefix);
}


// ============================================================
//  Exports — identical API surface
// ============================================================

/**
 * Default cipher-suite offers, in preference order.
 *
 * SINGLE SOURCE OF TRUTH, alongside the TLS_CIPHER_SUITES table this module
 * already owns — the same rule as ecdh.js/SUPPORTED_GROUPS and
 * signing.js/default_signature_schemes. Previously TLSSocket, DTLSSession and
 * the TLSSession client default each carried their own hardcoded list, and
 * they had already drifted (one offered ChaCha20 for 1.2, another offered
 * AES-256-ECDSA instead).
 */
const DEFAULT_CIPHER_SUITES_TLS13 = [
  0x1301, // TLS_AES_128_GCM_SHA256
  0x1302, // TLS_AES_256_GCM_SHA384
  0x1303, // TLS_CHACHA20_POLY1305_SHA256
];

const DEFAULT_CIPHER_SUITES_TLS12 = [
  0xC02F, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
  0xC030, // ECDHE_RSA_WITH_AES_256_GCM_SHA384
  0xC02B, // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  0xC02C, // ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  0xCCA8, // ECDHE_RSA_WITH_CHACHA20_POLY1305
  0xCCA9, // ECDHE_ECDSA_WITH_CHACHA20_POLY1305
];

/** Default offer list for a version range. */
/**
 * Can the record layer actually protect traffic with this cipher suite?
 *
 * TLS_CIPHER_SUITES describes suites the code can NAME — including CBC ones
 * kept for parsing peer offers and for reporting — but record.js implements
 * AEAD only. A suite that is merely described is not a capability: selecting
 * one produces a handshake that agrees on parameters and then cannot encrypt a
 * single record.
 *
 * This mirrors ecdh.js's is_supported_group, and exists for the same reason: a
 * configured list is not an implementation. Selection asks this, never the
 * table's mere presence.
 */
function is_usable_cipher_suite(id) {
  let m = TLS_CIPHER_SUITES[id];
  return !!(m && m.aead === true);
}

/**
 * May this cipher suite be used with this negotiated version?
 *
 * RFC 8446 §B.4 defines 0x1301..0x1303 for TLS 1.3 ONLY; they are not valid
 * TLS 1.2 suites and a 1.2 peer must ignore them. The converse holds too — an
 * ECDHE_RSA_WITH_AES_128_GCM suite has no meaning in a 1.3 handshake, where
 * key exchange and authentication are negotiated separately from the AEAD.
 *
 * The suite table already records which version each entry belongs to (`tls`:
 * 12 or 13); this makes selection ask. Without it a server whose configured
 * list happened to contain a 1.3 suite would select it while negotiating 1.2,
 * producing a ServerHello no 1.2 client can act on.
 */
function suite_matches_version(id, negotiatedVersion) {
  let m = TLS_CIPHER_SUITES[id];
  if (!m) return false;
  if (negotiatedVersion === null || negotiatedVersion === undefined) return true;
  let is13 = negotiatedVersion === 0x0304 || negotiatedVersion === 0xFEFC;
  return is13 ? (m.tls === 13) : (m.tls === 12);
}

function default_cipher_suites(includeTls13, includeTls12) {
  let out = [];
  if (includeTls13) out = out.concat(DEFAULT_CIPHER_SUITES_TLS13);
  if (includeTls12) out = out.concat(DEFAULT_CIPHER_SUITES_TLS12);
  return out;
}

export {
  is_usable_cipher_suite,
  suite_matches_version,
  LABEL_PREFIX_TLS13,
  LABEL_PREFIX_DTLS13,
  DEFAULT_CIPHER_SUITES_TLS13,
  DEFAULT_CIPHER_SUITES_TLS12,
  default_cipher_suites,

  TLS_CIPHER_SUITES,
  getHashFn,
  getHashLen,
  hmac,
  hkdf_extract,
  hkdf_expand,
  build_hkdf_label,
  hkdf_expand_label,
  tls_derive_from_master_secret_tls12,
  tls12_prf,
  derive_handshake_traffic_secrets,
  derive_handshake_traffic_secrets_with_hash,
  derive_app_traffic_secrets,
  derive_app_traffic_secrets_with_hash,
  derive_resumption_master_secret,
  derive_resumption_master_secret_with_hash,
  derive_psk,
  derive_binder_key,
  compute_psk_binder,
  derive_handshake_traffic_secrets_psk,
  derive_handshake_traffic_secrets_psk_with_hash,
  build_cert_verify_tbs,
  build_cert_verify_tbs_with_hash,
  get_handshake_finished,
  get_handshake_finished_with_hash,
  derive_sn_key,
  derive_exporter_master_secret_with_hash,
  tls13_exporter,
  tls12_exporter,
};