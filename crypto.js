
import {
  concatUint8Arrays
} from './utils.js';

import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { hkdf, extract as hkdf_extract_noble, expand as hkdf_expand_noble } from '@noble/hashes/hkdf.js';
import { sha256, sha384 } from '@noble/hashes/sha2.js';

import { p256 } from '@noble/curves/nist.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';

var nobleHashes = { 
  hmac: nobleHmac,
  hkdf: hkdf,
  hkdf_extract: hkdf_extract_noble,
  hkdf_expand: hkdf_expand_noble,
  sha256: sha256,
};



var TLS_CIPHER_SUITES = {
  // ----------------------
  // TLS 1.3 (RFC 8446)
  // ----------------------
  0x1301: { // TLS_AES_128_GCM_SHA256
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
    tls:          12,
    kex:          'ECDHE_RSA',
    sig:          'RSA',
    cipher:       'CHACHA20_POLY1305',
    aead:         true,
    keylen:       32,
    fixed_ivlen:  4,
    record_ivlen: 8,
    ivlen:        12,
    hash:         'sha256'
  },
  0xCCA9: { // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    tls:          12,
    kex:          'ECDHE_ECDSA',
    sig:          'ECDSA',
    cipher:       'CHACHA20_POLY1305',
    aead:         true,
    keylen:       32,
    fixed_ivlen:  4,
    record_ivlen: 8,
    ivlen:        12,
    hash:         'sha256'
  },
  0xCCAA: { // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    tls:          12,
    kex:          'DHE_RSA',
    sig:          'RSA',
    cipher:       'CHACHA20_POLY1305',
    aead:         true,
    keylen:       32,
    fixed_ivlen:  4,
    record_ivlen: 8,
    ivlen:        12,
    hash:         'sha256'
  },
  0x009C: { // TLS_RSA_WITH_AES_128_GCM_SHA256
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





// --- Hash helpers: מקבלים מחרוזת ומחזירים פונקציית hash + outputLen ---
function getHashFn(hashName) {
  if (hashName === 'sha256') return sha256;
  if (hashName === 'sha384') return sha384;
  throw new Error('Unsupported hash: ' + hashName);
}
function getHashLen(hashName) {
  var fn = getHashFn(hashName);
  return fn.outputLen|0;
}

// --- HMAC (עם noble) ---
function hmac(hashName, keyU8, dataU8) {
  var hashFn = getHashFn(hashName);
  return nobleHmac(hashFn, keyU8, dataU8); // Uint8Array
}

// --- HKDF wrappers (hash כמחרוזת) ---
function hkdf_extract(hashName, saltU8, ikmU8) {
  var hashFn = getHashFn(hashName);
  // extract(hash, ikm, salt?)
  return hkdf_extract_noble(hashFn, ikmU8, saltU8);
}
function hkdf_expand(hashName, prkU8, infoU8, length) {
  var hashFn = getHashFn(hashName);
  // expand(hash, prk, info, length)
  return hkdf_expand_noble(hashFn, prkU8, infoU8, length|0);
}

// --- TLS 1.3 label builder ---
function build_hkdf_label(label, context, length) {
  var prefix = 'tls13 ';
  var enc = new TextEncoder();
  var full = enc.encode(prefix + label);
  var info = new Uint8Array(2 + 1 + full.length + 1 + context.length);

  // length (2 bytes BE)
  info[0] = (length >>> 8) & 0xff;
  info[1] = (length       ) & 0xff;

  // label
  info[2] = full.length;
  info.set(full, 3);

  // context
  var ofs = 3 + full.length;
  info[ofs] = context.length;
  info.set(context, ofs + 1);

  return info;
}

function hkdf_expand_label(hashName, secret, label, context, length) {
  var info = build_hkdf_label(label, context, length|0);
  return hkdf_expand(hashName, secret, info, length|0);
}

// --- TLS 1.3: derive handshake secrets ---
function derive_handshake_traffic_secrets(hashName, shared_secret, transcript) {
  var hashFn  = getHashFn(hashName);

  var hashLen = hashFn.outputLen|0;

  var empty = new Uint8Array(0);
  var zeros = new Uint8Array(hashLen); // "zeros" כ־salt בגודל hashLen

  // early_secret = HKDF-Extract(zeros, PSK=empty) כשאין PSK
  var early_secret = hkdf_extract(hashName, empty, zeros);

  // derived_secret = HKDF-Expand-Label(early_secret, "derived", Hash(""), Hash.length)
  var h_empty = hashFn(empty);
  var derived_secret = hkdf_expand_label(hashName, early_secret, 'derived', h_empty, hashLen);

  // handshake_secret = HKDF-Extract(derived_secret, shared_secret)
  var handshake_secret = hkdf_extract(hashName, derived_secret, shared_secret);

  // transcript_hash עד הנקודה הנוכחית

  var transcript_hash = hashFn(transcript);

  // תנועת handshake
  var client_handshake_traffic_secret = hkdf_expand_label(hashName, handshake_secret, 'c hs traffic', transcript_hash, hashLen);
  var server_handshake_traffic_secret = hkdf_expand_label(hashName, handshake_secret, 's hs traffic', transcript_hash, hashLen);

  return {
    handshake_secret: handshake_secret,
    client_handshake_traffic_secret: client_handshake_traffic_secret,
    server_handshake_traffic_secret: server_handshake_traffic_secret,
  };
}

// --- TLS 1.3: derive application secrets ---
function derive_app_traffic_secrets(hashName, handshake_secret, transcript) {
  var hashFn  = getHashFn(hashName);
  var hashLen = hashFn.outputLen|0;

  var empty = new Uint8Array(0);
  var zeros = new Uint8Array(hashLen);

  // derived_secret = HKDF-Expand-Label(handshake_secret, "derived", Hash(""), Hash.length)
  var h_empty = hashFn(empty);
  var derived_secret = hkdf_expand_label(hashName, handshake_secret, 'derived', h_empty, hashLen);

  // master_secret = HKDF-Extract(derived_secret, zeros)
  var master_secret = hkdf_extract(hashName, derived_secret, zeros);

  // hash של ה־transcript (עד Finished של ה־server בד"כ)
  var transcript_hash = hashFn(transcript);

  // תנועת application
  var client_app_traffic_secret = hkdf_expand_label(hashName, master_secret, 'c ap traffic', transcript_hash, hashLen);
  var server_app_traffic_secret = hkdf_expand_label(hashName, master_secret, 's ap traffic', transcript_hash, hashLen);

  return {
    client_app_traffic_secret: client_app_traffic_secret,
    server_app_traffic_secret: server_app_traffic_secret,
    master_secret: master_secret
  };
}


function build_cert_verify_tbs(hashName, isServer, transcript){
  if(isServer){
    var label = new TextEncoder().encode("TLS 1.3, server CertificateVerify");
  }else{
    var label = new TextEncoder().encode("TLS 1.3, client CertificateVerify");
  }
  var separator = new Uint8Array([0x00]);
  var padding = new Uint8Array(64).fill(0x20);

  var hashFn  = getHashFn(hashName);
  var transcript_hash = hashFn(transcript);

  return concatUint8Arrays([padding, label, separator, transcript_hash]);
}


function get_handshake_finished(hashName, traffic_secret, transcript) {
  var hashFn  = getHashFn(hashName);
  var hashLen = hashFn.outputLen|0;

  var empty = new Uint8Array(0);

  var finished_key = hkdf_expand_label(hashName, traffic_secret, 'finished', empty, hashLen);
  var transcript_hash = hashFn(transcript);
  var verify_data=hmac(hashName, finished_key, transcript_hash);

  return verify_data;
}

// --- Exports ---
export {
  TLS_CIPHER_SUITES,
  getHashFn,
  getHashLen,
  hmac,
  hkdf_extract,
  hkdf_expand,
  build_hkdf_label,
  hkdf_expand_label,
  derive_handshake_traffic_secrets,
  derive_app_traffic_secrets,
  build_cert_verify_tbs,
  get_handshake_finished
};