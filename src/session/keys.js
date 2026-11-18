/**
 * Keys: the certificate's private key that signs, and a peer's public key
 * that verifies. Read by cryptographic-formats (PKCS#8, SEC 1, PKCS#1,
 * SPKI, encrypted PKCS#8 and legacy encrypted PEM), signed and verified by
 * cryptographic-primitives — the library picks native or pure JavaScript.
 *
 * A key carries the two fields of node:crypto's KeyObject that lemon-tls
 * reads to choose a signature scheme, under the same names:
 *   asymmetricKeyType     'rsa', 'rsa-pss', 'ec', 'ed25519', 'ed448',
 *                         'ml-dsa-44' / '-65' / '-87' (public keys also
 *                         'slh-dsa-*'), or null for a key it cannot use
 *   asymmetricKeyDetails  { namedCurve } for EC ('prime256v1', ...),
 *                         { modulusLength } for RSA
 * and pss: an RSA-PSS key's limits ({ hash, mgf_hash, salt_length }) or null.
 */

import * as PEM from 'cryptographic-formats/pem';
import * as PKCS8 from 'cryptographic-formats/pkcs8';
import * as SPKI from 'cryptographic-formats/spki';
import * as X509 from 'cryptographic-formats/x509';
import * as SIG from 'cryptographic-formats/signature';
import * as P12 from 'cryptographic-formats/pkcs12';
import { p256, p384, p521 } from 'cryptographic-primitives/nist.js';
import * as secp256k1 from 'cryptographic-primitives/secp256k1.js';
import { brainpoolP256r1, brainpoolP384r1, brainpoolP512r1 } from 'cryptographic-primitives/brainpool.js';
import * as RSA from 'cryptographic-primitives/rsa.js';
import * as ED25519 from 'cryptographic-primitives/ed25519.js';
import * as ED448 from 'cryptographic-primitives/ed448.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from 'cryptographic-primitives/ml_dsa.js';
import * as SLH from 'cryptographic-primitives/slh_dsa.js';
import { sha1_sync } from 'cryptographic-primitives/sha1.js';
import { sha224_sync, sha256_sync, sha384_sync, sha512_sync } from 'cryptographic-primitives/sha2.js';
import { md5_sync } from 'cryptographic-primitives/md5.js';
import { shake256_sync } from 'cryptographic-primitives/sha3.js';
import { pbkdf2_sync, pkcs12_kdf_sync } from 'cryptographic-primitives/kdf.js';
import { hmac_sync } from 'cryptographic-primitives/hmac.js';
import { rc2_cbc_decrypt_sync } from 'cryptographic-primitives/rc2.js';
import { aes_cbc_decrypt_sync } from 'cryptographic-primitives/aes.js';
import { des_cbc_decrypt_sync, des3_cbc_decrypt_sync } from 'cryptographic-primitives/des.js';

const HASH = { md5: md5_sync, sha1: sha1_sync, sha224: sha224_sync, sha256: sha256_sync, sha384: sha384_sync, sha512: sha512_sync };
const HASH_LEN = { md5: 16, sha1: 20, sha224: 28, sha256: 32, sha384: 48, sha512: 64 };

// cryptographic-formats's curve name: the library's curve, and node:crypto's name.
const CURVES = {
  secp256r1: [p256, 'prime256v1', 32], secp384r1: [p384, 'secp384r1', 48], secp521r1: [p521, 'secp521r1', 66],
  secp256k1: [secp256k1, 'secp256k1', 32], brainpoolP256r1: [brainpoolP256r1, 'brainpoolP256r1', 32],
  brainpoolP384r1: [brainpoolP384r1, 'brainpoolP384r1', 48], brainpoolP512r1: [brainpoolP512r1, 'brainpoolP512r1', 64],
};
const ML_DSA = { mlDsa44: [ml_dsa44, 'ml-dsa-44'], mlDsa65: [ml_dsa65, 'ml-dsa-65'], mlDsa87: [ml_dsa87, 'ml-dsa-87'] };
const EDDSA = { Ed25519: [ED25519, 'ed25519'], Ed448: [ED448, 'ed448'] };

// cryptographic-formats's SLH-DSA algorithm name (slhDsaSha2_128s) to the
// library's (slh_dsa_sha2_128s) and node:crypto's (slh-dsa-sha2-128s).
function slh(alg) {
  let m = /^slhDsa(Sha2|Shake)_(\d+[sf])$/.exec(alg);
  if (!m) return null;
  let lib = SLH['slh_dsa_' + m[1].toLowerCase() + '_' + m[2]];
  return lib ? [lib, 'slh-dsa-' + m[1].toLowerCase() + '-' + m[2]] : null;
}

function big(bytes) {
  let n = 0n;
  for (let i = 0; i < bytes.length; i++) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}
function bytes_of(n) {
  let h = n.toString(16);
  let b = Buffer.from(h.length % 2 ? '0' + h : h, 'hex');
  return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
}
function bit_length(bytes) {
  let i = 0;
  while (i < bytes.length && bytes[i] === 0) i++;
  if (i === bytes.length) return 0;
  return (bytes.length - i - 1) * 8 + (32 - Math.clz32(bytes[i]));
}
function same_bytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function rsa_public_of(r) { return { n: big(r.n), e: big(r.e) }; }

// ECDSA's DER signature (TLS and X.509 both carry it so) and the {r, s} the
// library signs and verifies.
function ecdsa_to_der(sig) { return SIG.from_pair({ r: bytes_of(sig.r), s: bytes_of(sig.s) }); }
function ecdsa_from_der(der) {
  let p;
  try { p = SIG.parse_der({ der: der }); } catch (e) { return null; }
  return { r: big(p.r), s: big(p.s) };
}

/* ---------------------------------------------------------------- public */

/**
 * A public key from its SPKI (DER, or cryptographic-formats's parsed SPKI),
 * or one with asymmetricKeyType null when it is of a kind this cannot use.
 */
// A certificate's SPKI, as cryptographic-formats reads it.
function X509_spki(der) { return X509.from_der(der).public_key; }

function public_key(spki) {
  let p = spki instanceof Uint8Array ? SPKI.from_der(spki) : spki;
  let k = { asymmetricKeyType: null, asymmetricKeyDetails: {}, pss: null, _alg: p.algorithm };
  let c, x;
  if (p.algorithm === 'ecPublicKey' && (c = CURVES[p.curve])) {
    k.asymmetricKeyType = 'ec';
    k.asymmetricKeyDetails = { namedCurve: c[1] };
    k._curve = c[0];
    k._point = p.point;
  } else if (p.algorithm === 'rsaEncryption' || p.algorithm === 'rsassaPss') {
    k.asymmetricKeyType = p.algorithm === 'rsaEncryption' ? 'rsa' : 'rsa-pss';
    k.asymmetricKeyDetails = { modulusLength: bit_length(p.rsa.n) };
    k.pss = p.pss || null;
    k._rsa = rsa_public_of(p.rsa);
  } else if ((x = EDDSA[p.algorithm])) {
    k.asymmetricKeyType = x[1];
    k._eddsa = x[0];
    k._raw = p.point;
  } else if ((x = ML_DSA[p.algorithm]) || (x = slh(p.algorithm))) {
    k.asymmetricKeyType = x[1];
    k._fips = x[0];
    k._raw = p.point;
  }
  return k;
}

/**
 * Whether `sig` is `key`'s signature over `msg`. `how`: { sig: 'ecdsa' |
 * 'rsa' | 'eddsa' | 'mldsa' | 'slh-dsa', hash, isPSS, salt_length?,
 * mgf_hash? } — salt_length and mgf_hash default to the hash's (TLS's
 * rule); a certificate's PSS parameters give its own. False, never a throw,
 * for anything that is not a valid signature.
 */
function verify(key, how, msg, sig) {
  try {
    switch (how.sig) {
      case 'ecdsa': {
        let rs = key._curve && HASH[how.hash] ? ecdsa_from_der(sig) : null;
        return rs !== null && verifier(key).verify_message_sync(HASH[how.hash], msg, rs) === true;
      }
      case 'rsa': {
        if (!key._rsa || !HASH[how.hash]) return false;
        if (!how.isPSS) return verifier(key).verify_pkcs1_message_sync(msg, sig, HASH[how.hash]) === true;
        let mgf = HASH[how.mgf_hash || how.hash];
        if (!mgf) return false;
        let salt = how.salt_length != null ? how.salt_length : HASH_LEN[how.hash];
        return verifier(key).verify_pss_message_sync(msg, sig, HASH[how.hash], salt, mgf) === true;
      }
      case 'eddsa': return !!key._eddsa && verifier(key).verify_sync(msg, sig) === true;
      case 'mldsa':
      case 'slh-dsa': return !!key._fips && key._fips.verify_sync(key._raw, msg, sig) === true;
      default: return false;
    }
  } catch (e) {
    return false;
  }
}

// The library's verifier for `key`, made on its first verification and
// kept with it: the key is read (and, native, loaded) once — a certificate's
// key verifies every handshake that sends it (session/x509.js reads a
// certificate once). EdDSA strict: RFC 8032's cofactorless check, which is
// what OpenSSL applies.
function verifier(key) {
  if (!key._verifier) {
    key._verifier = key._curve ? key._curve.verifier_create(key._point)
                  : key._rsa ? RSA.verifier_create(key._rsa)
                  : key._eddsa.verifier_create(key._raw, undefined, undefined, 'strict');
  }
  return key._verifier;
}

/* --------------------------------------------------------------- private */

// The PKCS#8 of an RFC 1421 encrypted PEM block (Proc-Type / DEK-Info):
// OpenSSL's EVP_BytesToKey with MD5, one round, the IV's first 8 bytes as
// the salt. The block inside is the key in its traditional form.
const LEGACY_CIPHERS = {
  'AES-128-CBC': [16, aes_cbc_decrypt_sync], 'AES-192-CBC': [24, aes_cbc_decrypt_sync], 'AES-256-CBC': [32, aes_cbc_decrypt_sync],
  'DES-EDE3-CBC': [24, des3_cbc_decrypt_sync], 'DES-CBC': [8, des_cbc_decrypt_sync],
};
function legacy_decrypt(block, pass) {
  let c = LEGACY_CIPHERS[String(block.encrypted.algorithm).toUpperCase()];
  if (!c) throw new Error('unsupported legacy PEM cipher ' + block.encrypted.algorithm);
  let salt = block.encrypted.iv.subarray(0, 8), key = new Uint8Array(0), d = new Uint8Array(0);
  while (key.length < c[0]) {
    d = md5_sync(concat([d, pass, salt]));
    key = concat([key, d]);
  }
  let plain = c[1](key.subarray(0, c[0]), block.encrypted.iv, block.der);
  if (plain === null) throw bad_decrypt();
  return plain;
}

// PBES2 (RFC 8018): PBKDF2 and a CBC cipher, as encrypted PKCS#8 carries them.
const PBES2_CIPHERS = { aes128CBC: aes_cbc_decrypt_sync, aes192CBC: aes_cbc_decrypt_sync, aes256CBC: aes_cbc_decrypt_sync,
                        des_ede3_cbc: des3_cbc_decrypt_sync, desCBC: des_cbc_decrypt_sync };
const PBES2_PRF = { hmacWithSHA1: sha1_sync, hmacWithSHA224: sha224_sync, hmacWithSHA256: sha256_sync,
                    hmacWithSHA384: sha384_sync, hmacWithSHA512: sha512_sync };
function pbes2_decrypt(der, pass) {
  let e = PKCS8.encrypted_from_der(der);
  let cipher = PBES2_CIPHERS[e.cipher], prf = PBES2_PRF[e.prf];
  if (e.kdf !== 'pbkdf2' || !cipher || !prf) throw new Error('unsupported encrypted key (' + e.kdf + ', ' + e.cipher + ')');
  let plain = cipher(pbkdf2_sync(prf, pass, e.salt, e.iterations, e.key_length), e.iv, e.data);
  if (plain === null) throw bad_decrypt();
  return plain;
}
/**
 * A PKCS#12 file (node:tls's `pfx`), opened with `passphrase` (none: the
 * empty one): { key, certs } — the first private key as PKCS#8 DER, and the
 * certificates, its own first, then the others in the file's order (the
 * chain a server sends). The MAC is checked first: a wrong passphrase, or a
 * file altered, throws. The structure is cryptographic-formats's; the
 * decryption cryptographic-primitives's: PBES2 (AES, 3DES — what OpenSSL 3
 * writes), and the older PKCS#12 PBE with 3DES or 40-bit RC2.
 */
function pfx_open(der, passphrase) {
  let pw = passphrase == null ? '' : String(passphrase);
  let utf8 = new TextEncoder().encode(pw);
  let ciphers = Object.assign({ rc2CBC: rc2_cbc_decrypt_sync }, PBES2_CIPHERS);
  let lib = {
    // RFC 7292 appendix B; the library takes the ID before the count.
    pkcs12_kdf: function (hash, password, salt, iterations, id, length) {
      return pkcs12_kdf_sync(HASH[hash], password, salt, id, iterations, length);
    },
    pbkdf2: function (prf, password, salt, iterations, length) {
      if (!PBES2_PRF[prf]) throw new Error('pfx: unsupported PRF ' + prf);
      return pbkdf2_sync(PBES2_PRF[prf], typeof password === 'string' ? utf8 : password, salt, iterations, length);
    },
    decrypt: function (cipher, key, iv, data) {
      if (!ciphers[cipher]) throw new Error('pfx: unsupported cipher ' + cipher);
      let plain = ciphers[cipher](key, iv, data);
      if (plain === null) throw bad_decrypt();
      return plain;
    },
    hmac: function (hash, key, data) {
      if (!HASH[hash]) throw new Error('pfx: unsupported MAC hash ' + hash);
      return hmac_sync(HASH[hash], key, data);
    },
  };
  let r;
  try { r = P12.open(der instanceof Uint8Array ? der : new Uint8Array(der), pw, lib); }
  catch (e) {
    if (e && e.code === 'bad-mac') { let err = new Error('mac verify failure'); err.code = 'ERR_CRYPTO_OPERATION_FAILED'; throw err; }
    throw e;
  }
  if (r.keys.length === 0) throw new Error('pfx: no private key in the file');
  let key = r.keys[0].key;
  PKCS8.from_der(key);
  let mine = private_key(key).public;
  let certs = r.certificates.map(function (b) { return b.certificate; });
  let own = -1;
  for (let i = 0; i < certs.length && own < 0; i++) {
    try { if (same_public_key(mine, public_key(X509_spki(certs[i])))) own = i; } catch (e) { /* the next */ }
  }
  if (own < 0) throw new Error('pfx: no certificate in the file for its private key');
  return { key: key, certs: [certs[own]].concat(certs.filter(function (c, i) { return i !== own; })) };
}

function bad_decrypt() {
  let err = new Error('error:1C800064:Provider routines::bad decrypt');
  err.code = 'ERR_OSSL_BAD_DECRYPT';
  return err;
}
function concat(parts) {
  let n = 0;
  for (let i = 0; i < parts.length; i++) n += parts[i].length;
  let out = new Uint8Array(n), o = 0;
  for (let i = 0; i < parts.length; i++) { out.set(parts[i], o); o += parts[i].length; }
  return out;
}

// The readers of a private key's DER forms, by name.
const READERS = { pkcs8: PKCS8.from_der, pkcs1: PKCS8.pkcs1_from_der, sec1: PKCS8.sec1_from_der };
// PEM labels (RFC 7468 §10, §11; OpenSSL's traditional ones).
const PEM_KEY_TYPES = { 'PRIVATE KEY': 'pkcs8', 'ENCRYPTED PRIVATE KEY': 'pkcs8-encrypted',
                        'RSA PRIVATE KEY': 'pkcs1', 'EC PRIVATE KEY': 'sec1' };

/**
 * A private key as PKCS#8 DER, from a PEM text or DER (Buffer/Uint8Array)
 * of any of the forms node:tls reads — PKCS#8, encrypted PKCS#8, PKCS#1, SEC 1,
 * legacy encrypted PEM — decrypted with `passphrase` where it is encrypted.
 * Throws what node:crypto would on a key it cannot read, and on a wrong or
 * missing passphrase.
 */
function private_key_pkcs8(input, passphrase) {
  let pass = passphrase == null ? null : (typeof passphrase === 'string' ? new TextEncoder().encode(passphrase) : new Uint8Array(passphrase));
  let need_pass = function () {
    if (pass !== null) return pass;
    let e = new TypeError('Passphrase required for encrypted key');
    e.code = 'ERR_MISSING_PASSPHRASE';
    throw e;
  };
  let text = typeof input === 'string' ? input : (looks_pem(input) ? new TextDecoder().decode(input) : null);
  let der, form;
  if (text !== null) {
    let blocks = PEM.decode(text);
    let block = null;
    for (let i = 0; i < blocks.length && !block; i++) if (PEM_KEY_TYPES[blocks[i].label]) block = blocks[i];
    if (!block) throw new Error('createSecureContext: no private key in the PEM (' + blocks.map(function (b) { return b.label; }).join(', ') + ')');
    form = PEM_KEY_TYPES[block.label];
    der = block.encrypted ? legacy_decrypt(block, need_pass()) : block.der;
  } else {
    der = input instanceof Uint8Array ? input : new Uint8Array(input);
    form = null;
    for (let f of ['pkcs8', 'pkcs8-encrypted', 'pkcs1', 'sec1']) {
      try { (f === 'pkcs8-encrypted' ? PKCS8.encrypted_from_der : READERS[f])(der); form = f; break; } catch (e) { /* the next */ }
    }
    if (form === null) throw new Error('createSecureContext: the key is not PKCS#8, PKCS#1 or SEC 1 DER');
  }
  if (form === 'pkcs8-encrypted') { der = pbes2_decrypt(der, need_pass()); form = 'pkcs8'; }
  if (form === 'pkcs8') { PKCS8.from_der(der); return der; }
  return PKCS8.to_der(READERS[form](der));
}
// DER starts with a SEQUENCE (0x30); a PEM text with "-----BEGIN" after
// whatever comes before it.
function looks_pem(buf) {
  return buf.length > 0 && buf[0] !== 0x30;
}

// One key object per PKCS#8 DER array (a context's key signs every
// handshake): the library's signer made once.
const PRIVATE_KEYS = new WeakMap();

/**
 * The signing key of a PKCS#8 DER: the KeyObject fields (above), its
 * public key (`public`, as public_key gives it — for pairing a key with its
 * certificate) and sign(how, msg) (the bytes TLS and X.509 carry; ECDSA in
 * DER). Throws for a key of a kind this cannot sign with.
 */
function private_key(der) {
  let k = PRIVATE_KEYS.get(der);
  if (k) return k;
  let p = PKCS8.from_der(der);
  let c, x, signer = null, make, pub;
  k = { asymmetricKeyType: null, asymmetricKeyDetails: {}, pss: null };
  if (p.algorithm === 'ecPublicKey' && (c = CURVES[p.curve])) {
    k.asymmetricKeyType = 'ec';
    k.asymmetricKeyDetails = { namedCurve: c[1] };
    let point = c[0].get_public_key_sync(p.scalar, false);
    pub = { algorithm: 'ecPublicKey', curve: p.curve, point: point };
    make = function () { return c[0].signer_create(p.scalar); };
  } else if (p.algorithm === 'rsaEncryption' || p.algorithm === 'rsassaPss') {
    k.asymmetricKeyType = p.algorithm === 'rsaEncryption' ? 'rsa' : 'rsa-pss';
    k.asymmetricKeyDetails = { modulusLength: bit_length(p.rsa.n) };
    k.pss = p.pss || null;
    pub = { algorithm: p.algorithm, rsa: { n: p.rsa.n, e: p.rsa.e }, pss: k.pss };
    let r = p.rsa;
    make = function () {
      return RSA.signer_create({ n: big(r.n), e: big(r.e), d: big(r.d), p: big(r.p), q: big(r.q), dp: big(r.dp), dq: big(r.dq), qinv: big(r.qinv) });
    };
  } else if ((x = EDDSA[p.algorithm])) {
    k.asymmetricKeyType = x[1];
    pub = { algorithm: p.algorithm, point: x[0].get_public_key_sync(p.scalar) };
    make = function () { return x[0].signer_create(p.scalar); };
  } else if ((x = ML_DSA[p.algorithm])) {
    k.asymmetricKeyType = x[1];
    let sk = p.seed || p.expanded_key;
    // From a seed, the public key is the key pair's. An expanded key does
    // not hold it, only tr = H(pk) (FIPS 204 §7.2, bytes 64..127): enough to
    // tell its certificate (same_public_key).
    if (p.seed) pub = { algorithm: p.algorithm, point: x[0].keygen_sync(p.seed).pk };
    else k._tr = sk.subarray(64, 128);
    make = function () { return x[0].signer_create(sk); };
  } else {
    let e = new Error('unsupported private key algorithm ' + p.algorithm);
    e.code = 'ERR_OSSL_UNSUPPORTED';
    throw e;
  }
  k.public = pub ? public_key(pub) : { asymmetricKeyType: k.asymmetricKeyType, asymmetricKeyDetails: {}, pss: null, _tr: k._tr };
  k.sign = function (how, msg) {
    if (signer === null) signer = make();
    switch (how.sig) {
      case 'ecdsa': return ecdsa_to_der(signer.sign_message_sync(HASH[how.hash], msg));
      case 'rsa': return how.isPSS ? signer.sign_pss_message_sync(msg, HASH[how.hash], null, HASH_LEN[how.hash])
                                   : signer.sign_pkcs1_message_sync(msg, HASH[how.hash]);
      default: return signer.sign_sync(msg);   // EdDSA and ML-DSA: the whole message, no context
    }
  };
  PRIVATE_KEYS.set(der, k);
  return k;
}

/**
 * Whether two public keys (as public_key gives them) are one key — a
 * private key's and a certificate's: the same kind, and the same EC point
 * (compressed or not), RSA modulus and exponent, or raw key.
 */
function same_public_key(a, b) {
  if (!a || !b || a.asymmetricKeyType === null || a.asymmetricKeyType !== b.asymmetricKeyType) return false;
  if (a._tr || b._tr) {
    let tr = a._tr || b._tr, raw = a._tr ? b._raw : a._raw;
    return !!raw && same_bytes(shake256_sync(raw, 64), tr);
  }
  if (a._curve) {
    if (a._curve !== b._curve) return false;
    let pa = a._curve.decode_point_sync(a._point), pb = b._curve.decode_point_sync(b._point);
    return !!pa && !!pb && pa.x === pb.x && pa.y === pb.y;
  }
  if (a._rsa) return a._rsa.n === b._rsa.n && a._rsa.e === b._rsa.e;
  return same_bytes(a._raw, b._raw);
}

export { public_key, private_key, private_key_pkcs8, pfx_open, verify, same_public_key };
