/**
 * HPKE — Hybrid Public Key Encryption (RFC 9180).
 *
 * Encrypting to a public key: the sender makes an ephemeral key pair, a
 * Diffie-Hellman with the recipient's public key gives a shared secret, and
 * from it come an AEAD key and nonce for any number of messages — while
 * only the ephemeral public key (`enc`) has to travel with them. TLS
 * Encrypted Client Hello (ECH) encrypts the real ClientHello this way, to
 * the key a server publishes in DNS; MLS and Oblivious HTTP use it too.
 *
 * All four modes (base, psk, auth, auth_psk); the KEMs, KDFs and AEADs of
 * the RFC's registry that node:crypto has:
 *
 *   KEM   0x0010 DHKEM(P-256, HKDF-SHA256)    0x0011 DHKEM(P-384, HKDF-SHA384)
 *         0x0012 DHKEM(P-521, HKDF-SHA512)    0x0020 DHKEM(X25519, HKDF-SHA256)
 *         0x0021 DHKEM(X448, HKDF-SHA512)
 *   KDF   0x0001 HKDF-SHA256   0x0002 HKDF-SHA384   0x0003 HKDF-SHA512
 *   AEAD  0x0001 AES-128-GCM   0x0002 AES-256-GCM   0x0003 ChaCha20-Poly1305
 *         0xFFFF export-only
 *
 * Synchronous, like the rest of the handshake's crypto.
 */

import crypto from 'node:crypto';
import { hkdf_extract, hkdf_expand } from '../crypto.js';
import { x25519_get_public_key, x25519_get_shared_secret } from './ecdh.js';

var MODE_BASE = 0x00, MODE_PSK = 0x01, MODE_AUTH = 0x02, MODE_AUTH_PSK = 0x03;

var te = new TextEncoder();
function u8(s) { return te.encode(s); }
function i2osp(n, len) {
  var out = new Uint8Array(len);
  for (var i = len - 1; i >= 0; i--) { out[i] = n & 0xff; n = Math.floor(n / 256); }
  return out;
}
function concat() {
  var len = 0, i;
  for (i = 0; i < arguments.length; i++) len += arguments[i].length;
  var out = new Uint8Array(len), off = 0;
  for (i = 0; i < arguments.length; i++) { out.set(arguments[i], off); off += arguments[i].length; }
  return out;
}
function hexToBig(h) { return BigInt('0x' + h); }
function bytesToBig(b) { return b.length ? BigInt('0x' + Buffer.from(b).toString('hex')) : 0n; }

var HPKE_V1 = u8('HPKE-v1');
var EMPTY = new Uint8Array(0);


// ============================================================
//  Labeled HKDF (RFC 9180 §4)
// ============================================================

function labeled_extract(hash, suite_id, salt, label, ikm) {
  return hkdf_extract(hash, salt, concat(HPKE_V1, suite_id, u8(label), ikm));
}

function labeled_expand(hash, suite_id, prk, label, info, L) {
  return hkdf_expand(hash, prk, concat(i2osp(L, 2), HPKE_V1, suite_id, u8(label), info), L);
}


// ============================================================
//  KEMs: DH groups (RFC 9180 §4.1, §7.1)
// ============================================================

// The two Montgomery curves, through node:crypto's raw-key DER wrapping.
var X448_PKCS8 = Buffer.from('3046020100300506032b656f043a0438', 'hex');
var X448_SPKI  = Buffer.from('3042300506032b656f033900', 'hex');

function x448_public_key(sk) {
  var priv = crypto.createPrivateKey({ key: Buffer.concat([X448_PKCS8, Buffer.from(sk)]), format: 'der', type: 'pkcs8' });
  return new Uint8Array(crypto.createPublicKey(priv).export({ type: 'spki', format: 'der' }).subarray(X448_SPKI.length));
}
function x448_shared(sk, pk) {
  var priv = crypto.createPrivateKey({ key: Buffer.concat([X448_PKCS8, Buffer.from(sk)]), format: 'der', type: 'pkcs8' });
  var pub  = crypto.createPublicKey({ key: Buffer.concat([X448_SPKI, Buffer.from(pk)]), format: 'der', type: 'spki' });
  var dh = new Uint8Array(crypto.diffieHellman({ privateKey: priv, publicKey: pub }));
  // RFC 9180 §7.1.4 / RFC 7748 §6.2: an all-zero result means a low-order
  // public key — the sender would know the "secret". Constant time.
  var acc = 0;
  for (var i = 0; i < dh.length; i++) acc |= dh[i];
  if (acc === 0) throw new Error('HPKE: X448 shared secret is all zero (invalid public key)');
  return dh;
}

// The NIST curves: a private key is a scalar below the group order;
// DeriveKeyPair draws candidates until one is (§7.1.3).
function nist(curve, order, bitmask) {
  return {
    order: order,
    bitmask: bitmask,
    public_key: function (sk) {
      var e = crypto.createECDH(curve); e.setPrivateKey(Buffer.from(sk));
      return new Uint8Array(e.getPublicKey(null, 'uncompressed'));
    },
    // computeSecret validates the peer point (on the curve, not infinity)
    // and gives the x-coordinate: the DH value of §7.1.
    shared: function (sk, pk) {
      var e = crypto.createECDH(curve); e.setPrivateKey(Buffer.from(sk));
      return new Uint8Array(e.computeSecret(Buffer.from(pk)));
    }
  };
}

var KEMS = {};
KEMS[0x0010] = Object.assign(nist('prime256v1',
  hexToBig('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'), 0xff),
  { id: 0x0010, name: 'DHKEM(P-256, HKDF-SHA256)', hash: 'sha256', Nsecret: 32, Nenc: 65, Npk: 65, Nsk: 32 });
KEMS[0x0011] = Object.assign(nist('secp384r1',
  hexToBig('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'), 0xff),
  { id: 0x0011, name: 'DHKEM(P-384, HKDF-SHA384)', hash: 'sha384', Nsecret: 48, Nenc: 97, Npk: 97, Nsk: 48 });
KEMS[0x0012] = Object.assign(nist('secp521r1',
  hexToBig('01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409'), 0x01),
  { id: 0x0012, name: 'DHKEM(P-521, HKDF-SHA512)', hash: 'sha512', Nsecret: 64, Nenc: 133, Npk: 133, Nsk: 66 });
KEMS[0x0020] = { id: 0x0020, name: 'DHKEM(X25519, HKDF-SHA256)', hash: 'sha256', Nsecret: 32, Nenc: 32, Npk: 32, Nsk: 32,
  public_key: x25519_get_public_key,
  shared: x25519_get_shared_secret };       // rejects the all-zero result itself
KEMS[0x0021] = { id: 0x0021, name: 'DHKEM(X448, HKDF-SHA512)', hash: 'sha512', Nsecret: 64, Nenc: 56, Npk: 56, Nsk: 56,
  public_key: x448_public_key,
  shared: x448_shared };

function kem_suite_id(kem) { return concat(u8('KEM'), i2osp(kem.id, 2)); }

/** §7.1.3: a key pair from `ikm` (at least Nsk bytes of entropy). */
function kem_derive_key_pair(kem, ikm) {
  var sid = kem_suite_id(kem);
  var prk = labeled_extract(kem.hash, sid, EMPTY, 'dkp_prk', ikm);
  var sk;
  if (!kem.order) {
    sk = labeled_expand(kem.hash, sid, prk, 'sk', EMPTY, kem.Nsk);
  } else {
    for (var counter = 0; ; counter++) {
      if (counter > 255) throw new Error('HPKE: DeriveKeyPair found no key');
      var bytes = labeled_expand(kem.hash, sid, prk, 'candidate', i2osp(counter, 1), kem.Nsk);
      bytes[0] &= kem.bitmask;
      var n = bytesToBig(bytes);
      if (n !== 0n && n < kem.order) { sk = bytes; break; }
    }
  }
  return { private_key: sk, public_key: kem.public_key(sk) };
}

function kem_generate_key_pair(kem) {
  return kem_derive_key_pair(kem, new Uint8Array(crypto.randomBytes(kem.Nsk)));
}

function kem_check_public_key(kem, pk) {
  if (!(pk instanceof Uint8Array) || pk.length !== kem.Npk) throw new Error('HPKE: public key must be ' + kem.Npk + ' bytes for ' + kem.name);
  if (kem.order && pk[0] !== 0x04) throw new Error('HPKE: public key is not an uncompressed point');
}

function kem_extract_and_expand(kem, dh, kem_context) {
  var sid = kem_suite_id(kem);
  var prk = labeled_extract(kem.hash, sid, EMPTY, 'eae_prk', dh);
  return labeled_expand(kem.hash, sid, prk, 'shared_secret', kem_context, kem.Nsecret);
}

// §4.1 Encap / Decap, and their authenticated forms. `ephemeral` replaces
// the random key pair — for the RFC's test vectors only.
function kem_encap(kem, pkR, skS, ephemeral) {
  kem_check_public_key(kem, pkR);
  var e = ephemeral || kem_generate_key_pair(kem);
  var dh = kem.shared(e.private_key, pkR);
  var kem_context = concat(e.public_key, pkR);
  if (skS) {
    dh = concat(dh, kem.shared(skS, pkR));
    kem_context = concat(kem_context, kem.public_key(skS));
  }
  return { shared_secret: kem_extract_and_expand(kem, dh, kem_context), enc: e.public_key };
}

function kem_decap(kem, enc, skR, pkS, pkR) {
  kem_check_public_key(kem, enc);
  var dh = kem.shared(skR, enc);
  var kem_context = concat(enc, pkR || kem.public_key(skR));
  if (pkS) {
    kem_check_public_key(kem, pkS);
    dh = concat(dh, kem.shared(skR, pkS));
    kem_context = concat(kem_context, pkS);
  }
  return kem_extract_and_expand(kem, dh, kem_context);
}


// ============================================================
//  KDFs and AEADs (RFC 9180 §7.2, §7.3)
// ============================================================

var KDFS = {
  0x0001: { id: 0x0001, hash: 'sha256', Nh: 32 },
  0x0002: { id: 0x0002, hash: 'sha384', Nh: 48 },
  0x0003: { id: 0x0003, hash: 'sha512', Nh: 64 }
};

var AEADS = {
  0x0001: { id: 0x0001, algo: 'aes-128-gcm',       Nk: 16, Nn: 12, Nt: 16 },
  0x0002: { id: 0x0002, algo: 'aes-256-gcm',       Nk: 32, Nn: 12, Nt: 16 },
  0x0003: { id: 0x0003, algo: 'chacha20-poly1305', Nk: 32, Nn: 12, Nt: 16 },
  0xffff: { id: 0xffff, algo: null,                Nk: 0,  Nn: 0,  Nt: 0 }    // export-only
};

function aead_seal(aead, key, nonce, aad, pt) {
  var c = crypto.createCipheriv(aead.algo, key, nonce, { authTagLength: aead.Nt });
  c.setAAD(aad);
  var a = c.update(pt), b = c.final();
  return new Uint8Array(Buffer.concat([a, b, c.getAuthTag()]));
}

function aead_open(aead, key, nonce, aad, ct) {
  if (ct.length < aead.Nt) return null;
  var d = crypto.createDecipheriv(aead.algo, key, nonce, { authTagLength: aead.Nt });
  d.setAAD(aad);
  d.setAuthTag(ct.subarray(ct.length - aead.Nt));
  try {
    var a = d.update(ct.subarray(0, ct.length - aead.Nt)), b = d.final();
    return new Uint8Array(Buffer.concat([a, b]));
  } catch (e) { return null; }
}


// ============================================================
//  Suites and the key schedule (RFC 9180 §5.1)
// ============================================================

/**
 * A cipher suite by its registry ids. Throws on one this build does not
 * have. `{ kem, kdf, aead, id: suite_id, Nenc, … }`.
 */
function hpke_suite(kem_id, kdf_id, aead_id) {
  var kem = KEMS[kem_id], kdf = KDFS[kdf_id], aead = AEADS[aead_id];
  if (!kem)  throw new Error('HPKE: unsupported KEM 0x' + (kem_id >>> 0).toString(16));
  if (!kdf)  throw new Error('HPKE: unsupported KDF 0x' + (kdf_id >>> 0).toString(16));
  if (!aead) throw new Error('HPKE: unsupported AEAD 0x' + (aead_id >>> 0).toString(16));
  return {
    kem: kem, kdf: kdf, aead: aead,
    suite_id: concat(u8('HPKE'), i2osp(kem.id, 2), i2osp(kdf.id, 2), i2osp(aead.id, 2)),
    Nenc: kem.Nenc, Npk: kem.Npk, Nsk: kem.Nsk, Nk: aead.Nk, Nn: aead.Nn, Nt: aead.Nt
  };
}

function is_supported_hpke_suite(kem_id, kdf_id, aead_id) {
  return !!(KEMS[kem_id] && KDFS[kdf_id] && AEADS[aead_id]);
}

function verify_psk_inputs(mode, psk, psk_id) {
  var got_psk = psk.length > 0, got_id = psk_id.length > 0;
  if (got_psk !== got_id) throw new Error('HPKE: psk and psk_id must be given together');
  var needs = (mode === MODE_PSK || mode === MODE_AUTH_PSK);
  if (got_psk !== needs) throw new Error(needs ? 'HPKE: this mode needs a psk' : 'HPKE: a psk was given to a mode without one');
  // §5.1.1: at least 32 bytes of entropy
  if (got_psk && psk.length < 32) throw new Error('HPKE: psk must be at least 32 bytes');
}

function key_schedule(suite, mode, shared_secret, info, psk, psk_id, role) {
  verify_psk_inputs(mode, psk, psk_id);
  var h = suite.kdf.hash, sid = suite.suite_id;
  var psk_id_hash = labeled_extract(h, sid, EMPTY, 'psk_id_hash', psk_id);
  var info_hash   = labeled_extract(h, sid, EMPTY, 'info_hash', info);
  var key_schedule_context = concat(new Uint8Array([mode]), psk_id_hash, info_hash);
  var secret = labeled_extract(h, sid, shared_secret, 'secret', psk);

  var key = EMPTY, base_nonce = EMPTY;
  if (suite.aead.algo) {
    key        = labeled_expand(h, sid, secret, 'key', key_schedule_context, suite.Nk);
    base_nonce = labeled_expand(h, sid, secret, 'base_nonce', key_schedule_context, suite.Nn);
  }
  var exporter_secret = labeled_expand(h, sid, secret, 'exp', key_schedule_context, suite.kdf.Nh);
  return new HpkeContext(suite, role, key, base_nonce, exporter_secret);
}


// ============================================================
//  The encryption context (RFC 9180 §5.2, §5.3)
// ============================================================

function HpkeContext(suite, role, key, base_nonce, exporter_secret) {
  this.suite = suite;
  this.role = role;                       // 'sender' | 'recipient'
  this.key = key;
  this.base_nonce = base_nonce;
  this.exporter_secret = exporter_secret;
  this.seq = 0;
}

HpkeContext.prototype._nonce = function () {
  // base_nonce XOR seq, seq big-endian in the nonce's low bytes. 2^53
  // messages is far past any use; seal/open refuse beyond it.
  if (this.seq >= Number.MAX_SAFE_INTEGER) throw new Error('HPKE: message limit reached');
  var n = this.base_nonce.slice(0), s = i2osp(this.seq, n.length);
  for (var i = 0; i < n.length; i++) n[i] ^= s[i];
  return n;
};

/** Encrypt the next message. Sender only. */
HpkeContext.prototype.seal = function (aad, pt) {
  if (this.role !== 'sender') throw new Error('HPKE: seal on a recipient context');
  if (!this.suite.aead.algo) throw new Error('HPKE: export-only suite cannot seal');
  var ct = aead_seal(this.suite.aead, this.key, this._nonce(), aad || EMPTY, pt);
  this.seq++;
  return ct;
};

/**
 * Decrypt the next message: the plaintext, or null if it does not open —
 * and then the sequence does not advance, so the next valid message still
 * does. Recipient only.
 */
HpkeContext.prototype.open = function (aad, ct) {
  if (this.role !== 'recipient') throw new Error('HPKE: open on a sender context');
  if (!this.suite.aead.algo) throw new Error('HPKE: export-only suite cannot open');
  var pt = aead_open(this.suite.aead, this.key, this._nonce(), aad || EMPTY, ct);
  if (pt) this.seq++;
  return pt;
};

/** §5.3: a secret of `L` bytes for `exporter_context`. */
HpkeContext.prototype.export = function (exporter_context, L) {
  if (!(L >= 0) || L > 255 * this.suite.kdf.Nh) throw new Error('HPKE: export length out of range');
  return labeled_expand(this.suite.kdf.hash, this.suite.suite_id, this.exporter_secret, 'sec', exporter_context || EMPTY, L);
};


// ============================================================
//  Setup (RFC 9180 §5.1.1 - §5.1.4)
// ============================================================

function opt_bytes(v) { return v ? (v instanceof Uint8Array ? v : new Uint8Array(v)) : EMPTY; }

function mode_of(opts) {
  var psk = !!(opts && opts.psk), auth = !!(opts && (opts.sender_private_key || opts.sender_public_key));
  return auth ? (psk ? MODE_AUTH_PSK : MODE_AUTH) : (psk ? MODE_PSK : MODE_BASE);
}

/**
 * The sender's side: `{ enc, context }`. `enc` goes to the recipient with
 * the messages; `context.seal()` encrypts them.
 *
 * opts (all optional): `psk` + `psk_id` (psk modes), `sender_private_key`
 * (auth modes), `ephemeral` — a `{ private_key, public_key }` to use in
 * place of a fresh one, for test vectors only.
 */
function setup_sender(suite, recipient_public_key, info, opts) {
  opts = opts || {};
  var mode = mode_of(opts);
  var r = kem_encap(suite.kem, recipient_public_key, opts.sender_private_key || null, opts.ephemeral || null);
  var ctx = key_schedule(suite, mode, r.shared_secret, opt_bytes(info), opt_bytes(opts.psk), opt_bytes(opts.psk_id), 'sender');
  return { enc: r.enc, context: ctx };
}

/**
 * The recipient's side: the context to `open()` with. Throws when `enc` is
 * not a valid public key; a wrong key or info shows as `open()` → null.
 *
 * opts: `psk` + `psk_id`, `sender_public_key` (auth modes),
 * `recipient_public_key` — the public key of `recipient_private_key`, when
 * known, saving a scalar multiplication per setup (it must be that key's).
 */
function setup_recipient(suite, enc, recipient_private_key, info, opts) {
  opts = opts || {};
  var mode = mode_of(opts);
  var ss = kem_decap(suite.kem, opt_bytes(enc), recipient_private_key, opts.sender_public_key || null,
                     opts.recipient_public_key || null);
  return key_schedule(suite, mode, ss, opt_bytes(info), opt_bytes(opts.psk), opt_bytes(opts.psk_id), 'recipient');
}

/** Single-shot (§6.1): one message. `{ enc, ct }`. */
function hpke_seal(suite, recipient_public_key, info, aad, pt, opts) {
  var s = setup_sender(suite, recipient_public_key, info, opts);
  return { enc: s.enc, ct: s.context.seal(aad, pt) };
}

/** Single-shot (§6.1): the plaintext, or null. */
function hpke_open(suite, enc, recipient_private_key, info, aad, ct, opts) {
  var ctx;
  try { ctx = setup_recipient(suite, enc, recipient_private_key, info, opts); }
  catch (e) { return null; }
  return ctx.open(aad, ct);
}

/** A new key pair for `kem_id`: `{ private_key, public_key }`, raw bytes. */
function hpke_generate_key_pair(kem_id) {
  var kem = KEMS[kem_id];
  if (!kem) throw new Error('HPKE: unsupported KEM 0x' + (kem_id >>> 0).toString(16));
  return kem_generate_key_pair(kem);
}

/** The key pair `ikm` determines (§7.1.3). */
function hpke_derive_key_pair(kem_id, ikm) {
  var kem = KEMS[kem_id];
  if (!kem) throw new Error('HPKE: unsupported KEM 0x' + (kem_id >>> 0).toString(16));
  return kem_derive_key_pair(kem, opt_bytes(ikm));
}

/** The public key of a private key. */
function hpke_public_key(kem_id, private_key) {
  var kem = KEMS[kem_id];
  if (!kem) throw new Error('HPKE: unsupported KEM 0x' + (kem_id >>> 0).toString(16));
  return kem.public_key(private_key);
}

export {
  MODE_BASE, MODE_PSK, MODE_AUTH, MODE_AUTH_PSK,
  hpke_suite,
  is_supported_hpke_suite,
  setup_sender,
  setup_recipient,
  hpke_seal,
  hpke_open,
  hpke_generate_key_pair,
  hpke_derive_key_pair,
  hpke_public_key,
};
