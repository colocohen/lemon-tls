/**
 * ECDH key generation and shared secret helpers using node:crypto.
 * X25519, P-256 and P-384; ML-KEM alone and in hybrids with them (below).
 */

import * as crypto from 'crypto';

// DER prefixes for raw X25519 key import/export
let X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
let X25519_SPKI_PREFIX  = Buffer.from('302a300506032b656e032100', 'hex');

/**
 * Derive the X25519 public key from a 32-byte private key.
 */
function x25519_get_public_key(privateKeyRaw) {
  let der = Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(privateKeyRaw)]);
  let privObj = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  let pubObj = crypto.createPublicKey(privObj);
  let spki = pubObj.export({ type: 'spki', format: 'der' });
  return new Uint8Array(spki.subarray(X25519_SPKI_PREFIX.length));
}

/**
 * Compute X25519 shared secret from local private key and remote public key (both raw 32 bytes).
 */
function x25519_get_shared_secret(localPrivateRaw, remotePublicRaw) {
  let privDer = Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(localPrivateRaw)]);
  let pubDer  = Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(remotePublicRaw)]);
  let privObj = crypto.createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  let pubObj  = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
  let secret  = new Uint8Array(crypto.diffieHellman({ privateKey: privObj, publicKey: pubObj }));

  // RFC 7748 §6.1: implementations MUST reject an all-zero shared secret. A peer
  // that sends a low-order/small-order public key can force the X25519 result to
  // be all zeros — a value it knows in advance — which would let it choose the
  // key material. The `break` here is safe (does not leak a secret): the peer's
  // public key is public, so an early exit reveals nothing exploitable.
  let allZero = true;
  for (let i = 0; i < secret.length; i++) {
    if (secret[i] !== 0) { allZero = false; break; }
  }
  if (allZero) {
    throw new Error('X25519: all-zero shared secret — invalid peer public key (RFC 7748 §6.1)');
  }

  return secret;
}

/**
 * Generate a P-256 keypair. Returns { private_key: Uint8Array, public_key: Uint8Array(65) }.
 * Public key is uncompressed format (0x04 || x || y).
 */
function p256_generate_keypair() {
  let ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return {
    private_key: new Uint8Array(ecdh.getPrivateKey()),
    public_key: new Uint8Array(ecdh.getPublicKey(null, 'uncompressed'))
  };
}

/**
 * Compute P-256 shared secret (raw x-coordinate, 32 bytes).
 */
function p256_get_shared_secret(localPrivateRaw, remotePublicRaw) {
  let ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(localPrivateRaw));
  return new Uint8Array(ecdh.computeSecret(Buffer.from(remotePublicRaw)));
}

/**
 * Generate a P-384 keypair. Returns { private_key: Uint8Array(48), public_key: Uint8Array(97) }.
 * Public key is uncompressed format (0x04 || x || y).
 */
function p384_generate_keypair() {
  let ecdh = crypto.createECDH('secp384r1');
  ecdh.generateKeys();
  return {
    private_key: new Uint8Array(ecdh.getPrivateKey()),
    public_key: new Uint8Array(ecdh.getPublicKey(null, 'uncompressed'))
  };
}

/**
 * Compute P-384 shared secret (raw x-coordinate, 48 bytes).
 */
function p384_get_shared_secret(localPrivateRaw, remotePublicRaw) {
  let ecdh = crypto.createECDH('secp384r1');
  ecdh.setPrivateKey(Buffer.from(localPrivateRaw));
  return new Uint8Array(ecdh.computeSecret(Buffer.from(remotePublicRaw)));
}

/**
 * Named groups this module actually implements, in preference order.
 *
 * SINGLE SOURCE OF TRUTH: consumers (TLSSession defaults, TLSSocket options,
 * DTLSSession) must derive their advertised supported_groups from this list
 * rather than hardcoding their own. Previously three call sites carried three
 * different hardcoded lists — DTLS advertised P-384 while TLS did not, even
 * though the code below has supported it all along, so a peer offering only
 * P-384 got "no curve supported by both" from a stack that could do P-384.
 *
 * Adding a curve should be a change to THIS file only.
 */
const NAMED_GROUP = {
  X25519:    0x001d,
  SECP256R1: 0x0017,
  SECP384R1: 0x0018,
  // Post-quantum. KEMs, not Diffie-Hellman: the server does not make a key
  // pair of its own, it ENCAPSULATES to the client's — see kem_server_exchange.
  //   Hybrids (draft-ietf-tls-ecdhe-mlkem): ML-KEM (FIPS 203) and an ECDH
  //   group together, safe if either one holds. X25519MLKEM768 is what Chrome,
  //   Firefox, Safari and Cloudflare negotiate; the two NIST-curve hybrids are
  //   for deployments that must use approved curves.
  X25519MLKEM768:     0x11ec,
  SECP256R1MLKEM768:  0x11eb,
  SECP384R1MLKEM1024: 0x11ed,
  //   ML-KEM alone (draft-ietf-tls-mlkem): no classical half. MLKEM1024 is
  //   CNSA 2.0's key exchange.
  MLKEM512:  0x0200,
  MLKEM768:  0x0201,
  MLKEM1024: 0x0202,
};

// Each group's name — the IANA registry's, as OpenSSL and node:tls spell them.
const GROUP_NAMES = {
  0x001d: 'X25519', 0x0017: 'P-256', 0x0018: 'P-384',
  0x11ec: 'X25519MLKEM768', 0x11eb: 'SecP256r1MLKEM768', 0x11ed: 'SecP384r1MLKEM1024',
  0x0200: 'MLKEM512', 0x0201: 'MLKEM768', 0x0202: 'MLKEM1024',
};
function group_name(group) { return GROUP_NAMES[group] || null; }

// ML-KEM's three parameter sets (FIPS 203 Table 3): encapsulation key and
// ciphertext sizes. The shared secret is 32 bytes for each.
const MLKEM = {
  512:  { type: 'ml-kem-512',  ek: 800,  ct: 768 },
  768:  { type: 'ml-kem-768',  ek: 1184, ct: 1088 },
  1024: { type: 'ml-kem-1024', ek: 1568, ct: 1568 },
};

// The classical halves of the hybrids: a share's size, a key pair, a secret.
const ECDH_PART = {
  x25519: { len: 32,
            generate: function () { let priv = new Uint8Array(crypto.randomBytes(32)); return { private_key: priv, public_key: x25519_get_public_key(priv) }; },
            shared: function (priv, pub) { return x25519_get_shared_secret(priv, pub); } },
  p256:   { len: 65, generate: function () { return p256_generate_keypair(); },
            shared: function (priv, pub) { check_point(pub, 65); return p256_get_shared_secret(priv, pub); } },
  p384:   { len: 97, generate: function () { return p384_generate_keypair(); },
            shared: function (priv, pub) { check_point(pub, 97); return p384_get_shared_secret(priv, pub); } },
};
function check_point(pub, len) {
  if (pub.length !== len || pub[0] !== 0x04) throw new Error('the ECDH part must be a ' + len + '-byte uncompressed point');
}

// The KEM groups: which ML-KEM, which ECDH half (none for ML-KEM alone), and
// which comes first — in X25519MLKEM768 the ML-KEM part leads, in both shares
// and in the shared secret (the draft's one exception, kept for the Kyber
// deployments); in the two NIST-curve hybrids the ECDH part leads.
const KEM_GROUPS = {
  0x11ec: { kem: 768,  ecdh: 'x25519', kemFirst: true },
  0x11eb: { kem: 768,  ecdh: 'p256',   kemFirst: false },
  0x11ed: { kem: 1024, ecdh: 'p384',   kemFirst: false },
  0x0200: { kem: 512 },
  0x0201: { kem: 768 },
  0x0202: { kem: 1024 },
};

// ML-KEM comes from node:crypto (crypto.encapsulate / decapsulate) and from
// nothing else: Node 24.7+ on OpenSSL 3.5, and Electron once its Node has the
// BoringSSL wiring (Node 24.18+). A parameter set node:crypto lacks makes its
// groups simply not implemented — not offered, not accepted.
//
// Decided once per parameter set, by a real round trip rather than by the
// functions existing (on BoringSSL, crypto.encapsulate can be defined and
// still not know ML-KEM) — and the raw key's SPKI wrapping taken from the key
// made: a fixed DER prefix, as for X25519 above.
const MLKEM_SPKI_PREFIX = {};
function probe_mlkem(bits) {
  if (typeof crypto.encapsulate !== 'function' || typeof crypto.decapsulate !== 'function') return false;
  try {
    let p = MLKEM[bits];
    let kp = crypto.generateKeyPairSync(p.type);
    let enc = crypto.encapsulate(kp.publicKey);
    let dec = crypto.decapsulate(kp.privateKey, enc.ciphertext);
    if (enc.ciphertext.length !== p.ct || Buffer.compare(Buffer.from(enc.sharedKey), Buffer.from(dec)) !== 0) return false;
    let spki = kp.publicKey.export({ format: 'der', type: 'spki' });
    MLKEM_SPKI_PREFIX[bits] = Buffer.from(spki.subarray(0, spki.length - p.ek));
    return true;
  } catch (e) {
    return false;
  }
}
const MLKEM_SETS = { 512: probe_mlkem(512), 768: probe_mlkem(768), 1024: probe_mlkem(1024) };
const MLKEM_AVAILABLE = MLKEM_SETS[768];

// Import checks the key (FIPS 203 §7.2: every coefficient below q) and throws
// on a bad one — before any secret exists.
function mlkem_public_key(bits, raw) {
  return crypto.createPublicKey({ key: Buffer.concat([MLKEM_SPKI_PREFIX[bits], Buffer.from(raw)]), format: 'der', type: 'spki' });
}

function kem_group_available(group) {
  let d = KEM_GROUPS[group];
  return !!(d && MLKEM_SETS[d.kem]);
}
// The sizes of a KEM group's shares: the client's (encapsulation key and
// ECDH public key) and the server's (ciphertext and ECDH public key).
function kem_sizes(group) {
  let d = KEM_GROUPS[group], m = MLKEM[d.kem], e = d.ecdh ? ECDH_PART[d.ecdh].len : 0;
  return { client: m.ek + e, server: m.ct + e, ek: m.ek, ct: m.ct, ecdh: e };
}

// A client's default offer: the hybrid post-quantum group first where
// node:crypto has ML-KEM, then the classical groups — what node:tls offers by
// default (OpenSSL 3.5: X25519MLKEM768 and X25519 shares) and Chrome and
// Firefox do. With the hybrid first, an X25519 share goes beside it
// (tls_session), so a classical server costs no extra round trip. The cost:
// a ClientHello of ~1.4 KB rather than ~0.3 (two QUIC Initial packets), and
// key generation of ~0.1 ms — node:crypto's, native. Without ML-KEM (Node
// before 24.7), the classical groups alone, X25519 first. The other
// post-quantum groups are there to ask for (ecdhCurve), not offered unasked:
// each is another 1–1.7 KB in every ClientHello.
const SUPPORTED_GROUPS = (MLKEM_AVAILABLE ? [NAMED_GROUP.X25519MLKEM768] : []).concat([
  NAMED_GROUP.X25519,     // preferred classical: fastest, no point validation pitfalls
  NAMED_GROUP.SECP256R1,
  NAMED_GROUP.SECP384R1,
]);

// A server's default preference: every post-quantum group node:crypto can do,
// first — the hybrids (X25519MLKEM768 first: what browsers send), then
// ML-KEM alone, strongest first — then the classical ones. A client that
// offers any post-quantum group gets one (tls_session: its first, by its own
// order, with a HelloRetryRequest when it sent no share for it); any other
// client gets the classical group it asked for.
const SERVER_DEFAULT_GROUPS = [
  NAMED_GROUP.X25519MLKEM768, NAMED_GROUP.SECP256R1MLKEM768, NAMED_GROUP.SECP384R1MLKEM1024,
  NAMED_GROUP.MLKEM1024, NAMED_GROUP.MLKEM768, NAMED_GROUP.MLKEM512,
].filter(kem_group_available).concat([
  NAMED_GROUP.X25519,
  NAMED_GROUP.SECP256R1,
  NAMED_GROUP.SECP384R1,
]);

// Everything implemented here, on either side. A KEM group only where
// node:crypto has its ML-KEM — a list that names it anyway (a hardcoded server
// list, a client's options.groups) has it skipped, as with any unimplemented
// group.
const IMPLEMENTED_GROUPS = SERVER_DEFAULT_GROUPS;

function is_supported_group(group) {
  return IMPLEMENTED_GROUPS.indexOf(group) >= 0;
}

function is_kem_group(group) {
  return !!KEM_GROUPS[group];
}

/**
 * Generate a keypair for any supported group.
 * Returns { private_key, public_key } or null for an unsupported group.
 */
function generate_keypair(group) {
  if (group === NAMED_GROUP.X25519) return ECDH_PART.x25519.generate();
  if (group === NAMED_GROUP.SECP256R1) return p256_generate_keypair();
  if (group === NAMED_GROUP.SECP384R1) return p384_generate_keypair();
  if (kem_group_available(group)) {
    // The CLIENT side: an ML-KEM key pair, and an ECDH one for a hybrid; the
    // share is the two public keys in the group's order.
    let d = KEM_GROUPS[group], sz = kem_sizes(group);
    let kem = crypto.generateKeyPairSync(MLKEM[d.kem].type);
    let spki = kem.publicKey.export({ format: 'der', type: 'spki' });
    let ek = spki.subarray(spki.length - sz.ek);
    let ec = d.ecdh ? ECDH_PART[d.ecdh].generate() : null;
    let pub = new Uint8Array(sz.client);
    if (!ec) pub.set(ek, 0);
    else if (d.kemFirst) { pub.set(ek, 0); pub.set(ec.public_key, sz.ek); }
    else { pub.set(ec.public_key, 0); pub.set(ek, sz.ecdh); }
    return { private_key: { kem: kem.privateKey, ecdh: ec ? ec.private_key : null }, public_key: pub };
  }
  return null;
}

// The two halves of a share or a ciphertext, by the group's layout.
function split_share(group, buf, kemLen) {
  let d = KEM_GROUPS[group];
  if (!d.ecdh) return { kem: buf, ecdh: null };
  let e = ECDH_PART[d.ecdh].len;
  return d.kemFirst ? { kem: buf.subarray(0, kemLen), ecdh: buf.subarray(kemLen) }
                    : { ecdh: buf.subarray(0, e), kem: buf.subarray(e) };
}
// The shared secret: ML-KEM's and the ECDH one, concatenated in the group's
// order (draft-ietf-tls-ecdhe-mlkem §3); ML-KEM alone, its own.
function join_secret(group, kemSecret, ecdhSecret) {
  let d = KEM_GROUPS[group];
  if (!d.ecdh) return new Uint8Array(kemSecret);
  let out = new Uint8Array(kemSecret.length + ecdhSecret.length);
  if (d.kemFirst) { out.set(kemSecret, 0); out.set(ecdhSecret, kemSecret.length); }
  else { out.set(ecdhSecret, 0); out.set(kemSecret, ecdhSecret.length); }
  return out;
}

/**
 * The SERVER side of a KEM group: from the client's key share, the server's
 * key share and the shared secret, together. There is no server key pair to
 * make first — the ciphertext IS the server's share (with, for a hybrid, the
 * server's ECDH public key).
 * Throws on a malformed share; the caller turns that into illegal_parameter.
 */
function kem_server_exchange(group, clientShare) {
  if (!kem_group_available(group)) throw new Error('not an implemented KEM group: 0x' + (group >>> 0).toString(16));
  let d = KEM_GROUPS[group], sz = kem_sizes(group);
  if (!clientShare || clientShare.length !== sz.client) {
    throw new Error(group_name(group) + ' client key_exchange must be ' + sz.client + ' bytes, got ' + (clientShare ? clientShare.length : 0));
  }
  let parts = split_share(group, clientShare, sz.ek);
  let enc = crypto.encapsulate(mlkem_public_key(d.kem, parts.kem));
  let ec = null, ecdhSecret = null;
  if (d.ecdh) {
    ec = ECDH_PART[d.ecdh].generate();
    ecdhSecret = ECDH_PART[d.ecdh].shared(ec.private_key, parts.ecdh);   // throws on a bad point / all-zero X25519
  }
  let share = new Uint8Array(sz.server);
  if (!ec) share.set(enc.ciphertext, 0);
  else if (d.kemFirst) { share.set(enc.ciphertext, 0); share.set(ec.public_key, sz.ct); }
  else { share.set(ec.public_key, 0); share.set(enc.ciphertext, sz.ecdh); }
  return { public_key: share, shared_secret: join_secret(group, new Uint8Array(enc.sharedKey), ecdhSecret) };
}

/**
 * Validate a peer's key_exchange value for `group` and normalize it to the
 * form the primitives below expect.
 *
 * Point-format knowledge belongs HERE, next to the curve implementations —
 * not in the handshake state machine, which only needs to know "valid or not"
 * so it can decide whether to abort. Throws on anything malformed; the caller
 * converts that into an illegal_parameter alert.
 */
function normalize_peer_public_key(group, pub) {
  if (!pub || pub.length === 0) throw new Error('empty key_exchange');

  if (is_kem_group(group)) {
    // A client's share (encapsulation key, and the ECDH part of a hybrid) or
    // a server's (ciphertext, and the ECDH part) — nothing else. The ML-KEM
    // key's own validity is checked by encapsulate; the ECDH part by its
    // primitive.
    if (!kem_group_available(group)) throw new Error('unsupported group 0x' + (group >>> 0).toString(16));
    let sz = kem_sizes(group);
    if (pub.length !== sz.client && pub.length !== sz.server) {
      throw new Error(group_name(group) + ' key_exchange must be ' + sz.client + ' or ' + sz.server + ' bytes, got ' + pub.length);
    }
    return pub;
  }

  if (group === NAMED_GROUP.X25519) {
    if (pub.length !== 32) {
      throw new Error('X25519 key_exchange must be 32 bytes, got ' + pub.length);
    }
    return pub;
  }

  let coordLen = (group === NAMED_GROUP.SECP256R1) ? 32
               : (group === NAMED_GROUP.SECP384R1) ? 48 : 0;
  if (coordLen === 0) throw new Error('unsupported group 0x' + (group >>> 0).toString(16));

  // RFC 8446 §4.2.8.2: for the secp*r1 groups the key_exchange is an
  // UNCOMPRESSED point — 0x04 || X || Y — and nothing else. The length is
  // therefore exact.
  //
  // This used to also accept a bare X || Y (no 0x04) and re-prefix it, as a
  // tolerance for TLS 1.2 peers that strip the prefix. That tolerance is a
  // security hole, not a kindness: truncating a valid 65-byte P-256 point by
  // one byte yields exactly 64 bytes, which the tolerance then reinterpreted
  // as a DIFFERENT, prefix-less point and happily fed to the ECDH. The same
  // arithmetic applies to P-384 (97 → 96). Malformed input must be rejected,
  // not silently reinterpreted.
  let expected = 1 + 2 * coordLen;

  if (pub.length !== expected) {
    // Name the two shapes we know we are refusing, so the failure is
    // diagnosable rather than just "bad length".
    if (pub.length === 2 * coordLen) {
      throw new Error('key_exchange is missing the 0x04 uncompressed-point prefix (got ' +
        pub.length + ' bytes, expected ' + expected + ')');
    }
    if (pub.length === 1 + coordLen && (pub[0] === 0x02 || pub[0] === 0x03)) {
      throw new Error('compressed points are not permitted; key_exchange must be uncompressed (RFC 8446 §4.2.8.2)');
    }
    throw new Error('key_exchange must be a ' + expected + '-byte uncompressed point, got ' + pub.length);
  }

  if (pub[0] !== 0x04) {
    throw new Error('key_exchange must start with the 0x04 uncompressed-point marker, got 0x' +
      pub[0].toString(16));
  }

  // Whether the point actually lies on the curve is checked by the ECDH
  // primitive below (node throws ERR_CRYPTO_ECDH_INVALID_PUBLIC_KEY), which
  // happens before any secret is produced — so an off-curve point can never
  // yield key material.
  return pub;
}

/**
 * Compute the ECDHE shared secret for any supported group.
 * Validates the peer's public key first; throws on invalid input (including
 * the RFC 7748 §6.1 all-zero X25519 result and node's own on-curve checks).
 */
function get_shared_secret(group, localPrivateRaw, remotePublicRaw) {
  let pub = normalize_peer_public_key(group, remotePublicRaw);

  if (group === NAMED_GROUP.X25519)    return x25519_get_shared_secret(localPrivateRaw, pub);
  if (group === NAMED_GROUP.SECP256R1) return p256_get_shared_secret(localPrivateRaw, pub);
  if (group === NAMED_GROUP.SECP384R1) return p384_get_shared_secret(localPrivateRaw, pub);
  if (kem_group_available(group)) {
    // The CLIENT side: the server's share is the ciphertext (and, for a
    // hybrid, the server's ECDH public key), in the group's order.
    let sz = kem_sizes(group);
    if (pub.length !== sz.server) {
      throw new Error(group_name(group) + ' server key_exchange must be ' + sz.server + ' bytes, got ' + pub.length);
    }
    let d = KEM_GROUPS[group];
    let parts = split_share(group, pub, sz.ct);
    let kemShared = new Uint8Array(crypto.decapsulate(localPrivateRaw.kem, parts.kem));
    let ecdhShared = d.ecdh ? ECDH_PART[d.ecdh].shared(localPrivateRaw.ecdh, parts.ecdh) : null;
    return join_secret(group, kemShared, ecdhShared);
  }

  throw new Error('unsupported group 0x' + (group >>> 0).toString(16));
}

export {
  NAMED_GROUP,
  GROUP_NAMES,
  group_name,
  kem_group_available,
  SUPPORTED_GROUPS,
  SERVER_DEFAULT_GROUPS,
  MLKEM_AVAILABLE,
  is_supported_group,
  is_kem_group,
  kem_server_exchange,
  generate_keypair,
  normalize_peer_public_key,
  get_shared_secret,
  x25519_get_public_key,
  x25519_get_shared_secret,
  p256_generate_keypair,
  p256_get_shared_secret,
  p384_generate_keypair,
  p384_get_shared_secret
};