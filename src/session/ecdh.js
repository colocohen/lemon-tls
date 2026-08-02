/**
 * ECDH key generation and shared secret helpers using node:crypto.
 * Supports X25519 and P-256 (secp256r1).
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
};

const SUPPORTED_GROUPS = [
  NAMED_GROUP.X25519,     // preferred: fastest, no point validation pitfalls
  NAMED_GROUP.SECP256R1,
  NAMED_GROUP.SECP384R1,
];

function is_supported_group(group) {
  return SUPPORTED_GROUPS.indexOf(group) >= 0;
}

/**
 * Generate a keypair for any supported group.
 * Returns { private_key, public_key } or null for an unsupported group.
 */
function generate_keypair(group) {
  if (group === NAMED_GROUP.X25519) {
    let priv = new Uint8Array(crypto.randomBytes(32));
    return { private_key: priv, public_key: x25519_get_public_key(priv) };
  }
  if (group === NAMED_GROUP.SECP256R1) return p256_generate_keypair();
  if (group === NAMED_GROUP.SECP384R1) return p384_generate_keypair();
  return null;
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

  throw new Error('unsupported group 0x' + (group >>> 0).toString(16));
}

export {
  NAMED_GROUP,
  SUPPORTED_GROUPS,
  is_supported_group,
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
