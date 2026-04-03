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
  return new Uint8Array(crypto.diffieHellman({ privateKey: privObj, publicKey: pubObj }));
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

export {
  x25519_get_public_key,
  x25519_get_shared_secret,
  p256_generate_keypair,
  p256_get_shared_secret,
  p384_generate_keypair,
  p384_get_shared_secret
};
