/**
 * TLS signature scheme helpers.
 * Handles scheme negotiation and signing for both TLS 1.2 and 1.3.
 */

import * as crypto from 'crypto';

let TLS_VERSION_TLS1_2 = 0x0303;
let TLS_VERSION_TLS1_3 = 0x0304;

/**
 * Decode a SignatureScheme (u16) into hash/sig/isPSS info.
 * Returns null if the scheme is unsupported for the given TLS version.
 */
function scheme_info(version, scheme) {
  let h = (scheme >>> 8) & 0xff, s = scheme & 0xff;

  // EdDSA (TLS 1.3 only)
  if (scheme === 0x0807 || scheme === 0x0808) {
    if (version === TLS_VERSION_TLS1_2) return null;
    return { hash: null, sig: 'eddsa', isPSS: false };
  }

  // TLS 1.3: RSA means RSA-PSS
  if (version === TLS_VERSION_TLS1_3) {
    if (scheme === 0x0804) return { hash: 'sha256', sig: 'rsa', isPSS: true };
    if (scheme === 0x0805) return { hash: 'sha384', sig: 'rsa', isPSS: true };
    if (scheme === 0x0806) return { hash: 'sha512', sig: 'rsa', isPSS: true };
    if (scheme === 0x0403) return { hash: 'sha256', sig: 'ecdsa', isPSS: false };
    if (scheme === 0x0503) return { hash: 'sha384', sig: 'ecdsa', isPSS: false };
    if (scheme === 0x0603) return { hash: 'sha512', sig: 'ecdsa', isPSS: false };
    return null;
  }

  // TLS 1.2: classic (hash, sig) interpretation
  if (h === 0x04 && s === 0x01) return { hash: 'sha256', sig: 'rsa',   isPSS: false };
  if (h === 0x05 && s === 0x01) return { hash: 'sha384', sig: 'rsa',   isPSS: false };
  if (h === 0x06 && s === 0x01) return { hash: 'sha512', sig: 'rsa',   isPSS: false };
  if (h === 0x04 && s === 0x03) return { hash: 'sha256', sig: 'ecdsa', isPSS: false };
  if (h === 0x05 && s === 0x03) return { hash: 'sha384', sig: 'ecdsa', isPSS: false };
  if (h === 0x06 && s === 0x03) return { hash: 'sha512', sig: 'ecdsa', isPSS: false };

  return null;
}

/**
 * Pick the best signature scheme given the server's key type and client's supported list.
 */
function pick_scheme(version, certKeyObj, clientSupported) {
  let cands = [];
  if (certKeyObj.asymmetricKeyType === 'rsa') {
    if (version === TLS_VERSION_TLS1_3) cands.push(0x0804, 0x0805, 0x0806);
    else cands.push(0x0401, 0x0501, 0x0601);
  } else if (certKeyObj.asymmetricKeyType === 'ec') {
    let c = (certKeyObj.asymmetricKeyDetails && certKeyObj.asymmetricKeyDetails.namedCurve) || '';
    if (c === 'prime256v1') cands.push(0x0403);
    if (c === 'secp384r1')  cands.push(0x0503);
    if (c === 'secp521r1')  cands.push(0x0603);
  } else if (certKeyObj.asymmetricKeyType === 'ed25519' && version === TLS_VERSION_TLS1_3) {
    cands.push(0x0807);
  } else if (certKeyObj.asymmetricKeyType === 'ed448' && version === TLS_VERSION_TLS1_3) {
    cands.push(0x0808);
  }

  let pref = (version === TLS_VERSION_TLS1_3)
    ? [0x0807, 0x0808, 0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806]
    : [0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601];

  for (let s of pref) {
    if (cands.includes(s) && clientSupported.includes(s)) return s;
  }
  return null;
}

/**
 * Sign data using the given scheme. Works for both TLS 1.2 and 1.3.
 */
function sign_with_scheme(version, scheme, tbs, certKeyObj) {
  let info = scheme_info(version, scheme);
  if (!info) return null;

  if (info.sig === 'eddsa') {
    return new Uint8Array(crypto.sign(null, tbs, certKeyObj));
  }

  if (info.sig === 'ecdsa') {
    return new Uint8Array(crypto.sign(info.hash, tbs, certKeyObj));
  }

  if (info.sig === 'rsa') {
    if (info.isPSS) {
      let saltLen = (info.hash === 'sha256') ? 32 : (info.hash === 'sha384') ? 48 : 64;
      return new Uint8Array(crypto.sign(info.hash, tbs, {
        key: certKeyObj,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: saltLen
      }));
    } else {
      return new Uint8Array(crypto.sign(info.hash, tbs, {
        key: certKeyObj,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }));
    }
  }
  return null;
}

/**
 * Normalize a public key from the wire for TLS 1.2 ECDHE.
 * P-256: add 0x04 prefix if missing. X25519: strip 0x04 prefix if present.
 */
function normalizeServerPubKeyForTls12(group, pub) {
  let p = pub;
  if (group === 0x0017) { // P-256
    if (p.length === 64) {
      const tmp = new Uint8Array(65); tmp[0] = 0x04; tmp.set(p, 1); p = tmp;
    }
  } else if (group === 0x001d) { // X25519
    if (p.length === 33 && p[0] === 0x04) p = p.slice(1);
  }
  return p;
}

export {
  scheme_info,
  pick_scheme,
  sign_with_scheme,
  normalizeServerPubKeyForTls12
};
