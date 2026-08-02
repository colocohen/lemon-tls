/**
 * TLS signature scheme helpers.
 * Handles scheme negotiation and signing for both TLS 1.2 and 1.3.
 */

import * as crypto from 'crypto';

let TLS_VERSION_TLS1_2 = 0x0303;
let TLS_VERSION_TLS1_3 = 0x0304;

/**
 * Default SignatureScheme offers, in preference order.
 *
 * SINGLE SOURCE OF TRUTH, for the same reason ecdh.js owns SUPPORTED_GROUPS:
 * this list must never advertise something scheme_info/sign_with_scheme below
 * cannot actually produce or verify, and it was previously hardcoded in three
 * consumers (TLSSession client defaults, TLSSocket server defaults,
 * DTLSSession) that could drift apart.
 *
 * MODERN covers schemes valid in both TLS 1.3 and 1.2 (RFC 8447 §3 / RFC 8422
 * §5.1.3).
 *
 * LEGACY_PKCS1 needs care, because "offer" and "use" are NOT the same thing
 * (RFC 8446 §4.2.3): signature_algorithms describes signatures we can verify,
 * and that includes the signatures ON CERTIFICATES IN THE CHAIN — which are
 * very commonly RSASSA-PKCS1-v1_5. So these MUST be advertised even in a
 * TLS 1.3-only handshake. What §4.4.3 forbids is *using* them in
 * CertificateVerify, and that is enforced separately in scheme_info (which
 * returns null for them at 1.3) and pick_scheme (whose 1.3 RSA candidates are
 * PSS only). Withholding them from the offer made peers with PKCS#1-signed
 * chains unable to authenticate at all.
 */
const SIG_SCHEMES_MODERN = [
  0x0807, 0x0808,           // ed25519, ed448
  0x0403, 0x0503, 0x0603,   // ecdsa_secp256r1/384r1/521r1
  0x0804, 0x0805, 0x0806,   // rsa_pss_rsae_sha256/384/512
];

const SIG_SCHEMES_LEGACY_PKCS1 = [
  0x0401, 0x0501, 0x0601,   // rsa_pkcs1_sha256/384/512
];

/**
 * SHA-1 schemes. Deliberately last, and deliberately still offered.
 *
 * Same offer/use split as the PKCS#1 set above, taken one step further: SHA-1
 * is unacceptable for a handshake signature, and scheme_info already refuses
 * these at TLS 1.3 so they can never be selected for CertificateVerify. But
 * signature_algorithms also describes the signatures we can verify ON
 * CERTIFICATES (RFC 8446 §4.2.3), and SHA-1-signed intermediates still exist
 * in real chains. Withholding them from the offer tells a peer we cannot
 * verify such a chain at all, which is a different — and wrong — statement
 * from "we will not sign with SHA-1".
 */
const SIG_SCHEMES_LEGACY_SHA1 = [
  0x0201,   // rsa_pkcs1_sha1
  0x0203,   // ecdsa_sha1
];

/**
 * Default offer list — the same for every version range, deliberately taking
 * no parameter.
 *
 * An earlier version accepted an "includeTls12" flag and then ignored it,
 * which is worse than having no parameter: three call sites passed three
 * different meaningful-looking values and a reader would reasonably conclude
 * the version range changed the offer. It does not.
 *
 * PKCS#1 is always offered because signature_algorithms also covers the
 * signatures ON CERTIFICATES in the chain (RFC 8446 §4.2.3). Where a scheme
 * may be USED is enforced by scheme_info / scheme_matches_key, not by
 * trimming this list.
 */
function default_signature_schemes() {
  return SIG_SCHEMES_MODERN
    .concat(SIG_SCHEMES_LEGACY_PKCS1)
    .concat(SIG_SCHEMES_LEGACY_SHA1);
}


/**
 * Decode a SignatureScheme (u16) into hash/sig/isPSS info.
 * Returns null if the scheme is unsupported for the given TLS version.
 */
function scheme_info(version, scheme) {
  let h = (scheme >>> 8) & 0xff, s = scheme & 0xff;

  // SignatureScheme codepoints are a single global registry, not per-version.
  // RFC 8446 defined them, and RFC 8447 §3 / RFC 8422 §5.1.3 make the PSS and
  // EdDSA entries usable in TLS 1.2 as well. Treating them as "TLS 1.3 only"
  // is what made a modern peer unverifiable over TLS 1.2: OpenSSL 3.x signs
  // ServerKeyExchange with rsa_pss_rsae_sha256 (0x0804) by default, and this
  // returned null for it — the signature then failed to verify not because it
  // was wrong but because we refused to describe it.
  //
  // Handled here, before the legacy (hash, sig) decoding below, so both
  // versions agree on every modern codepoint. sign_with_scheme and
  // verify_with_scheme share this function, so signing and verification can
  // never drift apart.

  // EdDSA
  if (scheme === 0x0807 || scheme === 0x0808) {
    return { hash: null, sig: 'eddsa', isPSS: false };
  }

  // RSASSA-PSS (rsa_pss_rsae_* and rsa_pss_pss_*)
  if (scheme === 0x0804 || scheme === 0x0809) return { hash: 'sha256', sig: 'rsa', isPSS: true };
  if (scheme === 0x0805 || scheme === 0x080a) return { hash: 'sha384', sig: 'rsa', isPSS: true };
  if (scheme === 0x0806 || scheme === 0x080b) return { hash: 'sha512', sig: 'rsa', isPSS: true };

  // ECDSA with a fixed curve+hash pairing
  if (scheme === 0x0403) return { hash: 'sha256', sig: 'ecdsa', isPSS: false };
  if (scheme === 0x0503) return { hash: 'sha384', sig: 'ecdsa', isPSS: false };
  if (scheme === 0x0603) return { hash: 'sha512', sig: 'ecdsa', isPSS: false };

  // TLS 1.3 forbids the legacy PKCS#1 v1.5 codepoints in CertificateVerify
  // (RFC 8446 §4.4.3); TLS 1.2 still uses them.
  if (version === TLS_VERSION_TLS1_3) return null;

  // TLS 1.2: classic (hash, sig) interpretation
  if (h === 0x02 && s === 0x01) return { hash: 'sha1',   sig: 'rsa',   isPSS: false };
  if (h === 0x04 && s === 0x01) return { hash: 'sha256', sig: 'rsa',   isPSS: false };
  if (h === 0x05 && s === 0x01) return { hash: 'sha384', sig: 'rsa',   isPSS: false };
  if (h === 0x06 && s === 0x01) return { hash: 'sha512', sig: 'rsa',   isPSS: false };
  if (h === 0x02 && s === 0x03) return { hash: 'sha1',   sig: 'ecdsa', isPSS: false };

  return null;
}

/**
 * Pick the best signature scheme given the server's key type and client's supported list.
 */
function pick_scheme(version, certKeyObj, peerSupported) {
  // Iterate the PEER's list, in the peer's own order.
  //
  // RFC 8446 §4.2.3: signature_algorithms is "in descending order of
  // preference" — it is the sender telling us what it wants, not merely what
  // it tolerates. Walking OUR order instead and taking the first entry the
  // peer happened to include inverts that: a peer asking for
  // rsa_pss_rsae_sha384 first was answered with sha256 purely because sha256
  // sits earlier in our own list. Our preference only decides among schemes
  // the peer did not rank, which is nothing — so it has no say here at all.
  //
  // scheme_matches_key does the filtering (key type, curve, and version — it
  // rejects rsa_pkcs1_* and SHA-1 at TLS 1.3 because scheme_info does), so a
  // peer cannot steer us into a scheme that is unusable with our certificate
  // or forbidden at this version just by listing it first.
  if (!Array.isArray(peerSupported) || peerSupported.length === 0) return null;

  let picked = null;
  for (let i = 0; i < peerSupported.length; i++) {
    let s2 = peerSupported[i];
    if (typeof s2 !== 'number') continue;
    if (!scheme_matches_key(version, s2, certKeyObj)) continue;
    picked = s2;
    break;
  }


  return picked;
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
 * Does `scheme` legitimately go with `keyObj`?
 *
 * SINGLE SOURCE OF TRUTH for the scheme<->key relationship, used in BOTH
 * directions: pick_scheme asks "which scheme may I use with my key" and
 * verify_with_scheme asks "may the peer's scheme be checked against its key".
 * Those are the same question, and they were previously answered by two
 * separate hand-rolled tables that had already drifted (pick_scheme still
 * restricted EdDSA to TLS 1.3 after scheme_info was corrected to allow it at
 * 1.2 per RFC 8422).
 *
 * A scheme names an algorithm AND the kind of key it may be used with
 * (RFC 8446 §4.2.3):
 *   rsa_pss_rsae_*  → plain rsaEncryption key
 *   rsa_pss_pss_*   → RSASSA-PSS key
 *   rsa_pkcs1_*     → plain RSA, and never valid in a TLS 1.3
 *                     CertificateVerify (scheme_info returns null there)
 *   ecdsa_*         → EC key on exactly the curve the scheme names
 *   ed25519/ed448   → the matching Edwards key
 * Returns false for any scheme unusable at this version, so callers get
 * version filtering for free.
 */
function scheme_matches_key(version, scheme, keyObj) {
  let info = scheme_info(version, scheme);
  if (!info || !keyObj) return false;

  let kt = keyObj.asymmetricKeyType;

  if (info.sig === 'rsa') {
    if (info.isPSS) {
      // 0x0809-0x080b are the *_pss_pss_* family; 0x0804-0x0806 are *_pss_rsae_*.
      let wantsPssKey = (scheme === 0x0809 || scheme === 0x080a || scheme === 0x080b);
      if (wantsPssKey) return kt === 'rsa-pss';
      return kt === 'rsa';
    }
    return kt === 'rsa';
  }

  if (info.sig === 'ecdsa') {
    if (kt !== 'ec') return false;
    // The curve is part of the scheme, not a free choice: signing P-256 data
    // with a P-384 key (or vice versa) is a type confusion the RFC forbids.
    let curve = null;
    try {
      curve = keyObj.asymmetricKeyDetails && keyObj.asymmetricKeyDetails.namedCurve;
    } catch (e) { curve = null; }
    if (!curve) return true;   // unknown curve metadata — let the crypto layer decide
    let want = (scheme === 0x0403) ? 'prime256v1'
             : (scheme === 0x0503) ? 'secp384r1'
             : (scheme === 0x0603) ? 'secp521r1' : null;
    return want === null || curve === want;
  }

  if (info.sig === 'eddsa') {
    if (scheme === 0x0807) return kt === 'ed25519';
    if (scheme === 0x0808) return kt === 'ed448';
    return false;
  }

  return false;
}

/**
 * Verify a signature made with the given scheme. The exact mirror of
 * sign_with_scheme — same scheme decoding, same padding/salt rules — so the
 * two can never drift apart.
 *
 * @param version   negotiated TLS version (0x0303 / 0x0304)
 * @param scheme    SignatureScheme from the wire (NOT a locally chosen one)
 * @param tbs       the exact bytes that were signed
 * @param publicKey crypto.KeyObject of the peer's certificate public key
 * @param signature signature bytes from the wire
 * @returns {boolean} true only if the signature verifies
 */
function verify_with_scheme(version, scheme, tbs, publicKey, signature) {
  let info = scheme_info(version, scheme);
  if (!info) return false;

  // Scheme<->key binding is one named concept (see scheme_matches_key),
  // shared with pick_scheme so the two can never disagree.
  if (!scheme_matches_key(version, scheme, publicKey)) return false;

  try {
    if (info.sig === 'eddsa') {
      return crypto.verify(null, tbs, publicKey, signature);
    }

    if (info.sig === 'ecdsa') {
      // node's default DER encoding is what TLS uses for ECDSA signatures.
      return crypto.verify(info.hash, tbs, publicKey, signature);
    }

    if (info.sig === 'rsa') {
      if (info.isPSS) {
        let saltLen = (info.hash === 'sha256') ? 32 : (info.hash === 'sha384') ? 48 : 64;
        return crypto.verify(info.hash, tbs, {
          key: publicKey,
          padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
          saltLength: saltLen
        }, signature);
      }
      return crypto.verify(info.hash, tbs, {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING
      }, signature);
    }
  } catch (e) {
    // Malformed signature encoding (bad DER, wrong size, ...) — node throws
    // rather than returning false. A throw here is still a verification
    // failure, never an acceptance.
    return false;
  }

  return false;
}

export {
  scheme_info,
  pick_scheme,
  sign_with_scheme,
  verify_with_scheme,
  SIG_SCHEMES_MODERN,
  SIG_SCHEMES_LEGACY_PKCS1,
  SIG_SCHEMES_LEGACY_SHA1,
  default_signature_schemes
};
