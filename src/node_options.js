// ============================================================
//  node:tls option strings → the codes lemon-tls works with
// ============================================================
//
// node:tls takes `ciphers`, `ecdhCurve` and `sigalgs` as OpenSSL strings,
// colon-separated; lemon-tls works with code points (allowedCipherSuites,
// groups, signatureAlgorithms). compat.js promised Node's API and never read
// the three — a server given `ciphers` or `ecdhCurve` ran with the defaults
// and said nothing. These turn them into the lists, once, where an option is
// taken (compat.js, and QUICO for both TCP and QUIC), and refuse what cannot
// be honoured, as Node does ("no cipher match", "Failed to set ECDH curve").
//
// What is understood:
//   ciphers    suite names — OpenSSL's for TLS 1.2 (ECDHE-RSA-AES128-GCM-SHA256)
//              and the standard ones (TLS_AES_128_GCM_SHA256, or for 1.2
//              TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256), in the order given;
//              `!name` / `-name` take one out; DEFAULT, HIGH and ALL stand for
//              every suite this library implements — it implements no weak
//              ones. Other OpenSSL keywords (aNULL, MD5, …) select nothing
//              here and are skipped: what remains must name something.
//   ecdhCurve  'auto' (the default list) or names: X25519, P-256
//              (prime256v1, secp256r1), P-384 (secp384r1), and post-quantum:
//              X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024,
//              MLKEM512, MLKEM768, MLKEM1024 (OpenSSL's names; case ignored).
//   sigalgs    scheme names (ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256,
//              ed25519, …) or OpenSSL's SIG+HASH form (ECDSA+SHA256,
//              RSA-PSS+SHA256, RSA+SHA256).

import { TLS_CIPHER_SUITES, DEFAULT_CIPHER_SUITES_TLS13, DEFAULT_CIPHER_SUITES_TLS12 } from './crypto.js';
import { SERVER_DEFAULT_GROUPS } from './session/ecdh.js';
import { MLDSA_AVAILABLE } from './session/signing.js';

function splitList(s) {
  return String(s).split(/[:,\s]+/).filter(function (x) { return x !== ''; });
}

var cipherByName = null;
function cipherTable() {
  if (cipherByName) return cipherByName;
  cipherByName = {};
  for (var code in TLS_CIPHER_SUITES) {
    var info = TLS_CIPHER_SUITES[code];
    if (info.name) cipherByName[info.name.toUpperCase()] = Number(code);
    if (info.standardName) cipherByName[info.standardName.toUpperCase()] = Number(code);
  }
  return cipherByName;
}

/** `ciphers` → [code, …] in the order given. Throws when nothing is left. */
function parseCiphers(str) {
  if (str === undefined || str === null) return null;
  if (typeof str !== 'string') throw new TypeError('ciphers must be a string, got ' + typeof str);
  var table = cipherTable(), all = DEFAULT_CIPHER_SUITES_TLS13.concat(DEFAULT_CIPHER_SUITES_TLS12);
  var out = [], removed = [];
  var tokens = splitList(str);
  for (var i = 0; i < tokens.length; i++) {
    var t = tokens[i], neg = t[0] === '!' || t[0] === '-';
    if (neg || t[0] === '+') t = t.slice(1);
    var u = t.toUpperCase(), codes;
    if (u === 'DEFAULT' || u === 'HIGH' || u === 'ALL') codes = all;
    else if (u in table) codes = [table[u]];
    else continue;                                   // a keyword this library has nothing for
    for (var j = 0; j < codes.length; j++) {
      if (neg) { removed.push(codes[j]); var k = out.indexOf(codes[j]); if (k >= 0) out.splice(k, 1); }
      else if (out.indexOf(codes[j]) < 0 && removed.indexOf(codes[j]) < 0) out.push(codes[j]);
    }
  }
  if (out.length === 0) throw new Error('ciphers: no cipher match in "' + str + '"');
  return out;
}

var GROUPS = {
  'X25519': 0x001d,
  'P-256': 0x0017, 'PRIME256V1': 0x0017, 'SECP256R1': 0x0017,
  'P-384': 0x0018, 'SECP384R1': 0x0018,
  'X25519MLKEM768': 0x11ec,
  'SECP256R1MLKEM768': 0x11eb, 'SECP384R1MLKEM1024': 0x11ed,
  'MLKEM512': 0x0200, 'MLKEM768': 0x0201, 'MLKEM1024': 0x0202,
};

/** `ecdhCurve` → [group, …]; 'auto' → null, the role's own default list
 *  (a server's has the hybrid first, a client's does not offer it unasked).
 *  Throws on a name it does not implement. */
function parseEcdhCurve(str) {
  if (str === undefined || str === null) return null;
  if (typeof str !== 'string') throw new TypeError('ecdhCurve must be a string, got ' + typeof str);
  if (str.trim().toLowerCase() === 'auto') return null;
  var out = [], tokens = splitList(str);
  for (var i = 0; i < tokens.length; i++) {
    var g = GROUPS[tokens[i].toUpperCase()];
    if (g === undefined) throw new Error('ecdhCurve: unsupported curve "' + tokens[i] + '"');
    // The hybrid group only where node:crypto has ML-KEM (session/ecdh.js).
    if (SERVER_DEFAULT_GROUPS.indexOf(g) < 0) throw new Error('ecdhCurve: "' + tokens[i] + '" is not available in this Node.js');
    if (out.indexOf(g) < 0) out.push(g);
  }
  if (out.length === 0) throw new Error('ecdhCurve: no curve in "' + str + '"');
  return out;
}

var SCHEMES = {
  'RSA_PKCS1_SHA256': 0x0401, 'RSA_PKCS1_SHA384': 0x0501, 'RSA_PKCS1_SHA512': 0x0601,
  'ECDSA_SECP256R1_SHA256': 0x0403, 'ECDSA_SECP384R1_SHA384': 0x0503, 'ECDSA_SECP521R1_SHA512': 0x0603,
  'RSA_PSS_RSAE_SHA256': 0x0804, 'RSA_PSS_RSAE_SHA384': 0x0805, 'RSA_PSS_RSAE_SHA512': 0x0806,
  'ED25519': 0x0807, 'ED448': 0x0808,
  'RSA_PSS_PSS_SHA256': 0x0809, 'RSA_PSS_PSS_SHA384': 0x080a, 'RSA_PSS_PSS_SHA512': 0x080b,
  // ML-DSA (FIPS 204), as OpenSSL names it.
  'MLDSA44': 0x0904, 'MLDSA65': 0x0905, 'MLDSA87': 0x0906,
  // OpenSSL's SIG+HASH spelling.
  'ECDSA+SHA256': 0x0403, 'ECDSA+SHA384': 0x0503, 'ECDSA+SHA512': 0x0603,
  'RSA-PSS+SHA256': 0x0804, 'RSA-PSS+SHA384': 0x0805, 'RSA-PSS+SHA512': 0x0806,
  'RSA+SHA256': 0x0401, 'RSA+SHA384': 0x0501, 'RSA+SHA512': 0x0601,
};

/** `sigalgs` → [scheme, …]. Throws on a name it does not know. */
function parseSigalgs(str) {
  if (str === undefined || str === null) return null;
  if (typeof str !== 'string') throw new TypeError('sigalgs must be a string, got ' + typeof str);
  var out = [], tokens = splitList(str);
  for (var i = 0; i < tokens.length; i++) {
    var s = SCHEMES[tokens[i].toUpperCase()];
    if (s === undefined) throw new Error('sigalgs: unsupported signature algorithm "' + tokens[i] + '"');
    // ML-DSA only where node:crypto has it (session/signing.js).
    if (s >= 0x0904 && s <= 0x0906 && !MLDSA_AVAILABLE) throw new Error('sigalgs: "' + tokens[i] + '" is not available in this Node.js');
    if (out.indexOf(s) < 0) out.push(s);
  }
  if (out.length === 0) throw new Error('sigalgs: none in "' + str + '"');
  return out;
}

/** 'TLSv1.2' / 'TLSv1.3' → 0x0303 / 0x0304, as node:tls names them. */
function parseTlsVersion(v, name) {
  if (v === undefined || v === null) return null;
  if (v === 'TLSv1.3') return 0x0304;
  if (v === 'TLSv1.2') return 0x0303;
  throw new Error(name + ': "' + v + '" is not supported (TLSv1.2 or TLSv1.3)');
}

export { parseCiphers, parseEcdhCurve, parseSigalgs, parseTlsVersion };
