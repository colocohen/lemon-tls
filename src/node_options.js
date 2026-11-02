// ============================================================
//  node:tls option strings → the codes lemon-tls works with
// ============================================================
//
// node:tls takes `ciphers`, `ecdhCurve` and `sigalgs` as OpenSSL strings,
// colon-separated; lemon-tls works with code points (allowedCipherSuites,
// groups, signatureAlgorithms). compat.js promised Node's API and never read
// the three — a server given `ciphers` or `ecdhCurve` ran with the defaults
// and said nothing. These turn them into the lists, once, where an option is
// taken (compat.js, and a layer above for its own transports), and refuse what cannot
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

import { TLS_CIPHER_SUITES, DEFAULT_CIPHER_SUITES_TLS13, DEFAULT_CIPHER_SUITES_TLS12, is_usable_cipher_suite, default_cipher_suites } from './crypto.js';
import { SERVER_DEFAULT_GROUPS, GROUP_NAMES } from './session/ecdh.js';
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

/**
 * A list of cipher-suite code points (allowedCipherSuites; DTLS cipherSuites)
 * → the suites of it this library carries, in the order given; null when not
 * given. Throws when none is, as `ciphers` does ("no cipher match"): a list of
 * only suites it does not carry (RSA key transport, DHE, CBC — removed) left
 * the server with nothing to choose and no alert to send, and the handshake
 * stalled until the client gave up.
 */
function checkCipherSuites(list, name) {
  if (list === undefined || list === null) return null;
  if (!Array.isArray(list)) throw new TypeError(name + ' must be an array of cipher-suite code points');
  var out = [];
  for (var i = 0; i < list.length; i++) {
    var c = list[i];
    if (Number.isInteger(c) && is_usable_cipher_suite(c) && out.indexOf(c) < 0) out.push(c);
  }
  if (out.length === 0) {
    throw new Error(name + ': no cipher match in [' + list.map(function (c) { return '0x' + (Number(c) >>> 0).toString(16).padStart(4, '0'); }).join(', ') +
      '] — this library carries TLS 1.3 suites and TLS 1.2 ECDHE with AES-GCM or ChaCha20-Poly1305');
  }
  return out;
}

// The groups by name: the registry's (session/ecdh.js, GROUP_NAMES) and
// OpenSSL's curve names for the NIST ones.
var GROUPS = (function () {
  var out = {};
  for (var code in GROUP_NAMES) out[GROUP_NAMES[code].toUpperCase()] = Number(code);
  var aliases = { 'PRIME256V1': 0x0017, 'SECP256R1': 0x0017, 'SECP384R1': 0x0018, 'SECP521R1': 0x0019 };
  for (var a in aliases) out[a] = aliases[a];
  return out;
})();

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

// ---- versions ----
//
// minVersion / maxVersion → the versions offered (or taken), newest first:
// one reading for TLSSocket (client and server) and DTLSSession, which each
// had their own — a lenient parser on one side, inline string compares on
// the other that took an unknown name silently. Names as node:tls spells
// them (TLSv1.2, TLSv1.3) and their DTLS twins (DTLSv1.2, DTLSv1.3; a TLS
// name is taken for its DTLS twin), or a version's code point. A minimum
// below 1.2 (node:tls's 'TLSv1', 'TLSv1.1') starts at 1.2, the oldest here;
// anything else unknown is an error, as node:tls throws for it.
var VERSION_RANKS = { 'TLSV1': 1, 'TLSV1.1': 2, 'TLSV1.2': 3, 'TLSV1.3': 4, 'DTLSV1': 2, 'DTLSV1.2': 3, 'DTLSV1.3': 4 };
function versionRank(v, name) {
  if (v === undefined || v === null) return null;
  if (typeof v === 'number') {
    if (v >= 0x0301 && v <= 0x0304) return v - 0x0300;
    if (v === 0xfeff) return 2;
    if (v === 0xfefd) return 3;
    if (v === 0xfefc) return 4;
  } else if (typeof v === 'string' && VERSION_RANKS[v.toUpperCase()] !== undefined) {
    return VERSION_RANKS[v.toUpperCase()];
  }
  throw new Error(name + ': "' + v + '" is not a TLS version (TLSv1.2, TLSv1.3, DTLSv1.2, DTLSv1.3)');
}
/** [code, …] of (D)TLS 1.3 and 1.2 within [min, max], newest first; throws when none is. */
function versionsInRange(min, max, dtls) {
  var lo = Math.max(3, versionRank(min, 'minVersion') || 3), hi = versionRank(max, 'maxVersion') || 4;
  var out = [];
  if (lo <= 4 && hi >= 4) out.push(dtls ? 0xfefc : 0x0304);
  if (lo <= 3 && hi >= 3) out.push(dtls ? 0xfefd : 0x0303);
  if (out.length === 0) throw new Error('minVersion ' + min + ', maxVersion ' + max + ': no version this library has (1.2, 1.3) in between');
  return out;
}
/** 'TLSv1.2' / 'TLSv1.3' → 0x0303 / 0x0304 (null when not given). */
function parseTlsVersion(v, name) {
  var r = versionRank(v, name || 'version');
  if (r === null) return null;
  if (r < 3) throw new Error((name || 'version') + ': "' + v + '" is not supported (TLSv1.2 or TLSv1.3)');
  return 0x0300 + r;
}

// ---- the lists a session negotiates with, from the options ----
//
// One function for TLS over TCP (TLSSocket, both roles) and DTLS
// (DTLSSession), which each built them — and differently: a DTLS server
// took no signatureAlgorithms, no prioritizeChaCha, no allowedCipherSuites.
// Only what the options say: what they leave out, TLSSession fills by its
// role (fill_default_lists). The names are TLSSocket's; DTLS's older ones —
// cipherSuites, alpnProtocols — taken as the same.
// The suites to negotiate with, in preference order: those of `allowed`
// (allowedCipherSuites, cipherSuites, or `ciphers` parsed) that the versions
// in range can use, IN THE ORDER GIVEN — the order is the preference, as
// node:tls takes `ciphers`; or, without a list, `defaults`. Then
// prioritizeChaCha moves the ChaCha20-Poly1305 suites to the front.
//
// The list only filtered the defaults, and kept their order: a server could
// not prefer AES-256 to AES-128 (honorCipherOrder took our order, and ours
// was always the default one — BoGo TLS13-Server-StrictPreference), and a
// client offered its suites in the default order, whatever it listed.
function chooseCipherSuites(defaults, prioritizeChaCha, allowed) {
  var ciphers = allowed ? allowed.filter(function (c) { return defaults.indexOf(c) >= 0; }) : defaults.slice();
  if (prioritizeChaCha) {
    var isChaCha = function (c) { return !!TLS_CIPHER_SUITES[c] && TLS_CIPHER_SUITES[c].cipher === 'CHACHA20_POLY1305'; };
    ciphers = ciphers.filter(isChaCha).concat(ciphers.filter(function (c) { return !isChaCha(c); }));
  }
  return ciphers;
}
function localLists(options, versions) {
  var out = { local_supported_versions: versions };
  var allowed = checkCipherSuites(options.allowedCipherSuites != null ? options.allowedCipherSuites : options.cipherSuites,
                                  options.allowedCipherSuites != null ? 'allowedCipherSuites' : 'cipherSuites');
  if (allowed || options.prioritizeChaCha) {
    var has13 = versions.some(function (v) { return v === 0x0304 || v === 0xfefc; });
    var has12 = versions.some(function (v) { return v === 0x0303 || v === 0xfefd; });
    out.local_supported_cipher_suites = chooseCipherSuites(default_cipher_suites(has13, has12), options.prioritizeChaCha, allowed);
    // Narrowed to nothing for these versions (1.3 suites only, a 1.2-only
    // profile): as the list with nothing in it at all.
    if (out.local_supported_cipher_suites.length === 0) throw new Error('allowedCipherSuites: no cipher match for the versions in range');
  }
  if (options.groups) out.local_supported_groups = options.groups.slice();
  if (options.signatureAlgorithms) out.local_supported_signature_algorithms = options.signatureAlgorithms.slice();
  var alpn = options.ALPNProtocols || options.alpnProtocols;
  if (Array.isArray(alpn) && alpn.length > 0) {
    out.local_supported_alpns = alpn.map(function (p) { return Buffer.isBuffer(p) ? p.toString('latin1') : String(p); });
  }
  return out;
}

// External PSK at the socket layers (TLSSocket, DTLSSocket), as node:tls
// takes it, to what the session takes (TLSSession, DTLSSession). Client:
// pskCallback(hint) → { psk, identity } or null, asked once — TLS 1.3 has no
// identity hint, so hint is null, as in Node — or the psk option itself.
// Server: pskCallback(socket, identity) → the key (or { psk, hash }), or
// null; the identity as a string, as Node gives it. The sessions take the
// identity as bytes: pskCallback(identity).
function pskOptions(options, socket) {
  if (typeof options.pskCallback !== 'function') return { psk: options.isServer ? null : (options.psk || null), pskCallback: null };
  if (options.isServer) {
    return { psk: null, pskCallback: function (identity) { return options.pskCallback(socket, Buffer.from(identity).toString('utf8')); } };
  }
  var r = options.pskCallback(null);
  return { psk: r ? { identity: r.identity, psk: r.psk, hash: r.hash } : null, pskCallback: null };
}

export { parseCiphers, checkCipherSuites, parseEcdhCurve, parseSigalgs, parseTlsVersion, versionsInRange, localLists, pskOptions };
