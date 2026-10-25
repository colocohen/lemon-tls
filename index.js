import TLSSession from './src/tls_session.js';
import TLSSocket from './src/tls_socket.js';
import createSecureContext from './src/secure_context.js';
import {
  TLS_CIPHER_SUITES,
  getHashFn,
  getHashLen,
  hkdf_extract,
  hkdf_expand,
  hkdf_expand_label,
  hmac,
  tls12_prf,
  tls12_exporter,
  tls13_exporter,
} from './src/crypto.js';
import * as wire from './src/wire.js';
import * as record from './src/record.js';
import {
  connect,
  createServer,
  Server,
  getCiphers,
  checkServerIdentity,
  getCACertificates,
  setDefaultCACertificates,
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS,
  DEFAULT_ECDH_CURVE,
} from './src/compat.js';
import { parseCiphers, parseEcdhCurve, parseSigalgs, parseTlsVersion } from './src/node_options.js';
import { certificateObject } from './src/utils.js';
import { parse_cert_compression, precompress_certificate_body, supported_cert_compression } from './src/session/cert_compression.js';
import { build_tls_message } from './src/session/message.js';
import { client_session_info } from './src/session/ticket.js';

/** A saved session ('session' event's Buffer) described without its secrets:
 *  { version, servername, alpn, created, expiresAt, earlyData }, or null. */
function sessionInfo(blob) { return client_session_info(blob); }
import { SERVER_DEFAULT_GROUPS } from './src/session/ecdh.js';
import { default_signature_schemes } from './src/session/signing.js';

/** The signature schemes offered by default (signature_algorithms), in
 *  order, as code points: the modern ones, ML-DSA where this Node.js has it,
 *  then the legacy ones (accepted on certificates, never used in a TLS 1.3
 *  CertificateVerify). A copy. */
const DEFAULT_SIGNATURE_SCHEMES = Object.freeze(default_signature_schemes());

/** The key-exchange groups a server offers by default, in its preference:
 *  every post-quantum group this Node.js has (the hybrids, then ML-KEM
 *  alone), then X25519, P-256, P-384 — as code points. A copy. */
const DEFAULT_SERVER_GROUPS = Object.freeze(SERVER_DEFAULT_GROUPS.slice());

/** certificateCompression (RFC 8879): ['brotli', 'zlib', 'zstd'] in order,
 *  true (all this build has) or false (none) → algorithm codes; null when
 *  unset (the default). Throws on a name it does not know, so a server can
 *  check the option when it is made rather than at the first handshake. */
function parseCertificateCompression(value) { return parse_cert_compression(value); }

/** A server's certificate chain compressed now (RFC 8879), in the
 *  background, for each algorithm it may be sent in — `algorithms` as the
 *  certificateCompression option takes them (unset: all this build has) —
 *  so the first TLS 1.3 handshake to send it does not compress it while
 *  its client waits. `secureContext`: from createSecureContext(). Optional:
 *  without it the first handshake compresses, and caches, as before.
 *  callback() when done. */
function precompressCertificate(secureContext, algorithms, callback) {
  if (typeof algorithms === 'function') { callback = algorithms; algorithms = undefined; }
  const algs = parse_cert_compression(algorithms) || supported_cert_compression();
  // Its chain, and those of its other key/certificate pairs (key/cert arrays).
  const chains = secureContext ? [secureContext.certificateChain].concat((secureContext.alternates || []).map((a) => a.certificateChain)) : [];
  let left = 1;
  const done = () => { if (--left === 0 && callback) callback(); };
  for (const chain of chains) {
    if (!Array.isArray(chain) || chain.length === 0 || algs.length === 0) continue;
    // The Certificate message's body as a TLS 1.3 server sends it: an empty
    // request context, each entry without extensions (an OCSP response
    // stapled to the leaf makes another body, compressed when it is sent).
    const body = build_tls_message({ type: 'certificate', version: 0x0304, entries: chain, certificate_request_context: new Uint8Array(0) }).subarray(4);
    left++;
    precompress_certificate_body(body, algs, done);
  }
  process.nextTick(done);
}
import { generate_ech_key, prepare_ech_server } from './src/session/ech.js';
import { hpke_suite, setup_sender, setup_recipient, hpke_seal, hpke_open,
         hpke_generate_key_pair, hpke_derive_key_pair } from './src/session/hpke.js';
import nodeTls from 'node:tls';

/** Node-compat: the shipped CA bundle, same array Node exposes. */
const rootCertificates = nodeTls.rootCertificates;

// DTLS
import DTLSSession from './src/dtls_session.js';
import {
  DTLSSocket,
  createDTLSServer,
  connectDTLS,
} from './src/dtls_socket.js';

/**
 * Crypto primitives for QUIC and custom transport consumers.
 */
var crypto = {
  TLS_CIPHER_SUITES,
  getHashFn,
  getHashLen,
  hkdf_extract,
  hkdf_expand,
  hkdf_expand_label,
  hmac,
  // Keying-material exporters (RFC 5705 / RFC 8446 §7.5) — standalone
  // primitives for consumers that hold raw secrets (offline analysis,
  // custom transports). Live sessions should prefer
  // session.exportKeyingMaterial(), which picks the right one.
  tls12_prf,
  tls12_exporter,
  tls13_exporter,
  // HPKE (RFC 9180) — what ECH encrypts with; also the base of Oblivious
  // HTTP and MLS.
  hpke: {
    suite: hpke_suite,
    setupSender: setup_sender,
    setupRecipient: setup_recipient,
    seal: hpke_seal,
    open: hpke_open,
    generateKeyPair: hpke_generate_key_pair,
    deriveKeyPair: hpke_derive_key_pair,
  },
};

/**
 * A new Encrypted Client Hello key (RFC 9849) for a server:
 * { config, privateKey, configList, configListBase64 }.
 * Pass { keys: [{ config, privateKey }] } as the server's `ech` option and
 * publish configListBase64 as `ech=` in the domain's HTTPS record.
 */
function generateEchKey(options) {
  return generate_ech_key(options);
}

/**
 * Check a server's `ech` option — { keys: [{ config, privateKey, retry }] }
 * — and throw, saying what is wrong, if it would not work: a config that
 * does not parse, a private key that is not its config's. For a server
 * built on TLSSession directly, which would otherwise learn of it on the
 * first connection. createServer checks by itself.
 */
function checkEchKeys(ech) {
  prepare_ech_server(ech);
}

export {
  TLSSocket,
  TLSSession,
  createSecureContext,
  connect,
  createServer,
  Server,
  getCiphers,
  checkServerIdentity,
  getCACertificates,
  setDefaultCACertificates,
  rootCertificates,
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS,
  DEFAULT_ECDH_CURVE,
  crypto,
  wire,
  record,
  // node:tls option strings → code lists (node_options.js)
  parseCiphers,
  parseEcdhCurve,
  parseSigalgs,
  parseTlsVersion,
  parseCertificateCompression,
  precompressCertificate,
  DEFAULT_SERVER_GROUPS,
  DEFAULT_SIGNATURE_SCHEMES,
  sessionInfo,
  certificateObject,
  generateEchKey,
  checkEchKeys,

  // DTLS
  DTLSSession,
  DTLSSocket,
  createDTLSServer,
  connectDTLS,
};

/**
 * Default export — Node.js tls API compatible + DTLS.
 */
export default {
  TLSSocket,
  TLSSession,
  createSecureContext,
  connect,
  createServer,
  Server,
  getCiphers,
  checkServerIdentity,
  getCACertificates,
  setDefaultCACertificates,
  rootCertificates,
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS,
  DEFAULT_ECDH_CURVE,
  crypto,
  wire,
  record,
  parseCiphers,
  parseEcdhCurve,
  parseSigalgs,
  parseTlsVersion,
  parseCertificateCompression,
  precompressCertificate,
  DEFAULT_SERVER_GROUPS,
  DEFAULT_SIGNATURE_SCHEMES,
  sessionInfo,
  certificateObject,
  generateEchKey,
  checkEchKeys,

  // DTLS
  DTLSSession,
  DTLSSocket,
  createDTLSServer,
  connectDTLS,
};
