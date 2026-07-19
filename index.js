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
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS,
  DEFAULT_ECDH_CURVE,
} from './src/compat.js';

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
};

export {
  TLSSocket,
  TLSSession,
  createSecureContext,
  connect,
  createServer,
  Server,
  getCiphers,
  checkServerIdentity,
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS,
  DEFAULT_ECDH_CURVE,
  crypto,
  wire,
  record,

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
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS,
  DEFAULT_ECDH_CURVE,
  crypto,
  wire,
  record,

  // DTLS
  DTLSSession,
  DTLSSocket,
  createDTLSServer,
  connectDTLS,
};
