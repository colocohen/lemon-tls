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
