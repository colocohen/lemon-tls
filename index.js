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
  getCiphers,
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
} from './src/compat.js';

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
  getCiphers,
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
  crypto,
  wire,
  record,
};

/**
 * Default export — Node.js tls API compatible.
 *
 * Usage:
 *   import tls from 'lemon-tls';
 *   tls.connect(443, 'example.com', { ... });
 *   tls.createServer({ key, cert }, (socket) => { ... });
 */
export default {
  TLSSocket,
  TLSSession,
  createSecureContext,
  connect,
  createServer,
  getCiphers,
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
  crypto,
  wire,
  record,
};
