/**
 * compat.js — Node.js tls module API compatibility layer.
 *
 * Provides tls.connect(), tls.createServer(), and additional
 * TLSSocket methods to match Node.js tls API conventions.
 */

import net from 'node:net';
import crypto from 'node:crypto';
import { TLS_CIPHER_SUITES } from './crypto.js';
import TLSSession from './tls_session.js';
import TLSSocket from './tls_socket.js';
import createSecureContext from './secure_context.js';

// ===================== Constants =====================

const DEFAULT_MIN_VERSION = 'TLSv1.2';
const DEFAULT_MAX_VERSION = 'TLSv1.3';

// ===================== tls.getCiphers() =====================

/** Returns array of supported cipher names (lowercase, OpenSSL-style). */
function getCiphers() {
  let out = [];
  for (let code in TLS_CIPHER_SUITES) {
    let info = TLS_CIPHER_SUITES[code];
    if (info.name) out.push(info.name.toLowerCase());
  }
  return out;
}

// ===================== tls.connect() =====================

/**
 * Node.js compatible tls.connect().
 *
 * Usage:
 *   tls.connect(port, host, options, callback)
 *   tls.connect(port, host, callback)
 *   tls.connect(port, options, callback)
 *   tls.connect(options, callback)
 */
function connect(/* ...args */) {
  let port, host, options, connectListener;

  // Parse overloaded arguments
  let args = Array.from(arguments);

  if (typeof args[0] === 'object' && !Array.isArray(args[0])) {
    options = args[0];
    connectListener = typeof args[1] === 'function' ? args[1] : null;
    port = options.port;
    host = options.host || 'localhost';
  } else {
    port = args[0];
    if (typeof args[1] === 'string') {
      host = args[1];
      if (typeof args[2] === 'object') {
        options = args[2];
        connectListener = typeof args[3] === 'function' ? args[3] : null;
      } else {
        options = {};
        connectListener = typeof args[2] === 'function' ? args[2] : null;
      }
    } else if (typeof args[1] === 'object') {
      options = args[1];
      host = options.host || 'localhost';
      connectListener = typeof args[2] === 'function' ? args[2] : null;
    } else {
      options = {};
      host = 'localhost';
      connectListener = typeof args[1] === 'function' ? args[1] : null;
    }
  }

  options = options || {};

  let socket = new TLSSocket(null, {
    isServer: false,
    servername: options.servername || host,
    rejectUnauthorized: options.rejectUnauthorized,
    ca: options.ca,
    session: options.session,
    ALPNProtocols: options.ALPNProtocols,
    minVersion: options.minVersion,
    maxVersion: options.maxVersion,
    signatureAlgorithms: options.signatureAlgorithms,
    groups: options.groups,
    prioritizeChaCha: options.prioritizeChaCha,
    maxRecordSize: options.maxRecordSize,
    noTickets: options.noTickets,
    cert: options.cert,
    key: options.key,
    maxHandshakeSize: options.maxHandshakeSize,
  });

  addCompatMethods(socket);

  if (connectListener) {
    socket.on('secureConnect', connectListener);
  }

  let tcp = net.connect(port, host, function() {
    socket.setSocket(tcp);
  });

  tcp.on('error', function(e) {
    socket.emit('error', e);
  });

  return socket;
}

// ===================== tls.createServer() =====================

/**
 * Node.js compatible tls.createServer().
 *
 * Usage:
 *   tls.createServer(options, connectionListener)
 */
function createServer(options, connectionListener) {
  if (typeof options === 'function') {
    connectionListener = options;
    options = {};
  }
  options = options || {};

  let ctx = null;
  if (options.key && options.cert) {
    ctx = createSecureContext({ key: options.key, cert: options.cert });
  }

  // Shared ticketKeys for all connections (enables PSK across connections)
  let sharedTicketKeys = options.ticketKeys || crypto.randomBytes(48);

  let server = net.createServer(function(tcp) {
    let socketOpts = {
      isServer: true,
      ticketKeys: sharedTicketKeys,
      ALPNProtocols: options.ALPNProtocols,
      minVersion: options.minVersion || DEFAULT_MIN_VERSION,
      maxVersion: options.maxVersion || DEFAULT_MAX_VERSION,
      signatureAlgorithms: options.signatureAlgorithms,
      groups: options.groups,
      prioritizeChaCha: options.prioritizeChaCha,
      maxRecordSize: options.maxRecordSize,
      noTickets: options.noTickets,
      requestCert: options.requestCert,
      maxHandshakeSize: options.maxHandshakeSize,
      allowedCipherSuites: options.allowedCipherSuites,
    };

    if (options.SNICallback) {
      socketOpts.SNICallback = options.SNICallback;
    } else if (ctx) {
      socketOpts.SNICallback = function(servername, cb) {
        cb(null, ctx);
      };
    }

    let socket = new TLSSocket(tcp, socketOpts);
    addCompatMethods(socket);

    if (connectionListener) {
      socket.on('secureConnect', function() {
        connectionListener(socket);
      });
    }

    server.emit('secureConnection', socket);
  });

  return server;
}

// ===================== Compat methods for TLSSocket =====================

function addCompatMethods(socket) {
  let session = socket.getSession();

  /** Node.js compat: isSessionReused() */
  socket.isSessionReused = function() {
    return socket.isResumed;
  };

  /** Node.js compat: getFinished() */
  socket.getFinished = function() {
    return session.getFinished ? session.getFinished() : null;
  };

  /** Node.js compat: getPeerFinished() */
  socket.getPeerFinished = function() {
    return session.getPeerFinished ? session.getPeerFinished() : null;
  };

  /** Node.js compat: exportKeyingMaterial(length, label, context) */
  socket.exportKeyingMaterial = function(length, label, context) {
    return session.exportKeyingMaterial ? session.exportKeyingMaterial(length, label, context) : new Uint8Array(0);
  };

  /** Node.js compat: getEphemeralKeyInfo() */
  socket.getEphemeralKeyInfo = function() {
    let group = session.context.selected_group;
    if (group === 0x001d) return { type: 'X25519', size: 253 };
    if (group === 0x0017) return { type: 'ECDH', name: 'prime256v1', size: 256 };
    return {};
  };

  /** Node.js compat: setServername(name) */
  socket.setServername = function(name) {
    session.set_context({ local_sni: name });
  };

  /** Node.js compat: disableRenegotiation() — no-op (renegotiation not supported) */
  socket.disableRenegotiation = function() {};

  /** Node.js compat: address() — delegates to underlying transport */
  socket.address = function() {
    try { return session.context && session.context.transport ? session.context.transport.address() : {}; }
    catch(e) { return {}; }
  };
}

// ===================== Exports =====================

export {
  connect,
  createServer,
  createSecureContext,
  getCiphers,
  addCompatMethods,
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
};
