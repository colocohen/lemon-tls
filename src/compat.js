/**
 * compat.js — Node.js tls module API compatibility layer.
 *
 * Provides tls.connect(), tls.createServer(), tls.Server, and additional
 * TLSSocket methods to match Node.js tls API conventions.
 */

import net from 'node:net';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { TLS_CIPHER_SUITES } from './crypto.js';
import TLSSession from './tls_session.js';
import TLSSocket from './tls_socket.js';
import createSecureContext from './secure_context.js';

// ===================== Constants =====================

const DEFAULT_MIN_VERSION = 'TLSv1.2';
const DEFAULT_MAX_VERSION = 'TLSv1.3';

// Matches Node's default cipher list for TLS 1.3 and the modern-TLS 1.2 subset
// we actually support. Apps can pass a `ciphers` option to override per-connection.
const DEFAULT_CIPHERS = [
  'TLS_AES_256_GCM_SHA384',
  'TLS_CHACHA20_POLY1305_SHA256',
  'TLS_AES_128_GCM_SHA256',
  'ECDHE-RSA-AES256-GCM-SHA384',
  'ECDHE-ECDSA-AES256-GCM-SHA384',
  'ECDHE-RSA-AES128-GCM-SHA256',
  'ECDHE-ECDSA-AES128-GCM-SHA256',
].join(':');

const DEFAULT_ECDH_CURVE = 'auto'; // Node default since v13

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

// ===================== tls.checkServerIdentity() =====================

/**
 * Verifies that the peer certificate matches the hostname per RFC 6125.
 * Returns undefined on success, or an Error on mismatch.
 *
 * This is the default identity check Node uses when `rejectUnauthorized: true`
 * (the default for tls.connect). Apps can override via the `checkServerIdentity`
 * option in tls.connect to supply their own check.
 *
 * Matching rules:
 *   1. If the cert has Subject Alternative Name (SAN) entries:
 *      - For DNS SANs: compare against hostname (supports leftmost-label wildcards
 *        like *.example.com). IP address in hostname only matches IP SAN, not DNS SAN.
 *      - For IP SANs: compare against hostname as IP.
 *      - CN is IGNORED (per RFC 6125 and modern browsers).
 *   2. If no SAN entries exist, fall back to the cert's CN (common name)
 *      with the same matching rules — legacy path, deprecated by RFC 6125
 *      but still accepted by Node and common CAs.
 *
 * cert: the object returned by tlsSocket.getPeerCertificate() — must have
 *       `subject` (with `CN`) and `subjectaltname` (OpenSSL-formatted string).
 */
function checkServerIdentity(hostname, cert) {
  if (!cert) return new Error('checkServerIdentity: no certificate');
  const host = String(hostname || '').toLowerCase();
  if (!host) return new Error('checkServerIdentity: hostname required');

  const isIp = /^(\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-fA-F:]+\]?$/.test(host);

  // Parse subjectaltname (OpenSSL format: "DNS:a.com, DNS:*.b.com, IP Address:1.2.3.4")
  const altnames = [];
  if (cert.subjectaltname && typeof cert.subjectaltname === 'string') {
    const parts = cert.subjectaltname.split(',');
    for (let p of parts) {
      p = p.trim();
      if (p.startsWith('DNS:')) altnames.push({ type: 'DNS', value: p.slice(4).toLowerCase() });
      else if (p.startsWith('IP Address:')) altnames.push({ type: 'IP', value: p.slice(11).trim() });
      else if (p.startsWith('IP:')) altnames.push({ type: 'IP', value: p.slice(3).trim() });
      // Other SAN types (URI, email, etc.) ignored
    }
  }

  // DNS wildcard matcher: the wildcard must be the leftmost label only.
  //   *.example.com  matches foo.example.com, NOT foo.bar.example.com, NOT example.com.
  function dnsMatches(pattern, name) {
    if (pattern === name) return true;
    if (!pattern.startsWith('*.')) return false;
    const dot = name.indexOf('.');
    if (dot < 0) return false;
    return pattern.slice(2) === name.slice(dot + 1);
  }

  // IP match: string-equal for IPv4; normalize brackets/case for IPv6.
  function ipMatches(pattern, name) {
    return pattern.replace(/^\[|\]$/g, '').toLowerCase()
         === name.replace(/^\[|\]$/g, '').toLowerCase();
  }

  // RFC 6125: if SANs are present, do NOT fall back to CN.
  if (altnames.length > 0) {
    for (const s of altnames) {
      if (isIp && s.type === 'IP' && ipMatches(s.value, host)) return undefined;
      if (!isIp && s.type === 'DNS' && dnsMatches(s.value, host)) return undefined;
    }
    const details = altnames.map(s => `${s.type}:${s.value}`).join(', ');
    return new Error(`Hostname/IP does not match certificate's altnames: Host: ${hostname}. is not in the cert's altnames: ${details}`);
  }

  // Legacy CN fallback (only when no SAN present)
  const cn = cert.subject && cert.subject.CN;
  if (cn) {
    const cnLower = String(cn).toLowerCase();
    if (isIp) {
      if (ipMatches(cnLower, host)) return undefined;
    } else {
      if (dnsMatches(cnLower, host)) return undefined;
    }
    return new Error(`Hostname/IP does not match certificate's CN: Host: ${hostname}. is not cert's CN: ${cn}`);
  }

  return new Error(`Hostname/IP does not match any certificate identity`);
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
    sessionTickets: options.sessionTickets,
    ticketLifetime: options.ticketLifetime,
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

// ===================== tls.Server =====================

/**
 * Node.js compatible tls.Server class.
 *
 * Wraps a net.Server and emits:
 *   - 'secureConnection' (socket)              — after TLS handshake completes
 *   - 'newSession' (id, data, callback)        — for TLS 1.2 Session ID storage
 *   - 'resumeSession' (id, callback(err,data)) — for TLS 1.2 Session ID retrieval
 *   - 'tlsClientError' (err, socket)           — handshake errors
 *
 * Provides:
 *   - listen(), close(), address(), getConnections()
 *   - getTicketKeys(), setTicketKeys(), setSecureContext()
 */
function Server(options, connectionListener) {
  if (!(this instanceof Server)) return new Server(options, connectionListener);
  EventEmitter.call(this);

  let self = this;
  options = options || {};

  // Shared ticketKeys across all connections
  self._ticketKeys = options.ticketKeys ? Buffer.from(options.ticketKeys) : crypto.randomBytes(48);

  // sessionTimeout: seconds to cache a TLS 1.2 Session ID (Node default: 300)
  let sessionTimeoutSec = (typeof options.sessionTimeout === 'number' && options.sessionTimeout > 0)
    ? (options.sessionTimeout >>> 0)
    : 300;

  // sessionIdContext: opaque tag. Sessions stored under one context cannot be resumed
  // under another (matches Node/OpenSSL behavior — prevents cross-server leakage).
  // Stored as a hex prefix on cache keys.
  let sessionIdContextHex = '';
  if (options.sessionIdContext != null) {
    let sidCtxBuf = Buffer.isBuffer(options.sessionIdContext)
      ? options.sessionIdContext
      : Buffer.from(String(options.sessionIdContext));
    sessionIdContextHex = sidCtxBuf.toString('hex');
  }

  // Pre-compiled default SecureContext if key+cert provided directly (no SNICallback)
  let defaultCtx = null;
  if (options.key && options.cert) {
    defaultCtx = createSecureContext({ key: options.key, cert: options.cert });
  }

  // In-memory fallback session store for TLS 1.2 Session IDs.
  // Entry shape: { data: Buffer, expiresAt: ms }
  // Only used when the user hasn't registered their own 'newSession'/'resumeSession' handlers.
  // Keys are namespaced by sessionIdContext so multiple servers don't cross-pollinate.
  let inMemoryStore = {};

  function storeKey(id) {
    return sessionIdContextHex + ':' + toHex(id);
  }

  function buildSocketOpts() {
    let socketOpts = {
      isServer: true,
      ticketKeys: self._ticketKeys,
      ticketLifetime: options.ticketLifetime,
      ALPNProtocols: options.ALPNProtocols,
      minVersion: options.minVersion || DEFAULT_MIN_VERSION,
      maxVersion: options.maxVersion || DEFAULT_MAX_VERSION,
      signatureAlgorithms: options.signatureAlgorithms,
      groups: options.groups,
      prioritizeChaCha: options.prioritizeChaCha,
      maxRecordSize: options.maxRecordSize,
      sessionTickets: options.sessionTickets,
      requestCert: options.requestCert,
      maxHandshakeSize: options.maxHandshakeSize,
      allowedCipherSuites: options.allowedCipherSuites,
      handshakeTimeout: options.handshakeTimeout,
    };

    if (options.SNICallback) {
      socketOpts.SNICallback = options.SNICallback;
    } else if (defaultCtx) {
      socketOpts.SNICallback = function(servername, cb) {
        cb(null, defaultCtx);
      };
    }

    return socketOpts;
  }

  self._tcpServer = net.createServer(function(tcp) {
    let socket;
    try {
      socket = new TLSSocket(tcp, buildSocketOpts());
    } catch (err) {
      self.emit('tlsClientError', err, null);
      try { tcp.destroy(); } catch(e){}
      return;
    }

    addCompatMethods(socket);

    // Bridge TLS 1.2 Session ID events from socket → server.
    // If the user has registered their own handlers, delegate to them. Otherwise,
    // use the built-in in-memory cache (with sessionTimeout expiry and sessionIdContext
    // isolation).
    socket.on('newSession', function(id, data, cb) {
      if (self.listenerCount('newSession') > 0) {
        self.emit('newSession', Buffer.from(id), Buffer.from(data), cb);
      } else {
        inMemoryStore[storeKey(id)] = {
          data: Buffer.from(data),
          expiresAt: Date.now() + sessionTimeoutSec * 1000,
        };
        cb();
      }
    });

    socket.on('resumeSession', function(id, cb) {
      if (self.listenerCount('resumeSession') > 0) {
        self.emit('resumeSession', Buffer.from(id), cb);
      } else {
        let key = storeKey(id);
        let entry = inMemoryStore[key];
        if (!entry) return cb(null, null);
        if (entry.expiresAt < Date.now()) {
          // Expired → evict and treat as cache miss
          delete inMemoryStore[key];
          return cb(null, null);
        }
        cb(null, entry.data);
      }
    });

    // 'secureConnection' fires AFTER handshake completes (Node.js semantics)
    socket.on('secureConnect', function() {
      if (connectionListener) connectionListener(socket);
      self.emit('secureConnection', socket);
    });

    // Forward keylog to server level with Node.js signature (line, tlsSocket)
    socket.on('keylog', function(line) {
      self.emit('keylog', line, socket);
    });

    // Surface pre-handshake errors as 'tlsClientError' (Node.js semantics)
    socket.on('error', function(err) {
      if (!socket.secureEstablished) {
        self.emit('tlsClientError', err, socket);
      }
    });
  });

  // Delegate net.Server methods
  self.listen = function() {
    return self._tcpServer.listen.apply(self._tcpServer, arguments);
  };

  self.close = function(cb) {
    return self._tcpServer.close(cb);
  };

  self.address = function() {
    return self._tcpServer.address();
  };

  self.getConnections = function(cb) {
    return self._tcpServer.getConnections(cb);
  };

  // Ticket key management
  self.getTicketKeys = function() {
    return Buffer.from(self._ticketKeys);
  };

  self.setTicketKeys = function(keys) {
    if (!Buffer.isBuffer(keys) && !(keys instanceof Uint8Array)) {
      throw new TypeError('setTicketKeys requires a Buffer/Uint8Array');
    }
    if (keys.length !== 48) {
      throw new RangeError('ticketKeys must be exactly 48 bytes');
    }
    self._ticketKeys = Buffer.from(keys);
  };

  // setSecureContext — replace cert/key without restart (Node.js compat)
  self.setSecureContext = function(opts) {
    if (opts && opts.key && opts.cert) {
      defaultCtx = createSecureContext({ key: opts.key, cert: opts.cert });
    }
  };

  return self;
}

// Inherit from EventEmitter
Object.setPrototypeOf(Server.prototype, EventEmitter.prototype);
Object.setPrototypeOf(Server, EventEmitter);

// ===================== tls.createServer() =====================

/**
 * Node.js compatible tls.createServer().
 *   tls.createServer([options][, connectionListener])
 */
function createServer(options, connectionListener) {
  if (typeof options === 'function') {
    connectionListener = options;
    options = {};
  }
  return new Server(options, connectionListener);
}

// ===================== Helpers =====================

function toHex(buf) {
  if (!buf) return '';
  let b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  return b.toString('hex');
}

// ===================== Compat methods for TLSSocket =====================

function addCompatMethods(socket) {
  let session = socket._getTLSSession();

  /** Node.js compat: isSessionReused() — method form (same as isResumed getter) */
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
    if (group === 0x0018) return { type: 'ECDH', name: 'secp384r1', size: 384 };
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
  Server,
  createSecureContext,
  getCiphers,
  checkServerIdentity,
  addCompatMethods,
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS,
  DEFAULT_ECDH_CURVE,
};
