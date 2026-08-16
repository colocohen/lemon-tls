/**
 * compat.js — Node.js tls module API compatibility layer.
 *
 * Provides tls.connect(), tls.createServer(), tls.Server, and additional
 * TLSSocket methods to match Node.js tls API conventions.
 */

import net from 'node:net';
import nodeTls from 'node:tls';   // for the shipped CA bundle only
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

/* ===================== Default CA store ===================== */

/**
 * The trust anchors Node ships (Mozilla's CA bundle). Exposed under the same
 * name Node uses so `tls.rootCertificates` works unchanged, and so this
 * library has a real default to chain against.
 *
 * That default matters more than parity. Until now, "no `ca` configured" meant
 * "authorize every certificate", while `rejectUnauthorized` defaulted to true
 * — the connection reported itself verified without ever verifying anything.
 * Node never behaved that way: it falls back to this bundle.
 *
 * Parsing all ~144 certificates costs a few tens of milliseconds, so it is
 * done once, lazily, and only if something actually needs it.
 */
let _rootPems = null;
function getRootCertificates() {
  if (_rootPems === null) {
    try { _rootPems = nodeTls.rootCertificates.slice(); }
    catch (e) { _rootPems = []; }   // a build without the bundle
  }
  return _rootPems;
}

/** Node-compat: tls.getCACertificates([type]). 'default' and 'bundled' both
 *  resolve to the shipped bundle; 'extra' and 'system' are not sourced here
 *  and return empty rather than pretending. */
function getCACertificates(type) {
  let t = type || 'default';
  if (t === 'default' || t === 'bundled') return getRootCertificates().slice();
  return [];
}

/** Node-compat: tls.setDefaultCACertificates(certs). Replaces the bundle for
 *  every subsequent connection that does not pass its own `ca`. */
function setDefaultCACertificates(certs) {
  if (!Array.isArray(certs)) throw new TypeError('certs must be an array');
  _rootPems = certs.slice();
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
    checkServerIdentity: options.checkServerIdentity,
    // Stream-shape options Node forwards to the socket. Both were dropped
    // here, so allowHalfOpen could not be set through connect() at all.
    allowHalfOpen: options.allowHalfOpen,
    highWaterMark: options.highWaterMark,
    secureContext: options.secureContext,
    passphrase: options.passphrase,
    ca: options.ca,
    useDefaultCA: options.useDefaultCA,
    defaultCA: getRootCertificates,
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

  let tcp = null;

  if (options.socket) {
    // Node: "Establish secure connection on a given socket rather than
    // creating a new socket... If this option is specified, path, host, and
    // port are ignored, except for certificate validation." Crucially it also
    // says connection and teardown of that socket remain the caller's job and
    // that tls.connect() will not call net.connect() at all — so we attach and
    // nothing else. This is what STARTTLS needs: the caller speaks cleartext
    // first (SMTP, IMAP, PostgreSQL), then upgrades the same connection.
    //
    // The socket is usually already connected, but it need not be; the
    // handshake simply starts once it is writable.
    tcp = options.socket;
    socket.setSocket(tcp);
  } else {
    tcp = net.connect(port, host, function() {
      socket.setSocket(tcp);
    });
  }

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

  // Node throws on this combination rather than picking one, and so do we: the
  // two answer the same question by different means, and silently preferring
  // either would leave a server running a policy its author did not write.
  if (options.ALPNProtocols && options.ALPNCallback) {
    throw new TypeError(
      'The ALPNProtocols and ALPNCallback options are mutually exclusive');
  }

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

  // Pre-compiled default SecureContext.
  //
  // Node parity: a caller may hand us a context they built once with
  // tls.createSecureContext() and reuse across servers, instead of paying to
  // re-parse the same PEM on every construction. An explicit `secureContext`
  // wins over key/cert — same precedence Node uses.
  // SNI contexts registered through addContext(). Each is compiled ONCE here
  // and handed out by reference, which is the whole point: a hand-written
  // SNICallback that calls createSecureContext() per connection re-parses the
  // same PEM every time, and if it reads the files inside the callback it also
  // does disk I/O on the handshake path.
  //
  // Node's matching rule: last registration wins on a tie, and an exact
  // hostname beats a wildcard. Insertion order is preserved, so a later
  // addContext() for the same pattern replaces the earlier one in place.
  let sniContexts = [];   // [{ pattern, re, ctx }]

  let defaultCtx = null;
  if (options.secureContext) {
    defaultCtx = options.secureContext;
  } else if (options.key && options.cert) {
    defaultCtx = createSecureContext(options);
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
      ALPNCallback: options.ALPNCallback,
      minVersion: options.minVersion || DEFAULT_MIN_VERSION,
      maxVersion: options.maxVersion || DEFAULT_MAX_VERSION,
      signatureAlgorithms: options.signatureAlgorithms,
      groups: options.groups,
      prioritizeChaCha: options.prioritizeChaCha,
      maxRecordSize: options.maxRecordSize,
      sessionTickets: options.sessionTickets,
      requestCert: options.requestCert,
      // Client-authentication policy. These were missing, so a server's
      // rejectUnauthorized/ca never reached TLSSession and it fell back to the
      // session default (rejectUnauthorized: true). The effect was invisible
      // until client auth was actually exercised: `requestCert: true` WITHOUT
      // `rejectUnauthorized` is the standard "ask for a certificate but accept
      // clients that have none" configuration, and it rejected them instead.
      // requestCert was forwarded and its two companions were not, which is
      // exactly the kind of half-wired option that looks correct at a glance.
      rejectUnauthorized: options.rejectUnauthorized,
      ca: options.ca,
      maxHandshakeSize: options.maxHandshakeSize,
      allowedCipherSuites: options.allowedCipherSuites,
      handshakeTimeout: options.handshakeTimeout,
    };

    if (options.SNICallback) {
      // An explicit callback wins outright — it may do things the registry
      // cannot, such as fetching a certificate on demand.
      socketOpts.SNICallback = options.SNICallback;
    } else if (defaultCtx || sniContexts.length > 0) {
      socketOpts.SNICallback = function(servername, cb) {
        cb(null, contextForServername(servername));
      };
    }

    return socketOpts;
  }

  function acceptConnection(tcp) {
    // Node: "emitted when a new TCP stream is established, before the TLS
    // handshake begins... can also be explicitly emitted by users to inject
    // connections into the TLS server. In that case, any Duplex stream can be
    // passed." Emitting first is what makes that injection path work.
    self.emit('connection', tcp);
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
  }

  self._tcpServer = net.createServer(acceptConnection);

  /**
   * Node documents 'connection' as injectable: emitting it by hand feeds an
   * arbitrary Duplex into the TLS server. That cannot be done by listening for
   * our own event — acceptConnection emits it, so the listener would re-enter
   * on every real connection and loop. A method is the honest shape.
   */
  self.injectConnection = function(stream) {
    if (!stream || typeof stream.write !== 'function') {
      throw new TypeError('injectConnection requires a Duplex stream');
    }
    acceptConnection(stream);
    return self;
  };

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
    if (!opts) return;
    if (opts.secureContext) { defaultCtx = opts.secureContext; return; }
    if (opts.key && opts.cert) defaultCtx = createSecureContext(opts);
  };

  /**
   * Node-compat: addContext(hostname, context)
   *
   * Register a certificate for an SNI host name or wildcard. `context` is
   * either a compiled context from createSecureContext() or the plain
   * { key, cert, ... } options to compile from — Node accepts both.
   *
   * The declarative alternative to writing an SNICallback by hand. It matters
   * for more than tidiness: the common hand-rolled callback compiles a context
   * per connection, and often reads the cert off disk inside it. Here every
   * context is compiled once at registration and served by reference.
   */
  self.addContext = function(hostname, context) {
    if (!hostname) throw new TypeError('addContext requires a hostname');
    let ctx = context;
    if (!ctx || (!ctx.certificateChain && !ctx.privateKey)) {
      if (!context || !context.key || !context.cert) {
        throw new TypeError('addContext requires a SecureContext or { key, cert }');
      }
      ctx = createSecureContext(context);
    }
    let pattern = String(hostname).toLowerCase();
    let entry = { pattern: pattern, re: sniPatternToRegExp(pattern), ctx: ctx };

    // Replace in place rather than appending a duplicate, so re-registering a
    // host swaps its certificate without leaving the old one shadowing it.
    let i = sniContexts.findIndex(function(e){ return e.pattern === pattern; });
    if (i >= 0) sniContexts[i] = entry;
    else sniContexts.push(entry);
    return self;
  };

  /**
   * Wildcards match ONE label and only as the leftmost one, per RFC 6125:
   * `*.example.com` covers `a.example.com` but neither `a.b.example.com` nor
   * the bare `example.com`. A bare `*` matches any single-or-multi label name
   * and is the documented catch-all.
   */
  function sniPatternToRegExp(pattern) {
    if (pattern === '*') return /^.+$/;
    let esc = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp('^' + esc.replace(/\*/g, '[^.]+') + '$');
  }

  /**
   * Resolve a servername to a context. Exact matches beat wildcards; among
   * equals the most recently added wins, which is what Node documents.
   */
  function contextForServername(servername) {
    if (!servername) return defaultCtx;
    let name = String(servername).toLowerCase();
    for (let i = sniContexts.length - 1; i >= 0; i--) {
      if (sniContexts[i].pattern === name) return sniContexts[i].ctx;
    }
    for (let i = sniContexts.length - 1; i >= 0; i--) {
      if (sniContexts[i].re.test(name)) return sniContexts[i].ctx;
    }
    return defaultCtx;
  }

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

  // Polyfill semantics: only define a method if the socket doesn't already
  // provide it natively. TLSSocket has been growing first-class
  // implementations (exportKeyingMaterial, getRemoteExtension(s), …) and a
  // blind `socket.x = …` here would clobber them with a thinner shim —
  // exactly the kind of silent duplication this layer must not create.
  // compat.js stays what it claims to be: a gap-filler, never an override.
  function def(name, fn) {
    if (typeof socket[name] !== 'function') socket[name] = fn;
  }

  // isSessionReused, getFinished, getPeerFinished, getEphemeralKeyInfo and
  // address now ship natively on TLSSocket, so their shims here were dead code
  // that def() would never install — and they had drifted from Node in ways
  // the native versions fix: getFinished returned null where Node documents
  // undefined, and getEphemeralKeyInfo reported type 'X25519', which is not
  // one of the three types Node defines ('DH', 'ECDH', 'TLSGroup'), and never
  // returned null on a server socket. Two divergent implementations of one
  // method is the duplication this layer exists to avoid, so they are gone.

  /** Node.js compat: exportKeyingMaterial(length, label, context).
   *  TLSSocket now ships this natively (RFC 5705 / RFC 8446 §7.5 via the
   *  session) — this shim only covers older socket-likes. Same
   *  null-until-ready convention as the native method. */
  def('exportKeyingMaterial', function(length, label, context) {
    return session.exportKeyingMaterial ? session.exportKeyingMaterial(length, label, context) : null;
  });

  /** Node.js compat: setServername(name) */
  def('setServername', function(name) {
    session.set_context({ local_sni: name });
  });

  /** Node.js compat: disableRenegotiation() — no-op (renegotiation not supported) */
  def('disableRenegotiation', function() {});

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
  getCACertificates,
  setDefaultCACertificates,
  DEFAULT_MIN_VERSION,
  DEFAULT_MAX_VERSION,
  DEFAULT_CIPHERS,
  DEFAULT_ECDH_CURVE,
};
