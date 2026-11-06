/**
 * compat.js — Node.js tls module API compatibility layer.
 *
 * Provides tls.connect(), tls.createServer(), tls.Server, and additional
 * TLSSocket methods to match Node.js tls API conventions.
 */

import net from 'node:net';
import { getRootCertificates, setRootCertificates } from './ca_store.js';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { TLS_CIPHER_SUITES } from './crypto.js';
import TLSSession from './tls_session.js';
import TLSSocket from './tls_socket.js';
import createSecureContext from './secure_context.js';
import { parseCiphers, checkCipherSuites, checkSignatureAlgorithms, parseEcdhCurve, parseSigalgs } from './node_options.js';
import { prepare_ech_server } from './session/ech.js';
import { matches_host, matches_altnames } from './session/x509.js';

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

// The trust anchors Node ships (Mozilla's CA bundle), under the name Node
// uses, so `tls.rootCertificates` works unchanged. The store is ca_store.js:
// every session given no `ca` chains against it, as Node's does.

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
  setRootCertificates(certs);
}

// ===================== tls.checkServerIdentity() =====================

/**
 * node:tls's tls.checkServerIdentity(hostname, cert): undefined when the
 * certificate is for the host, an Error (code ERR_TLS_CERT_ALTNAME_INVALID,
 * reason, host, cert) when it is not. The handshake's own check —
 * session/x509.js matches_host, one implementation: the subjectAltName only
 * (no common-name fallback, RFC 9525 §6.3), wildcards a whole leftmost
 * label. Node still falls back to the common name of a certificate without
 * a DNS name; this does not, as browsers do not — and as the handshake does
 * not, which this used to disagree with.
 *
 * cert: what getPeerCertificate() returns — its `raw` DER is what is read.
 */
function checkServerIdentity(hostname, cert) {
  const host = String(hostname || '');
  let err = null;
  if (!cert) err = new Error('checkServerIdentity: no certificate to check');
  else if (!host) err = new Error('checkServerIdentity: hostname required');
  else {
    // By the DER when the object has it (getPeerCertificate()'s does), or
    // by its subjectaltname string, as Node reads it.
    let ok = false;
    try { ok = cert.raw ? matches_host(cert.raw, host.toLowerCase()) : matches_altnames(cert.subjectaltname, host); } catch (e) { ok = false; }
    if (ok) return undefined;
    err = new Error("Hostname/IP does not match certificate's altnames: Host: " + host + ". is not in the cert's altnames: " +
                    (cert.subjectaltname || '(none)'));
  }
  err.code = 'ERR_TLS_CERT_ALTNAME_INVALID';
  err.reason = err.message;
  err.host = host;
  err.cert = cert;
  return err;
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

  // Every option goes on to the socket (and from it to the session), with
  // what connect() settles itself over them — the lists that picked options
  // one by one dropped a documented option time and again (pins, ech,
  // customExtensions, recordSizeLimit …).
  let socket = new TLSSocket(null, Object.assign({}, options, {
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
    session: options.session,
    ALPNProtocols: options.ALPNProtocols,
    minVersion: options.minVersion,
    maxVersion: options.maxVersion,
    // node:tls's own strings (ciphers, ecdhCurve, sigalgs) — taken by
    // nothing until now — or lemon-tls's code lists, which win.
    signatureAlgorithms: checkSignatureAlgorithms(options.signatureAlgorithms) || parseSigalgs(options.sigalgs),
    groups: options.groups || parseEcdhCurve(options.ecdhCurve),
    prioritizeChaCha: options.prioritizeChaCha,
    // Forwarded on the server side but dropped here, so a client could not
    // narrow the suites it offers.
    allowedCipherSuites: checkCipherSuites(options.allowedCipherSuites, 'allowedCipherSuites') || parseCiphers(options.ciphers),
    maxRecordSize: options.maxRecordSize,
    sessionTickets: options.sessionTickets,
    ticketLifetime: options.ticketLifetime,
    // RFC 8879: algorithms to offer for the server's certificate chain.
    certificateCompression: options.certificateCompression,
    // node:tls: ask the server for a stapled OCSP response ('OCSPResponse').
    requestOCSP: options.requestOCSP === true,
    cert: options.cert,
    key: options.key,
    maxHandshakeSize: options.maxHandshakeSize,
    // Encrypted Client Hello (RFC 9849): the server's ECHConfigList (bytes or
    // base64 — the `ech=` of its HTTPS record), or GREASE ECH without one.
    ech: options.ech,
    echGrease: options.echGrease === true,
    // ClientHello shaping, documented as connect() options and dropped
    // here: neither reached the socket.
    grease: options.grease,
    permuteExtensions: options.permuteExtensions,
    // Four more documented options (index.d.ts) this list left behind, so
    // connect() ignored them without a word: certificate pins — a client
    // that set them was not pinned at all — the handshake timeout, raw
    // extensions, and noTickets (the older spelling of sessionTickets: false).
    pins: options.pins,
    handshakeTimeout: options.handshakeTimeout,
    customExtensions: options.customExtensions,
    ...(options.sessionTickets === undefined && options.noTickets === true ? { sessionTickets: false } : {}),
    // 0-RTT: with `session` whose ticket allows it, what is written before
    // 'secureConnect' goes in the first flight ('earlyData' says if taken).
    earlyData: options.earlyData === true,
  }));

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
    // The rest of the options go to net.connect, as node:tls does ("any
    // socket.connect() option not already listed"): noDelay, keepAlive,
    // keepAliveInitialDelay, localAddress, localPort, family, lookup, timeout.
    // Dropped here, none of them could be set through connect() at all.
    let netOptions = Object.assign({}, options, { port: port, host: host });
    delete netOptions.socket;
    tcp = net.connect(netOptions, function() {
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
 *   - getEchKeys(), setEchKeys() — Encrypted Client Hello keys (RFC 9849)
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

  // Encrypted Client Hello keys, checked here — a key that does not match
  // its config throws now, not as every client's handshake failing.
  prepare_ech_server(options.ech);
  self._ech = options.ech || null;

  // node:tls's strings, read once (node_options.js) — a bad one throws here,
  // as Node's createServer does, not on the first connection.
  let nodeSuites = checkCipherSuites(options.allowedCipherSuites, 'allowedCipherSuites') || parseCiphers(options.ciphers);
  let nodeGroups = options.groups || parseEcdhCurve(options.ecdhCurve);
  let nodeSigalgs = checkSignatureAlgorithms(options.signatureAlgorithms) || parseSigalgs(options.sigalgs);

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
    // Every server option goes on to each socket, with what the server
    // settles over them. Not the key and certificate themselves: they are in
    // the secure context (defaultCtx) — with several pairs, its alternates.
    let socketOpts = Object.assign({}, options, {
      key: undefined, cert: undefined, pfx: undefined, passphrase: undefined, SNICallback: undefined,
      isServer: true,
      ticketKeys: self._ticketKeys,
      // node:tls's sessionTimeout is how long a session stays good — a
      // ticket's lifetime as much as a cached Session ID's. It set the cache
      // alone, and tickets went out with the default 7200 s whatever it said.
      // ticketLifetime, lemon-tls's own name, where given.
      ticketLifetime: options.ticketLifetime != null ? options.ticketLifetime
                    : (typeof options.sessionTimeout === 'number' ? options.sessionTimeout : undefined),
      ticketData: options.ticketData,
      // RFC 8879: compress the chain for a client that offers it (all
      // algorithms unless set; false: never).
      certificateCompression: options.certificateCompression,
      // node:tls: the cipher suite by the server's order (default: the client's).
      honorCipherOrder: options.honorCipherOrder === true,
      // Encrypted Client Hello (RFC 9849): { keys: [{ config, privateKey, retry }] }.
      ech: self._ech,
      // node:tls's 'OCSPRequest': (certificate, issuer, callback) when a
      // client asks for a stapled OCSP response. Without a listener nothing
      // is stapled — and nothing waits.
      ocspRequest: function (certificate, issuer, callback) {
        if (self.listenerCount('OCSPRequest') === 0) return callback(null, null);
        self.emit('OCSPRequest', Buffer.from(certificate), issuer ? Buffer.from(issuer) : null, callback);
      },
      ALPNProtocols: options.ALPNProtocols,
      ALPNCallback: options.ALPNCallback,
      // 0-RTT (off unless asked for): tickets that allow it, and taking it
      // under the session's checks — read on each socket as it comes
      // (socket.isEarlyData), before 'secureConnection'.
      earlyData: options.earlyData === true,
      earlyDataMaxAge: options.earlyDataMaxAge,
      earlyDataReplay: options.earlyDataReplay,
      maxEarlyData: options.maxEarlyData,
      minVersion: options.minVersion || DEFAULT_MIN_VERSION,
      maxVersion: options.maxVersion || DEFAULT_MAX_VERSION,
      signatureAlgorithms: nodeSigalgs,
      groups: nodeGroups,
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
      allowedCipherSuites: nodeSuites,
      // node:tls's default for a server, 120 s. TLSSocket's own is none
      // (it is also the client's, where Node has none either), and a server
      // left at it let a client that sent half a ClientHello hold its socket
      // for as long as it liked.
      handshakeTimeout: options.handshakeTimeout != null ? options.handshakeTimeout : 120000,
      // The server's default certificate. With an explicit SNICallback it was
      // never handed to the socket, so a client sending no server_name got
      // the callback asked with null instead of this certificate, as in Node.
      secureContext: defaultCtx || undefined,
    });

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
    let established = false;
    socket.on('secureConnect', function() {
      established = true;
      if (connectionListener) connectionListener(socket);
      self.emit('secureConnection', socket);
    });

    // Forward keylog to server level with Node.js signature (line, tlsSocket)
    socket.on('keylog', function(line) {
      self.emit('keylog', line, socket);
    });

    // Surface pre-handshake errors as 'tlsClientError' (Node.js semantics) —
    // those only. It read socket.secureEstablished, which no socket has: every
    // error, after the handshake too (a reset, a bad record), was a
    // tlsClientError as well.
    socket.on('error', function(err) {
      if (!established) {
        self.emit('tlsClientError', err, socket);
      }
    });
  }

  // node:tls's Server IS a net.Server, built from the same options object, so
  // the TCP ones apply to every connection it accepts. Only those: the stream
  // shape of the raw socket (allowHalfOpen, pauseOnConnect) is this layer's
  // to manage, and the TLS socket takes allowHalfOpen itself.
  self._tcpServer = net.createServer({
    noDelay: options.noDelay === true,
    keepAlive: options.keepAlive === true,
    keepAliveInitialDelay: options.keepAliveInitialDelay || 0,
  }, acceptConnection);

  // The net.Server's own events, re-emitted: node:tls's Server IS a net.Server
  // and emits these itself, and code written for it listens for them here.
  // Without this, 'listening' never fired, and a failed bind (EADDRINUSE,
  // EACCES) was emitted on an inner object nobody could reach — an uncaught
  // exception that took the whole process down.
  ['listening', 'error', 'close', 'drop'].forEach(function (name) {
    self._tcpServer.on(name, function () {
      if (name === 'error' && self.listenerCount('error') === 0) {
        // Same as node:tls when nobody listens: it throws. Preserved, rather
        // than swallowed — but from the Server a caller can now listen on.
        throw arguments[0];
      }
      self.emit.apply(self, [name].concat(Array.prototype.slice.call(arguments)));
    });
  });

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

  // node:net's: whether it is listening, and whether the process may exit
  // while it does.
  Object.defineProperty(self, 'listening', { get: function() { return self._tcpServer.listening; }, enumerable: true });
  self.ref = function() { self._tcpServer.ref(); return self; };
  self.unref = function() { self._tcpServer.unref(); return self; };

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

  // ECH keys. Rotation without a restart: publish the new config in DNS,
  // then setEchKeys with the new key first (retry: true) and the old one
  // kept (retry: false) until the old DNS record's TTL has run out — clients
  // still holding it can then connect. New connections use the new set.
  self.getEchKeys = function() {
    return self._ech;
  };

  self.setEchKeys = function(ech) {
    prepare_ech_server(ech);          // throws on a bad key, keeping the old set
    self._ech = ech || null;
  };

  // setSecureContext — replace cert/key without restart (Node.js compat).
  // A bad one throws, as Node's does, and the certificate in use stays: it
  // returned quietly when key or cert was missing, and a renewal that read
  // an empty file went unnoticed until the old certificate expired.
  self.setSecureContext = function(opts) {
    if (!opts || typeof opts !== 'object') throw new TypeError('setSecureContext requires { key, cert } or { secureContext }');
    defaultCtx = opts.secureContext ? opts.secureContext : createSecureContext(opts);
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
