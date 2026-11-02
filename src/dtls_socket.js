/**
 * dtls_socket.js — UDP transport wrapper for DTLS.
 *
 * DTLSSocket: wraps a single DTLS connection over a UDP socket.
 * createDTLSServer: listens on a UDP port, manages multiple DTLS sessions.
 * connectDTLS: client convenience — creates UDP socket + DTLSSocket.
 *
 * Usage (client):
 *   let socket = connectDTLS({ host: 'example.com', port: 4433 });
 *   socket.on('connect', () => socket.send('hello'));
 *   socket.on('data', (buf) => console.log(buf));
 *
 * Usage (server):
 *   let server = createDTLSServer({ key: KEY, cert: CERT }, (socket) => {
 *     socket.on('data', (buf) => socket.send(buf)); // echo
 *   });
 *   server.listen(4433);
 */

import dgram from 'node:dgram';
import dns from 'node:dns';
import net from 'node:net';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import DTLSSession, { SERVER_CID_LEN } from './dtls_session.js';
import { datagramCid } from './record.js';
import { localLists, versionsInRange, pskOptions } from './node_options.js';


// ============================================================
//  DTLSSocket — single DTLS connection over UDP
// ============================================================

// connectDTLS's own UDP socket (not exported): the DTLSSocket may replace it
// by one of the family its host name resolves to, and closes it when done.
const kOwnsTransport = Symbol('ownsTransport');
const kTransport = Symbol('transport');
// The server's: told when one of its connections takes a new address
// (setRemoteAddress), to find it there.
const kAddressMoved = Symbol('addressMoved');


// The UDP sockets this module binds itself (createDTLSServer, connectDTLS):
// 4 MB receive and send buffers, or socketBufferSize (bytes; 0 or false, the
// OS default). The default (208 KB on Linux) holds some 180 datagrams, and a
// burst bigger than one event-loop turn drains is dropped in the kernel,
// silently: a retransmission, and a cut in the peer's sending rate.
// The kernel caps the size at net.core.rmem_max / wmem_max. A socket handed
// in (new DTLSSocket(udp, ...)) is the caller's, and keeps its own.
const DEFAULT_SOCKET_BUFFER_SIZE = 4 << 20;
function checkedSocketBufferSize(v) {
  if (v === undefined || v === null) return DEFAULT_SOCKET_BUFFER_SIZE;
  if (v === 0 || v === false) return 0;
  if (!Number.isInteger(v) || v < 0 || v > 0x7fffffff) throw new RangeError('socketBufferSize must be a positive integer (bytes), 0 or false, got ' + v);
  return v;
}
function createUdpSocket(base, size) {
  return dgram.createSocket(size > 0 ? Object.assign({}, base, { recvBufferSize: size, sendBufferSize: size }) : base);
}

// What a DTLSSocket — or the server, for each of its connections — sets
// itself. Every other option goes on to the DTLSSession as the caller gave
// it: these were hand-copied lists, and what one left out did not exist —
// createDTLSServer dropped ca, rejectUnauthorized, checkServerIdentity and
// cipherSuites, so a server with requestCert and a ca took ANY client
// certificate (a self-signed one included).
function sessionOptions(options, own) {
  return Object.assign({}, options, own);
}

function DTLSSocket(udpSocket, options) {
  if (!(this instanceof DTLSSocket)) return new DTLSSocket(udpSocket, options);
  options = options || {};

  let self = this;
  let ev = new EventEmitter();

  let remoteAddress = options.remoteAddress || null;
  let remotePort = options.remotePort || null;
  let ownsTransport = options[kOwnsTransport] === true;

  // A client given a host NAME: resolved once, here. It was used as the
  // address as it was — every datagram sent to it paid a lookup of its own
  // (dgram resolves a name per send), and every datagram back was dropped,
  // its rinfo.address (an IP) never equal to the name: connectDTLS to
  // 'localhost' never connected. What the session sends meanwhile — its
  // ClientHello — waits for the address; what arrives meanwhile is no one's.
  // A socket of our own (connectDTLS) resolves to IPv4 or IPv6, whichever the
  // name has first, and gets a UDP socket of that family; a caller's socket
  // keeps its family and the name must resolve to it.
  let resolving = null;
  if (!options.isServer && remoteAddress && net.isIP(remoteAddress) === 0) {
    let name = remoteAddress;
    remoteAddress = null;
    resolving = [];
    let family = ownsTransport ? 0 : (udpSocket && udpSocket.type === 'udp6' ? 6 : 4);
    dns.lookup(name, { family: family }, function(err, address, fam) {
      let held = resolving;
      resolving = null;
      // Closed meanwhile: the UDP socket may be gone, and nothing is owed.
      if (session.state === 'closed') return;
      if (err) { ev.emit('error', err); session.close(); return; }
      if (ownsTransport && (fam === 6) !== (udpSocket.type === 'udp6')) {
        detachTransport(udpSocket);
        try { udpSocket.close(); } catch (e) {}
        udpSocket = createUdpSocket({ type: fam === 6 ? 'udp6' : 'udp4' }, checkedSocketBufferSize(options.socketBufferSize));
        attachTransport(udpSocket);
      }
      remoteAddress = address;
      for (let i = 0; i < held.length; i++) transmit(held[i]);
    });
  }

  // External PSK as node:tls takes it, as TLSSocket does (pskOptions).
  let session = new DTLSSession(sessionOptions(options, Object.assign({ isServer: !!options.isServer }, pskOptions(options, self))));

  // Wire session → UDP
  // Datagrams handed to the UDP socket and not yet sent: dgram's send() is
  // asynchronous, and a socket closed with one queued drops it. The last
  // datagram of a failed connection is its alert — closed at once after it,
  // the peer never learned why (the client's illegal_parameter, BoGo
  // FragmentMessage*Mismatch). whenFlushed() waits for them.
  // One callback for every send, not a closure per datagram. A send error
  // comes to it (not as the UDP socket's 'error' event): this connection's,
  // reported on it — on a server's shared socket, not the whole server's.
  let pendingSends = 0, flushWaiters = [];
  function onSent(err) {
    if (err) ev.emit('error', err);
    if (--pendingSends === 0 && flushWaiters.length > 0) {
      let w = flushWaiters; flushWaiters = [];
      for (let i = 0; i < w.length; i++) w[i]();
    }
  }
  function transmit(data) {
    udpSocket.send(data, 0, data.length, remotePort, remoteAddress, onSent);
    pendingSends++;   // counted once queued: a send that throws queued nothing
  }
  session.on('packet', function(data) {
    if (resolving) { resolving.push(data); return; }
    if (!remoteAddress || !remotePort) return;
    transmit(data);
  });
  self.whenFlushed = function(fn) { if (pendingSends === 0) fn(); else flushWaiters.push(fn); };

  session.on('connect', function() {
    ev.emit('connect');
    ev.emit('secureConnect');
  });

  session.on('data', function(data) {
    ev.emit('data', data);
  });

  session.on('error', function(err) {
    ev.emit('error', err);
  });

  session.on('close', function() {
    ev.emit('close');
  });

  session.on('session', function(ticket) {
    ev.emit('session', ticket);
  });

  // Server-side callers use this to inspect the peer's offered extensions
  // (session.getRemoteExtension) and answer via set_context BEFORE the
  // ServerHello is built — e.g. DTLS-SRTP's use_srtp (RFC 5764).
  session.on('clienthello', function(data, message) {
    ev.emit('clienthello', data, message);
  });

  // An alert received (the peer's warnings among them), and the Connection
  // IDs agreed or moved: as DTLSSession reports them.
  session.on('alert', function(a) { ev.emit('alert', a); });
  session.on('connectionId', function(ids) { ev.emit('connectionId', ids); });

  /**
   * Feed an incoming UDP datagram (filtered by remote address/port).
   * Called by the UDP socket's message handler or by DTLSServer.
   *
   * With Connection IDs agreed, a datagram of this connection may come from
   * another address (a NAT that rebound the peer's port; the server finds
   * the connection by its CID). It is taken, and when it holds the newest
   * authenticated record yet the new address is reported:
   * 'remoteAddressChange' { address, port }. It is not taken over by itself
   * — RFC 9146 §6 (and RFC 9147 §9) forbid it without a way of knowing the
   * peer is there; an application that has one calls setRemoteAddress.
   */
  function feedDatagram(data, rinfo) {
    // Update remote address on first datagram (server side)
    if (!remoteAddress && rinfo) {
      remoteAddress = rinfo.address;
      remotePort = rinfo.port;
    }

    let newest = session.feedDatagram(data);
    if (newest && rinfo && (rinfo.address !== remoteAddress || rinfo.port !== remotePort) && session.getConnectionIds()) {
      ev.emit('remoteAddressChange', { address: rinfo.address, port: rinfo.port });
    }
  }

  /** Send to another address from now on — the peer's new one, as the
   *  application knows it (see feedDatagram). */
  function setRemoteAddress(address, port) {
    if (net.isIP(address) === 0 || !Number.isInteger(port) || port <= 0 || port > 65535) throw new TypeError('setRemoteAddress: an IP address and a port');
    let previous = { address: remoteAddress, port: remotePort };
    remoteAddress = address;
    remotePort = port;
    if (typeof options[kAddressMoved] === 'function') options[kAddressMoved](previous, { address: address, port: port });
  }

  // A client reads its UDP socket itself (a server's connections are fed by
  // the server). A socket of our own also reports its errors here — it had
  // no 'error' listener, and one (a failed bind) took the process down.
  function onMessage(msg, rinfo) {
    if (resolving) return;
    if (remoteAddress && (rinfo.address !== remoteAddress || rinfo.port !== remotePort)) return;
    feedDatagram(msg, rinfo);
  }
  function onTransportError(err) { ev.emit('error', err); session.close(); }
  function attachTransport(u) {
    u.on('message', onMessage);
    if (ownsTransport) u.on('error', onTransportError);
  }
  function detachTransport(u) {
    u.removeListener('message', onMessage);
    u.removeListener('error', onTransportError);
  }
  if (!options.isServer && udpSocket) attachTransport(udpSocket);
  self[kTransport] = function() { return udpSocket; };

  // ---- Public API ----

  self.send = function(data) { session.send(data); };
  self.close = function() { session.close(); };
  self.feedDatagram = feedDatagram;
  self.setRemoteAddress = setRemoteAddress;

  self.on = function(name, fn) { ev.on(name, fn); };
  self.off = function(name, fn) { ev.off(name, fn); };

  Object.defineProperty(self, 'connected', { get: function() { return session.connected; } });
  Object.defineProperty(self, 'state', { get: function() { return session.state; } });
  Object.defineProperty(self, 'version', { get: function() { return session.version; } });
  Object.defineProperty(self, 'remoteAddress', { get: function() { return remoteAddress; } });
  Object.defineProperty(self, 'remotePort', { get: function() { return remotePort; } });

  self.getNegotiationResult = function() { return session.getNegotiationResult(); };
  self.getALPN = function() { return session.getALPN(); };
  self.getEchStatus = function() { return session.getEchStatus(); };
  self.isEchBackend = function() { return session.isEchBackend(); };
  /** External PSK: the identity (a Buffer, as TLSSocket's), or null. */
  self.getPskIdentity = function() { let id = session.getPskIdentity(); return id ? Buffer.from(id) : null; };
  self.getConnectionIds = function() { return session.getConnectionIds(); };
  self.getPeerCertificate = function() { return session.getPeerCertificate(); };

  /** TLS fingerprints, { hash, raw } or null (see TLSSession): JA4 and JA5
   *  of the ClientHello, JA4S of the ServerHello — in either role. */
  self.getJA4 = function(opts) { return session.getJA4(opts); };
  self.getJA5 = function(opts) { return session.getJA5(opts); };
  self.getJA4S = function(opts) { return session.getJA4S(opts); };

  /** Set the key and certificate for this connection (Node parity). */
  self.setKeyCert = function(ctxOrOpts) {
    if (session.setKeyCert) session.setKeyCert(ctxOrOpts);
  };

  /** Finished verify_data — the tls-unique channel binding of RFC 5929.
   *  DTLS-SRTP callers use this alongside exportKeyingMaterial(). */
  self.getFinished = function() {
    let v = session.getFinished ? session.getFinished() : null;
    return v == null ? undefined : v;
  };
  self.getPeerFinished = function() {
    let v = session.getPeerFinished ? session.getPeerFinished() : null;
    return v == null ? undefined : v;
  };

  /** The last session ('session' event's Buffer) — pass it as `session` to resume. */
  self.getSession = function() { return session.getSession(); };
  /** The path MTU (largest datagram written); see DTLSSession.setMTU. */
  self.setMTU = function(mtu) { session.setMTU(mtu); };
  self.getMTU = function() { return session.getMTU(); };
  /** Where each flight's retransmission timer starts; see DTLSSession. */
  self.setInitialRetransmitTimeout = function(ms) { session.setInitialRetransmitTimeout(ms); };

  /** Whether this connection resumed an earlier session. */
  self.isSessionReused = function() {
    return session.isSessionReused ? session.isSessionReused() : false;
  };

  /** RFC 5705 / RFC 8446 §7.5 exporter (Node tls.TLSSocket parity).
   *  DTLS-SRTP: exportKeyingMaterial(len, 'EXTRACTOR-dtls_srtp') — no context.
   *  Returns Buffer, or null before secrets are available. */
  self.exportKeyingMaterial = function(length, label, context_value) {
    return session.exportKeyingMaterial(length, label, context_value);
  };

  /** Negotiated DTLS-SRTP protection profile (RFC 5764), or null. */
  self.getSelectedSrtpProfile = function() {
    return session.getSelectedSrtpProfile();
  };

  /** Peer hello extensions / single extension by numeric type. */
  self.getRemoteExtensions = function() { return session.getRemoteExtensions(); };
  self.getRemoteExtension = function(type) { return session.getRemoteExtension(type); };

  /** Pass config through to the underlying session (e.g. local_extensions
   *  from a 'clienthello' handler). */
  self.set_context = function(opts) { session.set_context(opts); };

  /** Access to internal DTLSSession (for advanced use). */
  self.session = session;

  return self;
}


// ============================================================
//  createDTLSServer — manages multiple DTLS sessions on one UDP port
// ============================================================

function createDTLSServer(options, connectionListener) {
  if (typeof options === 'function') {
    connectionListener = options;
    options = {};
  }
  options = options || {};
  // Checked here, once, as createServer does: not on each client's hello.
  localLists(options, versionsInRange(options.minVersion, options.maxVersion, true));
  // Connection IDs: one per connection, drawn here — a single one given for
  // the server would be every connection's, and find none of them.
  if (options.connectionId !== undefined && options.connectionId !== null && typeof options.connectionId !== 'boolean') {
    throw new TypeError('createDTLSServer: connectionId is true or false (each connection is given its own)');
  }
  let cidOn = options.connectionId === true;
  let socketBufferSize = checkedSocketBufferSize(options.socketBufferSize);
  let byCid = {};       // CID (hex) → DTLSSocket

  let ev = new EventEmitter();
  let udpSocket = null;
  let connections = {};  // 'addr:port' → DTLSSocket

  // One ticket key for the server, not one per connection: a ticket is
  // opened by the connection that comes back, not the one that issued it.
  // Each DTLSSocket drew its own, so no ticket of this server could ever
  // be used (as TLSServer: tls_socket.js keeps one per server too).
  let ticketKeys = options.ticketKeys ? Buffer.from(options.ticketKeys) : crypto.randomBytes(48);

  // A ClientHello: an unprotected (epoch 0) handshake record whose message
  // is type 1 — the first record of the datagram, as a ClientHello comes.
  function isClientHello(msg) {
    return msg.length > 25 && msg[0] === 22 && msg[3] === 0 && msg[4] === 0 && msg[13] === 1;
  }

  function newConnection(key, rinfo) {
    let cid = null;
    if (cidOn) {
      do { cid = crypto.randomBytes(SERVER_CID_LEN); } while (byCid[cid.toString('hex')]);
    }
    let socket = new DTLSSocket(udpSocket, sessionOptions(options, {
      isServer: true,
      remoteAddress: rinfo.address,
      remotePort: rinfo.port,
      ticketKeys: ticketKeys,
      connectionId: cid || false,
      // Moved (setRemoteAddress): found at its new address from now on —
      // unless another connection holds it; its own records, with the CID,
      // find it anyway (onDatagram), and the other is not ended on the
      // application's word.
      [kAddressMoved]: function(from, to) {
        let next = to.address + ':' + to.port;
        if (connections[key] === socket) delete connections[key];
        if (replacing[key] === socket) delete replacing[key];
        key = next;
        if (!connections[key]) connections[key] = socket;
      },
    }));
    if (cid) byCid[cid.toString('hex')] = socket;

    socket.on('close', function() {
      if (connections[key] === socket) delete connections[key];
      if (replacing[key] === socket) delete replacing[key];
      if (cid && byCid[cid.toString('hex')] === socket) delete byCid[cid.toString('hex')];
    });

    socket.on('connect', function() {
      // A new association from the address of an existing one (below): it
      // has completed its handshake — the client is there — and takes the
      // old one's place.
      if (replacing[key] === socket) {
        let old = connections[key];
        connections[key] = socket;
        delete replacing[key];
        if (old) old.close();
      }
      if (connectionListener) connectionListener(socket);
      ev.emit('connection', socket);
    });

    socket.on('error', function(err) {
      ev.emit('clientError', err, socket);
    });
    return socket;
  }

  // RFC 6347 §4.2.8 (and RFC 9147 §5.9 the same): a ClientHello from the
  // address of an established association is a new one — the client
  // restarted, or a NAT gave its port to another — and the server "SHOULD
  // proceed with a new handshake but MUST NOT destroy the existing
  // association until the client has demonstrated reachability", by
  // completing the handshake. It went to the old session, which took it for
  // a stray retransmission: the client was never answered while that entry
  // lived — for good, if its close_notify was lost (a dtls_loss_test
  // handshake in ~150 hung so, with no loss at all).
  // So the new handshake runs beside the old association (replacing), and
  // replaces it when it connects. Meanwhile every other datagram goes to
  // both: a protected record opens only under the keys it was made with,
  // and each session drops what it cannot open — and a spoofed ClientHello
  // never touches the old one.
  let replacing = {};   // 'addr:port' → the DTLSSocket of a new handshake there

  function onDatagram(msg, rinfo) {
    // A record with one of our CIDs is that connection's, whatever address
    // it comes from — the peer moved, maybe onto an address another
    // connection still holds (a NAT that gave the port on).
    if (cidOn) {
      let c = datagramCid(msg, SERVER_CID_LEN);
      let owner = c ? byCid[Buffer.from(c).toString('hex')] : null;
      if (owner) { owner.feedDatagram(msg, rinfo); return; }
    }
    let key = rinfo.address + ':' + rinfo.port;
    let conn = connections[key];
    if (!conn) {
      conn = connections[key] = newConnection(key, rinfo);
      conn.feedDatagram(msg, rinfo);
      return;
    }
    if (isClientHello(msg) && conn.state === 'connected') {
      if (!replacing[key]) replacing[key] = newConnection(key, rinfo);
      replacing[key].feedDatagram(msg, rinfo);
      return;
    }
    conn.feedDatagram(msg, rinfo);
    if (replacing[key]) replacing[key].feedDatagram(msg, rinfo);
  }

  // listen(port[, address][, callback]). The address's family decides the
  // socket's: an IPv6 one, an IPv6 socket. No address: '::', dual-stack —
  // IPv4 clients too (as '::ffff:a.b.c.d'), as node:net and node:tls listen
  // — or, on a host without IPv6, 0.0.0.0. It was IPv4 only, whatever the
  // address: an IPv6 client could never reach a DTLS server.
  function listen(port, address, callback) {
    if (typeof address === 'function') { callback = address; address = undefined; }
    let open = function(type, bindAddress, fallback) {
      let u = createUdpSocket({ type: type, ipv6Only: false }, socketBufferSize);
      let onBindError = function(err) {
        u.removeListener('error', onBindError);
        try { u.close(); } catch (e) {}
        if (fallback && (err.code === 'EAFNOSUPPORT' || err.code === 'EADDRNOTAVAIL' || err.code === 'EPROTONOSUPPORT' || err.code === 'EINVAL')) { fallback(); return; }
        ev.emit('error', err);
      };
      u.on('error', onBindError);
      u.bind(port, bindAddress, function() {
        u.removeListener('error', onBindError);
        udpSocket = u;
        u.on('message', onDatagram);
        u.on('error', function(err) { ev.emit('error', err); });
        if (callback) callback();
        ev.emit('listening');
      });
    };
    if (address !== undefined && address !== null) open(net.isIP(address) === 6 ? 'udp6' : 'udp4', address, null);
    else open('udp6', '::', function() { open('udp4', undefined, null); });
  }

  // Every connection's close_notify first, then the socket — once they have
  // gone (whenFlushed): closed at once, it dropped them.
  function close(callback) {
    let open = Object.keys(connections).map(function(k) { return connections[k]; })
      .concat(Object.keys(replacing).map(function(k) { return replacing[k]; }));
    connections = {};
    replacing = {};
    byCid = {};
    let sock = udpSocket;
    udpSocket = null;
    for (let i = 0; i < open.length; i++) open[i].close();
    if (!sock) return;
    let waiting = open.length + 1;
    let done = function() { if (--waiting === 0) sock.close(callback); };
    for (let i = 0; i < open.length; i++) open[i].whenFlushed(done);
    done();
  }

  function address() {
    return udpSocket ? udpSocket.address() : null;
  }

  return {
    listen: listen,
    close: close,
    address: address,
    on: function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },
  };
}


// ============================================================
//  connectDTLS — client convenience
// ============================================================

function connectDTLS(options, callback) {
  options = options || {};
  let host = options.host || options.hostname || '127.0.0.1';
  let port = options.port || 4433;

  // An IPv6 literal needs an IPv6 socket; for a name, the DTLSSocket picks
  // the family it resolves to (kOwnsTransport).
  let udp = createUdpSocket({ type: net.isIP(host) === 6 ? 'udp6' : 'udp4' }, checkedSocketBufferSize(options.socketBufferSize));

  // Every option goes on to the session (sessionOptions), as given: the
  // client's certificate, ca, cipherSuites, ... — this list too had dropped
  // whatever it did not name.
  let socket = new DTLSSocket(udp, sessionOptions(options, {
    isServer: false,
    remoteAddress: host,
    remotePort: port,
    servername: options.servername || host,
    [kOwnsTransport]: true,
  }));

  if (callback) socket.on('connect', callback);

  // After what is still queued has gone — the closing alert above all.
  socket.on('close', function() {
    socket.whenFlushed(function() { try { socket[kTransport]().close(); } catch(e) {} });
  });

  return socket;
}


// ============================================================
//  Exports
// ============================================================

export { DTLSSocket, createDTLSServer, connectDTLS };
