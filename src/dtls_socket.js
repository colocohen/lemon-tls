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
import { EventEmitter } from 'node:events';
import DTLSSession from './dtls_session.js';


// ============================================================
//  DTLSSocket — single DTLS connection over UDP
// ============================================================

function DTLSSocket(udpSocket, options) {
  if (!(this instanceof DTLSSocket)) return new DTLSSocket(udpSocket, options);
  options = options || {};

  let self = this;
  let ev = new EventEmitter();

  let remoteAddress = options.remoteAddress || null;
  let remotePort = options.remotePort || null;

  // Create DTLSSession
  let session = new DTLSSession({
    isServer: !!options.isServer,
    servername: options.servername,
    SNICallback: options.SNICallback,
    cert: options.cert,
    key: options.key,
    rejectUnauthorized: options.rejectUnauthorized,
    ca: options.ca,
    alpnProtocols: options.alpnProtocols,
    minVersion: options.minVersion,
    maxVersion: options.maxVersion,
    mtu: options.mtu,
    ticketKeys: options.ticketKeys,
    useCookies: options.useCookies,
  });

  // Wire session → UDP
  session.on('packet', function(data) {
    if (!remoteAddress || !remotePort) return;
    udpSocket.send(data, 0, data.length, remotePort, remoteAddress);
  });

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

  /**
   * Feed an incoming UDP datagram (filtered by remote address/port).
   * Called by the UDP socket's message handler or by DTLSServer.
   */
  function feedDatagram(data, rinfo) {
    // Update remote address on first datagram (server side)
    if (!remoteAddress && rinfo) {
      remoteAddress = rinfo.address;
      remotePort = rinfo.port;
    }

    session.feedDatagram(data);
  }

  // If not server, bind to UDP messages directly
  if (!options.isServer && udpSocket) {
    udpSocket.on('message', function(msg, rinfo) {
      if (remoteAddress && (rinfo.address !== remoteAddress || rinfo.port !== remotePort)) return;
      feedDatagram(msg, rinfo);
    });
  }

  // ---- Public API ----

  self.send = function(data) { session.send(data); };
  self.close = function() { session.close(); };
  self.feedDatagram = feedDatagram;

  self.on = function(name, fn) { ev.on(name, fn); };
  self.off = function(name, fn) { ev.off(name, fn); };

  Object.defineProperty(self, 'connected', { get: function() { return session.connected; } });
  Object.defineProperty(self, 'state', { get: function() { return session.state; } });
  Object.defineProperty(self, 'version', { get: function() { return session.version; } });
  Object.defineProperty(self, 'remoteAddress', { get: function() { return remoteAddress; } });
  Object.defineProperty(self, 'remotePort', { get: function() { return remotePort; } });

  self.getNegotiationResult = function() { return session.getNegotiationResult(); };
  self.getALPN = function() { return session.getALPN(); };
  self.getPeerCertificate = function() { return session.getPeerCertificate(); };

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

  let ev = new EventEmitter();
  let udpSocket = null;
  let connections = {};  // 'addr:port' → DTLSSocket

  function listen(port, address, callback) {
    if (typeof address === 'function') { callback = address; address = undefined; }

    udpSocket = dgram.createSocket('udp4');

    udpSocket.on('message', function(msg, rinfo) {
      let key = rinfo.address + ':' + rinfo.port;

      if (!(key in connections)) {
        // New client
        let socket = new DTLSSocket(udpSocket, {
          isServer: true,
          remoteAddress: rinfo.address,
          remotePort: rinfo.port,
          cert: options.cert,
          key: options.key,
          SNICallback: options.SNICallback,
          alpnProtocols: options.alpnProtocols,
          minVersion: options.minVersion,
          maxVersion: options.maxVersion,
          mtu: options.mtu,
          ticketKeys: options.ticketKeys,
          useCookies: options.useCookies,
        });

        connections[key] = socket;

        socket.on('close', function() {
          delete connections[key];
        });

        socket.on('connect', function() {
          if (connectionListener) connectionListener(socket);
          ev.emit('connection', socket);
        });

        socket.on('error', function(err) {
          ev.emit('clientError', err, socket);
        });
      }

      connections[key].feedDatagram(msg, rinfo);
    });

    udpSocket.on('error', function(err) {
      ev.emit('error', err);
    });

    udpSocket.bind(port, address, function() {
      if (callback) callback();
      ev.emit('listening');
    });
  }

  function close(callback) {
    for (let key in connections) {
      connections[key].close();
    }
    connections = {};
    if (udpSocket) {
      udpSocket.close(callback);
      udpSocket = null;
    }
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

  let udp = dgram.createSocket('udp4');

  let socket = new DTLSSocket(udp, {
    isServer: false,
    remoteAddress: host,
    remotePort: port,
    servername: options.servername || host,
    rejectUnauthorized: options.rejectUnauthorized,
    ca: options.ca,
    alpnProtocols: options.alpnProtocols,
    minVersion: options.minVersion,
    maxVersion: options.maxVersion,
    mtu: options.mtu,
  });

  if (callback) socket.on('connect', callback);

  socket.on('close', function() {
    try { udp.close(); } catch(e) {}
  });

  return socket;
}


// ============================================================
//  Exports
// ============================================================

export { DTLSSocket, createDTLSServer, connectDTLS };
