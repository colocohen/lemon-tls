<p align="center">
  <img src="https://github.com/colocohen/lemon-tls/raw/main/lemontls.svg" width="450" alt="LemonTLS"/>
</p>

<h1 align="center">LemonTLS</h1>
<p align="center">
  <em>🍋 Pure JavaScript implementation of TLS for Node.js, exposing cryptographic keys and record-layer control for implementing advanced protocols.</em>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/lemon-tls">
    <img src="https://img.shields.io/npm/v/lemon-tls?color=blue" alt="npm">
  </a>
  <img src="https://img.shields.io/badge/status-in%20development-yellow" alt="status">
  <img src="https://img.shields.io/github/license/colocohen/lemon-tls?color=brightgreen" alt="license">
</p>

---

> **⚠️ Project status: *Active development*.**
> APIs may change without notice until we reach v1.0.
> Use at your own risk and please report issues!

## ✨ Features

* 🔒 **Pure JavaScript** – no OpenSSL, no native bindings. Zero dependencies.
* ⚡ **TLS 1.3 (RFC 8446)** + **TLS 1.2** – both server and client.
* 🌐 **Browser-tested** – verified interop with Chrome, curl, Node.js, openssl s_client, and msquic.
* 🔑 **Key Access** – read handshake secrets, traffic keys, ECDHE shared secret, and resumption data at any point.
* 🔁 **Session Resumption** – session tickets + PSK with binder validation.
* 🔄 **Key Update** – refresh traffic keys on long-lived TLS 1.3 connections.
* 🔃 **HelloRetryRequest** – automatic group negotiation fallback (X25519, P-256, P-384).
* 📜 **Client Certificate Auth** – mutual TLS (mTLS) with `requestCert` / `cert` / `key` options.
* 🛡 **Designed for extensibility** – exposes cryptographic keys and record-layer primitives for QUIC, DTLS, or custom transports.
* 🧩 **Two API levels** – high-level `TLSSocket` (drop-in Node.js Duplex stream) and low-level `TLSSession` (state machine only, you handle the transport).
* 🔧 **Beyond Node.js** – per-connection cipher/sigalg/group selection, JA3 fingerprinting, certificate pinning, and more options that are impossible or require `openssl.cnf` hacks in Node.js.
* 📘 **TypeScript support** – full `.d.ts` bundled, type-checked in strict mode.

## 📦 Installation

```
npm i lemon-tls
```

## 🚀 Quick Start

### Drop-in Node.js Replacement

```js
import tls from 'lemon-tls';  // not 'node:tls' - same API
import fs from 'node:fs';

// Server
const server = tls.createServer({
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.crt'),
}, (socket) => {
  console.log('Protocol:', socket.getProtocol());
  console.log('Cipher:', socket.getCipher().name);
  socket.write('Hello from LemonTLS!\n');
});
server.listen(8443);

// Client
const socket = tls.connect(8443, 'localhost', { rejectUnauthorized: false }, () => {
  socket.write('Hello from client!\n');
});
socket.on('data', (d) => console.log(d.toString()));
```

### Low-Level: TLSSocket with TCP

```js
import net from 'node:net';
import fs from 'node:fs';
import { TLSSocket, createSecureContext } from 'lemon-tls';

const server = net.createServer((tcp) => {
  const socket = new TLSSocket(tcp, {
    isServer: true,
    SNICallback: (servername, cb) => {
      cb(null, createSecureContext({
        key: fs.readFileSync('server.key'),
        cert: fs.readFileSync('server.crt'),
      }));
    }
  });
  socket.on('secureConnect', () => socket.write('hi\n'));
  socket.on('data', (d) => console.log('Got:', d.toString()));
});
server.listen(8443);
```

### Session Resumption (PSK)

```js
let savedSession = null;

// First connection - the 'session' event emits an opaque Buffer (Node-compatible).
// Treat it as a blob: store it, pass it back — don't introspect the bytes.
socket.on('session', (sessionBuffer) => { savedSession = sessionBuffer; });

// Second connection - resume (no certificate exchange, faster)
const socket2 = tls.connect(8443, 'localhost', { session: savedSession }, () => {
  console.log('Resumed:', socket2.isSessionReused());  // true
});
```

### Mutual TLS (Client Certificate)

```js
// Server: request client certificate
const server = tls.createServer({
  key: serverKey, cert: serverCert,
  requestCert: true,
});

// Client: provide certificate
const socket = tls.connect(8443, 'localhost', {
  cert: fs.readFileSync('client.crt'),
  key: fs.readFileSync('client.key'),
});
```

## 📚 API

### Module-Level Functions

```js
import tls from 'lemon-tls';

tls.connect(port, host, options, callback)         // Node.js compatible
tls.createServer(options, callback)                // Node.js compatible — returns tls.Server
tls.createSecureContext({ key, cert })             // PEM → opaque SecureContext
tls.checkServerIdentity(hostname, cert)            // RFC 6125 hostname verification
tls.getCiphers()                                   // ['tls_aes_128_gcm_sha256', ...]
tls.DEFAULT_MIN_VERSION                            // 'TLSv1.2'
tls.DEFAULT_MAX_VERSION                            // 'TLSv1.3'
tls.DEFAULT_CIPHERS                                // 'TLS_AES_256_GCM_SHA384:...'
tls.DEFAULT_ECDH_CURVE                             // 'auto'
```

### `tls.Server` (returned by `createServer`)

```js
server.listen(port, host?, callback?)              // Start listening
server.close(callback?)                            // Stop accepting new connections
server.setSecureContext({ key, cert })             // Runtime cert rotation (Let's Encrypt, etc.)
server.getTicketKeys()                             // 48-byte Buffer (ticket encryption keys)
server.setTicketKeys(keys)                         // For clustered deployments
server.address()                                   // { port, family, address }
```

**Server events:**

| Event | Callback | Description |
|---|---|---|
| `secureConnection` | `(socket)` | Handshake complete — handle the new connection |
| `tlsClientError` | `(err, socket)` | Client handshake failed |
| `keylog` | `(line, socket)` | SSLKEYLOGFILE-format line (for Wireshark) |
| `newSession` | `(id, data, cb)` | Store a TLS 1.2 Session ID (for custom session stores) |
| `resumeSession` | `(id, cb)` | Look up a TLS 1.2 Session ID (for custom session stores) |
| `error` / `close` | — | Transport-level |

### `TLSSocket`

High-level wrapper extending `stream.Duplex`, API-compatible with Node.js [`tls.TLSSocket`](https://nodejs.org/api/tls.html#class-tlstlssocket).

#### Constructor Options

**Standard (Node.js compatible):**

| Option | Type | Description |
|---|---|---|
| `isServer` | boolean | Server or client mode |
| `servername` | string | SNI hostname (client) |
| `SNICallback` | function | `(servername, cb) => cb(null, secureContext)` (server) |
| `minVersion` | string | `'TLSv1.2'` or `'TLSv1.3'` |
| `maxVersion` | string | `'TLSv1.2'` or `'TLSv1.3'` |
| `ALPNProtocols` | string[] | Offered ALPN protocols |
| `rejectUnauthorized` | boolean | Validate peer certificate (default: `true`) |
| `ca` | Buffer/string | CA certificate(s) for validation |
| `ticketKeys` | Buffer | 48-byte key for session ticket encryption (server) |
| `session` | Buffer | Saved session blob from `'session'` event (client resumption) |
| `requestCert` | boolean | Request client certificate (server) |
| `cert` | Buffer/string | Client certificate PEM (for mTLS) |
| `key` | Buffer/string | Client private key PEM (for mTLS) |

**LemonTLS-only (not available in Node.js):**

| Option | Type | Description |
|---|---|---|
| `sessionTickets` | boolean | Enable/disable session tickets (default: `true`) |
| `signatureAlgorithms` | number[] | Per-connection sigalg list, e.g. `[0x0804]` for RSA-PSS only |
| `groups` | number[] | Per-connection curves, e.g. `[0x001d]` for X25519 only |
| `prioritizeChaCha` | boolean | Move ChaCha20-Poly1305 before AES in cipher preference |
| `maxRecordSize` | number | Max plaintext per TLS record (default: 16384) |
| `allowedCipherSuites` | number[] | Whitelist - only these ciphers are offered |
| `pins` | string[] | Certificate pinning: `['sha256/AAAA...']` |
| `handshakeTimeout` | number | Abort handshake after N ms |
| `maxHandshakeSize` | number | Max handshake bytes - DoS protection |
| `certificateCallback` | function | Dynamic cert selection: `(info, cb) => cb(null, ctx)` |

#### Events

| Event | Callback | Description |
|---|---|---|
| `secureConnect` | `()` | Handshake complete, data can flow |
| `data` | `(Buffer)` | Decrypted application data received |
| `session` | `(Buffer)` | **Opaque session blob** — pass back to `connect({ session })` to resume |
| `keyUpdate` | `(direction)` | Traffic keys refreshed: `'send'` or `'receive'` |
| `keylog` | `(Buffer)` | SSLKEYLOGFILE-format line (for Wireshark) |
| `clienthello` | `(raw, parsed)` | Raw ClientHello received (server, for JA3) |
| `handshakeMessage` | `(type, raw, parsed)` | Every handshake message (debugging) |
| `certificateRequest` | `(msg)` | Server requested a client certificate |
| `error` | `(Error)` | TLS or transport error |
| `close` | `()` | Connection closed |

#### Properties & Methods

**Node.js compatible:**

| | |
|---|---|
| `socket.getProtocol()` | `'TLSv1.3'` or `'TLSv1.2'` |
| `socket.getCipher()` | `{ name, standardName, version }` |
| `socket.getPeerCertificate()` | `{ subject, issuer, valid_from, fingerprint256, raw, ... }` |
| `socket.getPeerX509Certificate()` | Native `crypto.X509Certificate` of the peer's leaf cert |
| `socket.getCertificate()` | Info about **our** local cert (mirror of `getPeerCertificate`) |
| `socket.getX509Certificate()` | Native `crypto.X509Certificate` of our local cert |
| `socket.getSession()` | Opaque serialized session as `Buffer` (or `undefined`) |
| `socket.getTLSTicket()` | TLS 1.2 raw ticket (`Buffer` or `undefined`) |
| `socket.getFinished()` | Local Finished verify_data (Buffer) |
| `socket.getPeerFinished()` | Peer Finished verify_data (Buffer) |
| `socket.getSharedSigalgs()` | Array of shared signature algorithm names (server-side) |
| `socket.getEphemeralKeyInfo()` | `{ type: 'X25519', size: 253 }` |
| `socket.exportKeyingMaterial(len, label, ctx)` | RFC 5705 keying material |
| `socket.isSessionReused()` | `true` if session was resumed |
| `socket.setMaxSendFragment(size)` | Cap outgoing record plaintext size `[512, 16384]` |
| `socket.setServername(name)` | Set SNI (client-side, before handshake) |
| `socket.disableRenegotiation()` | No-op stub (TLS 1.3 removed renegotiation) |
| `socket.enableTrace()` | No-op stub (use `keylog` / `handshakeMessage` for insight) |
| `socket.authorized` | `true` if peer certificate is valid |
| `socket.authorizationError` | Error string or `null` |
| `socket.alpnProtocol` | Negotiated ALPN protocol or `false` |
| `socket.servername` | SNI value (string or `false`) |
| `socket.encrypted` | Always `true` |
| `socket.remoteAddress` / `.remotePort` | Peer address (delegated to transport) |
| `socket.setNoDelay()` / `.setKeepAlive()` / `.setTimeout()` | Transport delegation |
| `socket.write(data)` | Send encrypted application data |
| `socket.end()` | Send `close_notify` alert and close |

**LemonTLS-only:**

| | |
|---|---|
| `socket.session` | Access the underlying `TLSSession` (low-level state machine) |
| `socket.isResumed` | Alias for `isSessionReused()` |
| `socket.handshakeDuration` | Handshake time in ms |
| `socket.getJA3()` | `{ hash, raw }` - JA3 fingerprint (server-side) |
| `socket.getSharedSecret()` | ECDHE shared secret (Buffer) |
| `socket.getNegotiationResult()` | `{ version, cipher, group, sni, alpn, resumed, helloRetried, ... }` |
| `socket.rekeySend()` | Refresh outgoing encryption keys (TLS 1.3) |
| `socket.rekeyBoth()` | Refresh keys for both directions (TLS 1.3) |

### `TLSSession`

The **core state machine** for a TLS connection. Performs handshake, key derivation, and state management - but does **no I/O**. You provide the transport.

This is the API to use for QUIC, DTLS, or any custom transport.

```js
import { TLSSession } from 'lemon-tls';

const session = new TLSSession({ isServer: true });

// Feed incoming handshake bytes from your transport:
session.message(handshakeBytes);

// Session tells you what to send:
session.on('message', (epoch, seq, type, data) => {
  // epoch: 0=cleartext, 1=handshake-encrypted, 2=app-encrypted
  myTransport.send(data);
});

session.on('hello', () => {
  session.set_context({
    local_supported_versions: [0x0304],
    local_supported_cipher_suites: [0x1301, 0x1302, 0x1303],
    local_cert_chain: myCerts,
    cert_private_key: myKey,
  });
});

session.on('secureConnect', () => {
  const secrets = session.getTrafficSecrets();
  const result = session.getNegotiationResult();
  console.log(session.handshakeDuration, 'ms');
});

// Key Update
session.requestKeyUpdate(true); // true = request peer to update too
session.on('keyUpdate', ({ direction, secret }) => { /* ... */ });

// PSK callback - full control over ticket validation (server)
session.on('psk', (identity, callback) => {
  const psk = myTicketStore.lookup(identity);
  callback(psk ? { psk, cipher: 0x1301 } : null);
});

// JA3 fingerprinting (server)
session.on('clienthello', (raw, parsed) => {
  console.log(session.getJA3()); // { hash: 'abc...', raw: '769,47-53,...' }
});
```

### Record Layer Module

Shared encrypt/decrypt primitives for QUIC, DTLS, and custom transport consumers:

```js
import { deriveKeys, encryptRecord, decryptRecord, getNonce, getAeadAlgo }
  from 'lemon-tls/record';

const { key, iv } = deriveKeys(trafficSecret, cipherSuite);
const nonce = getNonce(iv, sequenceNumber);
const algo = getAeadAlgo(cipherSuite);  // 'aes-128-gcm' | 'chacha20-poly1305'
const encrypted = encryptRecord(contentType, plaintext, key, nonce, algo);
```

## 🔧 Advanced Options (Not Available in Node.js)

LemonTLS gives you control that Node.js doesn't expose - without `openssl.cnf` hacks:

```js
import tls from 'lemon-tls';

// Per-connection cipher/group/sigalg selection (impossible in Node.js)
const socket = tls.connect(443, 'api.example.com', {
  groups: [0x001d],                        // X25519 only (Node: ecdhCurve is global)
  signatureAlgorithms: [0x0804],           // RSA-PSS-SHA256 only (Node: no control)
  prioritizeChaCha: true,                  // ChaCha20 before AES (Node: no control)
  allowedCipherSuites: [0x1301, 0x1303],   // whitelist (Node: string-based, error-prone)
});

// Disable session tickets (in Node.js requires openssl.cnf)
tls.createServer({ key, cert, sessionTickets: false });

// Certificate pinning
tls.connect(443, 'bank.example.com', {
  pins: ['sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg='],
});

// Handshake timeout - DoS protection
tls.connect(443, 'host', { handshakeTimeout: 5000 });

// Max handshake size - prevents oversized certificate chains
tls.createServer({ key, cert, maxHandshakeSize: 65536 });

// Dynamic certificate selection (beyond SNI - based on cipher, version, extensions)
tls.createServer({
  certificateCallback: (info, cb) => {
    // info = { servername, version, ciphers, sigalgs, groups, alpns }
    const ctx = pickCertFor(info);
    cb(null, ctx);
  }
});

// Wireshark debugging
socket.on('keylog', (line) => fs.appendFileSync('keys.log', line));
// Wireshark: Edit → Preferences → TLS → Pre-Master-Secret log filename → keys.log

// JA3 fingerprinting (server-side bot detection)
server.on('secureConnection', (socket) => {
  const ja3 = socket.getJA3();
  console.log(ja3.hash); // 'e7d705a3286e19ea42f587b344ee6865'
});

// Full negotiation result
socket.on('secureConnect', () => {
  console.log(socket.getNegotiationResult());
  // { version: 0x0304, versionName: 'TLSv1.3', cipher: 0x1301,
  //   cipherName: 'TLS_AES_128_GCM_SHA256', group: 0x001d, groupName: 'X25519',
  //   sni: 'example.com', alpn: 'h2', resumed: false, helloRetried: false,
  //   handshakeDuration: 23 }
});

// ECDHE shared secret access (for research)
console.log(socket.getSharedSecret()); // Buffer<...>
```

## 🌐 Interoperability

LemonTLS is verified against real-world TLS implementations:

| Peer | Role | TLS Versions | Notes |
|---|---|---|---|
| **Chrome** (browser) | Client | 1.3 | Full HTTPS page loads, favicon, streaming 100KB responses under 3G throttling |
| **curl** | Client | 1.2 / 1.3 | Including `--curves P-384:X25519` to force HelloRetryRequest |
| **Node.js `tls`** | Client / Server | 1.2 / 1.3 | Bidirectional interop + session resumption |
| **openssl s_client** | Client | 1.2 / 1.3 | All supported ciphers & groups |
| **msquic** | (via QUICO) | 1.3 | HRR + P-384 + AES-256-GCM-SHA384 tested |

## ⚡ Performance

Benchmarks on Windows (Node v25.9.0, Lemon↔Lemon localhost, 10MB transfers, median of 25 iterations):

| Metric | LemonTLS | Node native | Ratio |
|---|---|---|---|
| Upload TLS 1.2 | **459 MB/s** | 680 MB/s | 68% |
| Upload TLS 1.3 | **301 MB/s** | 640 MB/s | 47% |
| Download TLS 1.2 (cross-process) | **716 MB/s** | 870 MB/s | 82% |
| Echo bidirectional TLS 1.3 | **396 MB/s** | — | — |
| Small burst (100B × 2000) | **1.67M writes/s** | 2.7M writes/s | 62% |
| OpenSSL s_time handshakes/sec | **1,511** (TLS 1.3), **1,723** (TLS 1.2) | ~1800 | 85–95% |

For a pure-JavaScript implementation with zero native dependencies, this is within striking distance of OpenSSL on most paths.

## 🛣 Roadmap

✅ = Completed  🔄 = Implemented, needs testing  ⏳ = Planned

### ✅ Completed

| Status | Item |
|---|---|
| ✅ | TLS 1.3 - Server + Client |
| ✅ | TLS 1.2 - Server + Client |
| ✅ | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| ✅ | X25519 / P-256 / **P-384** key exchange |
| ✅ | RSA-PSS / ECDSA / RSA-PKCS#1 signatures |
| ✅ | SNI, ALPN extensions |
| ✅ | HelloRetryRequest (both client and server side) |
| ✅ | Session tickets + PSK resumption (TLS 1.3) |
| ✅ | Session ID / ticket resumption (TLS 1.2) |
| ✅ | Extended Master Secret (RFC 7627, TLS 1.2) |
| ✅ | Key Update (TLS 1.3) |
| ✅ | Client Certificate Auth (mTLS) |
| ✅ | Certificate validation (dates, hostname via `checkServerIdentity`, CA chain) |
| ✅ | Alert handling (close_notify, fatal alerts) |
| ✅ | `TLSSocket` - Node.js compatible Duplex stream |
| ✅ | `TLSSession` - raw state machine for QUIC/DTLS |
| ✅ | `record.js` - shared AEAD module for custom transports |
| ✅ | Node.js `tls` compat — **41 API methods/properties verified** |
| ✅ | TypeScript typings bundled (`index.d.ts`) |
| ✅ | DTLS 1.2 baseline (via `DTLSSocket` / `createDTLSServer`) |
| ✅ | Zero dependencies - `node:crypto` only |
| ✅ | **72 automated tests** (compat, resumption, data transfer) |
| ✅ | Browser-tested (Chrome) |

### ⏳ Planned

| Status | Item | Notes |
|---|---|---|
| ⏳ | Loss detection + PTO (for QUIC integration) | Buffer ready, needs timers |
| ⏳ | 0-RTT Early Data | Risky (replay attacks), low priority |
| ⏳ | Full certificate chain validation | Including CA/revocation checks |
| ⏳ | OCSP stapling | Rare in modern web, low priority |
| ⏳ | Fuzz testing | Security hardening |

### Compatibility Test Summary

```
Module API:            exports, getCiphers, createSecureContext,
                       DEFAULT_MIN_VERSION / MAX_VERSION / CIPHERS / ECDH_CURVE,
                       checkServerIdentity
tls.connect():         positional + options-object forms
tls.createServer():    options + callback + "secureConnection" event
TLSSocket methods:     getProtocol, getCipher, getPeerCertificate,
                       getPeerX509Certificate, getCertificate, getX509Certificate,
                       getSession, getTLSTicket, getSharedSigalgs,
                       isSessionReused, getFinished, getPeerFinished,
                       exportKeyingMaterial, getEphemeralKeyInfo,
                       disableRenegotiation, enableTrace, setServername,
                       setMaxSendFragment
Server methods:        setSecureContext, getTicketKeys / setTicketKeys
Properties:            .encrypted, .authorized, .alpnProtocol, .servername
Transport delegation:  remoteAddress, remotePort, setNoDelay, setKeepAlive,
                       setTimeout
Events:                'session' (Buffer), 'keylog', 'tlsClientError'
Stream behavior:       write/read echo, pipe, 200KB record fragmentation
Resumption:            connect({session}) round-trip with isSessionReused()
```

## 📁 Project Structure

```
index.js                 - ESM entry: TLSSocket, TLSSession, connect,
                           createServer, checkServerIdentity, crypto, wire, record
index.cjs                - CommonJS wrapper
index.d.ts               - TypeScript definitions
src/
  tls_session.js         - TLS state machine (reactive set_context pattern)
  tls_socket.js          - Duplex stream wrapper, Node.js compatible API
  record.js              - shared AEAD encrypt/decrypt, key derivation
  wire.js                - binary encode/decode of all TLS messages + constants
  crypto.js              - key schedule (HKDF, PRF, resumption primitives)
  compat.js              - Node.js tls API wrappers (connect, createServer,
                           checkServerIdentity, Server)
  secure_context.js      - PEM/DER cert/key loading
  utils.js               - array helpers
  dtls_session.js        - DTLS state machine
  dtls_socket.js         - DTLS socket wrapper (UDP transport)
  session/
    signing.js           - signature scheme selection + signing
    ecdh.js              - X25519 / P-256 / P-384 key exchange
    message.js           - high-level message build/parse
    ticket.js            - TLS 1.2 session ticket encryption
```

## 🤝 Contributing

Pull requests are welcome!
Please open an issue before submitting major changes.

## 💖 Sponsors

This project is part of the [colocohen](https://github.com/colocohen) Node.js infrastructure stack (QUIC, WebRTC, DNSSEC, TLS, and more).
You can support ongoing development via [GitHub Sponsors](https://github.com/sponsors/colocohen).

## 📚 References

* [RFC 8446 – TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
* [RFC 5246 – TLS 1.2](https://datatracker.ietf.org/doc/html/rfc5246)
* [RFC 6066 – TLS Extensions (SNI)](https://datatracker.ietf.org/doc/html/rfc6066)
* [RFC 7301 – ALPN](https://datatracker.ietf.org/doc/html/rfc7301)
* [RFC 7627 – Extended Master Secret](https://datatracker.ietf.org/doc/html/rfc7627)
* [RFC 6125 – Hostname Verification](https://datatracker.ietf.org/doc/html/rfc6125)
* [RFC 5705 – Exported Keying Material](https://datatracker.ietf.org/doc/html/rfc5705)
* [RFC 5077 – Stateless Session Resumption (TLS 1.2 tickets)](https://datatracker.ietf.org/doc/html/rfc5077)

## 📜 License

**Apache License 2.0**

```
Copyright © 2025 colocohen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```