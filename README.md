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
* 🔑 **Key Access** – read handshake secrets, traffic keys, ECDHE shared secret, and resumption data at any point.
* 🔁 **Session Resumption** – session tickets + PSK with binder validation.
* 🔄 **Key Update** – refresh traffic keys on long-lived TLS 1.3 connections.
* 🔃 **HelloRetryRequest** – automatic group negotiation fallback.
* 📜 **Client Certificate Auth** – mutual TLS (mTLS) with `requestCert` / `cert` / `key` options.
* 🛡 **Designed for extensibility** – exposes cryptographic keys and record-layer primitives for QUIC, DTLS, or custom transports.
* 🧩 **Two API levels** – high-level `TLSSocket` (drop-in Node.js Duplex stream) and low-level `TLSSession` (state machine only, you handle the transport).
* 🔧 **Beyond Node.js** – per-connection cipher/sigalg/group selection, JA3 fingerprinting, certificate pinning, and more options that are impossible or require `openssl.cnf` hacks in Node.js.
 
## 📦 Installation
 
```
npm i lemon-tls
```
 
## 🚀 Quick Start
 
### Drop-in Node.js Replacement
 
```js
import tls from 'lemon-tls';  // not 'node:tls' — same API
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
 
// First connection — save the ticket
socket.on('session', (ticketData) => { savedSession = ticketData; });
 
// Second connection — resume (no certificate exchange, faster)
const socket2 = tls.connect(8443, 'localhost', { session: savedSession }, () => {
  console.log('Resumed:', socket2.isResumed);  // true
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
 
tls.connect(port, host, options, callback)   // Node.js compatible
tls.createServer(options, callback)          // Node.js compatible
tls.createSecureContext({ key, cert })       // PEM → { certificateChain, privateKey }
tls.getCiphers()                             // ['tls_aes_128_gcm_sha256', ...]
tls.DEFAULT_MIN_VERSION                      // 'TLSv1.2'
tls.DEFAULT_MAX_VERSION                      // 'TLSv1.3'
```
 
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
| `session` | object | Saved ticket data from `'session'` event (client resumption) |
| `requestCert` | boolean | Request client certificate (server) |
| `cert` | Buffer/string | Client certificate PEM (for mTLS) |
| `key` | Buffer/string | Client private key PEM (for mTLS) |
 
**LemonTLS-only (not available in Node.js):**
 
| Option | Type | Description |
|---|---|---|
| `noTickets` | boolean | Disable session tickets (in Node.js requires `openssl.cnf`) |
| `signatureAlgorithms` | number[] | Per-connection sigalg list, e.g. `[0x0804]` for RSA-PSS only |
| `groups` | number[] | Per-connection curves, e.g. `[0x001d]` for X25519 only |
| `prioritizeChaCha` | boolean | Move ChaCha20-Poly1305 before AES in cipher preference |
| `maxRecordSize` | number | Max plaintext per TLS record (default: 16384) |
| `allowedCipherSuites` | number[] | Whitelist — only these ciphers are offered |
| `pins` | string[] | Certificate pinning: `['sha256/AAAA...']` |
| `handshakeTimeout` | number | Abort handshake after N ms |
| `maxHandshakeSize` | number | Max handshake bytes — DoS protection |
| `certificateCallback` | function | Dynamic cert selection: `(info, cb) => cb(null, ctx)` |
 
#### Events
 
| Event | Callback | Description |
|---|---|---|
| `secureConnect` | `()` | Handshake complete, data can flow |
| `data` | `(Buffer)` | Decrypted application data received |
| `session` | `(ticketData)` | New session ticket available for resumption |
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
| `socket.isResumed` | `true` if PSK resumption was used |
| `socket.isSessionReused()` | Same as `isResumed` (Node.js compat) |
| `socket.authorized` | `true` if peer certificate is valid |
| `socket.authorizationError` | Error string or `null` |
| `socket.alpnProtocol` | Negotiated ALPN protocol or `false` |
| `socket.encrypted` | Always `true` |
| `socket.getFinished()` | Local Finished verify_data (Buffer) |
| `socket.getPeerFinished()` | Peer Finished verify_data (Buffer) |
| `socket.exportKeyingMaterial(len, label, ctx)` | RFC 5705 keying material |
| `socket.getEphemeralKeyInfo()` | `{ type: 'X25519', size: 253 }` |
| `socket.write(data)` | Send encrypted application data |
| `socket.end()` | Send `close_notify` alert and close |
 
**LemonTLS-only:**
 
| | |
|---|---|
| `socket.getSession()` | Access the underlying `TLSSession` |
| `socket.handshakeDuration` | Handshake time in ms |
| `socket.getJA3()` | `{ hash, raw }` — JA3 fingerprint (server-side) |
| `socket.getSharedSecret()` | ECDHE shared secret (Buffer) |
| `socket.getNegotiationResult()` | `{ version, cipher, group, sni, alpn, resumed, helloRetried, ... }` |
| `socket.rekeySend()` | Refresh outgoing encryption keys (TLS 1.3) |
| `socket.rekeyBoth()` | Refresh keys for both directions (TLS 1.3) |
 
### `TLSSession`
 
The **core state machine** for a TLS connection. Performs handshake, key derivation, and state management — but does **no I/O**. You provide the transport.
 
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
 
// PSK callback — full control over ticket validation (server)
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
 
LemonTLS gives you control that Node.js doesn't expose — without `openssl.cnf` hacks:
 
```js
import tls from 'lemon-tls';
 
// Per-connection cipher/group/sigalg selection (impossible in Node.js)
const socket = tls.connect(443, 'api.example.com', {
  groups: [0x001d],                  // X25519 only (Node: ecdhCurve is global)
  signatureAlgorithms: [0x0804],     // RSA-PSS-SHA256 only (Node: no control)
  prioritizeChaCha: true,            // ChaCha20 before AES (Node: no control)
  allowedCipherSuites: [0x1301, 0x1303], // whitelist (Node: string-based, error-prone)
});
 
// Disable session tickets (in Node.js requires openssl.cnf)
tls.createServer({ key, cert, noTickets: true });
 
// Certificate pinning
tls.connect(443, 'bank.example.com', {
  pins: ['sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg='],
});
 
// Handshake timeout — DoS protection
tls.connect(443, 'host', { handshakeTimeout: 5000 });
 
// Max handshake size — prevents oversized certificate chains
tls.createServer({ key, cert, maxHandshakeSize: 65536 });
 
// Dynamic certificate selection (beyond SNI — based on cipher, version, extensions)
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
 
## 🛣 Roadmap
 
✅ = Completed  🔄 = Implemented, needs testing  ⏳ = Planned
 
### ✅ Completed
 
| Status | Item |
|---|---|
| ✅ | TLS 1.3 — Server + Client |
| ✅ | TLS 1.2 — Server + Client |
| ✅ | AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 |
| ✅ | X25519 / P-256 key exchange |
| ✅ | RSA-PSS / ECDSA signatures |
| ✅ | SNI, ALPN extensions |
| ✅ | Session tickets + PSK resumption (TLS 1.3) |
| ✅ | Extended Master Secret (RFC 7627, TLS 1.2) |
| ✅ | Certificate validation (dates, hostname, CA chain) |
| ✅ | Alert handling (close_notify, fatal alerts) |
| ✅ | `TLSSocket` — Node.js compatible Duplex stream |
| ✅ | `TLSSession` — raw state machine for QUIC/DTLS |
| ✅ | `record.js` — shared AEAD module for custom transports |
| ✅ | Node.js `tls` compat — `connect()`, `createServer()`, `getCiphers()` |
| ✅ | 27 Node.js API compatibility methods verified |
| ✅ | Zero dependencies — `node:crypto` only |
| ✅ | 45 automated tests |
 
### 🔄 Implemented (Needs Testing)
 
| Status | Item | Notes |
|---|---|---|
| 🔄 | HelloRetryRequest | Group negotiation fallback, transcript message_hash |
| 🔄 | Key Update (TLS 1.3) | `rekeySend()` / `rekeyBoth()` for long-lived connections |
| 🔄 | Client Certificate Auth | mTLS with `requestCert` / `cert` / `key` options |
 
### ⏳ Planned
 
| Status | Item | Notes |
|---|---|---|
| ⏳ | DTLS 1.2/1.3 | Datagram TLS over UDP |
| ⏳ | 0-RTT Early Data | Risky (replay attacks), low priority |
| ⏳ | Full certificate chain validation | Including revocation checks |
| ⏳ | TypeScript typings | Type safety and IDE integration |
| ⏳ | Benchmarks & performance tuning | Throughput, memory |
| ⏳ | Fuzz testing | Security hardening |
 
## 🧪 Testing
 
```bash
npm test                     # 11 tests — core TLS interop (OpenSSL)
node tests/test_https.js     # 7 tests — HTTPS server (browser + curl)
node tests/test_compat.js    # 27 tests — Node.js API compatibility
```
 
### Core Tests (`npm test`)
 
```
Server tests (LemonTLS server ↔ openssl s_client):
  ✅ TLS 1.3 — handshake + bidirectional data
  ✅ TLS 1.2 — handshake + bidirectional data
  ✅ ChaCha20-Poly1305 — cipher negotiation
  ✅ Session ticket — sent to client
 
Client tests (Node.js tls server ↔ LemonTLS client):
  ✅ TLS 1.3 — handshake + bidirectional data
  ✅ TLS 1.2 — handshake + bidirectional data
 
Resumption (LemonTLS ↔ LemonTLS):
  ✅ PSK — full handshake → ticket → resumed connection
 
Node.js compat API:
  ✅ tls.connect() / tls.createServer() / getCiphers()
  ✅ isSessionReused / getFinished / exportKeyingMaterial / ...
```
 
### HTTPS Integration Test
 
```bash
node tests/test_https.js
```
 
Starts a real HTTPS server powered by LemonTLS. After tests pass, open in your browser:
 
```
https://localhost:19600/
```
 
Requires: Node.js ≥ 16, OpenSSL in PATH.
 
## 📁 Project Structure
 
```
index.js                 — exports: TLSSocket, TLSSession, connect, createServer, crypto, wire, record
src/
  tls_session.js         — TLS state machine (reactive set_context pattern)
  tls_socket.js          — Duplex stream wrapper, Node.js compatible API
  record.js              — shared AEAD encrypt/decrypt, key derivation
  wire.js                — binary encode/decode of all TLS messages + constants
  crypto.js              — key schedule (HKDF, PRF, resumption primitives)
  compat.js              — Node.js tls API wrappers (connect, createServer, etc.)
  secure_context.js      — PEM/DER cert/key loading
  utils.js               — array helpers
  session/
    signing.js           — signature scheme selection + signing
    ecdh.js              — X25519/P-256 key exchange
    message.js           — high-level message build/parse
tests/
  test_all.js            — automated suite (npm test)
  test_https.js          — HTTPS integration (stays running for browser)
  test_compat.js         — Node.js API compatibility
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
* [RFC 7627 – Extended Master Secret](https://datatracker.ietf.org/doc/html/rfc7627)
 
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