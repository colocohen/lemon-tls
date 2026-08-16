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
* 📡 **DTLS 1.3 (RFC 9147)** + **DTLS 1.2** – server and client, with cookie exchange, retransmission, and **DTLS-SRTP** (RFC 5764) for WebRTC. Not a shim over TLS: the record layer, epochs, and sequence-number handling are implemented for datagrams.
* 🌐 **Browser-tested** – verified interop with Chrome, curl, Node.js, openssl s_client, and msquic.
* 🔑 **Key Access** – read handshake secrets, traffic keys, ECDHE shared secret, and resumption data at any point.
* 🔁 **Session Resumption** – session tickets + PSK with binder validation.
* 🔄 **Key Update** – refresh traffic keys on long-lived TLS 1.3 connections.
* 🔃 **HelloRetryRequest** – automatic group negotiation fallback (X25519, P-256, P-384).
* 📜 **Client Certificate Auth** – mutual TLS (mTLS) with `requestCert` / `cert` / `key` options.
* 🛡 **Designed for extensibility** – exposes cryptographic keys and record-layer primitives for QUIC or custom transports (DTLS ships implemented, see above).
* 🧩 **Two API levels** – high-level `TLSSocket` (drop-in Node.js Duplex stream) and low-level `TLSSession` (state machine only, you handle the transport).
* 🔍 **TLS fingerprinting, built in** – `getFingerprints()` returns **JA4**, **JA3**, **JA4S** and **JA3S** for the connection. Both the client and the server values are populated **in either role**, because both hellos are visible to both peers. Verified byte-for-byte against independent implementations. Node cannot do this at all: OpenSSL parses the ClientHello and discards the offer, so other libraries re-read the raw bytes off the socket in parallel — here the data is already in hand.
* 🎭 **Handshake shaping** – `permuteExtensions` (Chrome 110+ extension-order randomisation) and `grease` (RFC 8701, across all seven insertion points). Both opt-in, both collision-safe against anything you configured by hand.
* 🔧 **Beyond Node.js** – per-connection cipher/sigalg/group selection, certificate pinning, `ALPNCallback`, `setKeyCert`, and more options that are impossible or require `openssl.cnf` hacks in Node.js.
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

### Supported cipher suites

Sixteen suites are implemented; three are offered by default. Anything else has
to be asked for explicitly via `local_supported_cipher_suites` or narrowed with
`allowedCipherSuites` — the default list stays small on purpose, because every
extra suite widens the offer and changes your JA3/JA4.

**TLS 1.3** — offered by default

| Code | Suite | AEAD | Hash |
|---|---|---|---|
| `0x1301` | `TLS_AES_128_GCM_SHA256` | AES-128-GCM | SHA-256 |
| `0x1302` | `TLS_AES_256_GCM_SHA384` | AES-256-GCM | SHA-384 |
| `0x1303` | `TLS_CHACHA20_POLY1305_SHA256` | ChaCha20-Poly1305 | SHA-256 |

**TLS 1.2 — AEAD** (opt in)

| Code | Suite | Key exchange | AEAD |
|---|---|---|---|
| `0xC02B` | `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` | ECDHE_ECDSA | AES-128-GCM |
| `0xC02C` | `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` | ECDHE_ECDSA | AES-256-GCM |
| `0xC02F` | `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` | ECDHE_RSA | AES-128-GCM |
| `0xC030` | `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` | ECDHE_RSA | AES-256-GCM |
| `0xCCA8` | `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` | ECDHE_RSA | ChaCha20-Poly1305 |
| `0xCCA9` | `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` | ECDHE_ECDSA | ChaCha20-Poly1305 |
| `0xCCAA` | `TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256` | DHE_RSA | ChaCha20-Poly1305 |
| `0x009C` | `TLS_RSA_WITH_AES_128_GCM_SHA256` | RSA | AES-128-GCM |
| `0x009D` | `TLS_RSA_WITH_AES_256_GCM_SHA384` | RSA | AES-256-GCM |

**TLS 1.2 — CBC** (opt in; legacy, no forward secrecy on the RSA ones)

| Code | Suite | Key exchange | Cipher | MAC |
|---|---|---|---|---|
| `0xC013` | `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` | ECDHE_RSA | AES-128-CBC | SHA-1 |
| `0xC014` | `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` | ECDHE_RSA | AES-256-CBC | SHA-1 |
| `0x003C` | `TLS_RSA_WITH_AES_128_CBC_SHA256` | RSA | AES-128-CBC | SHA-256 |
| `0x003D` | `TLS_RSA_WITH_AES_256_CBC_SHA256` | RSA | AES-256-CBC | SHA-256 |

The `0xCCAA` / `0x009C` / `0x009D` suites and the CBC block carry no forward
secrecy with an RSA key exchange; they exist for interoperability with older
peers, not as a recommendation.

ChaCha20-Poly1305 uses a full 12-byte IV with no explicit nonce (RFC 7905),
unlike GCM — the registry records that per suite.

`prioritizeChaCha: true` moves the ChaCha suites ahead of AES. Note this
changes your **JA3** but not your **JA4**: JA4 sorts the cipher list before
hashing, so only *which* suites you offer matters there, never their order.



#### Events

| Event | Callback | Description |
|---|---|---|
| `secureConnect` | `()` | Handshake complete, data can flow |
| `data` | `(Buffer)` | Decrypted application data received |
| `session` | `(Buffer)` | **Opaque session blob** — pass back to `connect({ session })` to resume |
| `keyUpdate` | `(direction)` | Traffic keys refreshed: `'send'` or `'receive'` |
| `keylog` | `(Buffer)` | SSLKEYLOGFILE-format line (for Wireshark) |
| `secure` | `()` | Handshake complete. Fires on **both** sides and on sockets built with `new TLSSocket()` — unlike `secureConnect`, which Node does not emit there. The signal to use when wrapping an existing socket for STARTTLS |
| `clienthello` | `(raw, parsed)` | ClientHello received (server side). Fires **synchronously before the ServerHello is built** — use it for JA3/JA4 fingerprinting, or to inspect the client's offered extensions (`parsed.extensions` / `getRemoteExtension`) and answer them via `set_context({ local_extensions })` (e.g. DTLS-SRTP `use_srtp`) |
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
| `socket.exportKeyingMaterial(len, label, ctx)` | Exported keying material — RFC 5705 on (D)TLS 1.2, RFC 8446 §7.5 on (D)TLS 1.3. Returns `null` before secrets are ready (Node throws instead). Omit `ctx` for the no-context form (≠ empty context on 1.2!) — that's what DTLS-SRTP's `'EXTRACTOR-dtls_srtp'` uses |
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
| `allowHalfOpen` | When `false` (the Node default, and now ours) the writable side ends automatically once the peer stops writing. This was hardcoded `true`, the opposite of Node — code expecting the documented behaviour was left holding connections open |
| `checkServerIdentity(hostname, cert)` | Replaces the built-in RFC 6125 identity check. Return `undefined` to accept, an `Error` to reject. Runs **after** chain verification, as Node documents — a hook that only checks a pin cannot rescue a chain that failed |
| `socket` | Run the handshake over an existing `Duplex` instead of dialling out. `host`/`port` are then ignored and nothing is connected for you, so the caller can speak cleartext first and upgrade — STARTTLS for SMTP, IMAP, PostgreSQL |
| `secureContext` | A context from `createSecureContext()`, reused across connections instead of re-parsing the same PEM each time. Explicit `secureContext` wins over `key`/`cert` |
| `ALPNCallback` | `({ servername, protocols }) => protocol \| undefined`. Server-side, synchronous. Returning `undefined` refuses with `no_application_protocol`. Mutually exclusive with `ALPNProtocols` |
| `grease` | Insert GREASE (RFC 8701) reserved values into the ClientHello, as browsers do (default `false`). Covers cipher suites, extension types, supported groups, signature algorithms, supported versions, ALPN, `psk_key_exchange_modes` and a dummy `key_share` entry. **Changes no fingerprint** — JA3 and JA4 both strip GREASE — but its *absence* reads as "not a browser". Any list you already GREASE'd by hand is left alone, so `grease: true` never collides with manual configuration. Safe against public HTTPS servers; leave off for DTLS/WebRTC peers until tested |
| `permuteExtensions` | Shuffle ClientHello extension order per connection, as Chrome 110+ does (default `false`). Changes your **JA3** on every handshake; leaves your **JA4** byte-for-byte identical, since JA4 sorts before hashing. Order is chosen once and replayed on a post-HRR retry, per RFC 8446 §4.1.2 |
| `socket.getFingerprints()` | `{ ja3, ja4, ja3s, ja4s, ja4x }` - every fingerprint of the connection. Client values (`ja3`/`ja4`) **and** server values (`ja3s`/`ja4s`) are populated in either role, since both hellos are visible to both peers. Each is `{ hash, raw }`, or `null` before its hello has been seen. `ja4x` is reserved and always `null` for now. Pass `{ protocol: 'q' }` when driving the session from QUIC |
| `socket.getFinished()` / `getPeerFinished()` | The Finished verify_data, ours and the peer's — the `tls-unique` channel binding of RFC 5929. `undefined` before the handshake |
| `socket.isSessionReused()` | Whether this connection resumed an earlier session (same value as the `isResumed` property; Node spells it as a method) |
| `socket.address()` | `{ port, family, address }` of the underlying transport, `{}` when not connected |
| `socket.getEphemeralKeyInfo()` | `{ type, name, size }` for the negotiated key agreement. `null` on a server socket, as in Node |
| `socket.setKeyCert(context)` | Swap the certificate and key for this one connection. Takes a `createSecureContext()` result or a plain `{ key, cert }`. Pairs with `ALPNCallback`, where the protocol is known but `SNICallback` has already run |
| `socket.getJA3()` | `{ hash, raw }` - shorthand for `getFingerprints().ja3` |
| `socket.getSharedSecret()` | ECDHE shared secret (Buffer) |
| `socket.getNegotiationResult()` | `{ version, cipher, group, sni, alpn, resumed, helloRetried, ... }` |
| `socket.rekeySend()` | Refresh outgoing encryption keys (TLS 1.3) |
| `socket.rekeyBoth()` | Refresh keys for both directions (TLS 1.3) |
| `socket.getRemoteExtensions()` | All extensions the peer sent in its hello: `[{ type, name, data, value }]`. On TLS 1.3 clients this is the union of ServerHello + EncryptedExtensions |
| `socket.getRemoteExtension(type)` | One peer extension by numeric type (e.g. `14` = use_srtp, `0x39` = QUIC transport params), or `null` |

### `TLSSession`

The **core state machine** for a TLS connection. Performs handshake, key derivation, and state management - but does **no I/O**. You provide the transport.

This is the API to use for QUIC, DTLS, or any custom transport.

Key methods (in addition to `set_context` / `feedDatagram`-style plumbing): `getTrafficSecrets()`, `getHandshakeSecrets()`, `exportKeyingMaterial(length, label, context?)` (RFC 5705 / RFC 8446 §7.5, version-dispatched), `getRemoteExtensions()` / `getRemoteExtension(type)` for inspecting what the peer offered, and the `'clienthello'` event — emitted **synchronously before the ServerHello is built**, so a server can read the client's offered extensions and answer them via `set_context({ local_extensions })`. `DTLSSession` and both socket classes delegate all of these.

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

// Fingerprinting (server) — fires before the ServerHello is built, so this is
// where you drop a connection without spending a full handshake on it.
session.on('clienthello', (raw, parsed) => {
  const { ja4 } = session.getFingerprints();
  console.log(ja4.hash);  // 't13d521100_b262b3658495_8e6e362c5eac'
  // ja3s/ja4s are still null here — no ServerHello exists yet. Ask again
  // later in the session and they will be populated.
});
```

### DTLS API

Everything above has a DTLS twin. Same TLS state machine underneath, same
methods, plus datagram-specific plumbing (retransmission flights, epoch
handling, cookie exchange):

```js
import { DTLSSession, DTLSSocket, createDTLSServer, connectDTLS } from 'lemon-tls';
```

**`DTLSSession`** — transport-less state machine (the DTLS analog of
`TLSSession`). You move the datagrams:

```js
const dtls = new DTLSSession({
  cert, key,
  isServer: true,
  minVersion: 'DTLSv1.2',      // DTLS 1.2 and 1.3 both supported
  maxVersion: 'DTLSv1.3',
  requestCert: true,           // mutual auth (WebRTC-style)
  rejectUnauthorized: false,   // when doing fingerprint verification yourself
});

dtls.on('packet', (data) => udp.send(data, rport, raddr));  // outgoing datagrams
udp.on('message', (msg) => dtls.feedDatagram(msg));         // incoming datagrams
dtls.on('connect', () => { /* handshake done */ });
dtls.on('data', (plaintext) => { /* decrypted app data */ });
dtls.send(appData);
```

Delegated from the underlying `TLSSession` (identical semantics):
`exportKeyingMaterial`, `getRemoteExtensions` / `getRemoteExtension`,
`set_context`, `getNegotiationResult`, `getALPN`, `getPeerCertificate`,
the `'clienthello'` event, plus `.tls` for direct access to the session.

**`DTLSSocket` / `createDTLSServer` / `connectDTLS`** — UDP-transport
wrappers over `DTLSSession`, mirroring the TCP socket layer's shape.
The same delegated methods and events are available on the socket.

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


### DTLS-SRTP (WebRTC-style key export)

The full RFC 5764 flow — negotiate an SRTP profile via the `use_srtp`
extension, then export the SRTP master keys from the handshake:

```js
import { DTLSSession } from 'lemon-tls';

// Client side: offer profiles (GCM preferred, CM fallback):
//   body = u16 list_len | u16 profiles[] | u8 mki_len(0)
client.set_context({ local_extensions: [
  { type: 14, data: new Uint8Array([0x00,0x04, 0x00,0x07, 0x00,0x01, 0x00]) },
]});

// Server side: pick ONE from the client's offer, before ServerHello:
server.on('clienthello', (raw, parsed) => {
  const offer = parsed.extensions.find(e => e.type === 14);
  // ...parse offer.data, pick a profile `p`...
  server.set_context({ local_extensions: [
    { type: 14, data: new Uint8Array([0x00,0x02, p >> 8, p & 0xFF, 0x00]) },
  ]});
});

// After 'connect' on both sides — identical on client and server:
const km = session.exportKeyingMaterial(60, 'EXTRACTOR-dtls_srtp');
// (60 bytes for AES_CM_128_HMAC_SHA1_80, 56 for AEAD_AES_128_GCM.
//  Feed straight into rtp-packet's SrtpSession.fromDtlsKeyingMaterial.)
```

Works on DTLS 1.2 (answer in ServerHello) and DTLS 1.3 (answer in
EncryptedExtensions — `getRemoteExtension` sees both transparently).

### Crypto Primitives Module

The key-schedule building blocks are exported for consumers that hold raw
secrets (QUIC stacks, offline capture analysis, custom transports):

```js
import { crypto } from 'lemon-tls';

crypto.hkdf_extract(hash, salt, ikm);
crypto.hkdf_expand(hash, prk, info, len);
crypto.hkdf_expand_label(hash, secret, label, context, len);   // TLS 1.3 form
crypto.hmac(hash, key, data);
crypto.tls12_prf(secret, label, seed, len, hash);              // RFC 5246 PRF
crypto.TLS_CIPHER_SUITES;                                      // suite registry

// Standalone keying-material exporters — the same primitives
// session.exportKeyingMaterial() dispatches to. Use these directly only
// when you hold the raw secrets yourself; live connections should call
// the session/socket method, which picks the right one per version:
crypto.tls12_exporter(hash, masterSecret, label, clientRandom, serverRandom, ctxOrNull, len);  // RFC 5705
crypto.tls13_exporter(hash, exporterMasterSecret, label, ctxOrNull, len);                      // RFC 8446 §7.5
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

// Fingerprinting — server-side bot detection
server.on('secureConnection', (socket) => {
  const { ja3, ja4, ja4s } = socket.getFingerprints();
  console.log(ja4.hash);   // 't13d1516h2_8daaf6152771_e5627ece308c' — the client
  console.log(ja4.raw);    // unhashed form: shows which ciphers actually differ
  console.log(ja4s.hash);  // 't130200_1301_a56c5b993250' — how WE look to them
  console.log(ja3.hash);   // 2017 format, for anything already keyed on it
});

// Client side: the same call, and the same four values
const socket = connect({ host: 'example.com', port: 443 });
socket.on('secureConnect', () => {
  const { ja4, ja4s } = socket.getFingerprints();
  console.log(ja4.hash);   // how this library looks to the server
  console.log(ja4s.hash);  // which server stack answered
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
| ✅ | `exportKeyingMaterial` — RFC 5705 (1.2) + RFC 8446 §7.5 (1.3, proper two-stage `exporter_master_secret` derivation) |
| ✅ | Peer-extension introspection (`getRemoteExtension(s)`) + custom `local_extensions` answered in the 1.2 ServerHello and 1.3 EncryptedExtensions |
| ✅ | DTLS-SRTP keying flow (use_srtp negotiation + key export) verified end-to-end against rtp-packet |
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