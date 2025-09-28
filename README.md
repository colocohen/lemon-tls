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

> **⚠️ Project status: _Active development_.**  
> APIs may change without notice until we reach v1.0.  
> Use at your own risk and please report issues!



## ✨ Features
- 🔒 **Pure JavaScript** – no OpenSSL, no native bindings.
- ⚡ **TLS 1.3 (RFC 8446)** + **TLS 1.2** support.
- 🔑 **Key Schedule** – full HKDF-based derivation, AEAD, transcript hashing.
- 📜 **X.509 Certificates** – parsing and basic validation included.
- 🛡 **Designed for extensibility** – exposes cryptographic keys and record-layer primitives, making it possible to implement protocols such as QUIC, DTLS, or custom transports that depend on TLS. This level of flexibility is not possible when using OpenSSL directly.
- 🌐 **Currently server-only** – LemonTLS supports acting as a **TLS server** today.  
  TLS **client support** is planned and under design.


## 📦 Installation
```bash
npm i lemon-tls
```



## 🚀 Example
```js
var fs = require('fs');
var net = require("net");
var tls = require('lemon-tls');

// Example: TLS server over TCP

var server = net.createServer(function(tcp){
  
  var socket = new tls.TLSSocket(tcp, { 
    isServer: true, 
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.3',
    ALPNProtocols: ['http/1.1'],
    SNICallback: function (servername, cb) {
      console.log('get cert for: '+servername);
      cb(null, tls.createSecureContext({
        key: fs.readFileSync('YOUR_CERT_PEM_FILE_PATH'),
        cert: fs.readFileSync('YOUR_KEY_PEM_FILE_PATH')
      }));
    }
  });

  socket.on('secureConnect', function(){
    console.log('[SRV] secure handshake established');
    
    socket.write(new TextEncoder().encode('hi'));

  });

  socket.on('data', function(c){
    // echo
    socket.write(c);
  });

  socket.on('error', function(e){ console.error('[SRV TLS ERROR]', e); });
  socket.on('close', function(){ console.log('[SRV] closed'); });
});

server.listen(8443, function(){ console.log('[SRV] listening 8443'); });

```



## 📚 API


### `TLSSession`
`TLSSession` is the **core state machine** for a TLS connection. its exposes low-level cryptographic material:
- Handshake secrets and application traffic keys.
- Record-layer primitives for encrypting/decrypting TLS records.
- Hooks for ALPN, SNI, and extensions.


### `TLSSocket`
`TLSSocket` is a high-level wrapper designed to be API-compatible with Node.js [`tls.TLSSocket`](https://nodejs.org/api/tls.html#class-tlstlssocket).  
The main difference is that it uses a `TLSSession` from **LemonTLS** under the hood. This allows you to:
- Use familiar methods and events (`secureConnect`, `data`, `end`, etc.).
- Integrate seamlessly with existing Node.js applications.
- Gain access to LemonTLS’s advanced features by working directly with the underlying `TLSSession` if needed.



## 🛣 Roadmap

The following roadmap reflects the current and planned status of the LemonTLS project.  
✅ = Completed 🔄 = In progress ⏳ = Planned ❌ = Not planned

### ✅ Completed
| Status | Item |
|:------:|------|
| ✅ | TLS 1.3 - Server mode |
| ✅ | X.509 certificate parsing (basic) |

### 🔄 In Progress
| Status | Item | Notes |
|:------:|------|-------|
| 🔄 | TLS 1.3 - Client mode |
| 🔄 | TLS 1.2 - Server mode |
| 🔄 | TLS 1.2 - Client mode |
| 🔄 | Session tickets & resumption |
| 🔄 | ALPN & SNI extensions | API design ongoing |
| 🔄 | API alignment with Node.js `tls.TLSSocket` | Migration tests in progress |
| 🔄 | Modularization of key schedule & record layer | For reuse in QUIC/DTLS |

### ⏳ Planned
| Status | Item | Notes |
|:------:|------|-------|
| ⏳ | DTLS support | Datagram TLS 1.2/1.3 |
| ⏳ | Full certificate chain validation | Including revocation checks |
| ⏳ | Browser compatibility | Via WebCrypto integration |
| ⏳ | End-to-end interoperability tests | Against OpenSSL, rustls |
| ⏳ | Benchmarks & performance tuning | Resource usage, throughput |
| ⏳ | Fuzz testing & robustness checks | To improve security |
| ⏳ | Developer documentation & API reference | For easier onboarding |
| ⏳ | TypeScript typings | Type safety and IDE integration |

_Note: LemonTLS is an active work-in-progress project aiming to provide a fully auditable, pure JavaScript TLS implementation for Node.js and beyond._

_Please ⭐ star the repo to follow progress!_



## 🤝 Contributing
Pull requests are welcome!  
Please open an issue before submitting major changes.



## 💖 Sponsors
This project is part of the [colocohen](https://github.com/colocohen) Node.js infrastructure stack (QUIC, WebRTC, DNSSEC, TLS, and more).  
You can support ongoing development via [GitHub Sponsors](https://github.com/sponsors/colocohen).  



## 📚 Documentation
- [RFC 8446 – TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 5246 – TLS 1.2](https://datatracker.ietf.org/doc/html/rfc5246)  



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

