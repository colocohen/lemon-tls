import TLSSession from './tls_session.js';

import crypto from 'node:crypto';
import { Duplex } from 'node:stream';

import { TLS_CIPHER_SUITES } from './crypto.js';
import { TLS_CONTENT_TYPE as CT, TLS_ALERT_LEVEL, TLS_ALERT } from './wire.js';
import { decrypt_session_blob } from './session/ticket.js';

import {
  getAeadAlgo,
  deriveKeys as tls_derive_from_tls_secrets,
  getNonce as get_nonce,
  getNonceInto as get_nonce_into, // writes nonce into provided buffer — no alloc per record
  encryptRecord as encrypt_tls_record,
  encryptCompleteRecord13, // fused encrypt + header for TLS 1.3 app-data hot path
  decryptRecord as decrypt_tls_record,
  decryptRecordWithAadView as decrypt_tls_record_with_aad, // zero-alloc AAD path
  parseInnerPlaintext as parse_tls_inner_plaintext,
  encrypt12 as encrypt_tls12_gcm_fragment,
  encryptCompleteRecord12, // fused encrypt + header for TLS 1.2 app-data hot path
  decrypt12 as decrypt_tls12_gcm_fragment,
  deriveKeys12,
  writeRecord as writeRawRecord,
} from './record.js';

// legacy_record_version (TLS 1.3 uses 0x0303 in record header)
const REC_VERSION = 0x0303;

// TLS signature scheme codes → OpenSSL-style names (for getSharedSigalgs).
// Covers RFC 8446 §4.2.3 (TLS 1.3) and the common TLS 1.2 codes.
const SIGALG_NAMES = {
  0x0401: 'rsa_pkcs1_sha256',
  0x0501: 'rsa_pkcs1_sha384',
  0x0601: 'rsa_pkcs1_sha512',
  0x0403: 'ecdsa_secp256r1_sha256',
  0x0503: 'ecdsa_secp384r1_sha384',
  0x0603: 'ecdsa_secp521r1_sha512',
  0x0804: 'rsa_pss_rsae_sha256',
  0x0805: 'rsa_pss_rsae_sha384',
  0x0806: 'rsa_pss_rsae_sha512',
  0x0807: 'ed25519',
  0x0808: 'ed448',
  0x0809: 'rsa_pss_pss_sha256',
  0x080a: 'rsa_pss_pss_sha384',
  0x080b: 'rsa_pss_pss_sha512',
};
function sigalgCodeToName(code) {
  return SIGALG_NAMES[code] || `0x${code.toString(16).padStart(4, '0')}`;
}

// ==== עזרי המרה ====
function toBuf(u8){ return Buffer.isBuffer(u8) ? u8 : Buffer.from(u8 || []); }
function toU8(buf){ return (buf instanceof Uint8Array) ? buf : new Uint8Array(buf || []); }

function parseVersion(v) {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    let s = v.toUpperCase().replace(/[^0-9.]/g, '');
    if (s === '1.3' || s === '13') return 0x0304;
    if (s === '1.2' || s === '12') return 0x0303;
    if (s === '1.1' || s === '11') return 0x0302;
    if (s === '1.0' || s === '10') return 0x0301;
  }
  return null;
}









// ==== TLSSocket ====
function TLSSocket(duplex, options){
  if (!(this instanceof TLSSocket)) return new TLSSocket(duplex, options);
  options = options || {};

  // Inherit from Duplex stream
  // highWaterMark: raised to 256KB from the Node default of 16KB. TLS records max
  // at 16KB of plaintext, so the default meant "pause after one record" — terrible
  // for bulk transfers where we want many records in flight. 256KB keeps ~16 records
  // queuable and lets the kernel TCP stack see a continuous stream instead of many
  // small bursts interrupted by drain events. Most impactful on the Download path
  // where the sender is aggressive (tight-loop sock.write).
  Duplex.call(this, {
    allowHalfOpen: true,
    readableObjectMode: false,
    writableObjectMode: false,
    highWaterMark: 256 * 1024,
  });
  const self = this;

    let _ticketKeys = options.ticketKeys ? Buffer.from(options.ticketKeys) : crypto.randomBytes(48);

    let context = {

    options: options,

    // External transport (Duplex)
    transport: (duplex && typeof duplex.write === 'function') ? duplex : null,

    // Internal TLSSession
    session: new TLSSession({
        isServer: !!options.isServer,
        servername: options.servername,
        ALPNProtocols: options.ALPNProtocols || null,
        SNICallback: options.SNICallback || null,
        ticketKeys: _ticketKeys,
        ticketLifetime: options.ticketLifetime,
        session: options.session || null,
        psk: options.psk || null,
        rejectUnauthorized: options.rejectUnauthorized,
        ca: options.ca || null,
        sessionTickets: options.sessionTickets,
        maxHandshakeSize: options.maxHandshakeSize || 0,
        customExtensions: options.customExtensions || [],
        requestCert: !!options.requestCert,
        cert: options.cert || null,
        key: options.key || null,
    }),
    
    // Handshake write
    handshake_write_key: null,
    handshake_write_iv: null,
    handshake_write_seq: 0,
    handshake_write_aead: null,

    // Handshake read
    handshake_read_key: null,
    handshake_read_iv: null,
    handshake_read_seq: 0,
    handshake_read_aead: null,


    // Application write
    app_write_key: null,
    app_write_iv: null,
    app_write_seq: 0,
    app_write_aead: null,

    // Application read
    app_read_key: null,
    app_read_iv: null,
    app_read_seq: 0,
    app_read_aead: null,

    // Reusable 12-byte nonce scratch buffers — one per direction. Populated
    // in-place per record from (iv XOR seq) and handed to createCipheriv which
    // copies it into OpenSSL state. Saves 12-byte allocation per record —
    // ~7.7KB per 10MB transfer, less GC pressure.
    _nonceEncScratch: new Uint8Array(12),
    _nonceDecScratch: new Uint8Array(12),

    using_app_keys: false,

    remote_ccs_seen: false,
    local_ccs_sent: false,

    tls12_read_seq: 0,

    // Buffers and queues.
    //
    // readBuffer is a growable receive buffer with two offsets:
    //   - readStart: next byte to be parsed (advanced as records are consumed)
    //   - readEnd:   next byte to be written by an incoming chunk
    //
    // When readStart === readEnd the buffer is fully drained; both reset to 0 and
    // the underlying Buffer is reused (no reallocation). When a new chunk can't fit
    // at the end we compact by moving the unread portion back to 0. Only when that
    // still isn't enough do we double the buffer capacity.
    //
    // This gives O(N) total copy cost regardless of how data fragments across TCP
    // chunks — versus the quadratic cost of `readBuffer = Buffer.concat([...])`.
    // Initial 64KB capacity — fits 4 full TLS records (16KB each) or the entire
    // handshake transcript for most certs. Avoids the first ~3 grow-and-copy
    // cycles when readBuffer starts at 0 and an inbound 16KB chunk forces
    // immediate doubling from 0→64KB across 3 reallocs. For short-lived
    // connections (HTTP request/response), this single upfront allocation
    // commonly means ZERO readBuffer resizes during the connection's lifetime.
    readBuffer: Buffer.allocUnsafe(65536),
    readStart: 0,
    readEnd: 0,
    appWriteQueue: [],
    pendingHandshake: [],

    // General state
    destroyed: false,
    secureEstablished: false,
    aeadAlgo: null, // set when cipher suite is negotiated

    // Session ticket keys for PSK resumption
    ticketKeys: _ticketKeys,

    // Advanced options
    maxRecordSize: options.maxRecordSize || 16384,
    sessionTickets: options.sessionTickets !== false,
    pins: options.pins || null,              // ['sha256/AAAA...'] certificate pinning
    handshakeTimeout: options.handshakeTimeout || 0, // ms, 0 = no timeout
    allowedCipherSuites: options.allowedCipherSuites || null, // [0x1301, ...] whitelist
    certificateCallback: options.certificateCallback || null, // (info, cb) => cb(null, ctx)
    handshakeTimer: null,

    // legacy record version
    rec_version: 0x0303
    };

    let session = context.session;


     // === Record Layer ===
    // writeRecord returns the transport's backpressure signal (true = ready for more,
    // false = transport buffer full, wait for 'drain' before writing more).
    function writeRecord(type, payload){
        if (!context.transport) throw new Error('No transport attached to TLSSocket');
        if (context.destroyed || context.transport.destroyed || context.transport.writableEnded) return false;
        try { return writeRawRecord(context.transport, type, payload, context.rec_version); }
        catch(e){ self.emit('error', e); return false; }
    }

    const MAX_RECORD_PLAINTEXT = 16384; // TLS max record size (2^14)

    // writeAppData / writeAppDataSingle return the transport's backpressure signal:
    //   true  → transport is ready for more writes
    //   false → transport's internal buffer is full; caller should wait for 'drain'
    //           on context.transport before writing more. Propagated up to _write so
    //           user sock.write() returns false and Node's stream flow control kicks in.
    function writeAppData(plain){
        const total = plain.length;
        const maxSize = context.maxRecordSize || MAX_RECORD_PLAINTEXT;
        if (total > maxSize) {
            // Fragment across multiple records. Cork+uncork lets Node batch the
            // individual writes into a single TCP send (fewer syscalls, less overhead).
            const t = context.transport;
            const corkable = t && typeof t.cork === 'function' && typeof t.uncork === 'function';
            if (corkable) t.cork();
            let lastOk = true;
            try {
                for (let off = 0; off < total; off += maxSize) {
                    const endOff = off + maxSize > total ? total : off + maxSize;
                    if (!writeAppDataSingle(plain.subarray(off, endOff))) lastOk = false;
                }
            } finally {
                if (corkable) t.uncork();
            }
            return lastOk;
        }
        return writeAppDataSingle(plain);
    }

    function writeAppDataSingle(plain){
        // Hot path — single-allocation fused encrypt+frame.
        //
        // encryptCompleteRecord13/12 produce a complete TLS record (header +
        // encrypted body + tag) in ONE Buffer, which we hand directly to the
        // transport. This skips:
        //   - a separate AAD buffer (5 bytes for TLS 1.3, 13 for TLS 1.2)
        //   - Buffer.concat of ct+tag (which itself allocates + 3 copies)
        //   - writeRecord's rec allocation and rec.set(payload, 5) copy
        //
        // Net savings per record: 2 allocations + 1 × plaintext-sized copy.
        // For a 10MB transfer at 16KB records (640 records), that's ~10MB of
        // avoided copies and ~1300 fewer allocations → less GC pressure, higher
        // sustained throughput.

        if (context.destroyed || !context.transport) return false;
        const t = context.transport;
        if (t.destroyed || t.writableEnded) return false;

        if (context.isTls13) {
            if (context.app_write_key === null) {
                const ts = session.getTrafficSecrets();
                if (ts.localAppSecret === null) return true; // keys not ready — silently drop
                const d = tls_derive_from_tls_secrets(ts.localAppSecret, ts.cipher);
                context.app_write_key = d.key;
                context.app_write_iv = d.iv;
            }

            const algo = context.aeadAlgo || getAeadAlgo(session.getCipher());
            try {
                const rec = encryptCompleteRecord13(
                    CT.APPLICATION_DATA, plain,
                    context.app_write_key,
                    get_nonce_into(context._nonceEncScratch, context.app_write_iv, context.app_write_seq),
                    algo,
                    context.rec_version
                );
                context.app_write_seq++;
                return t.write(rec);
            } catch(e) {
                self.emit('error', e);
                return false;
            }
        } else {
            if (context.app_write_key === null) {
                const ts = session.getTrafficSecrets();
                const d12 = deriveKeys12(ts.masterSecret, ts.localRandom, ts.remoteRandom, ts.cipher, ts.isServer);
                context.app_write_key = d12.writeKey;
                context.app_write_iv = d12.writeIv;
            }

            try {
                const rec = encryptCompleteRecord12(
                    plain,
                    context.app_write_key,
                    context.app_write_iv,
                    context.app_write_seq,
                    CT.APPLICATION_DATA,
                    context.rec_version
                );
                context.app_write_seq++;
                return t.write(rec);
            } catch(e) {
                self.emit('error', e);
                return false;
            }
        }
    }

    function processCiphertext(body, header){
        // Hot path — same optimizations as writeAppDataSingle:
        //   - cached context.isTls13 instead of per-record session.getVersion()
        //   - cached context.aeadAlgo instead of per-record getAeadAlgo()
        //   - getTrafficSecrets() called once per key derivation (not per decrypt)
        //   - For TLS 1.3 app-data: header view is used directly as AAD, avoiding
        //     the 5-byte AAD allocation that decryptRecord would otherwise do
        let out = null;
        const isTls13 = context.isTls13 !== undefined
            ? context.isTls13
            : session.getVersion() === 0x0304; // early records (pre-secureConnect)

        if (!isTls13 && context.remote_ccs_seen === true) {
            // TLS 1.2: decrypt with key_block derived keys
            if (context.app_read_key === null) {
                const ts = session.getTrafficSecrets();

                // Guard: if master_secret isn't derived yet, we can't compute keys.
                if (!ts.masterSecret) {
                    self.emit('error', new Error('Received encrypted record before master_secret derived'));
                    return;
                }

                const d12 = deriveKeys12(ts.masterSecret, ts.localRandom, ts.remoteRandom, ts.cipher, ts.isServer);
                context.app_read_key = d12.readKey;
                context.app_read_iv = d12.readIv;
                context.app_write_key = d12.writeKey;
                context.app_write_iv = d12.writeIv;
            }

            const recordType = context.using_app_keys ? 0x17 : 0x16;
            out = decrypt_tls12_gcm_fragment(body, context.app_read_key, context.app_read_iv, context.tls12_read_seq, recordType);

        } else if (isTls13 && context.using_app_keys === true) {
            // TLS 1.3: decrypt app data with app traffic secret
            if (context.app_read_key === null) {
                const ts = session.getTrafficSecrets();
                if (ts.remoteAppSecret === null) return;
                const d = tls_derive_from_tls_secrets(ts.remoteAppSecret, ts.cipher);
                context.app_read_key = d.key;
                context.app_read_iv = d.iv;
            }

            const algo = context.aeadAlgo || getAeadAlgo(session.getCipher());
            // Use header-view AAD path when header is available (parseRecordsAndDispatch).
            // Saves a 5-byte allocation per record — small individually but meaningful
            // cumulatively on the Download hot path (many records per second).
            // get_nonce_into also reuses context._nonceDecScratch to avoid alloc per record.
            const nonce = get_nonce_into(context._nonceDecScratch, context.app_read_iv, context.app_read_seq);
            if (header !== undefined) {
                out = decrypt_tls_record_with_aad(header, body, context.app_read_key, nonce, algo);
            } else {
                out = decrypt_tls_record(body, context.app_read_key, nonce, algo);
            }
            context.app_read_seq++;

        } else if (isTls13) {
            // TLS 1.3: decrypt handshake with handshake traffic secret
            if (context.handshake_read_key === null) {
                const hs = session.getHandshakeSecrets();
                if (hs.remoteSecret === null || hs.cipher === null) return;
                const d = tls_derive_from_tls_secrets(hs.remoteSecret, hs.cipher);
                context.handshake_read_key = d.key;
                context.handshake_read_iv = d.iv;
            }

            const algo = context.aeadAlgo || getAeadAlgo(session.getCipher());
            const nonce = get_nonce_into(context._nonceDecScratch, context.handshake_read_iv, context.handshake_read_seq);
            if (header !== undefined) {
                out = decrypt_tls_record_with_aad(header, body, context.handshake_read_key, nonce, algo);
            } else {
                out = decrypt_tls_record(body, context.handshake_read_key, nonce, algo);
            }
            context.handshake_read_seq++;
        }
        

        if (out !== null) {
            // Reuse cached isTls13 computed at the top of this function
            if (isTls13) {
                // Inlined parseInnerPlaintext — parse_tls_inner_plaintext would
                // allocate a {type, content} object per record. With 640 records
                // per 10MB download, that's 640 short-lived objects just for
                // destructuring — enough GC pressure to matter. We do the scan
                // and dispatch directly here.
                let j = out.length - 1;
                while (j >= 0 && out[j] === 0) j--;
                if (j < 0) {
                    self.emit('error', new Error('Malformed TLSInnerPlaintext'));
                    return;
                }
                const content_type = out[j];

                if (content_type === CT.APPLICATION_DATA) {
                    // zero-copy view into the decrypted plaintext
                    self.push(out.subarray(0, j));
                } else if (content_type === CT.HANDSHAKE) {
                    session.message(out.subarray(0, j));
                } else if (content_type === CT.ALERT) {
                    // TODO: handle alert
                }
            } else {
                // TLS 1.2: no inner plaintext wrapping — `out` is the Buffer from decrypt12
                if (context.using_app_keys === true) {
                    self.push(out);
                } else {
                    session.message(out);
                }
            }
        }
    }


    // ============================================================================
    //  Read buffer management
    // ============================================================================
    // The incoming TLS record queue is stored in a single growable Buffer with two
    // offsets: readStart (next byte to read) and readEnd (next byte to write).
    //
    // Design rationale:
    //   - Chunks arriving from TCP are copied in-place at readEnd (single copy).
    //   - Records are parsed as zero-copy subarray views between readStart and readEnd.
    //   - When all data is consumed, both offsets reset to 0 (buffer is reused).
    //   - If the tail doesn't fit at the end, we compact (move unread to start).
    //   - Only if compaction isn't enough, we grow the buffer (doubling).
    //
    // Why this beats `readBuffer = Buffer.concat([readBuffer, chunk])`:
    //   The naive approach is O(N²) because each concat re-copies the entire
    //   growing buffer. With a 16KB record arriving in 1.4KB MTU chunks
    //   (~12 chunks), the naive approach performs ~110KB of copy work for 16KB
    //   of data. This approach performs 16KB.
    function _appendChunk(chunk) {
        const rb = context.readBuffer;
        const readStart = context.readStart;
        const readEnd = context.readEnd;
        const chunkLen = chunk.length;

        // Fast path: fits directly at the end of the existing buffer
        if (readEnd + chunkLen <= rb.length) {
            chunk.copy(rb, readEnd);
            context.readEnd = readEnd + chunkLen;
            return;
        }

        const unread = readEnd - readStart;
        const needed = unread + chunkLen;

        // Compact path: unread data + new chunk fit in existing buffer, but not at the end
        if (needed <= rb.length) {
            if (readStart > 0 && unread > 0) rb.copy(rb, 0, readStart, readEnd);
            chunk.copy(rb, unread);
            context.readStart = 0;
            context.readEnd = needed;
            return;
        }

        // Grow path: allocate a bigger buffer (doubling, with a minimum of 8KB)
        let newSize = rb.length > 0 ? rb.length * 2 : 8192;
        while (newSize < needed) newSize *= 2;
        const newBuf = Buffer.allocUnsafe(newSize);
        if (unread > 0) rb.copy(newBuf, 0, readStart, readEnd);
        chunk.copy(newBuf, unread);
        context.readBuffer = newBuf;
        context.readStart = 0;
        context.readEnd = needed;
    }

    function parseRecordsAndDispatch(){
        // Hot path — zero-copy parsing:
        //   - Work directly on readBuffer with moving readStart offset (no slicing)
        //   - Body is a subarray view (no copy) passed down to crypto
        //   - The 5-byte header view is also passed — TLS 1.3 uses it as AAD
        //     directly, avoiding a 5-byte allocation per decrypted record
        //   - Only tracks and advances offsets; buffer stays the same reference
        const rb = context.readBuffer;
        let off = context.readStart;
        const end = context.readEnd;

        while (end - off >= 5) {
            const type = rb[off];
            // Version at rb[off+1..off+3] — currently unused (legacy 0x0303 always)
            const len  = (rb[off + 3] << 8) | rb[off + 4];

            if (end - off < 5 + len) break; // record not fully received

            // Zero-copy views: header (5 bytes) + body
            const header = rb.subarray(off, off + 5);
            const body = rb.subarray(off + 5, off + 5 + len);
            off += 5 + len;

            if (type === CT.APPLICATION_DATA) {
                processCiphertext(body, header);
                context.tls12_read_seq++;
            } else if (type === CT.HANDSHAKE) {
                if (context.remote_ccs_seen === true) {
                    // Encrypted handshake (TLS 1.2 Finished post-CCS). decrypt output is
                    // a FRESH Buffer per record — safe to pass views of it downstream.
                    processCiphertext(body, header);
                } else {
                    // Plaintext handshake (ClientHello, ServerHello, Certificate, ...).
                    // `body` is a zero-copy view into readBuffer. session.message()
                    // stashes the raw bytes into the handshake transcript (used later
                    // for Finished MAC verification and TLS 1.3 key derivation), and
                    // also extracts fields like remote_random as subarray views.
                    //
                    // When the NEXT incoming chunk triggers readBuffer compact/reuse,
                    // those stashed views would point to overwritten bytes — causing
                    // bad key derivations and GCM tag failures much later. We must hand
                    // the session an owned Buffer so its transcript survives.
                    session.message(Buffer.from(body));
                }
                context.tls12_read_seq++;
            } else if (type === CT.CHANGE_CIPHER_SPEC) {
                context.tls12_read_seq = 0;
                context.remote_ccs_seen = true;
            } else if (type === CT.ALERT) {
                // Alert: 2 bytes — level (1=warning, 2=fatal), description
                if (body.length >= 2) {
                    const level = body[0];
                    const desc  = body[1];
                    self.emit('alert', { level: level, description: desc });
                    if (desc === TLS_ALERT.CLOSE_NOTIFY) {
                        session.close();
                        if (context.transport && typeof context.transport.end === 'function') {
                            context.transport.end();
                        }
                    }
                    if (level === TLS_ALERT_LEVEL.FATAL) {
                        if (context.transport && typeof context.transport.destroy === 'function') {
                            context.transport.destroy();
                        }
                    }
                }
            }
        }

        // Reset offsets when buffer is fully drained (enables fast path on next chunk)
        if (off >= end) {
            context.readStart = 0;
            context.readEnd = 0;
        } else {
            context.readStart = off;
        }
    }


    function bindTransport(){
        if (!context.transport) return;
        context.transport.on('data', function(chunk){
            _appendChunk(chunk);
            parseRecordsAndDispatch();
        });
        context.transport.on('error', function(err){ self.emit('error', err); });
        context.transport.on('close', function(){ self.emit('close'); });
    }

    session.on('message', function(epoch, seq, type, data){
        const buf = toBuf(data || []);

        // Resolve TLS version: use cached isTls13 if set (post-secureConnect); otherwise query.
        // During handshake we may not yet have context.isTls13 set — only after secureConnect.
        const isTls13 = context.isTls13 !== undefined
            ? context.isTls13
            : session.getVersion() === 0x0304;

        // Alert messages — encrypt based on current epoch (0=plaintext, 1=handshake, 2=app)
        if (type === 'alert') {
            if (epoch === 0) {
                // Pre-handshake: plaintext alert
                writeRecord(CT.ALERT, buf);
                return;
            }

            if (isTls13) {
                // TLS 1.3: wrap alert as APPLICATION_DATA (inner type is ALERT)
                const writeKey = (epoch === 2) ? context.app_write_key : context.handshake_write_key;
                const writeIv  = (epoch === 2) ? context.app_write_iv  : context.handshake_write_iv;
                const writeSeq = (epoch === 2) ? context.app_write_seq : context.handshake_write_seq;

                if (!writeKey) {
                    // Keys not ready — fall back to plaintext (defensive)
                    writeRecord(CT.ALERT, buf);
                    return;
                }

                const algo = context.aeadAlgo || getAeadAlgo(session.getCipher());
                const enc = encrypt_tls_record(CT.ALERT, buf, writeKey, get_nonce(writeIv, writeSeq), algo);

                if (epoch === 2) context.app_write_seq++;
                else             context.handshake_write_seq++;

                writeRecord(CT.APPLICATION_DATA, enc);
            } else {
                // TLS 1.2: post-CCS alerts are encrypted with app keys (AES-GCM).
                // Outer record type remains ALERT (21), body is encrypted.
                if (!context.app_write_key) {
                    writeRecord(CT.ALERT, buf);
                    return;
                }

                const fragment = encrypt_tls12_gcm_fragment(
                    buf, context.app_write_key, context.app_write_iv,
                    context.app_write_seq, CT.ALERT
                );
                context.app_write_seq++;
                writeRecord(CT.ALERT, fragment);
            }
            return;
        }

        if (epoch === 0) {
            // Cleartext handshake (ClientHello/ServerHello)
            if (!context.transport) {
                context.pendingHandshake.push({ type: CT.HANDSHAKE, data: buf });
                return;
            }
            writeRecord(CT.HANDSHAKE, buf);
            return;
        }

        if (epoch === 1) {
            if (isTls13) {
                // TLS 1.3: encrypt handshake messages with handshake traffic secret
                if (context.handshake_write_key === null) {
                    const hs = session.getHandshakeSecrets();
                    if (hs.localSecret === null) {
                        self.emit('error', new Error('Missing handshake write keys'));
                        return;
                    }
                    const d = tls_derive_from_tls_secrets(hs.localSecret, hs.cipher);
                    context.handshake_write_key = d.key;
                    context.handshake_write_iv = d.iv;
                }

                const algo = context.aeadAlgo || getAeadAlgo(session.getCipher());
                try {
                    // Fused encrypt+frame — produces a complete TLS record buffer
                    // ready for transport.write. Same optimization as writeAppDataSingle.
                    const rec = encryptCompleteRecord13(
                        CT.HANDSHAKE, buf,
                        context.handshake_write_key,
                        get_nonce_into(context._nonceEncScratch, context.handshake_write_iv, context.handshake_write_seq),
                        algo,
                        context.rec_version
                    );
                    context.handshake_write_seq++;
                    if (context.transport && !context.transport.destroyed && !context.transport.writableEnded) {
                        context.transport.write(rec);
                    }
                } catch(e) {
                    self.emit('error', e);
                }
            } else {
                // TLS 1.2: send CCS first, then encrypt Finished with key_block keys
                if (context.local_ccs_sent === false) {
                    writeRecord(CT.CHANGE_CIPHER_SPEC, Buffer.from([0x01]));
                    context.local_ccs_sent = true;
                    context.app_write_seq = 0;
                }

                // Derive keys once per direction
                if (context.app_write_key === null) {
                    const ts = session.getTrafficSecrets();
                    const d12 = deriveKeys12(ts.masterSecret, ts.localRandom, ts.remoteRandom, ts.cipher, ts.isServer);
                    context.app_read_key = d12.readKey;
                    context.app_read_iv = d12.readIv;
                    context.app_write_key = d12.writeKey;
                    context.app_write_iv = d12.writeIv;
                }

                try {
                    const rec = encryptCompleteRecord12(
                        buf, context.app_write_key, context.app_write_iv,
                        context.app_write_seq, CT.HANDSHAKE, context.rec_version
                    );
                    context.app_write_seq++;
                    if (context.transport && !context.transport.destroyed && !context.transport.writableEnded) {
                        context.transport.write(rec);
                    }
                } catch(e) {
                    self.emit('error', e);
                }
            }
        }

        if (epoch === 2) {
            // Post-handshake message encrypted with app keys (e.g. NewSessionTicket)
            if (!context.app_write_key) {
                const ts = session.getTrafficSecrets();
                if (ts.localAppSecret) {
                    const d = tls_derive_from_tls_secrets(ts.localAppSecret, ts.cipher);
                    context.app_write_key = d.key;
                    context.app_write_iv = d.iv;
                }
            }
            if (context.app_write_key) {
                const algo = context.aeadAlgo || getAeadAlgo(session.getCipher());
                try {
                    const rec = encryptCompleteRecord13(
                        CT.HANDSHAKE, buf,
                        context.app_write_key,
                        get_nonce_into(context._nonceEncScratch, context.app_write_iv, context.app_write_seq),
                        algo,
                        context.rec_version
                    );
                    context.app_write_seq++;
                    if (context.transport && !context.transport.destroyed && !context.transport.writableEnded) {
                        context.transport.write(rec);
                    }
                } catch(e) {
                    self.emit('error', e);
                }
            }
            return;
        }
    });


    session.on('hello', function(){
        context.rec_version = 0x0303; // legacy record version (both 1.2 and 1.3)

        // Client already sent its preferences in ClientHello — don't override
        if (!session.isServer) return;

        // Parse version range from options
        let maxVer = parseVersion(options.maxVersion) || 0x0304;
        let minVer = parseVersion(options.minVersion) || 0x0303;

        let versions = [];
        if (maxVer >= 0x0304 && minVer <= 0x0304) versions.push(0x0304);
        if (maxVer >= 0x0303 && minVer <= 0x0303) versions.push(0x0303);
        if (versions.length === 0) versions.push(0x0303); // fallback

        // Cipher suites based on supported versions
        let ciphers = [];
        if (versions.includes(0x0304)) {
            ciphers.push(0x1301, 0x1302, 0x1303); // TLS_AES_128_GCM, TLS_AES_256_GCM, TLS_CHACHA20
        }
        if (versions.includes(0x0303)) {
            ciphers.push(
                0xC02F, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC030, // ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xC02B, // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                0xCCA8  // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            );
        }

        // Signature algorithms: override or default
        let sigalgs = [];
        if (options.signatureAlgorithms) {
            sigalgs = options.signatureAlgorithms;
        } else {
            if (versions.includes(0x0304)) {
                sigalgs.push(0x0804, 0x0805, 0x0806); // RSA-PSS
                sigalgs.push(0x0403, 0x0503, 0x0603); // ECDSA
            }
            if (versions.includes(0x0303)) {
                sigalgs.push(0x0401, 0x0501, 0x0601); // RSA-PKCS1
            }
        }

        // Groups: override or default
        let groups = options.groups || [0x001d, 0x0017]; // X25519, P-256

        // prioritizeChaCha: move ChaCha20 to front of cipher list
        if (options.prioritizeChaCha) {
            let chacha = ciphers.filter(c => c === 0x1303 || c === 0xCCA8);
            let rest = ciphers.filter(c => c !== 0x1303 && c !== 0xCCA8);
            ciphers = [...chacha, ...rest];
        }

        // allowedCipherSuites: whitelist filter
        if (context.allowedCipherSuites) {
            ciphers = ciphers.filter(c => context.allowedCipherSuites.includes(c));
        }

        // ALPN from options
        let alpns = Array.isArray(options.ALPNProtocols) ? options.ALPNProtocols : [];

        session.set_context({
            local_supported_versions: versions,
            local_supported_alpns: alpns,
            local_supported_groups: groups,
            local_supported_cipher_suites: ciphers,
            local_supported_signature_algorithms: sigalgs,
        });

        // Resolve AEAD algorithm + isTls13 flag once cipher/version are negotiated.
        // For client, both are known after receiving ServerHello (this event fires after).
        // For server, these are cached again at secureConnect as a fallback.
        if (session.getCipher()) context.aeadAlgo = getAeadAlgo(session.getCipher());
        if (session.getVersion()) context.isTls13 = (session.getVersion() === 0x0304);
    });

    session.on('secureConnect', function(){
        context.using_app_keys=true;
        context.secureEstablished=true;
        context.aeadAlgo = getAeadAlgo(session.getCipher());
        // Cache isTls13 for hot-path decisions (avoids session.getVersion() calls per record)
        context.isTls13 = session.getVersion() === 0x0304;

        // Clear handshake timeout
        if (context.handshakeTimer) { clearTimeout(context.handshakeTimer); context.handshakeTimer = null; }

        // Certificate pinning
        if (context.pins && context.pins.length > 0) {
            try {
                let cert = session.getPeerCertificate();
                if (cert && cert.raw) {
                    let hash = 'sha256/' + crypto.createHash('sha256').update(cert.raw).digest('base64');
                    if (!context.pins.includes(hash)) {
                        self.emit('error', new Error('Certificate pin mismatch: ' + hash));
                        self.destroy();
                        return;
                    }
                }
            } catch(e) { /* pinning is best-effort if no raw cert */ }
        }

        // Emit keylog lines (SSLKEYLOGFILE compatible)
        try {
            let ts = session.getTrafficSecrets();
            let clientRandom = Buffer.from(session.context.local_random || session.context.remote_random || []).toString('hex');
            if (session.isServer) clientRandom = Buffer.from(session.context.remote_random || []).toString('hex');

            if (session.getVersion() === 0x0304) {
                // TLS 1.3 key log
                let hs = session.getHandshakeSecrets();
                if (hs.localSecret) self.emit('keylog', Buffer.from(`SERVER_HANDSHAKE_TRAFFIC_SECRET ${clientRandom} ${Buffer.from(session.isServer ? hs.localSecret : hs.remoteSecret).toString('hex')}\n`));
                if (hs.remoteSecret) self.emit('keylog', Buffer.from(`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${clientRandom} ${Buffer.from(session.isServer ? hs.remoteSecret : hs.localSecret).toString('hex')}\n`));
                if (ts.localAppSecret) self.emit('keylog', Buffer.from(`SERVER_TRAFFIC_SECRET_0 ${clientRandom} ${Buffer.from(session.isServer ? ts.localAppSecret : ts.remoteAppSecret).toString('hex')}\n`));
                if (ts.remoteAppSecret) self.emit('keylog', Buffer.from(`CLIENT_TRAFFIC_SECRET_0 ${clientRandom} ${Buffer.from(session.isServer ? ts.remoteAppSecret : ts.localAppSecret).toString('hex')}\n`));
            } else {
                // TLS 1.2 key log
                if (ts.masterSecret) self.emit('keylog', Buffer.from(`CLIENT_RANDOM ${clientRandom} ${Buffer.from(ts.masterSecret).toString('hex')}\n`));
            }
        } catch(e) { /* keylog is best-effort */ }

        // Flush any queued writes that arrived before the handshake completed.
        // Perf: cork the transport so all flushed fragments go out as a single TCP send.
        // For apps that .write() immediately after tls.connect() (before secureConnect),
        // this turns N flushed records + N syscalls into 1 syscall.
        if (context.appWriteQueue.length > 0) {
            const t = context.transport;
            const corkable = t && typeof t.cork === 'function' && typeof t.uncork === 'function';
            if (corkable) t.cork();
            try {
                const q = context.appWriteQueue;
                context.appWriteQueue = []; // swap out so re-entrant writes go to fresh queue
                for (let i = 0; i < q.length; i++) writeAppData(q[i]);
            } finally {
                if (corkable) t.uncork();
            }
        }

        self.emit('secureConnect');
    });

    // Forward session ticket event (Node.js compatible).
    // Also save the last session buffer so getSession() can return it (Node.js semantics).
    let _lastSessionBuffer;  // undefined until first 'session' event (matches Node's getSession())
    session.on('session', function(ticketData) {
        _lastSessionBuffer = Buffer.isBuffer(ticketData) ? ticketData : Buffer.from(ticketData);
        self.emit('session', ticketData);
    });

    // Forward handshakeMessage event (for debugging/inspection)
    session.on('handshakeMessage', function(type, raw, parsed) {
        self.emit('handshakeMessage', type, raw, parsed);
    });

    // Forward keylog event (Node.js compat — NSS SSLKEYLOGFILE format for Wireshark)
    session.on('keylog', function(line) {
        self.emit('keylog', line);
    });

    // Forward raw clienthello event (server-side, for JA3/inspection)
    session.on('clienthello', function(raw, parsed) {
        self.emit('clienthello', raw, parsed);
    });

    // Handshake timeout
    if (context.handshakeTimeout > 0) {
        context.handshakeTimer = setTimeout(function() {
            if (!context.secureEstablished) {
                self.emit('error', new Error('Handshake timeout after ' + context.handshakeTimeout + 'ms'));
                self.destroy();
            }
        }, context.handshakeTimeout);
    }

    // certificateCallback: dynamic cert selection (extends SNICallback)
    if (context.certificateCallback && options.isServer) {
        session.on('hello', function() {
            let info = {
                servername: session.context.remote_sni,
                version: session.context.selected_version,
                ciphers: session.context.remote_supported_cipher_suites,
                sigalgs: session.context.remote_supported_signature_algorithms,
                groups: session.context.remote_supported_groups,
                alpns: session.context.remote_supported_alpns,
            };
            context.certificateCallback(info, function(err, ctx) {
                if (!err && ctx) {
                    session.set_context({
                        local_cert_chain: ctx.certificateChain,
                        cert_private_key: ctx.privateKey,
                    });
                }
            });
        });
    }

    // KeyUpdate: swap record layer keys when TLSSession derives new secrets
    session.on('keyUpdate', function(info) {
        if (info.direction === 'send') {
            // We updated our send secret → derive new write keys, reset seq
            let d = tls_derive_from_tls_secrets(info.secret, session.getCipher());
            context.app_write_key = d.key;
            context.app_write_iv = d.iv;
            context.app_write_seq = 0;
        } else if (info.direction === 'receive') {
            // Peer updated their send secret → derive new read keys, reset seq
            let d = tls_derive_from_tls_secrets(info.secret, session.getCipher());
            context.app_read_key = d.key;
            context.app_read_iv = d.iv;
            context.app_read_seq = 0;
        }
        self.emit('keyUpdate', info.direction);
    });

    // Forward certificateRequest event
    session.on('certificateRequest', function(msg) {
        self.emit('certificateRequest', msg);
    });

    // Server: automatic PSK handler (decrypts TLS 1.3 tickets with ticketKeys).
    // The new 'psk' event payload is { identity, obfuscatedAge } (object), not raw identity.
    if (options.isServer) {
        session.on('psk', function(info, callback) {
            // First check if user has a custom handler on the socket
            if (self.listenerCount('psk') > 0) {
                // Let user handle it — pass through the same payload
                self.emit('psk', info, callback);
                return;
            }

            // Auto-decrypt ticket using ticketKeys (unified format)
            let state = decrypt_session_blob(info.identity, context.ticketKeys);
            if (state && state.v === 13 && state.psk && state.cipher) {
                callback({ psk: state.psk, cipher: state.cipher });
            } else {
                callback(null); // Decryption failed / not our ticket → full handshake
            }
        });
    }

    // Forward TLS 1.2 session resumption events to the socket level.
    // User can listen on socket.on('newSession') / socket.on('resumeSession') —
    // if no listener, the session still has a default (full handshake).
    session.on('newSession', function(sessionId, sessionData, cb) {
        if (self.listenerCount('newSession') > 0) {
            self.emit('newSession', sessionId, sessionData, cb);
        } else {
            // No listener — no-op (session won't be resumable via Session ID unless user stores it)
            cb();
        }
    });

    session.on('resumeSession', function(sessionId, cb) {
        if (self.listenerCount('resumeSession') > 0) {
            self.emit('resumeSession', sessionId, cb);
        } else {
            // No listener — fall through to full handshake
            cb(null, null);
        }
    });

    // If duplex was passed in constructor, start reading
    if (context.transport) {
        bindTransport();
    }

    // === Duplex stream implementation ===
    //
    // Two behaviors the callback scheduling controls:
    //
    //   1. Coalescing: Node's Writable only batches writes into _writev while the
    //      current _write/_writev is "in progress" (callback pending). If we call
    //      the callback synchronously, each stream.write() completes immediately
    //      and the next one goes through _write alone — no _writev, no batching.
    //      By deferring the callback to process.nextTick, writes issued in the
    //      same synchronous tick queue up, and Node delivers them to _writev in
    //      one batch — letting us pack them into a single TLS record.
    //
    //   2. Backpressure: if transport.write returns false, its internal buffer is
    //      full and we must wait for 'drain' before acknowledging the write. That
    //      makes stream.write() return false to the user, letting Node's flow
    //      control kick in (pauses pipes, emits 'drain' on our socket). Without
    //      this, bulk senders flood the transport and can hit memory exhaustion.

    // Wait for the transport to emit 'drain', or deliver an error if the
    // transport errors/closes before draining. Prevents callback leaks.
    function _awaitTransportDrain(callback) {
        const t = context.transport;
        if (!t) { process.nextTick(() => callback(new Error('No transport'))); return; }
        const cleanup = () => {
            t.removeListener('drain', onDrain);
            t.removeListener('error', onError);
            t.removeListener('close', onClose);
        };
        const onDrain = () => { cleanup(); callback(); };
        const onError = (err) => { cleanup(); callback(err); };
        const onClose = () => { cleanup(); callback(new Error('Transport closed before drain')); };
        t.once('drain', onDrain);
        t.once('error', onError);
        t.once('close', onClose);
    }

    /** Duplex _write — called by stream.write() */
    self._write = function(chunk, encoding, callback) {
        if (context.destroyed) { callback(new Error('Socket destroyed')); return; }
        const buf = toBuf(chunk);

        if (!context.using_app_keys) {
            // Pre-handshake: queue for flush at secureConnect.
            context.appWriteQueue.push(buf);
            process.nextTick(callback);
            return;
        }

        const transportOk = writeAppData(buf);
        if (transportOk !== false) {
            // Defer so Node's Writable can batch subsequent in-tick writes into _writev.
            process.nextTick(callback);
        } else {
            // Transport buffer is full — wait for 'drain' before completing.
            _awaitTransportDrain(callback);
        }
    };

    /** Duplex _writev — vectored write, called when multiple writes are pending.
     *
     *  Perf: coalesces N pending writes into a single buffer handed to writeAppData,
     *  which then packs them into as few TLS records as possible (16KB max per record).
     *  Without this, N calls to stream.write() produced N separate TLS records with
     *  N × 21 bytes of framing+GCM overhead. With this, a burst of small writes
     *  becomes a single record — the biggest throughput win for many-small-writes
     *  workloads (HTTP request bodies, WebSocket frames, RPC pipelines).
     */
    self._writev = function(chunks, callback) {
        if (context.destroyed) { callback(new Error('Socket destroyed')); return; }

        let combined;
        if (chunks.length === 1) {
            combined = toBuf(chunks[0].chunk);
        } else {
            // Sum lengths once, then do a single allocation + N copies.
            let totalLen = 0;
            for (let i = 0; i < chunks.length; i++) {
                const c = chunks[i].chunk;
                totalLen += Buffer.isBuffer(c) ? c.length : (c.byteLength || Buffer.byteLength(c));
            }
            combined = Buffer.allocUnsafe(totalLen);
            let off = 0;
            for (let i = 0; i < chunks.length; i++) {
                const buf = toBuf(chunks[i].chunk);
                buf.copy(combined, off);
                off += buf.length;
            }
        }

        if (!context.using_app_keys) {
            context.appWriteQueue.push(combined);
            process.nextTick(callback);
            return;
        }

        const transportOk = writeAppData(combined);
        if (transportOk !== false) {
            process.nextTick(callback);
        } else {
            _awaitTransportDrain(callback);
        }
    };

    /** Duplex _read — data is pushed when received, no pull needed */
    self._read = function() {};

    // === Node-compatible API ===

    /** Attach a raw transport (TCP socket) after construction. */
    self.setSocket = function(duplex2){
        if (!duplex2 || typeof duplex2.write !== 'function') throw new Error('setSocket expects a Duplex-like stream');
        context.transport = duplex2;
        bindTransport();
        // Flush any pending handshake messages (e.g. ClientHello queued before transport was ready)
        while (context.pendingHandshake.length > 0) {
            let msg = context.pendingHandshake.shift();
            writeRecord(msg.type, Buffer.from(msg.data));
        }
    };

    /** Send close_notify and gracefully close. */
    self.end = (function(originalEnd) {
        return function(data, encoding, callback) {
            if (context.destroyed) return this;
            session.close(); // sends close_notify alert
            try { context.transport && context.transport.end && context.transport.end(); } catch(e){}
            return originalEnd.call(this, data, encoding, callback);
        };
    })(self.end);

    self.destroy = (function(originalDestroy) {
        return function(err) {
            if (context.destroyed) return this;
            context.destroyed = true;
            try { context.transport && context.transport.destroy && context.transport.destroy(); } catch(e){}
            return originalDestroy.call(this, err);
        };
    })(self.destroy);

    /** Node.js compat: returns the serialized session as a Buffer, or null.
     *  Matches Node's TLSSocket.getSession() — the returned Buffer can be passed
     *  back as the `session` option on the next tls.connect() to resume. */
    self.getSession = function(){ return _lastSessionBuffer; };

    /** Internal: returns the underlying TLSSession object (LemonTLS-specific).
     *  Used by compat.js and advanced consumers. Not part of the Node.js API. */
    self._getTLSSession = function(){ return session; };

    /** Whether this connection used PSK resumption (true after secureConnect). */
    Object.defineProperty(self, 'isResumed', { get: function(){ return session.isResumed; } });

    /** Returns negotiated protocol string: 'TLSv1.3', 'TLSv1.2', etc. */
    self.getProtocol = function(){
        let v = session.getVersion();
        if (v === 0x0304) return 'TLSv1.3';
        if (v === 0x0303) return 'TLSv1.2';
        if (v === 0x0302) return 'TLSv1.1';
        if (v === 0x0301) return 'TLSv1';
        return null;
    };

    /** Returns cipher info: { name, standardName, version }. */
    self.getCipher = function(){
        let code = session.getCipher();
        if (code == null) return null;
        let info = TLS_CIPHER_SUITES[code];
        if (!info) return { name: '0x' + code.toString(16), standardName: 'unknown', version: self.getProtocol() };
        return {
            name: info.name || info.cipher || '0x' + code.toString(16),
            standardName: info.standardName || info.cipher || 'unknown',
            version: self.getProtocol()
        };
    };

    /** Returns negotiated ALPN protocol string, or false. */
    Object.defineProperty(self, 'alpnProtocol', {
        get: function(){ return session.getALPN() || false; },
        enumerable: true
    });

    /** Returns the SNI servername. On the server side this is the name the
     *  client sent in its ClientHello SNI extension (string). On the client
     *  side this is the name we sent ourselves. Returns false if not
     *  available (no SNI extension present).
     *
     *  Per Node docs: tlsSocket.servername — string | false. */
    Object.defineProperty(self, 'servername', {
        get: function(){
            // context.remote_sni is populated on the server from the client's SNI;
            // on the client side session.context.remote_sni will be null, so fall
            // back to options.servername (the name we sent).
            let name = null;
            try { name = session.context && session.context.remote_sni; } catch {}
            if (!name && options && options.servername) name = options.servername;
            return name || false;
        },
        enumerable: true
    });

    /** Whether the peer certificate was validated. */
    Object.defineProperty(self, 'authorized', {
        get: function(){ return session.authorized; },
        enumerable: true
    });

    /** Authorization error string, or null. */
    Object.defineProperty(self, 'authorizationError', {
        get: function(){ return session.authorizationError; },
        enumerable: true
    });

    /** Whether TLS is established. */
    Object.defineProperty(self, 'encrypted', {
        get: function(){ return context.secureEstablished; },
        enumerable: true
    });

    self.getPeerCertificate = function(){
        let chain = session.getPeerCertificate();
        if (!chain || chain.length === 0) return null;
        try {
            let certDer = chain[0].cert;
            let x509 = new crypto.X509Certificate(certDer);
            return {
                subject: x509.subject,
                issuer: x509.issuer,
                subjectaltname: x509.subjectAltName,
                valid_from: x509.validFrom,
                valid_to: x509.validTo,
                fingerprint: x509.fingerprint,
                fingerprint256: x509.fingerprint256,
                serialNumber: x509.serialNumber,
                raw: certDer
            };
        } catch(e) {
            return { raw: chain[0].cert };
        }
    };

    /** Node-compat: return the peer's leaf cert as a native X509Certificate
     *  object (introduced in Node 15.9). Apps prefer this over the legacy
     *  plain-object getPeerCertificate() for modern cert operations. */
    self.getPeerX509Certificate = function(){
        let chain = session.getPeerCertificate();
        if (!chain || chain.length === 0) return undefined;
        try { return new crypto.X509Certificate(chain[0].cert); }
        catch(e) { return undefined; }
    };

    /** Node-compat: return our LOCAL cert (what we presented) as an
     *  X509Certificate object. Returns undefined if we didn't send a cert
     *  (e.g. client without client-cert auth). */
    self.getX509Certificate = function(){
        let sctx = session.context;
        let localChain = sctx && sctx.local_cert_chain;
        if (!localChain || localChain.length === 0) return undefined;
        try {
            let der = localChain[0].cert || localChain[0];
            return new crypto.X509Certificate(der);
        } catch(e) { return undefined; }
    };

    /** Node-compat: return info about our LOCAL cert as a legacy plain
     *  object (mirror of getPeerCertificate). Empty object {} if we didn't
     *  present a cert — this matches Node's observed behavior. */
    self.getCertificate = function(){
        let sctx = session.context;
        let localChain = sctx && sctx.local_cert_chain;
        if (!localChain || localChain.length === 0) return {};
        try {
            let der = localChain[0].cert || localChain[0];
            let x509 = new crypto.X509Certificate(der);
            return {
                subject: x509.subject,
                issuer: x509.issuer,
                subjectaltname: x509.subjectAltName,
                valid_from: x509.validFrom,
                valid_to: x509.validTo,
                fingerprint: x509.fingerprint,
                fingerprint256: x509.fingerprint256,
                serialNumber: x509.serialNumber,
                raw: der
            };
        } catch(e) {
            return {};
        }
    };

    /** Node-compat: return the TLS 1.2 session ticket as a Buffer, or undefined.
     *  For a client, this is the ticket the server sent in NewSessionTicket.
     *  For TLS 1.3 this returns undefined — use getSession() instead (1.3 uses
     *  opaque PSK identities via NewSessionTicket, not ticket-encrypted state). */
    self.getTLSTicket = function(){
        let sctx = session.context;
        let t = sctx && sctx.tls12_received_ticket;
        if (!t || t.length === 0) return undefined;
        return Buffer.isBuffer(t) ? t : Buffer.from(t);
    };

    /** Node-compat: return signature algorithms shared between client and server
     *  (intersection of the two lists), as an array of lowercase OpenSSL-style
     *  names. Server populates both sides during ClientHello processing. */
    self.getSharedSigalgs = function(){
        let sctx = session.context;
        let local = (sctx && sctx.local_supported_signature_algorithms) || [];
        let remote = (sctx && sctx.remote_supported_signature_algorithms) || [];
        if (!local.length || !remote.length) return [];
        // Intersection preserves LOCAL preference order (matches Node behavior)
        let set = new Set(remote);
        let out = [];
        for (let code of local) {
            if (set.has(code)) out.push(sigalgCodeToName(code));
        }
        return out;
    };

    /** Node-compat: set the maximum plaintext fragment size for outgoing records.
     *  Node/OpenSSL accepts values in [512, 16384]. We store it and let the
     *  encrypt path chunk on this boundary; values outside the range throw. */
    self.setMaxSendFragment = function(size){
        size = Number(size);
        if (!Number.isInteger(size) || size < 512 || size > 16384) {
            throw new RangeError('setMaxSendFragment: size must be an integer in [512, 16384]');
        }
        self._maxSendFragment = size;
        return true;
    };

    /** Node-compat: enable OpenSSL handshake tracing to stderr. Node forwards
     *  this to SSL_CTX_set_msg_callback in OpenSSL. We don't have an equivalent
     *  backend, so this is a no-op — kept for API surface parity. Apps wanting
     *  handshake insight should use the 'keylog' and 'handshakeMessage' events. */
    self.enableTrace = function(){ /* no-op, see docstring */ };

    // === Node.js net.Socket compat — delegate to underlying transport ===
    // These getters/methods delegate to the wrapped TCP socket so that TLSSocket
    // exposes the same surface as Node's TLSSocket (which inherits from net.Socket).

    Object.defineProperty(self, 'remoteAddress', {
        get: function(){ return context.transport ? context.transport.remoteAddress : undefined; },
        enumerable: true
    });
    Object.defineProperty(self, 'remotePort', {
        get: function(){ return context.transport ? context.transport.remotePort : undefined; },
        enumerable: true
    });
    Object.defineProperty(self, 'remoteFamily', {
        get: function(){ return context.transport ? context.transport.remoteFamily : undefined; },
        enumerable: true
    });
    Object.defineProperty(self, 'localAddress', {
        get: function(){ return context.transport ? context.transport.localAddress : undefined; },
        enumerable: true
    });
    Object.defineProperty(self, 'localPort', {
        get: function(){ return context.transport ? context.transport.localPort : undefined; },
        enumerable: true
    });
    Object.defineProperty(self, 'localFamily', {
        get: function(){ return context.transport ? context.transport.localFamily : undefined; },
        enumerable: true
    });
    /** Bytes read from the underlying transport. */
    Object.defineProperty(self, 'bytesRead', {
        get: function(){ return context.transport ? context.transport.bytesRead : 0; },
        enumerable: true
    });
    /** Bytes written to the underlying transport. */
    Object.defineProperty(self, 'bytesWritten', {
        get: function(){ return context.transport ? context.transport.bytesWritten : 0; },
        enumerable: true
    });

    /** Delegate setNoDelay() to underlying TCP socket. */
    self.setNoDelay = function(noDelay){
        if (context.transport && typeof context.transport.setNoDelay === 'function') {
            context.transport.setNoDelay(noDelay);
        }
        return self;
    };
    /** Delegate setKeepAlive() to underlying TCP socket. */
    self.setKeepAlive = function(enable, initialDelay){
        if (context.transport && typeof context.transport.setKeepAlive === 'function') {
            context.transport.setKeepAlive(enable, initialDelay);
        }
        return self;
    };
    /** Delegate setTimeout() to underlying TCP socket (overrides Duplex default). */
    self.setTimeout = function(msecs, callback){
        if (context.transport && typeof context.transport.setTimeout === 'function') {
            context.transport.setTimeout(msecs, callback);
        }
        return self;
    };
    /** Delegate ref/unref to underlying TCP socket for event-loop control. */
    self.ref = function(){
        if (context.transport && typeof context.transport.ref === 'function') {
            context.transport.ref();
        }
        return self;
    };
    self.unref = function(){
        if (context.transport && typeof context.transport.unref === 'function') {
            context.transport.unref();
        }
        return self;
    };

    // === LemonTLS-only extensions (not in Node.js tls) ===

    /** Handshake duration in ms, or null if not completed. */
    Object.defineProperty(self, 'handshakeDuration', {
        get: function(){ return session.handshakeDuration; },
        enumerable: true
    });

    /** JA3 fingerprint from ClientHello (server-side only). Returns { hash, raw } or null. */
    self.getJA3 = function(){ return session.getJA3 ? session.getJA3() : null; };

    /** ECDHE shared secret (Buffer), or null. For research/advanced use. */
    self.getSharedSecret = function(){ return session.getSharedSecret ? session.getSharedSecret() : null; };

    /** Full negotiation result — all selected parameters in one object. */
    self.getNegotiationResult = function(){ return session.getNegotiationResult ? session.getNegotiationResult() : null; };

    /** Request Key Update — refresh outgoing encryption keys (TLS 1.3 only). */
    self.rekeySend = function(){ if (session.requestKeyUpdate) session.requestKeyUpdate(false); };

    /** Request Key Update for both directions (TLS 1.3 only). */
    self.rekeyBoth = function(){ if (session.requestKeyUpdate) session.requestKeyUpdate(true); };

    return self;
}

// Inherit from Duplex
Object.setPrototypeOf(TLSSocket.prototype, Duplex.prototype);
Object.setPrototypeOf(TLSSocket, Duplex);

export default TLSSocket;
