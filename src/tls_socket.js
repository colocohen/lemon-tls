
import fs from 'node:fs';

function writeClientRandomKeyLog(clientRandom, masterSecret, filePath) {
  function toHex(u8) {
    return Array.from(u8)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  const line = `CLIENT_RANDOM ${toHex(clientRandom)} ${toHex(masterSecret)}\n`;

  fs.appendFileSync(filePath, line, 'utf8');
  console.log(`✅ Added CLIENT_RANDOM line to ${filePath}`);
}

import TLSSession from './tls_session.js';

import crypto from 'node:crypto';
import { Duplex } from 'node:stream';

import { TLS_CIPHER_SUITES } from './crypto.js';
import { TLS_CONTENT_TYPE as CT, TLS_ALERT_LEVEL, TLS_ALERT } from './wire.js';

import {
  getAeadAlgo,
  deriveKeys as tls_derive_from_tls_secrets,
  getNonce as get_nonce,
  encryptRecord as encrypt_tls_record,
  decryptRecord as decrypt_tls_record,
  parseInnerPlaintext as parse_tls_inner_plaintext,
  encrypt12 as encrypt_tls12_gcm_fragment,
  decrypt12 as decrypt_tls12_gcm_fragment,
  deriveKeys12,
  writeRecord as writeRawRecord,
} from './record.js';

// legacy_record_version (TLS 1.3 uses 0x0303 in record header)
const REC_VERSION = 0x0303;

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
  Duplex.call(this, { allowHalfOpen: true, readableObjectMode: false, writableObjectMode: false });
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
        session: options.session || null,
        psk: options.psk || null,
        rejectUnauthorized: options.rejectUnauthorized,
        ca: options.ca || null,
        noTickets: !!options.noTickets,
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

    using_app_keys: false,

    remote_ccs_seen: false,
    local_ccs_sent: false,

    tls12_read_seq: 0,

    // Buffers and queues
    readBuffer: Buffer.alloc(0),
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
    noTickets: !!options.noTickets,
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
    function writeRecord(type, payload){
        if (!context.transport) throw new Error('No transport attached to TLSSocket');
        if (context.destroyed || context.transport.destroyed || context.transport.writableEnded) return;
        try { writeRawRecord(context.transport, type, payload, context.rec_version); }
        catch(e){ self.emit('error', e); }
    }

    const MAX_RECORD_PLAINTEXT = 16384; // TLS max record size (2^14)

    function writeAppData(plain){
        // Fragment large writes into multiple TLS records
        let maxSize = context.maxRecordSize || 16384;
        if (plain.length > maxSize) {
            for (let off = 0; off < plain.length; off += maxSize) {
                let chunk = plain.slice(off, Math.min(off + maxSize, plain.length));
                writeAppDataSingle(chunk);
            }
            return;
        }
        writeAppDataSingle(plain);
    }

    function writeAppDataSingle(plain){
        let isTls13 = session.getVersion() === 0x0304;

        if(isTls13){
            if(session.getTrafficSecrets().localAppSecret!==null){
                if(context.app_write_key==null || context.app_write_iv==null){
                    let d=tls_derive_from_tls_secrets(session.getTrafficSecrets().localAppSecret,session.getCipher());

                    context.app_write_key=d.key;
                    context.app_write_iv=d.iv;
                }
            }else{
                return;
            }

            let enc1 = encrypt_tls_record(CT.APPLICATION_DATA, plain, context.app_write_key, get_nonce(context.app_write_iv,context.app_write_seq), context.aeadAlgo || getAeadAlgo(session.getCipher()));

            context.app_write_seq++;

            try {
                writeRecord(CT.APPLICATION_DATA, Buffer.from(enc1));
            } catch(e){ 
                self.emit('error', e); 
            }

        }else{
            // TLS 1.2: derive keys if needed, then encrypt with GCM
            if(context.app_write_key==null || context.app_write_iv==null){
                let d12 = deriveKeys12(session.getTrafficSecrets().masterSecret, session.getTrafficSecrets().localRandom, session.getTrafficSecrets().remoteRandom, session.getCipher(), session.isServer);
                context.app_write_key = d12.writeKey;
                context.app_write_iv = d12.writeIv;
            }

            let fragment = encrypt_tls12_gcm_fragment(
                plain,
                context.app_write_key,
                context.app_write_iv,
                context.app_write_seq,
                CT.APPLICATION_DATA
            );

            context.app_write_seq++;

            writeRecord(CT.APPLICATION_DATA, Buffer.from(fragment));
        }

    }

    function processCiphertext(body){

        let out=null;
        let isTls13 = session.getVersion() === 0x0304;

        if(!isTls13 && context.remote_ccs_seen==true){
            // TLS 1.2: decrypt with key_block derived keys
            if(context.app_read_key==null || context.app_read_iv==null){

                let d12 = deriveKeys12(session.getTrafficSecrets().masterSecret, session.getTrafficSecrets().localRandom, session.getTrafficSecrets().remoteRandom, session.getCipher(), session.isServer);
                context.app_read_key = d12.readKey;
                context.app_read_iv = d12.readIv;
                context.app_write_key = d12.writeKey;
                context.app_write_iv = d12.writeIv;
            }

            let recordType = context.using_app_keys ? 0x17 : 0x16;
            out = decrypt_tls12_gcm_fragment(new Uint8Array(body), context.app_read_key, context.app_read_iv, context.tls12_read_seq, recordType);

        }else if(isTls13 && context.using_app_keys==true){
            // TLS 1.3: decrypt app data with app traffic secret
            if(session.getTrafficSecrets().remoteAppSecret!==null){
                if(context.app_read_key==null || context.app_read_iv==null){
                    let d=tls_derive_from_tls_secrets(session.getTrafficSecrets().remoteAppSecret,session.getCipher());
                    context.app_read_key=d.key;
                    context.app_read_iv=d.iv;
                }

                out = decrypt_tls_record(body, context.app_read_key, get_nonce(context.app_read_iv,context.app_read_seq), context.aeadAlgo || getAeadAlgo(session.getCipher()));
                context.app_read_seq++;
            }
        }else if(isTls13){
            // TLS 1.3: decrypt handshake with handshake traffic secret
            if(session.getHandshakeSecrets().remoteSecret!==null && session.getCipher()!==null){
                if(context.handshake_read_key==null || context.handshake_read_iv==null){
                    let d=tls_derive_from_tls_secrets(session.getHandshakeSecrets().remoteSecret,session.getCipher());
                    context.handshake_read_key=d.key;
                    context.handshake_read_iv=d.iv;
                }

                out = decrypt_tls_record(body, context.handshake_read_key, get_nonce(context.handshake_read_iv,context.handshake_read_seq), context.aeadAlgo || getAeadAlgo(session.getCipher()));
                context.handshake_read_seq++;
            }
        }
        

        if(out!==null){
            let isTls13 = session.getVersion() === 0x0304;

            if(isTls13){
                let {type: content_type, content} = parse_tls_inner_plaintext(out);
                
                if(content_type === CT.APPLICATION_DATA){
                    self.push(Buffer.from(content));

                }else if(content_type === CT.HANDSHAKE){
                    session.message(new Uint8Array(content));

                }else if(content_type === CT.ALERT){
                    // TODO: handle alert
                }
            }else{
                // TLS 1.2: no inner plaintext wrapping
                if(context.using_app_keys==true){
                    self.push(Buffer.from(out));
                }else{
                    session.message(new Uint8Array(out));
                }
            }
        }
        


    }


    function parseRecordsAndDispatch(){
        while (context.readBuffer.length >= 5) {
            let type = context.readBuffer.readUInt8(0);
            let ver  = context.readBuffer.readUInt16BE(1);
            let len  = context.readBuffer.readUInt16BE(3);
            if (context.readBuffer.length < 5 + len) break;

            let body = context.readBuffer.slice(5, 5+len);
            context.readBuffer = context.readBuffer.slice(5+len);
            
            if (type === CT.APPLICATION_DATA) {
                processCiphertext(body);

                context.tls12_read_seq++;

            }else if(type === CT.HANDSHAKE){
                if(context.remote_ccs_seen==true){
                    processCiphertext(body);
                }else{
                    session.message(new Uint8Array(body));
                }

                context.tls12_read_seq++;
                
            }else if(type === CT.CHANGE_CIPHER_SPEC){
                
                context.tls12_read_seq=0;
                context.remote_ccs_seen=true;
                
            }else if(type === CT.ALERT ){
                // Alert: 2 bytes — level (1=warning, 2=fatal), description
                if(body.length >= 2){
                    let level = body[0];
                    let desc = body[1];
                    self.emit('alert', { level: level, description: desc });
                    if(desc === TLS_ALERT.CLOSE_NOTIFY){
                        // Peer is closing — send close_notify back and close
                        session.close();
                        if(context.transport && typeof context.transport.end === 'function'){
                            context.transport.end();
                        }
                    }
                    if(level === TLS_ALERT_LEVEL.FATAL){
                        // Fatal alert — close immediately
                        if(context.transport && typeof context.transport.destroy === 'function'){
                            context.transport.destroy();
                        }
                    }
                }
            }


            
        }
    }


    function bindTransport(){
        if (!context.transport) return;
        context.transport.on('data', function(chunk){
            context.readBuffer = Buffer.concat([context.readBuffer, chunk]);
            parseRecordsAndDispatch();
        });
        context.transport.on('error', function(err){ self.emit('error', err); });
        context.transport.on('close', function(){ self.emit('close'); });
    }

    session.on('message', function(epoch, seq, type, data){
        let buf = toBuf(data || []);

        // Alert messages — send as ALERT record type
        if (type === 'alert') {
            let isTls13 = session.getVersion() === 0x0304;
            if (isTls13 && context.using_app_keys && context.app_write_key) {
                // TLS 1.3: post-handshake alerts are encrypted
                let enc = encrypt_tls_record(CT.ALERT, buf, context.app_write_key, get_nonce(context.app_write_iv, context.app_write_seq), context.aeadAlgo || getAeadAlgo(session.getCipher()));
                context.app_write_seq++;
                writeRecord(CT.APPLICATION_DATA, Buffer.from(enc));
            } else {
                writeRecord(CT.ALERT, buf);
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
            let isTls13 = session.getVersion() === 0x0304;
            
            if(isTls13){
                // TLS 1.3: encrypt handshake messages with handshake traffic secret
                if(session.getHandshakeSecrets().localSecret!==null){
                    
                    if(context.handshake_write_key==null || context.handshake_write_iv==null){
                        let d=tls_derive_from_tls_secrets(session.getHandshakeSecrets().localSecret,session.getCipher());

                        context.handshake_write_key=d.key;
                        context.handshake_write_iv=d.iv;
                    }

                    let enc1 = encrypt_tls_record(CT.HANDSHAKE, buf, context.handshake_write_key, get_nonce(context.handshake_write_iv,context.handshake_write_seq), context.aeadAlgo || getAeadAlgo(session.getCipher()));

                    context.handshake_write_seq++;

                    try {
                        writeRecord(CT.APPLICATION_DATA, Buffer.from(enc1));
                    } catch(e){ 
                        self.emit('error', e); 
                    }

                }else{
                    self.emit('error', new Error('Missing handshake write keys'));
                }

            }else{
                // TLS 1.2: send CCS first, then encrypt Finished with key_block keys
                if(context.local_ccs_sent==false){
                    writeRecord(CT.CHANGE_CIPHER_SPEC, Buffer.from([0x01]));
                    context.local_ccs_sent=true;
                    // Reset write seq after CCS (TLS 1.2 spec)
                    context.app_write_seq=0;
                }

                // Derive keys if not yet done
                if(context.app_write_key==null || context.app_write_iv==null){
                    let d12 = deriveKeys12(session.getTrafficSecrets().masterSecret, session.getTrafficSecrets().localRandom, session.getTrafficSecrets().remoteRandom, session.getCipher(), session.isServer);
                    context.app_read_key = d12.readKey;
                    context.app_read_iv = d12.readIv;
                    context.app_write_key = d12.writeKey;
                    context.app_write_iv = d12.writeIv;
                }

                let fragment = encrypt_tls12_gcm_fragment(
                    buf,
                    context.app_write_key,
                    context.app_write_iv,
                    context.app_write_seq,
                    CT.HANDSHAKE
                );

                context.app_write_seq++;

                writeRecord(CT.HANDSHAKE, Buffer.from(fragment));
            }
            
        }

        if (epoch === 2) {
            // Post-handshake message encrypted with app keys (e.g. NewSessionTicket)
            if (!context.app_write_key) {
                // Derive app write keys if not yet done
                let ts = session.getTrafficSecrets();
                if (ts.localAppSecret) {
                    let d = tls_derive_from_tls_secrets(ts.localAppSecret, session.getCipher());
                    context.app_write_key = d.key;
                    context.app_write_iv = d.iv;
                }
            }
            if (context.app_write_key) {
                let algo = context.aeadAlgo || getAeadAlgo(session.getCipher());
                let enc = encrypt_tls_record(CT.HANDSHAKE, buf, context.app_write_key, get_nonce(context.app_write_iv, context.app_write_seq), algo);
                context.app_write_seq++;
                writeRecord(CT.APPLICATION_DATA, Buffer.from(enc));
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

        // Resolve AEAD algorithm once cipher is negotiated
        if (session.getCipher()) context.aeadAlgo = getAeadAlgo(session.getCipher());
    });

    session.on('secureConnect', function(){
        context.using_app_keys=true;
        context.secureEstablished=true;
        context.aeadAlgo = getAeadAlgo(session.getCipher());

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

        // Flush any queued writes
        while (context.appWriteQueue.length > 0) {
            writeAppData(context.appWriteQueue.shift());
        }

        self.emit('secureConnect');
    });

    // Forward session ticket event (Node.js compatible)
    session.on('session', function(ticketData) {
        self.emit('session', ticketData);
    });

    // Forward handshakeMessage event (for debugging/inspection)
    session.on('handshakeMessage', function(type, raw, parsed) {
        self.emit('handshakeMessage', type, raw, parsed);
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

    // Server: automatic PSK handler (decrypts tickets with ticketKeys)
    if (options.isServer) {
        session.on('psk', function(identity, callback) {
            // First check if user has a custom handler
            if (self.listenerCount('psk') > 0) {
                // Let user handle it
                self.emit('psk', identity, callback);
                return;
            }

            // Auto-decrypt ticket using ticketKeys
            try {
                let tk = context.ticketKeys;
                let ticket_enc_key = tk.slice(0, 32);
                let id = Buffer.from(identity);
                if (id.length < 12 + 16) { callback(null); return; }

                let iv = id.slice(0, 12);
                let tag = id.slice(id.length - 16);
                let ct = id.slice(12, id.length - 16);

                let decipher = crypto.createDecipheriv('aes-256-gcm', ticket_enc_key, iv);
                decipher.setAuthTag(tag);
                let pt = decipher.update(ct);
                decipher.final();

                let data = JSON.parse(pt.toString());
                callback({
                    psk: new Uint8Array(Buffer.from(data.psk, 'base64')),
                    cipher: data.cipher,
                });
            } catch(e) {
                callback(null); // Decryption failed → full handshake
            }
        });
    }

    // If duplex was passed in constructor, start reading
    if (context.transport) {
        bindTransport();
    }

    // === Duplex stream implementation ===

    /** Duplex _write — called by stream.write() */
    self._write = function(chunk, encoding, callback) {
        if (context.destroyed) { callback(new Error('Socket destroyed')); return; }
        let buf = toBuf(chunk);
        if (!context.using_app_keys) {
            context.appWriteQueue.push(buf);
        } else {
            writeAppData(buf);
        }
        callback();
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

    /** Access the underlying TLSSession (for QUIC/advanced consumers). */
    self.getSession = function(){ return session; };

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
