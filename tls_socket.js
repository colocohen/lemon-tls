
var TLSSession = require('./tls_session');

var { AES } = require('@stablelib/aes');
var { GCM } = require('@stablelib/gcm');

var {
    TLS_CIPHER_SUITES,
    hkdf_expand_label
} = require('./crypto');



function Emitter(){
  var listeners = {};
  return {
    on: function(name, fn){ (listeners[name] = listeners[name] || []).push(fn); },
    emit: function(name){
      var args = Array.prototype.slice.call(arguments, 1);
      var arr = listeners[name] || [];
      for (var i=0;i<arr.length;i++){ try{ arr[i].apply(null, args); }catch(e){} }
    }
  };
}

// TLS ContentType
var CT = { CHANGE_CIPHER_SPEC:20, ALERT:21, HANDSHAKE:22, APPLICATION_DATA:23 };
// legacy_record_version בשדה כותרת הרשומה (TLS 1.3 שומר 0x0303)
var REC_VERSION = 0x0303;

// ==== עזרי המרה ====
function toBuf(u8){ return Buffer.isBuffer(u8) ? u8 : Buffer.from(u8 || []); }
function toU8(buf){ return (buf instanceof Uint8Array) ? buf : new Uint8Array(buf || []); }



function tls_derive_from_tls_secrets(traffic_secret, cipher_suite){

    var empty = new Uint8Array(0);

    var key = hkdf_expand_label(TLS_CIPHER_SUITES[cipher_suite].hash, traffic_secret, 'key', empty, TLS_CIPHER_SUITES[cipher_suite].keylen);

    var iv  = hkdf_expand_label(TLS_CIPHER_SUITES[cipher_suite].hash, traffic_secret, 'iv',  empty, 12);

    return { 
        key: key, 
        iv: iv,
    };
}


function get_nonce(iv,seq) {

    var seq_buf = new Uint8Array(12); // all zero
    var view = new DataView(seq_buf.buffer);
    view.setBigUint64(4, BigInt(seq)); // offset 4, 64-bit BE

    var nonce = new Uint8Array(12);
    for (var i = 0; i < 12; i++) {
        nonce[i] = iv[i] ^ seq_buf[i];
    }

    return nonce;
}

function encrypt_tls_record(innerType, plaintext, key, nonce) {
  const aes = new AES(key);
  const gcm = new GCM(aes);

  // TLSInnerPlaintext = content || content_type || padding(0x00…)
  const full_plaintext = new Uint8Array(plaintext.length + 1);
  full_plaintext.set(plaintext);
  full_plaintext[plaintext.length] = innerType;   // ← אל תשכח לבחור נכון

  // AAD = [ 0x17, 0x03, 0x03, len_hi, len_lo ]
  // len = ciphertext.length כולל tag = full_plaintext.length + 16 (ב-GCM)
  const aad = new Uint8Array(5);
  aad[0] = 0x17;
  aad[1] = 0x03; aad[2] = 0x03;
  const recLen = full_plaintext.length + 16; // tag=16
  aad[3] = (recLen >>> 8) & 0xff;
  aad[4] = (recLen      ) & 0xff;

  // הצפנה אחת עם AAD הנכון
  const ciphertext = gcm.seal(nonce, full_plaintext, aad); // אמור להחזיר ct||tag
  return ciphertext;
}



function decrypt_tls_record(ciphertext, key, nonce) {
  // הקמה: AES + GCM
  var aes = new AES(key);
  var gcm = new GCM(aes);

  // AAD לפי TLS 1.3: 0x17 (application_data), גרסה 0x0303, ואורך ה-ciphertext
  var aad = new Uint8Array(5);
  aad[0] = 0x17;         // record type תמיד 0x17 אחרי הצפנה
  aad[1] = 0x03; aad[2] = 0x03; // "גרסת" הרשומה (TLS 1.2 בפועל לשכבת הרשומה)
  var len = ciphertext.length;
  aad[3] = (len >> 8) & 0xff;
  aad[4] = len & 0xff;

  // פתיחה (אימות + פענוח). אם ה-tag לא תקף, תחזור null/undefined לפי המימוש
  var full_plaintext = gcm.open(nonce, ciphertext, aad);
  if (!full_plaintext) {
    throw new Error('GCM authentication failed (bad tag)');
  }

  return full_plaintext;
}

function parse_tls_inner_plaintext(full_plaintext) {
  var j = full_plaintext.length - 1;
  while (j >= 0 && full_plaintext[j] === 0x00) { j--; }
  if (j < 0) throw new Error('Malformed TLSInnerPlaintext (no content type)');

  var content_type = full_plaintext[j];
  var content = full_plaintext.slice(0, j); // חיתוך אמיתי
  return { content_type: content_type, content: content };
}


// ==== TLSSocket ====
function TLSSocket(duplex, options){
  if (!(this instanceof TLSSocket)) return new TLSSocket(duplex, options);
  options = options || {};

  var ev = Emitter();

    var context = {

    options: options,

    // transport (Duplex) שמחובר מבחוץ
    transport: (duplex && typeof duplex.write === 'function') ? duplex : null,

    // TLSSession פנימי בלבד
    session: new TLSSession({
        isServer: !!options.isServer,
        servername: options.servername,
        ALPNProtocols: options.ALPNProtocols || null,
        SNICallback: options.SNICallback || null
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




    // באפרים ותורים
    readBuffer: Buffer.alloc(0),
    appWriteQueue: [],

    // מצבים כלליים
    destroyed: false,
    secureEstablished: false,

    // legacy record version (TLS1.3)
    rec_version: 0x0303
    };


     // === שכבת הרשומות (Record Layer) ===
    function writeRecord(type, payload){
        if (!context.transport) throw new Error('No transport attached to TLSSocket');
        var rec = Buffer.allocUnsafe(5 + payload.length);
        rec.writeUInt8(type, 0);
        rec.writeUInt16BE(context.rec_version, 1);
        rec.writeUInt16BE(payload.length, 3);
        payload.copy(rec, 5);
        try { context.transport.write(rec); } catch(e){ ev.emit('error', e); }
    }

    function writeAppData(plain){
        //console.log('...');

        if(context.session.context.server_app_traffic_secret!==null){
            if(context.app_write_key==null || context.app_write_iv==null){
                var d=tls_derive_from_tls_secrets(context.session.context.server_app_traffic_secret,context.session.context.selected_cipher_suite);

                context.app_write_key=d.key;
                context.app_write_iv=d.iv;
            }
        }else{
            //console.log('no key yet...');
        }

        var enc1 = encrypt_tls_record(CT.APPLICATION_DATA,plain, context.app_write_key, get_nonce(context.app_write_iv,context.app_write_seq));

        context.app_write_seq++;

        try {

            //console.log(enc1);

            writeRecord(CT.APPLICATION_DATA, Buffer.from(enc1));
        } catch(e){ 
            ev.emit('error', e); 
        }

    }

    function processCiphertext(body){

        var out=null;

        if(context.using_app_keys==true){

            if(context.session.context.client_app_traffic_secret!==null){
                if(context.app_read_key==null || context.app_read_iv==null){
                    var d=tls_derive_from_tls_secrets(context.session.context.client_app_traffic_secret,context.session.context.selected_cipher_suite);

                    context.app_read_key=d.key;
                    context.app_read_iv=d.iv;
                }

                out = decrypt_tls_record(body, context.app_read_key, get_nonce(context.app_read_iv,context.app_read_seq));

                context.app_read_seq++;

            }else{
                //...
            }
        }else{
            
            
            if(context.session.context.client_handshake_traffic_secret!==null){
                if(context.handshake_read_key==null || context.handshake_read_iv==null){
                    var d=tls_derive_from_tls_secrets(context.session.context.client_handshake_traffic_secret,context.session.context.selected_cipher_suite);

                    context.handshake_read_key=d.key;
                    context.handshake_read_iv=d.iv;
                }

                out = decrypt_tls_record(body, context.handshake_read_key, get_nonce(context.handshake_read_iv,context.handshake_read_seq));

                context.handshake_read_seq++;

            }else{
                //...
            }
        }
        

        if(out!==null){
            var {content_type, content} = parse_tls_inner_plaintext(out);

            if (content_type === CT.HANDSHAKE || content_type === CT.ALERT) {
                //var cls = usingApp ? 2 : 1; // 1=handshake-keys, 2=app-keys
                try { context.session.message(new Uint8Array(content)); } catch(e){ ev.emit('error', e); }
                return;
            }

            if (content_type === CT.APPLICATION_DATA) { ev.emit('data', content); return; }
            if (content_type === CT.CHANGE_CIPHER_SPEC) { return; }
        }
        


    }


    function parseRecordsAndDispatch(){
        while (context.readBuffer.length >= 5) {
            var type = context.readBuffer.readUInt8(0);
            var ver  = context.readBuffer.readUInt16BE(1);
            var len  = context.readBuffer.readUInt16BE(3);
            if (context.readBuffer.length < 5 + len) break;

            var body = context.readBuffer.slice(5, 5+len);
            context.readBuffer = context.readBuffer.slice(5+len);

            if (type === CT.APPLICATION_DATA) {
            try { processCiphertext(body); } catch(e){ ev.emit('error', e); }
            continue;
            }

            if (type === CT.HANDSHAKE || type === CT.ALERT || type === CT.CHANGE_CIPHER_SPEC) {
            try { context.session.message(new Uint8Array(body)); } catch(e){ ev.emit('error', e); }
            continue;
            }
        }
    }


    function bindTransport(){
        if (!context.transport) return;
        context.transport.on('data', function(chunk){
            context.readBuffer = Buffer.concat([context.readBuffer, chunk]);
            parseRecordsAndDispatch();
        });
        context.transport.on('error', function(err){ ev.emit('error', err); });
        context.transport.on('close', function(){ ev.emit('close'); });
    }

    context.session.on('message', function(epoch, seq, type, data){
        var buf = toBuf(data || []);

        if (epoch === 0) {
            // ברור (ClientHello/ServerHello/CCS/Alert מוקדם)
            writeRecord(CT.HANDSHAKE, buf);
            return;
        }

        if (epoch === 1) {
            
            //need to create it...
            if(context.session.context.server_handshake_traffic_secret!==null){
                
                if(context.handshake_write_key==null || context.handshake_write_iv==null){
                    var d=tls_derive_from_tls_secrets(context.session.context.server_handshake_traffic_secret,context.session.context.selected_cipher_suite);

                    context.handshake_write_key=d.key;
                    context.handshake_write_iv=d.iv;
                }

                
                var enc1 = encrypt_tls_record(CT.HANDSHAKE, buf, context.handshake_write_key, get_nonce(context.handshake_write_iv,context.handshake_write_seq));

                context.handshake_write_seq++;

                try {
                    //var enc1 = aeadEncrypt(context.handshake_write_key, context.handshake_write_iv, TLS_CIPHER_SUITES[context.session.context.selected_cipher_suite].cipher, context.handshake_write_seq, 0x0304, CT.HANDSHAKE, buf);

                    //console.log(enc1);

                    writeRecord(CT.APPLICATION_DATA, Buffer.from(enc1));
                } catch(e){ 
                    ev.emit('error', e); 
                }

            }else{
                ev.emit('error', new Error('Missing handshake write keys'));
            }
        }

        if (epoch === 2) {
            // Post-Handshake מוצפן (inner_type=HANDSHAKE) תחת מפתחות Application
            if (!context.application_write) { ev.emit('error', new Error('Missing application write keys')); return; }
            try {
            var enc2 = aeadEncrypt(context.application_write, CT.HANDSHAKE, buf);
            writeRecord(CT.APPLICATION_DATA, enc2);
            } catch(e){ ev.emit('error', e); }
            return;
        }
    });


    context.session.on('hello', function(info){

        context.rec_version = 0x0303; // TLS 1.3 legacy record version

        context.session.set_context({

            local_versions: [0x0304],
            local_alpns: ['http/1.1'],
            local_groups: [0x001d, 0x0017, 0x0018],
            local_cipher_suites: [
                0x1301, 
                0x1302, 
                0xC02F, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
                0xC030, // ECDHE_RSA_WITH_AES_256_GCM_SHA384
                0xCCA8  // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (אם מימשת)
            ],

            // ---- אלגוריתמי חתימה (TLS 1.2 → RSA-PKCS1, לא PSS) ----
            // 0x0401 = rsa_pkcs1_sha256, 0x0501 = rsa_pkcs1_sha384, 0x0601 = rsa_pkcs1_sha512
            local_signature_algorithms: [0x0401, 0x0501, 0x0601],
            // אופציונלי (לטובת חלק מהלקוחות): אותו דבר גם ל-signature_algorithms_cert
            local_signature_algorithms_cert: [0x0401, 0x0501, 0x0601],
            
            //local_cert_chain: [{ cert: new Uint8Array(cert.raw)}],
            //cert_private_key: new Uint8Array(private_key_der)
        });
    });

    context.session.on('secureConnect', function(){
        context.using_app_keys=true;
        ev.emit('secureConnect');
    });

    // אם הועבר duplex בבנאי — להתחיל לקלוט
    if (context.transport) {
        bindTransport();
    }

    // === API ציבורי (ללא חשיפת session) ===
    var api = {
        on: function(name, fn){ ev.on(name, fn); },

        setSocket: function(duplex2){
            if (!duplex2 || typeof duplex2.write !== 'function') throw new Error('setSocket expects a Duplex-like stream');
            context.transport = duplex2;
            bindTransport();
        },

        write: function(data){
            if (context.destroyed) return false;
            var buf = toBuf(data);
            if (!context.using_app_keys) { context.appWriteQueue.push(buf); return true; }
            return writeAppData(buf);
        },

        end: function(data){
            if (context.destroyed) return;
            if (typeof data !== 'undefined' && data !== null) api.write(data);
            try { context.transport && context.transport.end && context.transport.end(); } catch(e){}
        },

        destroy: function(){
            if (context.destroyed) return;
            context.destroyed = true;
            try { context.transport && context.transport.destroy && context.transport.destroy(); } catch(e){}
        },

        getCipher: function(){
            var cs = context.session && context.session.context && context.session.context.selected_cipher_suite;
            return { name: cs || 'TLS_AES_128_GCM_SHA256', version: 'TLSv1.3' };
        },
        getPeerCertificate: function(){ return null; },
        authorized: function(){ return true; }
    };

    for (var k in api) if (Object.prototype.hasOwnProperty.call(api,k)) this[k] = api[k];
    

    return this;
}

module.exports = TLSSocket;