import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

import {
  TLS_CIPHER_SUITES,
  build_cert_verify_tbs,
  get_handshake_finished,
  tls12_prf,
  derive_handshake_traffic_secrets,
  derive_app_traffic_secrets,
  derive_resumption_master_secret,
  derive_psk,
  derive_binder_key,
  compute_psk_binder,
  derive_handshake_traffic_secrets_psk,
  hkdf_expand_label,
  getHashFn,
} from './crypto.js';

import {
  concatUint8Arrays,
  arraysEqual,
  uint8Equal
} from './utils.js';

import * as wire from './wire.js';

// Extracted modules
import { pick_scheme, sign_with_scheme } from './session/signing.js';
import createSecureContext from './secure_context.js';
import { x25519_get_public_key, x25519_get_shared_secret, p256_generate_keypair, p256_get_shared_secret, p384_generate_keypair, p384_get_shared_secret } from './session/ecdh.js';
import { build_tls_message, parse_tls_message } from './session/message.js';


function TLSSession(options){
  if (!(this instanceof TLSSession)) return new TLSSession(options);
  options = options || {};

  const ev = new EventEmitter();

  let context = {
    state: 'new', //new | negotiating | ...
    isServer: !!options.isServer,
    rejectUnauthorized: options.rejectUnauthorized !== false, // default true
    ca: options.ca || null, // CA certificates (PEM strings or Buffers)

    SNICallback: options.SNICallback || null,
    ticketKeys: options.ticketKeys || null, // 48 bytes for ticket encryption

    // Advanced options
    maxHandshakeSize: options.maxHandshakeSize || 0, // 0 = no limit
    customExtensions: options.customExtensions || [], // [{type:0xNN, data:Uint8Array}]
    handshakeBytes: 0,
    handshakeStartTime: null,
    handshakeEndTime: null,
    rawClientHello: null,  // saved for JA3/JA4 and 'clienthello' event

    //local stuff...
    local_sni: options.servername || null,
    local_session_id: 'sessionId' in options ? options.sessionId : null,

    local_random: null,
    local_extensions: [],


    local_supported_versions: [],
    local_supported_alpns: [],

    local_supported_cipher_suites: [],
    local_supported_signature_algorithms: [],
    local_supported_groups: [],


    //remote stuff...
    remote_sni: null,
    remote_session_id: null,

    remote_random: null,
    remote_extensions: [],

    remote_supported_versions: [],
    remote_supported_alpns: [],

    remote_supported_cipher_suites: [],
    remote_supported_signature_algorithms: [],    
    remote_supported_groups: [],

    
    //selected stuff...
    selected_extensions: [],
    selected_sni: null,
    selected_session_id: null,// for TLS 1.2 only

    selected_version: null,
    selected_alpn: null,
    selected_cipher_suite: null,
    selected_signature_algorithm: null,
    selected_group: null,
    


    local_key_groups: {},
    remote_key_groups: {},


    ecdhe_shared_secret: null,
    base_secret: null,


    transcript: [],
    transcriptHook: null,  // DTLSSession sets this to transform transcript entries


    //both
    hello_sent: false,
    finished_sent: false,
    cert_sent: false,

    //1.2 only
    key_exchange_sent: false,
    hello_done_sent: false,
    remote_hello_done: false,
    use_extended_master_secret: false,

    //1.3 only
    encrypted_exts_sent: false,
    cert_verify_sent: false,
    

    message_sent_seq: 0,

    remote_finished: null,
    expected_remote_finished: null,
    remote_finished_ok: false,
    local_finished_data: null,   // saved for getFinished()
    remote_finished_data: null,  // saved for getPeerFinished()

    remote_handshake_traffic_secret: null,
    local_handshake_traffic_secret: null,
    
    remote_app_traffic_secret: null,
    local_app_traffic_secret: null,

    local_cert_chain: null,
    remote_cert_chain: null,
    peerAuthorized: false,
    authorizationError: null,

    selected_cert: null,

    cert_private_key: null,

    // Client certificate authentication
    requestCert: !!options.requestCert,       // server: send CertificateRequest?
    clientCert: options.cert || null,          // client: cert to send if requested
    clientKey: options.key || null,            // client: private key for CertificateVerify
    certificateRequested: false,              // client: server sent CertificateRequest?
    certificateRequestSent: false,            // server: we sent CertificateRequest?
    certificateRequestContext: null,
    certificateRequestSigAlgs: [],
    clientCertSent: false,

    // HelloRetryRequest
    helloRetried: false,                      // true if HRR was sent/received

    // DTLS cookie (set by DTLSSession via set_context)
    dtls_cookie: undefined,                   // Uint8Array or undefined

    // TLS 1.3 resumption
    tls13_master_secret: null,
    resumption_master_secret: null,
    ticket_nonce_counter: 0,
    session_ticket_sent: false,
    noTickets: !!options.noTickets,
    psk_offered: null,       // client: { identity, psk, cipher } offered in ClientHello
    psk_accepted: false,     // server accepted PSK → abbreviated handshake
    isResumed: false,        // true if PSK was accepted
  };

  /**
   * Push a handshake message to the transcript.
   * If a transcriptHook is set (by DTLSSession), it transforms the data first.
   * This allows DTLS 1.2 to store DTLS-format entries (with reconstruction data)
   * while TLS and DTLS 1.3 store standard TLS-format entries.
   */
  function pushTranscript(data) {
    if (context.transcriptHook) {
      data = context.transcriptHook(data);
    }
    context.transcript.push(data);
  }

  function process_income_message(data){

    // Track handshake start time
    if (context.handshakeStartTime === null) context.handshakeStartTime = Date.now();

    // Track handshake size and enforce limit
    context.handshakeBytes += data.length;
    if (context.maxHandshakeSize > 0 && context.handshakeBytes > context.maxHandshakeSize) {
      ev.emit('error', new Error('Handshake size exceeded maxHandshakeSize (' + context.maxHandshakeSize + ')'));
      return;
    }

    let message = parse_tls_message(data);

    // Emit 'handshakeMessage' hook for every message
    ev.emit('handshakeMessage', message.type, data, message);

    if((context.isServer==false && message.type=='server_hello') || (context.isServer==true && message.type=='client_hello')){

      pushTranscript(data);

      // Save raw ClientHello + emit event (server side)
      if (context.isServer && message.type === 'client_hello') {
        context.rawClientHello = data;
        ev.emit('clienthello', data, message);
      }

      // Detect extended_master_secret (type 23 / 0x0017) from remote hello
      // Server: detects from ClientHello. Client: detects from ServerHello.
      if (Array.isArray(message.extensions)) {
        for (let ei = 0; ei < message.extensions.length; ei++) {
          if (message.extensions[ei].type === 0x0017) {
            context.use_extended_master_secret = true;
            break;
          }
        }
      }

      // Server: detect and validate PSK BEFORE set_context (so reactive loop sees psk_accepted)
      if (context.isServer && message.pre_shared_key && message.pre_shared_key.identities && message.pre_shared_key.identities.length > 0) {
        let pskIdentity = message.pre_shared_key.identities[0];
        let pskBinder = message.pre_shared_key.binders ? message.pre_shared_key.binders[0] : null;

        let pskResult = null;
        ev.emit('psk', pskIdentity.identity, function(result) {
          pskResult = result;
        });
        if (pskResult && pskResult.psk) {
          let pskCipher = pskResult.cipher || 0x1301;
          let hashName = TLS_CIPHER_SUITES[pskCipher] ? TLS_CIPHER_SUITES[pskCipher].hash : 'sha256';
          let binder_key = derive_binder_key(hashName, pskResult.psk, false);

          let hashLen = getHashFn(hashName).outputLen;
          let bindersSize = 2 + 1 + hashLen;
          let truncatedCH = data.slice(0, data.length - bindersSize);
          let expectedBinder = compute_psk_binder(hashName, binder_key, truncatedCH);

          let binderOk = pskBinder && expectedBinder.length === pskBinder.length;
          if (binderOk) {
            for (let bi = 0; bi < expectedBinder.length; bi++) {
              if (expectedBinder[bi] !== pskBinder[bi]) { binderOk = false; break; }
            }
          }

          if (binderOk) {
            context.psk_accepted = true;
            context.isResumed = true;
            context.psk_offered = {
              psk: pskResult.psk instanceof Uint8Array ? pskResult.psk : new Uint8Array(pskResult.psk),
              cipher: pskCipher,
            };
          }
        }
      }

      // Client: detect if server accepted PSK from ServerHello (BEFORE set_context)
      if (!context.isServer && message.pre_shared_key && typeof message.pre_shared_key.selected === 'number') {
        if (context.psk_offered) {
          context.psk_accepted = true;
          context.isResumed = true;
        }
      }

      // Client: detect HelloRetryRequest (ServerHello with magic random)
      if (!context.isServer && message.random && uint8Equal(message.random, wire.TLS13_HRR_RANDOM)) {
        context.helloRetried = true;

        // Get cipher from HRR to determine hash
        let hrrCipher = null;
        if (message.cipher_suites && message.cipher_suites.length > 0) hrrCipher = message.cipher_suites[0];
        else if (message.cipher_suite) hrrCipher = message.cipher_suite;
        if (!hrrCipher) hrrCipher = 0x1301;
        let hashName = TLS_CIPHER_SUITES[hrrCipher] ? TLS_CIPHER_SUITES[hrrCipher].hash : 'sha256';

        // Replace transcript: CH1 → message_hash (RFC 8446 §4.4.1)
        // BUG FIX: The HRR was already pushed to transcript at the top of this block (line 195).
        // We must remove it before hashing, since message_hash = Hash(ClientHello1) only.
        let hrrData = context.transcript.pop(); // remove HRR
        let ch1_hash = getHashFn(hashName)(concatUint8Arrays(context.transcript));
        let message_hash = wire.build_message(wire.TLS_MESSAGE_TYPE.MESSAGE_HASH, ch1_hash);
        context.transcript = [message_hash, hrrData]; // message_hash + HRR

        // Find the requested group from HRR key_share extension
        // After wire.js fix, key_groups contains [{group: N, key_exchange: empty}] for HRR
        let requestedGroup = null;
        if (message.key_groups && message.key_groups.length > 0) {
          requestedGroup = message.key_groups[0].group;
        } else if (message.supported_groups && message.supported_groups.length > 0) {
          requestedGroup = message.supported_groups[0];
        }

        // Extract cookie from HRR (if present, must be echoed in CH2)
        let hrrCookie = message.cookie || null;

        if (requestedGroup) {
          // Generate key for the requested group
          let newKeyGroup = null;
          if (requestedGroup === 0x001d) {
            let pk = new Uint8Array(crypto.randomBytes(32));
            let pub = x25519_get_public_key(pk);
            newKeyGroup = { group: requestedGroup, public_key: pub, private_key: pk };
            context.local_key_groups[requestedGroup] = { public_key: pub, private_key: pk };
          } else if (requestedGroup === 0x0017) {
            let kp = p256_generate_keypair();
            newKeyGroup = { group: requestedGroup, public_key: kp.public_key, private_key: kp.private_key };
            context.local_key_groups[requestedGroup] = { public_key: kp.public_key, private_key: kp.private_key };
          } else if (requestedGroup === 0x0018) {
            let kp = p384_generate_keypair();
            newKeyGroup = { group: requestedGroup, public_key: kp.public_key, private_key: kp.private_key };
            context.local_key_groups[requestedGroup] = { public_key: kp.public_key, private_key: kp.private_key };
          }

          if (newKeyGroup) {
            // Build and send new ClientHello (CH2) with:
            // - key_share for requested group
            // - cookie (if HRR included one)
            // - ALPN (same as CH1)
            // - custom extensions (QUIC transport params etc.)
            // - same cipher_suites, session_id, random as CH1
            let extensions = [
              { type: 'SUPPORTED_VERSIONS', value: context.local_supported_versions },
              { type: 'SUPPORTED_GROUPS', value: context.local_supported_groups },
              { type: 'KEY_SHARE', value: [{ group: requestedGroup, key_exchange: newKeyGroup.public_key }] },
              { type: 'SIGNATURE_ALGORITHMS', value: [
                  // Must match CH1 exactly (RFC 8446 §4.1.2)
                  0x0804, 0x0805, 0x0806,
                  0x0403, 0x0503, 0x0603,
                  0x0807, 0x0808,
                  0x0401, 0x0501, 0x0601
              ] },
              { type: 'RENEGOTIATION_INFO', value: new Uint8Array(0) },
              { type: 23, data: new Uint8Array(0) }, // extended_master_secret
            ];

            // SNI (must be first)
            if (context.local_sni) extensions.unshift({ type: 'SERVER_NAME', value: context.local_sni });

            // ALPN (same as CH1 — required for QUIC/h3)
            if (context.local_supported_alpns && context.local_supported_alpns.length > 0) {
              extensions.push({ type: 'ALPN', value: context.local_supported_alpns });
            }

            // Cookie from HRR (RFC 8446 §4.2.2 — MUST echo if present)
            if (hrrCookie) {
              extensions.push({ type: 'COOKIE', value: hrrCookie });
            }

            // Custom extensions (e.g. QUIC transport params 0x39)
            for (let ci in context.local_extensions) {
              extensions.push(context.local_extensions[ci]);
            }

            let ch2 = build_tls_message({
              type: 'client_hello',
              version: 0x0303,
              random: context.local_random,
              session_id: context.local_session_id,
              cookie: context.dtls_cookie,
              cipher_suite: context.local_supported_cipher_suites,
              extensions: extensions,
            });

            pushTranscript(ch2);
            ev.emit('message', 0, context.message_sent_seq, 'hello', ch2);
            context.message_sent_seq++;
          }
        }

        // Don't process HRR as a regular ServerHello
        return;
      }

      set_context({
        remote_random: message.random || null,
        remote_sni: message.sni || null,
        remote_session_id: message.session_id || null,
        remote_supported_versions: (message.supported_versions && message.supported_versions.length > 0)
          ? message.supported_versions
          : (message.legacy_version ? [message.legacy_version] : []),
        remote_supported_alpns: message.alpn || [],
        remote_supported_cipher_suites: message.cipher_suites || [],
        remote_supported_signature_algorithms: message.signature_algorithms || [],
        remote_supported_groups: message.supported_groups || [],
        remote_extensions: message.extensions || [],
        add_remote_key_groups: message.key_groups || []
      });

      ev.emit('hello');

      if(context.isServer==true){
        if(typeof context.SNICallback=='function'){
          context.SNICallback(context.remote_sni, function (err, creds) {
            if (!err && creds) {
              set_context({
                  local_cert_chain: creds.certificateChain,
                  cert_private_key: creds.privateKey
              });
            }
          });
        }
      }



    }else if(message.type=='client_key_exchange' || message.type=='server_key_exchange'){

      pushTranscript(data);

      if ([0xC02F,0xC02B,0xC030,0xC02C,0xC013,0xC014,0xC009,0xC00A].includes(context.selected_cipher_suite)==true) {//ECDHE

        // ServerKeyExchange carries the group; ClientKeyExchange does not (server already chose it)
        let kex_group = message.group || context.selected_group;

        let kex_updates = {
          add_remote_key_groups: [
            {
              group: kex_group,
              public_key: message.public_key
            }
          ],
        };
        // TLS 1.2 client: selected_group isn't set from ServerHello (no supported_groups ext).
        // Set it from the SKE group so the reactive loop can generate a keypair and build CKE.
        if (context.selected_group === null && kex_group) {
          kex_updates.selected_group = kex_group;
        }
        set_context(kex_updates);

      }else if ([0x009E,0x009F,0x0033,0x0039,0x0067,0x006B].includes(context.selected_cipher_suite)==true) {//DHE

        let client_dh_y=message.body.slice(2);

      }else if ([0x002F,0x0035,0x003C,0x003D,0x0005,0x000A].includes(context.selected_cipher_suite)==true) {//RSA
        
        let enc_pms=message.body.slice(2);

      }else if ([0xC004,0xC005,0xC00B,0xC00C].includes(context.selected_cipher_suite)==true) {//ECDH

      }

    }else if(message.type=='server_hello_done'){

      pushTranscript(data);


      set_context({
        remote_hello_done: true,
      });

    }else if(message.type=='encrypted_extensions'){

      pushTranscript(data);

      set_context({
        remote_supported_groups: message.supported_groups || [],
      });

    }else if(message.type=='certificate'){

      pushTranscript(data);

      set_context({
        remote_cert_chain: message.entries,
      });

      // Validate peer certificate
      validatePeerCertificate();
      if (context.rejectUnauthorized && !context.peerAuthorized) {
        sendAlert(2, 42); // fatal, bad_certificate
        return;
      }

    }else if(message.type=='certificate_verify'){

      pushTranscript(data);

    }else if(message.type=='finished'){

      set_context({
        remote_finished: message.body
      });

    }else if(message.type=='new_session_ticket'){

      // Client receives NewSessionTicket from server (post-handshake)
      if(!context.isServer && context.resumption_master_secret){
        let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
        let psk = derive_psk(hashName, context.resumption_master_secret, message.ticket_nonce);

        ev.emit('session', {
          ticket: message.ticket,
          ticket_nonce: message.ticket_nonce,
          psk: psk,
          cipher: context.selected_cipher_suite,
          lifetime: message.ticket_lifetime,
          age_add: message.ticket_age_add,
          maxEarlyDataSize: 0,
        });
      }

    }else if(message.type=='key_update'){

      // Peer is updating their traffic secret (we update our read key)
      if(context.state==='connected' && (context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3)){
        let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
        let hashLen = getHashLen(hashName);
        let newRemoteSecret = hkdf_expand_label(hashName, context.remote_app_traffic_secret, 'traffic upd', new Uint8Array(0), hashLen);
        context.remote_app_traffic_secret = newRemoteSecret;
        ev.emit('keyUpdate', { direction: 'receive', secret: newRemoteSecret });

        // If peer requested us to update too
        if(message.request_update === 1){
          let newLocalSecret = hkdf_expand_label(hashName, context.local_app_traffic_secret, 'traffic upd', new Uint8Array(0), hashLen);
          context.local_app_traffic_secret = newLocalSecret;

          // Send our KeyUpdate (not requesting back)
          let ku_data = build_tls_message({ type: 'key_update', request_update: 0 });
          ev.emit('message', 2, context.message_sent_seq, 'key_update', ku_data);
          context.message_sent_seq++;

          ev.emit('keyUpdate', { direction: 'send', secret: newLocalSecret });
        }
      }

    }else if(message.type=='certificate_request'){

      // Server is requesting a client certificate (TLS 1.3)
      if(!context.isServer){
        pushTranscript(data);
        context.certificateRequested = true;
        context.certificateRequestContext = message.certificate_request_context || new Uint8Array(0);
        context.certificateRequestSigAlgs = message.signature_algorithms || [];
        ev.emit('certificateRequest', message);
      }

    }

  }


  function set_context(options){
    let has_changed=false;

    if (options && typeof options === 'object'){


      if('local_supported_versions' in options){
        if(arraysEqual(options.local_supported_versions,context.local_supported_versions)==false){
          context.local_supported_versions=options.local_supported_versions;
          has_changed=true;
        }
      }

      if('local_supported_cipher_suites' in options){
        if(arraysEqual(options.local_supported_cipher_suites,context.local_supported_cipher_suites)==false){
          context.local_supported_cipher_suites=options.local_supported_cipher_suites;
          has_changed=true;
        }
      }

      if('local_supported_alpns' in options){
        if(arraysEqual(options.local_supported_alpns,context.local_supported_alpns)==false){
          context.local_supported_alpns=options.local_supported_alpns;
          has_changed=true;
        }
      }

      if('local_supported_groups' in options){
        if(arraysEqual(options.local_supported_groups,context.local_supported_groups)==false){
          context.local_supported_groups=options.local_supported_groups;
          has_changed=true;
        }
      }

      if('local_supported_signature_algorithms' in options){
        if(arraysEqual(options.local_supported_signature_algorithms,context.local_supported_signature_algorithms)==false){
          context.local_supported_signature_algorithms=options.local_supported_signature_algorithms;
          has_changed=true;
        }
      }

      if('local_extensions' in options){
        if(arraysEqual(options.local_extensions,context.local_extensions)==false){
          context.local_extensions=options.local_extensions;
          has_changed=true;
        }
      }

      if('remote_supported_versions' in options){
        if(arraysEqual(options.remote_supported_versions,context.remote_supported_versions)==false){
          context.remote_supported_versions=options.remote_supported_versions;
          has_changed=true;
        }
      }

      if('remote_supported_cipher_suites' in options){
        if(arraysEqual(options.remote_supported_cipher_suites,context.remote_supported_cipher_suites)==false){
          context.remote_supported_cipher_suites=options.remote_supported_cipher_suites;
          has_changed=true;
        }
      }

      if('remote_supported_alpns' in options){
        if(arraysEqual(options.remote_supported_alpns,context.remote_supported_alpns)==false){
          context.remote_supported_alpns=options.remote_supported_alpns;
          has_changed=true;
        }
      }

      if('remote_supported_groups' in options){
        if(arraysEqual(options.remote_supported_groups,context.remote_supported_groups)==false){
          context.remote_supported_groups=options.remote_supported_groups;
          has_changed=true;
        }
      }

      if('remote_supported_signature_algorithms' in options){
        if(arraysEqual(options.remote_supported_signature_algorithms,context.remote_supported_signature_algorithms)==false){
          context.remote_supported_signature_algorithms=options.remote_supported_signature_algorithms;
          has_changed=true;
        }
      }

      if('remote_extensions' in options){
        if(arraysEqual(options.remote_extensions,context.remote_extensions)==false){
          context.remote_extensions=options.remote_extensions;
          has_changed=true;
        }
      }

      if('remote_sni' in options){
        if(options.remote_sni!==context.remote_sni){
          context.remote_sni=options.remote_sni;
          has_changed=true;
        }
      }

      if('remote_session_id' in options){
        if(!uint8Equal(options.remote_session_id, context.remote_session_id)){
          context.remote_session_id=options.remote_session_id;
          has_changed=true;
        }
      }

      if('remote_random' in options){
        if(!uint8Equal(options.remote_random, context.remote_random)){
          context.remote_random=options.remote_random;
          has_changed=true;
        }
      }




      if('add_local_key_groups' in options){
        for(let i in options['add_local_key_groups']){

          let group=options['add_local_key_groups'][i].group;
          if(group in context.local_key_groups==false){
            context.local_key_groups[group]={
              public_key: null,
              private_key: null
            };
            has_changed=true;
          }

          if(context.local_key_groups[group].public_key==null && options['add_local_key_groups'][i].public_key!==null){
            context.local_key_groups[group].public_key=options['add_local_key_groups'][i].public_key;
            has_changed=true;
          }

          if(context.local_key_groups[group].private_key==null && options['add_local_key_groups'][i].private_key!==null){
            context.local_key_groups[group].private_key=options['add_local_key_groups'][i].private_key;
            has_changed=true;

            if(context.local_supported_groups.indexOf(Number(group))<0){
              context.local_supported_groups.push(Number(group));
            }
          }

        }
      }


      if('add_remote_key_groups' in options){
        for(let i in options['add_remote_key_groups']){

          let group=options['add_remote_key_groups'][i].group;
          if(group in context.remote_key_groups==false){
            context.remote_key_groups[group]={
              public_key: null,
            };
            has_changed=true;
          }

          if(context.remote_key_groups[group].public_key==null && options['add_remote_key_groups'][i].public_key!==null){
            context.remote_key_groups[group].public_key=options['add_remote_key_groups'][i].public_key;
            has_changed=true;

            if(context.remote_supported_groups.indexOf(Number(group))<0){
              context.remote_supported_groups.push(Number(group));
            }
          }

        }
      }

      if('remote_cert_chain' in options){
        if(context.remote_cert_chain==null || arraysEqual(options.remote_cert_chain,context.remote_cert_chain)==false){
          context.remote_cert_chain=options.remote_cert_chain;
          has_changed=true;
        }
      }

      if('remote_hello_done' in options){
        if(options.remote_hello_done!==context.remote_hello_done){
          context.remote_hello_done=options.remote_hello_done;
          has_changed=true;
        }
      }

      if('key_exchange_sent' in options){
        if(options.key_exchange_sent!==context.key_exchange_sent){
          context.key_exchange_sent=options.key_exchange_sent;
          has_changed=true;
        }
      }


      //selected stuff...

      if('selected_version' in options){
        if(options.selected_version!==context.selected_version){
          context.selected_version=options.selected_version;
          has_changed=true;
        }
      }

      if('selected_cipher_suite' in options){
        if(options.selected_cipher_suite!==context.selected_cipher_suite){
          context.selected_cipher_suite=options.selected_cipher_suite;
          has_changed=true;
        }
      }

      if('selected_alpn' in options){
        if(options.selected_alpn!==context.selected_alpn){
          context.selected_alpn=options.selected_alpn;
          has_changed=true;
        }
      }

      if('selected_group' in options){
        if(options.selected_group!==context.selected_group){
          context.selected_group=options.selected_group;
          has_changed=true;
        }
      }

      if('selected_signature_algorithm' in options){
        if(options.selected_signature_algorithm!==context.selected_signature_algorithm){
          context.selected_signature_algorithm=options.selected_signature_algorithm;
          has_changed=true;
        }
      }

      if('selected_extensions' in options){
        if(arraysEqual(options.selected_extensions,context.selected_extensions)==false){
          context.selected_extensions=options.selected_extensions;
          has_changed=true;
        }
      }

      if('selected_sni' in options){
        if(options.selected_sni!==context.selected_sni){
          context.selected_sni=options.selected_sni;
          has_changed=true;
        }
      }

      if('selected_session_id' in options){
        if(!uint8Equal(options.selected_session_id, context.selected_session_id)){
          context.selected_session_id=options.selected_session_id;
          has_changed=true;
        }
      }

      if('ecdhe_shared_secret' in options){
        if(context.ecdhe_shared_secret==null && options.ecdhe_shared_secret!==null){
          context.ecdhe_shared_secret=options.ecdhe_shared_secret;
          has_changed=true;
        }
      }

      if('base_secret' in options){
        // base_secret transitions: null → handshake_secret → null (after app secrets derived)
        if(options.base_secret !== context.base_secret){
          context.base_secret=options.base_secret;
          has_changed=true;
        }
      }

      if('tls13_master_secret' in options){
        if(context.tls13_master_secret==null && options.tls13_master_secret!==null){
          context.tls13_master_secret=options.tls13_master_secret;
          has_changed=true;
        }
      }


      if('remote_handshake_traffic_secret' in options){
        if(context.remote_handshake_traffic_secret==null && options.remote_handshake_traffic_secret!==null){
          context.remote_handshake_traffic_secret=options.remote_handshake_traffic_secret;
          has_changed=true;
          if(context.local_handshake_traffic_secret!==null){
            ev.emit('handshakeSecrets', context.local_handshake_traffic_secret, context.remote_handshake_traffic_secret);
          }
        }
      }

      if('local_handshake_traffic_secret' in options){
        if(context.local_handshake_traffic_secret==null && options.local_handshake_traffic_secret!==null){
          context.local_handshake_traffic_secret=options.local_handshake_traffic_secret;
          has_changed=true;
          if(context.remote_handshake_traffic_secret!==null){
            ev.emit('handshakeSecrets', context.local_handshake_traffic_secret, context.remote_handshake_traffic_secret);
          }
        }
      }

      if('remote_app_traffic_secret' in options){
        if(context.remote_app_traffic_secret==null && options.remote_app_traffic_secret!==null){
          context.remote_app_traffic_secret=options.remote_app_traffic_secret;
          has_changed=true;
          if(context.local_app_traffic_secret!==null){
            ev.emit('appSecrets', context.local_app_traffic_secret, context.remote_app_traffic_secret);
          }
        }
      }

      if('local_app_traffic_secret' in options){
        if(context.local_app_traffic_secret==null && options.local_app_traffic_secret!==null){
          context.local_app_traffic_secret=options.local_app_traffic_secret;
          has_changed=true;
          if(context.remote_app_traffic_secret!==null){
            ev.emit('appSecrets', context.local_app_traffic_secret, context.remote_app_traffic_secret);
          }
        }
      }



      if('local_cert_chain' in options){
        if(context.local_cert_chain==null && options.local_cert_chain!==null){
          context.local_cert_chain=options.local_cert_chain;
          has_changed=true;
        }
      }

      if('cert_private_key' in options){
        if(context.cert_private_key==null && options.cert_private_key!==null){
          context.cert_private_key=options.cert_private_key;
          has_changed=true;
        }
      }

      if('expected_remote_finished' in options){
        if(context.expected_remote_finished==null && options.expected_remote_finished!==null){
          context.expected_remote_finished=options.expected_remote_finished;
          has_changed=true;
        }
      }

      if('remote_finished' in options){
        if(context.remote_finished==null && options.remote_finished!==null){
          context.remote_finished=options.remote_finished;
          has_changed=true;
        }
      }

      if('remote_finished_ok' in options){
        if(context.remote_finished_ok!==options.remote_finished_ok){
          context.remote_finished_ok=options.remote_finished_ok;
          has_changed=true;
        }
      }

      if('dtls_cookie' in options){
        context.dtls_cookie=options.dtls_cookie;
        has_changed=true;
      }


    }


    if(has_changed==true){

      let params_to_set = {};

      

      
      
          
      //select version...
      if (context.selected_version == null && context.local_supported_versions.length > 0 && context.remote_supported_versions.length > 0) {
        for (let i = 0; i < context.local_supported_versions.length; i++) {
          let v = context.local_supported_versions[i] | 0;
          for (let j = 0; j < context.remote_supported_versions.length; j++) {
            if ((context.remote_supported_versions[j] | 0) == v) {
              params_to_set['selected_version'] = v;
              break;
            }
          }
          if ('selected_version' in params_to_set==true && params_to_set.selected_version !== null) break;
        }

        if('selected_version' in params_to_set==false || params_to_set.selected_version==null){
        }

        // TLS 1.2: clear key_share groups from ClientHello.
        // key_share is a TLS 1.3 extension; in TLS 1.2, keys come from CKE/SKE.
        // Without this, the server would compute the shared secret too early
        // (using CH key_share instead of waiting for CKE).
        if (context.isServer && params_to_set.selected_version !== null &&
            params_to_set.selected_version !== wire.TLS_VERSION.TLS1_3 &&
            params_to_set.selected_version !== wire.DTLS_VERSION.DTLS1_3) {
          context.remote_key_groups = {};
        }
      }

      //select selected_cipher...
      if (context.selected_cipher_suite == null && context.local_supported_cipher_suites.length > 0 && context.remote_supported_cipher_suites.length > 0) {
        
        for (let i2 = 0; i2 < context.local_supported_cipher_suites.length; i2++) {
          let cs = context.local_supported_cipher_suites[i2] | 0;
          for (let j2 = 0; j2 < context.remote_supported_cipher_suites.length; j2++) {
            
            if ((context.remote_supported_cipher_suites[j2] | 0) == cs) {
              params_to_set['selected_cipher_suite'] = cs;
              break;
            }
          }
          if ('selected_cipher_suite' in params_to_set==true && params_to_set.selected_cipher_suite !== null) break;
        }

        if('selected_cipher_suite' in params_to_set==false || params_to_set.selected_cipher_suite==null){
        }
      }

      //select alpn...
      if (context.selected_alpn == null && context.local_supported_alpns && context.remote_supported_alpns) {
        // iterate local list by preference order
        for (let a = 0; a < context.local_supported_alpns.length; a++) {
          let cand = context.local_supported_alpns[a];
          for (let b = 0; b < context.remote_supported_alpns.length; b++) {
            if (context.remote_supported_alpns[b] === cand) {
              params_to_set['selected_alpn'] = cand;
              break;
            }
          }
          if ('selected_alpn' in params_to_set==true && params_to_set.selected_alpn !== null) break;
        }
      }

      //select sni...
      if (context.selected_sni == null && context.remote_sni!==null) {
        params_to_set['selected_sni'] = context.remote_sni || null;
      }

      //select selected_session_id... (tls 1.2 only)
      if (context.selected_session_id == null) {
        params_to_set['selected_session_id'] = context.remote_session_id || new Uint8Array(0);
      }


      //select group...
      if (context.selected_group == null){
        if(context.local_supported_groups.length > 0 && context.remote_supported_groups.length > 0) {
          for (let i = 0; i < context.local_supported_groups.length; i++) {
            if(context.remote_supported_groups.indexOf(context.local_supported_groups[i])>=0){
              params_to_set['selected_group'] = context.local_supported_groups[i];
              break;
            }
          }
        }
      }
      


      //create the key by the group if dont have...
      if(context.selected_group !== null && context.selected_group in context.local_key_groups==false){

        if (context.selected_group === 0x001d) {

          const private_key = new Uint8Array(crypto.randomBytes(32));
          let public_key  = x25519_get_public_key(private_key);

          params_to_set['add_local_key_groups']=[
            {
              group: context.selected_group,
              private_key: private_key,
              public_key: public_key
            }
          ];

        } else if (context.selected_group === 0x0017) {

          let kp = p256_generate_keypair();
          let private_key = kp.private_key;
          let public_key  = kp.public_key;

          params_to_set['add_local_key_groups']=[
            {
              group: context.selected_group,
              private_key: private_key,
              public_key: public_key
            }
          ];

        } else if (context.selected_group === 0x0018) {

          let kp = p384_generate_keypair();
          let private_key = kp.private_key;
          let public_key  = kp.public_key;

          params_to_set['add_local_key_groups']=[
            {
              group: context.selected_group,
              private_key: private_key,
              public_key: public_key
            }
          ];

        }

        
      }

      //get shared_secret...
      if(context.selected_group !== null && context.ecdhe_shared_secret == null && context.selected_group in context.local_key_groups==true && context.selected_group in context.remote_key_groups==true){

        //check we have remote public key and local private key...
        if(context.remote_key_groups[context.selected_group].public_key!==null && context.local_key_groups[context.selected_group].private_key!==null){

          let remote_public_key=context.remote_key_groups[context.selected_group].public_key;
          let local_private_key=context.local_key_groups[context.selected_group].private_key;

          if (context.selected_group === 0x001d) { // X25519

            let ecdhe_shared_secret = x25519_get_shared_secret(local_private_key, remote_public_key);

            params_to_set['ecdhe_shared_secret']=ecdhe_shared_secret;

          } else if (context.selected_group === 0x0017) { // secp256r1 (P-256)

            let ecdhe_shared_secret = p256_get_shared_secret(local_private_key, remote_public_key);

            params_to_set['ecdhe_shared_secret']=ecdhe_shared_secret;

          } else if (context.selected_group === 0x0018) { // secp384r1 (P-384)

            let ecdhe_shared_secret = p384_get_shared_secret(local_private_key, remote_public_key);

            params_to_set['ecdhe_shared_secret']=ecdhe_shared_secret;

          }

        }
        
      }




      if(context.isServer==true){

        // HelloRetryRequest: if we selected a group but client didn't send a key_share for it
        if(context.hello_sent==false && !context.helloRetried && (context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) &&
           context.selected_group !== null && context.selected_cipher_suite !== null &&
           !(context.selected_group in context.remote_key_groups)){

          context.helloRetried = true;

          // Replace transcript with message_hash (RFC 8446 §4.4.1)
          let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
          let ch1_hash = getHashFn(hashName)(concatUint8Arrays(context.transcript));
          let message_hash = wire.build_message(wire.TLS_MESSAGE_TYPE.MESSAGE_HASH, ch1_hash);
          context.transcript = [message_hash];

          // Build and send HRR (it's a ServerHello with magic random)
          let hrr_body = wire.build_hello_retry_request({
            cipher_suite: context.selected_cipher_suite,
            selected_version: context.selected_version,
            selected_group: context.selected_group,
            session_id: context.remote_session_id,
          });
          let hrr_data = wire.build_message(wire.TLS_MESSAGE_TYPE.SERVER_HELLO, hrr_body);
          pushTranscript(hrr_data);

          ev.emit('message', 0, context.message_sent_seq, 'hello_retry_request', hrr_data);
          context.message_sent_seq++;

          // Reset for second ClientHello
          context.remote_random = null;
          context.remote_extensions = [];
          context.remote_supported_versions = [];
          context.remote_supported_cipher_suites = [];
          context.remote_supported_signature_algorithms = [];

          // Don't proceed to ServerHello — wait for new ClientHello
        }

        let can_send_hello=false;

        if(context.hello_sent==false){
          
          if(context.selected_version!==null && context.selected_cipher_suite!==null && context.selected_session_id!==null){
            if((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3)){
              if(context.selected_group in context.local_key_groups==true && context.local_key_groups[context.selected_group].public_key!==null){
                // After HRR, don't send ServerHello until CH2 provides the requested key_share
                if (!context.helloRetried || (context.selected_group in context.remote_key_groups)) {
                  can_send_hello=true;
                }
              }
            }else if((context.selected_version === wire.TLS_VERSION.TLS1_2 || context.selected_version === wire.DTLS_VERSION.DTLS1_2)){
              can_send_hello=true;
            }
          }
        }
        
        if(can_send_hello==true){

          if(context.local_random==null){
            context.local_random=new Uint8Array(crypto.randomBytes(32));
          }

          let build_message_params=null;

          if((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3)){

            let shExtensions = [
              { 
                type: 'SUPPORTED_VERSIONS', 
                value: context.selected_version
              },
              {
                type: 'KEY_SHARE', 
                value: { 
                  group: context.selected_group, 
                  key_exchange: context.local_key_groups[context.selected_group].public_key
                }
              }
            ];

            // PSK accepted → include PRE_SHARED_KEY with selected identity index
            if (context.psk_accepted) {
              shExtensions.push({ type: 'PRE_SHARED_KEY', value: { selected: 0 } });
            }

            build_message_params={
              type: 'server_hello',
              version: context.selected_version,
              random: context.local_random,
              session_id: context.remote_session_id,
              cipher_suite: context.selected_cipher_suite,
              extensions: shExtensions
            };
            

          }else if((context.selected_version === wire.TLS_VERSION.TLS1_2 || context.selected_version === wire.DTLS_VERSION.DTLS1_2)){

            
            // TLS 1.2 ServerHello: no SUPPORTED_VERSIONS or KEY_SHARE.
            // Include renegotiation_info (empty for initial handshake) and extended_master_secret.
            // ALPN (type=16) — optional, echoes selected protocol.

            let ext_list = [
              { type: 'RENEGOTIATION_INFO', value: new Uint8Array(0) }
            ];

            // Only echo extended_master_secret if client sent it
            if (context.use_extended_master_secret) {
              ext_list.push({ type: 23, data: new Uint8Array(0) });
            }

            if (context.alpn_selected) {
              // RFC 7301: ServerHello echoes a single selected protocol
              ext_list.push({ type: 'ALPN', value: [ String(context.alpn_selected) ] });
            }

            build_message_params = {
              type: 'server_hello',
              version: context.selected_version,
              random: context.local_random,
              session_id: context.remote_session_id || new Uint8Array(0), // echo client session_id
              cipher_suite: context.selected_cipher_suite,  // e.g. 0xC02F
              // compression_method always 0
              extensions: ext_list
            };

            



          }
          
          if(build_message_params!==null){


            let message_data = build_tls_message(build_message_params);

            pushTranscript(message_data);

            context.hello_sent=true;

            ev.emit('message',0,context.message_sent_seq,'hello',message_data);

            context.message_sent_seq++;
          }
        }
          
      }else{

      }
      


      

      //get base_secret
      if (context.base_secret==null && context.selected_cipher_suite !== null){
        if((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) && (context.ecdhe_shared_secret !== null)){

          let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
          let result;
          if (context.psk_accepted && context.psk_offered && context.psk_offered.psk) {
            // PSK + ECDHE key schedule
            result = derive_handshake_traffic_secrets_psk(hashName, context.psk_offered.psk, context.ecdhe_shared_secret, concatUint8Arrays(context.transcript));
          } else {
            // Standard key schedule (no PSK)
            result = derive_handshake_traffic_secrets(hashName, context.ecdhe_shared_secret, concatUint8Arrays(context.transcript));
          }

          params_to_set['base_secret']=result.handshake_secret;

          if(context.isServer==true){
            params_to_set['remote_handshake_traffic_secret']=result.client_handshake_traffic_secret;
            params_to_set['local_handshake_traffic_secret']=result.server_handshake_traffic_secret;
          }else{
            params_to_set['local_handshake_traffic_secret']=result.client_handshake_traffic_secret;
            params_to_set['remote_handshake_traffic_secret']=result.server_handshake_traffic_secret;
          }

        }else if((context.selected_version === wire.TLS_VERSION.TLS1_2 || context.selected_version === wire.DTLS_VERSION.DTLS1_2) && context.local_random!==null && context.remote_random!==null){
          if(context.ecdhe_shared_secret !== null){


            let server_random, client_random;
            if(context.isServer==true){
              server_random=context.local_random;
              client_random=context.remote_random;
            }else{
              server_random=context.remote_random;
              client_random=context.local_random;
            }

            if(context.use_extended_master_secret){
              // RFC 7627: extended master secret uses transcript hash through ClientKeyExchange.
              // Server: CKE just arrived, transcript is complete.
              // Client: must wait until CKE is sent and in transcript.
              if(context.isServer || context.key_exchange_sent){
                let hashFn  = getHashFn(TLS_CIPHER_SUITES[context.selected_cipher_suite].hash);

                // Use snapshot up to CKE if available (excludes CertificateVerify)
                let emsTranscript = context._emsTranscriptLen
                  ? context.transcript.slice(0, context._emsTranscriptLen)
                  : context.transcript;
                let transcript_hash = hashFn(concatUint8Arrays(emsTranscript));

                let master_secret = tls12_prf(context.ecdhe_shared_secret, "extended master secret", transcript_hash, 48, TLS_CIPHER_SUITES[context.selected_cipher_suite].hash);

                params_to_set['base_secret']=master_secret;
              }
            }else{
              let master_secret = tls12_prf(context.ecdhe_shared_secret, "master secret", concatUint8Arrays([client_random, server_random]), 48, TLS_CIPHER_SUITES[context.selected_cipher_suite].hash);

              params_to_set['base_secret']=master_secret;
            }

            
            
            


          }
        }
      }



      //send encrypted_extensions...
      if (context.isServer==true && (context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3)){
        if(context.encrypted_exts_sent==false && context.hello_sent==true && context.local_handshake_traffic_secret!==null){

          let extensions=[];
          if(context.selected_alpn!==null){
            extensions.push({ type: 'ALPN', value: [context.selected_alpn] });
          }


          for(let i in context.local_extensions){
            extensions.push(context.local_extensions[i]);
          }

          let message_data = build_tls_message({
            type: 'encrypted_extensions',
            extensions: extensions
          });

          pushTranscript(message_data);

          context.encrypted_exts_sent=true;

          ev.emit('message',1,context.message_sent_seq,'encrypted_extensions',message_data);

          context.message_sent_seq++;

        }
      }


      //send certificate... (skip for PSK resumption — no cert needed)
      // But first: send CertificateRequest if requestCert is set (TLS 1.3 only, between EE and Cert)
      if(context.isServer==true && context.requestCert==true && !context.certificateRequestSent && context.encrypted_exts_sent==true && context.local_handshake_traffic_secret!==null && (context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) && !context.psk_accepted){
        let cr_data = build_tls_message({
          type: 'certificate_request',
          certificate_request_context: new Uint8Array(0),
          signature_algorithms: context.local_supported_signature_algorithms,
        });
        pushTranscript(cr_data);
        context.certificateRequestSent = true;
        ev.emit('message', 1, context.message_sent_seq, 'certificate_request', cr_data);
        context.message_sent_seq++;
      }

      if(context.isServer==true && context.cert_sent==false && context.local_cert_chain!==null && !context.psk_accepted){
        if(((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) && context.encrypted_exts_sent==true && context.local_handshake_traffic_secret!==null) || ((context.selected_version === wire.TLS_VERSION.TLS1_2 || context.selected_version === wire.DTLS_VERSION.DTLS1_2) && context.hello_sent==true)){

          let message_data = build_tls_message({
            type: 'certificate',
            version: context.selected_version,
            entries: context.local_cert_chain
          });
          pushTranscript(message_data);

          context.cert_sent=true;

          if ((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3)){
            ev.emit('message',1,context.message_sent_seq,'certificate',message_data);
          }else{
            ev.emit('message',0,context.message_sent_seq,'certificate',message_data);
          }

          context.message_sent_seq++;
          

        }
      }



        


      //send certificate verify...
      if (context.isServer==true && (context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3)){
        if(context.cert_sent==true && context.cert_verify_sent==false && context.local_cert_chain!==null && context.local_handshake_traffic_secret!==null && context.selected_cipher_suite!==null){

          let tbs_data = build_cert_verify_tbs(TLS_CIPHER_SUITES[context.selected_cipher_suite].hash,true,concatUint8Arrays(context.transcript));

          let cert_private_key_obj = crypto.createPrivateKey({
            key: Buffer.from(context.cert_private_key),
            format: 'der',
            type: 'pkcs8',
          });

          const SIG = {
            ECDSA_P256_SHA256: 0x0403,
            ECDSA_P384_SHA384: 0x0503,
            ECDSA_P521_SHA512: 0x0603,
            RSA_PSS_SHA256:    0x0804,
            RSA_PSS_SHA384:    0x0805,
            RSA_PSS_SHA512:    0x0806,
            ED25519:           0x0807,
            ED448:             0x0808
          };

          let candidates=[];
          if (cert_private_key_obj.asymmetricKeyType === 'ed25519') candidates.push(SIG.ED25519);
          if (cert_private_key_obj.asymmetricKeyType === 'ed448')   candidates.push(SIG.ED448);
          if (cert_private_key_obj.asymmetricKeyType === 'rsa')     candidates.push(SIG.RSA_PSS_SHA256, SIG.RSA_PSS_SHA384, SIG.RSA_PSS_SHA512); // TLS 1.3: PSS only

          if (cert_private_key_obj.asymmetricKeyType === 'ec') {
            let c = (cert_private_key_obj.asymmetricKeyDetails && cert_private_key_obj.asymmetricKeyDetails && cert_private_key_obj.asymmetricKeyDetails.namedCurve) || '';
            if (c === 'prime256v1') candidates.push(SIG.ECDSA_P256_SHA256);
            if (c === 'secp384r1')  candidates.push(SIG.ECDSA_P384_SHA384);
            if (c === 'secp521r1')  candidates.push(SIG.ECDSA_P521_SHA512);
          }


          let preference_order = [
            SIG.ED25519, 
            SIG.ED448,
            SIG.ECDSA_P256_SHA256, 
            SIG.ECDSA_P384_SHA384, 
            SIG.ECDSA_P521_SHA512,
            SIG.RSA_PSS_SHA256, 
            SIG.RSA_PSS_SHA384, 
            SIG.RSA_PSS_SHA512
          ];

          let selected_scheme = null;
          for (let s of preference_order) {
            if (context.remote_supported_signature_algorithms.includes(s)==true && candidates.includes(s)==true) {
              selected_scheme = s;
              break;
            }
          }

          let sig_data=null;

          switch (selected_scheme) {
            case SIG.ED25519:
              sig_data = new Uint8Array(crypto.sign(null, tbs_data, cert_private_key_obj));
              break;

            case SIG.ECDSA_P256_SHA256:
              sig_data = new Uint8Array(crypto.sign('sha256', tbs_data, cert_private_key_obj));
              break;

            case SIG.ECDSA_P384_SHA384:
              sig_data = new Uint8Array(crypto.sign('sha384', tbs_data, cert_private_key_obj));
              break;

            case SIG.ECDSA_P521_SHA512:
              sig_data = new Uint8Array(crypto.sign('sha512', tbs_data, cert_private_key_obj));
              break;

            case SIG.RSA_PSS_SHA256:
              sig_data = new Uint8Array(crypto.sign('sha256', tbs_data, {
                key: cert_private_key_obj,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: 32
              }));
              break;

            case SIG.RSA_PSS_SHA384:
              sig_data = new Uint8Array(crypto.sign('sha384', tbs_data, {
                key: cert_private_key_obj,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: 48
              }));
              break;

            case SIG.RSA_PSS_SHA512:
              sig_data = new Uint8Array(crypto.sign('sha512', tbs_data, {
                key: cert_private_key_obj,
                padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: 64
              }));
              break;
          }



          if(sig_data){

            let message_data = build_tls_message({
              type: 'certificate_verify',
              scheme: selected_scheme,
              signature: sig_data
            });

            

            pushTranscript(message_data);

            context.cert_verify_sent=true;

            ev.emit('message',1,context.message_sent_seq,'certificate_verify',message_data);

            context.message_sent_seq++;
          }else{

            //..
          }

          
          

        }
      }





      // client/server key exchange - 1.2 only...
      if (context.key_exchange_sent == false && (context.selected_version === wire.TLS_VERSION.TLS1_2 || context.selected_version === wire.DTLS_VERSION.DTLS1_2)) {
        if(context.selected_group!==null && context.selected_group in context.local_key_groups==true && context.local_key_groups[context.selected_group].public_key!==null){

          if (context.isServer==false && context.remote_hello_done==true) {

            // TLS 1.2: send Certificate before CKE if server requested client auth
            if (context.certificateRequested && !context.clientCertSent) {
              context.clientCertSent = true;

              // Build TLS 1.2 Certificate message
              let certEntries = [];
              if (context.local_cert_chain && context.local_cert_chain.length > 0) {
                certEntries = context.local_cert_chain;
              }
              // TLS 1.2 Certificate: certificate_list<0..2^24-1>
              //   Each entry: cert_length<3> + cert_der
              let totalLen = 0;
              for (let ci = 0; ci < certEntries.length; ci++) {
                totalLen += 3 + certEntries[ci].cert.length;
              }
              let certBody = new Uint8Array(3 + totalLen);
              certBody[0] = (totalLen >> 16) & 0xff;
              certBody[1] = (totalLen >> 8) & 0xff;
              certBody[2] = totalLen & 0xff;
              let off = 3;
              for (let ci = 0; ci < certEntries.length; ci++) {
                let der = certEntries[ci].cert;
                certBody[off] = (der.length >> 16) & 0xff;
                certBody[off+1] = (der.length >> 8) & 0xff;
                certBody[off+2] = der.length & 0xff;
                certBody.set(der, off + 3);
                off += 3 + der.length;
              }
              let cert_data = wire.build_message(wire.TLS_MESSAGE_TYPE.CERTIFICATE, certBody);
              pushTranscript(cert_data);
              ev.emit('message', 0, context.message_sent_seq, 'certificate', cert_data);
              context.message_sent_seq++;
            }

            let public_key = context.local_key_groups[context.selected_group].public_key;

            let message_data = build_tls_message({
              type: 'client_key_exchange',
              public_key: public_key,
            });
            pushTranscript(message_data);

            // Set via params_to_set to trigger re-evaluation (EMS needs this)
            params_to_set['key_exchange_sent'] = true;

            // Save transcript length for EMS: session_hash includes up to CKE only (RFC 7627)
            context._emsTranscriptLen = context.transcript.length;
            
            ev.emit('message', 0, context.message_sent_seq, 'client_key_exchange', message_data);

            context.message_sent_seq++;

            // TLS 1.2 CertificateVerify: if we sent a non-empty Certificate, prove we own the private key
            if (context.certificateRequested && context.cert_private_key && context.local_cert_chain && context.local_cert_chain.length > 0) {
              // sign_with_scheme hashes internally, so pass RAW transcript (not pre-hashed)
              let transcript_data = concatUint8Arrays(context.transcript);

              // Pick scheme matching our cert + server's requested algorithms
              let cert_key_obj = crypto.createPrivateKey({ key: Buffer.from(context.cert_private_key), format: 'der', type: 'pkcs8' });
              let reqAlgs = context.certificateRequestSigAlgs.length > 0
                ? context.certificateRequestSigAlgs
                : context.local_supported_signature_algorithms;
              let scheme = pick_scheme(wire.TLS_VERSION.TLS1_2, cert_key_obj, reqAlgs);
              let signature = sign_with_scheme(wire.TLS_VERSION.TLS1_2, scheme, transcript_data, cert_key_obj);

              // Build CertificateVerify: scheme(2) + sig_length(2) + sig
              let cvBody = new Uint8Array(2 + 2 + signature.length);
              cvBody[0] = (scheme >> 8) & 0xff;
              cvBody[1] = scheme & 0xff;
              cvBody[2] = (signature.length >> 8) & 0xff;
              cvBody[3] = signature.length & 0xff;
              cvBody.set(signature, 4);

              let cv_data = wire.build_message(wire.TLS_MESSAGE_TYPE.CERTIFICATE_VERIFY, cvBody);
              pushTranscript(cv_data);
              ev.emit('message', 0, context.message_sent_seq, 'certificate_verify', cv_data);
              context.message_sent_seq++;
            }


          }else if (context.isServer==true && context.cert_sent == true) {

            // Build ServerECDHParams + sign (curve_type | namedcurve | ec_point)
            //    curve_type=3 (named_curve)

            let public_key = context.local_key_groups[context.selected_group].public_key;
            
            let params_head = wire.build_server_ecdh_params(context.selected_group,public_key);
            
            let tbs_data = concatUint8Arrays([ context.remote_random, context.local_random, params_head ]);


            let cert_private_key_obj = crypto.createPrivateKey({
              key: Buffer.from(context.cert_private_key),
              format: 'der',
              type: 'pkcs8'
            });

            let scheme12 = pick_scheme(wire.TLS_VERSION.TLS1_2, cert_private_key_obj, context.remote_supported_signature_algorithms);

            let sig_data = sign_with_scheme(wire.TLS_VERSION.TLS1_2, scheme12, tbs_data, cert_private_key_obj);

            
            let message_data = build_tls_message({
              type: 'server_key_exchange',
              group: context.selected_group,
              public_key: public_key,
              sig_alg: scheme12,
              signature: sig_data
            });
            pushTranscript(message_data);

            context.key_exchange_sent = true;
            
            ev.emit('message', 0, context.message_sent_seq, 'server_key_exchange', message_data);

            context.message_sent_seq++;

          }
        }
      }

      //server hello done - 1.2 only...
      if(context.isServer==true && (context.selected_version === wire.TLS_VERSION.TLS1_2 || context.selected_version === wire.DTLS_VERSION.DTLS1_2)){
        if(context.hello_done_sent==false && context.key_exchange_sent==true){

          let message_data = build_tls_message({
            type: 'server_hello_done'});
          pushTranscript(message_data);

          context.hello_done_sent=true;

          ev.emit('message',0,context.message_sent_seq,'server_hello_done',message_data);

          context.message_sent_seq++;

        }
      }
      
      

      //send finished...
      // Client: send Certificate + CertificateVerify before Finished (if server requested)
      if(context.isServer==false && context.certificateRequested && !context.clientCertSent &&
         context.remote_finished_ok==true && context.local_handshake_traffic_secret!==null){
        context.clientCertSent = true;

        if(context.clientCert && context.clientKey){
          // Send client certificate
          let certCtx = createSecureContext({ key: context.clientKey, cert: context.clientCert });
          let cert_data = build_tls_message({
            type: 'certificate',
            version: wire.TLS_VERSION.TLS1_3,
            entries: certCtx.certificateChain,
            certificate_request_context: context.certificateRequestContext || new Uint8Array(0),
          });
          pushTranscript(cert_data);
          ev.emit('message', 1, context.message_sent_seq, 'certificate', cert_data);
          context.message_sent_seq++;

          // Send CertificateVerify
          let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
          let transcript_hash = getHashFn(hashName)(concatUint8Arrays(context.transcript));
          let scheme = pick_scheme(context.certificateRequestSigAlgs.length > 0 ? context.certificateRequestSigAlgs : context.local_supported_signature_algorithms, certCtx.privateKey);
          let signature = sign_with_scheme(scheme, certCtx.privateKey, transcript_hash, false);
          let cv_data = build_tls_message({
            type: 'certificate_verify',
            scheme: scheme,
            signature: signature,
          });
          pushTranscript(cv_data);
          ev.emit('message', 1, context.message_sent_seq, 'certificate_verify', cv_data);
          context.message_sent_seq++;
        } else {
          // No client cert — send empty certificate
          let cert_data = build_tls_message({
            type: 'certificate',
            version: wire.TLS_VERSION.TLS1_3,
            entries: [],
            certificate_request_context: context.certificateRequestContext || new Uint8Array(0),
          });
          pushTranscript(cert_data);
          ev.emit('message', 1, context.message_sent_seq, 'certificate', cert_data);
          context.message_sent_seq++;
        }
      }

      // Note: TLS 1.3 uses local_handshake_traffic_secret for Finished (not base_secret).
      // base_secret may be null after app secrets are derived, so we also check handshake secret.
      if (context.finished_sent==false && context.selected_cipher_suite!==null && (context.base_secret!==null || context.local_handshake_traffic_secret!==null)){

        if((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) && context.local_handshake_traffic_secret!==null){

          if((context.isServer==false && context.remote_finished_ok==true && context.local_app_traffic_secret!==null && context.remote_app_traffic_secret!==null) || (context.isServer==true && context.cert_verify_sent==true && context.local_cert_chain!==null) || (context.isServer==true && context.psk_accepted==true && context.encrypted_exts_sent==true)){

            let finished_data=get_handshake_finished(TLS_CIPHER_SUITES[context.selected_cipher_suite].hash,context.local_handshake_traffic_secret,concatUint8Arrays(context.transcript));
            context.local_finished_data = finished_data;

            let message_data = build_tls_message({
              type: 'finished',
              data: finished_data
            });

            pushTranscript(message_data);

            context.finished_sent=true;

            ev.emit('message',1,context.message_sent_seq,'finished',message_data);

            context.message_sent_seq++;

          }

        }else if((context.selected_version === wire.TLS_VERSION.TLS1_2 || context.selected_version === wire.DTLS_VERSION.DTLS1_2)){

          if((context.isServer==true && context.remote_finished_ok==true) || (context.isServer==false && context.key_exchange_sent==true)){

            let hashFn  = getHashFn(TLS_CIPHER_SUITES[context.selected_cipher_suite].hash);
            let transcript_hash = hashFn(concatUint8Arrays(context.transcript));

            let finished_data;
            if(context.isServer==true){
              finished_data=tls12_prf(context.base_secret, "server finished", transcript_hash, 12, TLS_CIPHER_SUITES[context.selected_cipher_suite].hash);
            }else{
              finished_data=tls12_prf(context.base_secret, "client finished", transcript_hash, 12, TLS_CIPHER_SUITES[context.selected_cipher_suite].hash);
            }
            context.local_finished_data = finished_data;

            let message_data = build_tls_message({
              type: 'finished',
              data: finished_data
            });

            pushTranscript(message_data);

            context.finished_sent=true;

            ev.emit('message',1,context.message_sent_seq,'finished',message_data);

            context.message_sent_seq++;

          }

        }
        
      }

      //get app traffic secret...
      if ((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3)){
        if(context.base_secret!==null && context.local_app_traffic_secret==null && context.remote_app_traffic_secret==null){

          if((context.isServer==true && context.finished_sent==true && context.remote_finished_ok==false) || (context.isServer==false && context.finished_sent==false && context.remote_finished_ok==true)){

            let result2 = derive_app_traffic_secrets(TLS_CIPHER_SUITES[context.selected_cipher_suite].hash, context.base_secret, concatUint8Arrays(context.transcript));

            // Save master_secret for resumption before clearing
            params_to_set['tls13_master_secret'] = result2.master_secret;
            params_to_set['base_secret']=null;

            if (context.isServer === true) {
              params_to_set['local_app_traffic_secret']  = result2.server_app_traffic_secret;
              params_to_set['remote_app_traffic_secret'] = result2.client_app_traffic_secret;
            } else {
              params_to_set['local_app_traffic_secret']  = result2.client_app_traffic_secret;
              params_to_set['remote_app_traffic_secret'] = result2.server_app_traffic_secret;
            }
          }

        }
      }

      //expected_remote_finished...
      if (context.expected_remote_finished==null && context.selected_cipher_suite!==null){

        if((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) && context.remote_handshake_traffic_secret!==null){

          if((context.isServer==true && context.finished_sent==true) || (context.isServer==false && context.remote_finished !== null)){

            params_to_set['expected_remote_finished']=get_handshake_finished(TLS_CIPHER_SUITES[context.selected_cipher_suite].hash,context.remote_handshake_traffic_secret,concatUint8Arrays(context.transcript));

          }

        }else if((context.selected_version === wire.TLS_VERSION.TLS1_2 || context.selected_version === wire.DTLS_VERSION.DTLS1_2) && context.base_secret!==null){

          if(context.remote_finished!==null){


            let hashFn  = getHashFn(TLS_CIPHER_SUITES[context.selected_cipher_suite].hash);
            let transcript_hash = hashFn(concatUint8Arrays(context.transcript));

            if(context.isServer==true){
              params_to_set['expected_remote_finished']=tls12_prf(context.base_secret, "client finished", transcript_hash, 12, TLS_CIPHER_SUITES[context.selected_cipher_suite].hash);
            }else{
              params_to_set['expected_remote_finished']=tls12_prf(context.base_secret, "server finished", transcript_hash, 12, TLS_CIPHER_SUITES[context.selected_cipher_suite].hash);
            }

            



          }

        }

      }

      

      //compare finished to expected...
      if(context.remote_finished_ok==false && context.remote_finished!==null && context.expected_remote_finished!==null){

        if(uint8Equal(context.remote_finished, context.expected_remote_finished)==true){

          let message_data = build_tls_message({
            type: 'finished',
            data: context.remote_finished
          });

          pushTranscript(message_data);

          params_to_set['remote_finished_ok']=true;

          context.remote_finished_data = context.remote_finished;
          context.remote_finished=null;
          context.expected_remote_finished=null;



        }else{
          context.remote_finished=null;
        }

      }
      



      if(context.state!=='connected' && context.remote_finished_ok==true && (((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) && context.local_app_traffic_secret!==null && context.remote_app_traffic_secret!==null) || (context.selected_version === wire.TLS_VERSION.TLS1_2 || context.selected_version === wire.DTLS_VERSION.DTLS1_2))){
        context.state='connected';
        context.handshakeEndTime = Date.now();
        ev.emit('secureConnect');

        // TLS 1.3: compute resumption_master_secret (both client and server need it)
        if ((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) && context.tls13_master_secret && !context.resumption_master_secret) {
          let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
          context.resumption_master_secret = derive_resumption_master_secret(
            hashName, context.tls13_master_secret, concatUint8Arrays(context.transcript)
          );
        }

        // TLS 1.3 server: send NewSessionTicket
        if ((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) && context.isServer && !context.session_ticket_sent && !context.noTickets && context.resumption_master_secret) {
          context.session_ticket_sent = true;

          let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
          let ticket_nonce = new Uint8Array([context.ticket_nonce_counter++]);
          let psk = derive_psk(hashName, context.resumption_master_secret, ticket_nonce);
          let ticket_age_add = crypto.randomBytes(4).readUInt32BE(0);
          let ticket_lifetime = 7200; // 2 hours

          // Ticket = encrypted PSK + metadata using ticketKeys (or random fallback)
          // Format: iv(12) || encrypted_json || tag(16)
          // ticketKeys: 48 bytes = name(16) + aes_key(16) + hmac_key(16)
          // We use first 32 bytes as AES-256-GCM key for simplicity
          let tk = context.ticketKeys || crypto.randomBytes(48);
          let ticket_enc_key = tk.length >= 32 ? tk.slice(0, 32) : Buffer.concat([tk, crypto.randomBytes(32 - tk.length)]);
          let ticket_iv = crypto.randomBytes(12);
          let ticket_plaintext = Buffer.from(JSON.stringify({
            psk: Buffer.from(psk).toString('base64'),
            cipher: context.selected_cipher_suite,
            age_add: ticket_age_add,
            created: Date.now()
          }));
          let ticket_cipher = crypto.createCipheriv('aes-256-gcm', ticket_enc_key, ticket_iv);
          let ticket_ct = ticket_cipher.update(ticket_plaintext);
          ticket_cipher.final();
          let ticket_tag = ticket_cipher.getAuthTag();
          let ticket = Buffer.concat([ticket_iv, ticket_ct, ticket_tag]);

          let nst_data = wire.build_message(wire.TLS_MESSAGE_TYPE.NEW_SESSION_TICKET,
            wire.build_new_session_ticket({
              ticket_lifetime: ticket_lifetime,
              ticket_age_add: ticket_age_add,
              ticket_nonce: ticket_nonce,
              ticket: new Uint8Array(ticket),
              extensions: []
            })
          );

          ev.emit('message', 2, context.message_sent_seq, 'new_session_ticket', nst_data);
          context.message_sent_seq++;

          ev.emit('session', {
            ticket: new Uint8Array(ticket),
            ticket_nonce: ticket_nonce,
            psk: psk,
            cipher: context.selected_cipher_suite,
            lifetime: ticket_lifetime,
            age_add: ticket_age_add,
            maxEarlyDataSize: 0,
          });
        }
      }


      
      set_context(params_to_set);
    }
  }


  function validatePeerCertificate() {
    if (!context.remote_cert_chain || context.remote_cert_chain.length === 0) {
      context.authorizationError = 'NO_PEER_CERTIFICATE';
      context.peerAuthorized = false;
      return;
    }

    try {
      // Parse the leaf certificate (first in chain)
      let certDer = context.remote_cert_chain[0].cert;
      let x509 = new crypto.X509Certificate(certDer);

      // Check validity dates
      let now = new Date();
      if (now < new Date(x509.validFrom)) {
        context.authorizationError = 'CERT_NOT_YET_VALID';
        context.peerAuthorized = false;
        return;
      }
      if (now > new Date(x509.validTo)) {
        context.authorizationError = 'CERT_HAS_EXPIRED';
        context.peerAuthorized = false;
        return;
      }

      // Check hostname (client-side only, when SNI is set)
      if (!context.isServer && context.local_sni) {
        if (!x509.checkHost(context.local_sni)) {
          context.authorizationError = 'ERR_TLS_CERT_ALTNAME_INVALID';
          context.peerAuthorized = false;
          return;
        }
      }

      // Verify against CA if provided
      if (context.ca) {
        let cas = Array.isArray(context.ca) ? context.ca : [context.ca];
        let verified = false;
        for (let i = 0; i < cas.length; i++) {
          try {
            let caX509 = new crypto.X509Certificate(cas[i]);
            if (x509.checkIssued(caX509) && x509.verify(caX509.publicKey)) {
              verified = true;
              break;
            }
          } catch(e) { /* try next CA */ }
        }
        if (!verified) {
          context.authorizationError = 'UNABLE_TO_VERIFY_LEAF_SIGNATURE';
          context.peerAuthorized = false;
          return;
        }
      }

      // All checks passed
      context.peerAuthorized = true;
      context.authorizationError = null;

    } catch(e) {
      context.authorizationError = e.message || 'CERTIFICATE_PARSE_ERROR';
      context.peerAuthorized = false;
    }
  }


  function sendAlert(level, description) {
    let alertData = new Uint8Array([level, description]);
    // Epoch 0 for alerts during/before handshake
    let epoch = (context.state === 'connected') ? 2 : 0;
    ev.emit('message', epoch, 0, 'alert', alertData);
    ev.emit('alert', { level: level, description: description });
    if (level === 2) {
      // Fatal alert — session is dead
      context.state = 'error';
    }
  }

  function close(){
    if (context.state === 'closed') return;
    // Send close_notify (warning level, description 0)
    sendAlert(1, 0);
    context.state = 'closed';
  }


  if(context.isServer==false){
    setTimeout(function(){

      if(context.local_random==null){
        context.local_random=new Uint8Array(crypto.randomBytes(32));
      }

      if(context.local_session_id==null){
        context.local_session_id=new Uint8Array(crypto.randomBytes(32));
      }

      // Support both TLS 1.3 and 1.2 (server picks the best)
      if(context.local_supported_cipher_suites.length<=0){
        context.local_supported_cipher_suites=[
          // TLS 1.3
          0x1301, // TLS_AES_128_GCM_SHA256
          0x1302, // TLS_AES_256_GCM_SHA384
          0x1303, // TLS_CHACHA20_POLY1305_SHA256
          // TLS 1.2 ECDHE
          0xC02F, // ECDHE_RSA_WITH_AES_128_GCM_SHA256
          0xC030, // ECDHE_RSA_WITH_AES_256_GCM_SHA384
          0xC02B, // ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
          0xCCA8, // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        ];
      }

      if(context.local_supported_groups.length<=0){
        context.local_supported_groups=[0x001d, 0x0017]; // X25519, P-256
      }

      if(context.local_supported_versions.length<=0){
        context.local_supported_versions=[0x0304, 0x0303]; // TLS 1.3, TLS 1.2
      }

      // Generate X25519 keypair for key_share (TLS 1.3) and ECDHE (TLS 1.2)
      const private_key = new Uint8Array(crypto.randomBytes(32));
      let public_key  = x25519_get_public_key(private_key);

      context.local_key_groups[0x001d]={
        public_key: public_key,
        private_key: private_key
      };

      let extensions = [
        { 
          type: 'SUPPORTED_VERSIONS', 
          value: context.local_supported_versions
        },
        {
          type: 'SUPPORTED_GROUPS', 
          value: context.local_supported_groups
        },
        {
          type: 'KEY_SHARE', 
          value: [{
            group: 0x001d, 
            key_exchange: public_key 
          }]
        },
        {
          type: 'SIGNATURE_ALGORITHMS', 
          value: [
            // TLS 1.3 (PSS + ECDSA)
            0x0804, 0x0805, 0x0806,
            0x0403, 0x0503, 0x0603,
            0x0807, 0x0808,
            // TLS 1.2 (PKCS1)
            0x0401, 0x0501, 0x0601
          ]
        },
        // TLS 1.2 compatibility
        { type: 'RENEGOTIATION_INFO', value: new Uint8Array(0) },
        { type: 23, data: new Uint8Array(0) } // extended_master_secret
      ];

      // Add SNI if servername was provided
      if (context.local_sni) {
        extensions.unshift({ type: 'SERVER_NAME', value: context.local_sni });
      }

      // Add ALPN if provided (e.g. 'h3' for QUIC)
      if (context.local_supported_alpns && context.local_supported_alpns.length > 0) {
        extensions.push({ type: 'ALPN', value: context.local_supported_alpns });
      }

      // Add custom extensions (e.g. QUIC transport params 0x39)
      for (let i in context.local_extensions) {
        extensions.push(context.local_extensions[i]);
      }

      // PSK resumption: check if session/psk was provided
      let pskData = options.session || options.psk || null;
      let message_data;

      if (pskData && pskData.psk && pskData.ticket && pskData.cipher) {
        // Add PSK key exchange modes (psk_dhe_ke = 1)
        extensions.push({ type: 'PSK_KEY_EXCHANGE_MODES', value: [1] });

        // Save PSK for later verification
        context.psk_offered = {
          identity: pskData.ticket,
          psk: pskData.psk instanceof Uint8Array ? pskData.psk : new Uint8Array(pskData.psk),
          cipher: pskData.cipher,
          age_add: pskData.age_add || 0,
        };

        // Compute obfuscated ticket age
        let ticketAge = pskData.lifetime ? Math.min((Date.now() - (pskData.created || Date.now())) / 1000, pskData.lifetime) * 1000 : 0;
        let obfuscatedAge = ((ticketAge + (pskData.age_add || 0)) & 0xFFFFFFFF) >>> 0;

        // Build ClientHello with placeholder binder to compute truncated hash
        let hashName = TLS_CIPHER_SUITES[pskData.cipher] ? TLS_CIPHER_SUITES[pskData.cipher].hash : 'sha256';
        let hashLen = getHashFn(hashName).outputLen;
        let placeholderBinder = new Uint8Array(hashLen);

        let pskExt = {
          type: 'PRE_SHARED_KEY',
          value: {
            identities: [{ identity: pskData.ticket, age: obfuscatedAge }],
            binders: [placeholderBinder]
          }
        };
        extensions.push(pskExt); // MUST be last

        // Build the full message with placeholder
        let build_message_params = {
          type: 'client_hello',
          version: 0x0303,
          random: context.local_random,
          session_id: context.local_session_id,
          cookie: context.dtls_cookie,
          cipher_suite: context.local_supported_cipher_suites,
          extensions: extensions
        };
        let tempMessage = build_tls_message(build_message_params);

        // Truncation point: message length - binders vec (2 + 1 + hashLen)
        let bindersSize = 2 + 1 + hashLen;
        let truncatedMessage = tempMessage.slice(0, tempMessage.length - bindersSize);

        // Compute real binder
        let binder_key = derive_binder_key(hashName, context.psk_offered.psk, false);
        let binder = compute_psk_binder(hashName, binder_key, truncatedMessage);

        // Rebuild with real binder
        pskExt.value.binders = [binder];
        message_data = build_tls_message(build_message_params);

      } else {
        // No PSK — standard ClientHello
        let build_message_params = {
          type: 'client_hello',
          version: 0x0303,
          random: context.local_random,
          session_id: context.local_session_id,
          cookie: context.dtls_cookie,
          cipher_suite: context.local_supported_cipher_suites,
          extensions: extensions
        };
        message_data = build_tls_message(build_message_params);
      }

      pushTranscript(message_data);

      context.hello_sent=true;

      ev.emit('message',0,context.message_sent_seq,'hello',message_data);

      context.message_sent_seq++;

    },0);
  }

  

  let api = {
    /**
     * Raw context object. Advanced users (QUIC, DTLS) can read/write
     * any internal state directly. Use convenience getters below when possible.
     */
    context: context,

    /** Whether this session is server-side. */
    isServer: context.isServer,

    /** Whether this connection used PSK resumption (true after secureConnect if PSK was accepted). */
    get isResumed() { return context.isResumed; },

    /** Register an event listener.
     *  Events:
     *    'hello'            — fired when remote Hello is received. Server should
     *                          call set_context() with local preferences here.
     *    'message'          — (epoch, seq, type, data) handshake/alert message ready to send.
     *                          epoch 0=cleartext, 1=handshake-encrypted, 2=app-encrypted.
     *                          type: 'hello'|'finished'|'alert'|etc.
     *                          The caller must frame this into a TLS record.
     *    'alert'            — ({level, description}) TLS alert sent or received.
     *    'secureConnect'    — handshake complete, app data can flow.
     */
    on:  function(name, fn){ ev.on(name, fn); },
    off: function(name, fn){ ev.off(name, fn); },

    /** Feed an incoming handshake message (without record header). */
    message: process_income_message,

    /** Set negotiation parameters. See context fields for available keys. */
    set_context: set_context,

    /** Close the session (sends close_notify alert). */
    close: close,

    /** Send a TLS alert. level: 1=warning, 2=fatal. See wire.TLS_ALERT for descriptions. */
    sendAlert: sendAlert,

    // ---- Convenience getters ----

    /** Returns the negotiated TLS version (e.g. 0x0303 for TLS 1.2, 0x0304 for TLS 1.3), or null. */
    getVersion: function(){
      return context.selected_version;
    },

    /** Returns the negotiated cipher suite code (e.g. 0x1301, 0xC02F), or null. */
    getCipher: function(){
      return context.selected_cipher_suite;
    },

    /** Returns the negotiated ALPN protocol string (e.g. 'h2'), or null. */
    getALPN: function(){
      return context.alpn_selected || null;
    },

    /** Returns the remote certificate chain, or null. */
    getPeerCertificate: function(){
      return context.remote_cert_chain || null;
    },

    /** Whether the peer certificate passed validation. */
    get authorized() { return context.peerAuthorized; },

    /** The authorization error string, or null if authorized. */
    get authorizationError() { return context.authorizationError; },

    /** Returns traffic secrets for record-layer key derivation.
     *  Individual fields are null until negotiated.
     *  TLS 1.3: use localAppSecret/remoteAppSecret after secureConnect.
     *  TLS 1.2: use masterSecret + randoms after key exchange.
     */
    getTrafficSecrets: function(){
      return {
        isServer:         context.isServer,
        version:          context.selected_version,
        cipher:           context.selected_cipher_suite,
        // TLS 1.3
        localAppSecret:   context.local_app_traffic_secret,
        remoteAppSecret:  context.remote_app_traffic_secret,
        // TLS 1.2
        masterSecret:     context.base_secret,
        localRandom:      context.local_random,
        remoteRandom:     context.remote_random,
      };
    },

    /** Returns handshake traffic secrets (available during handshake, before secureConnect). */
    getHandshakeSecrets: function(){
      return {
        localSecret:  context.local_handshake_traffic_secret,
        remoteSecret: context.remote_handshake_traffic_secret,
        cipher:       context.selected_cipher_suite,
      };
    },

    exportKeyingMaterial: function(length, label, context_value){
      if (!context.local_app_traffic_secret || !context.selected_cipher_suite) return new Uint8Array(0);
      let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
      let hashFn = getHashFn(hashName);
      let ctx_hash = hashFn(context_value || new Uint8Array(0));
      return hkdf_expand_label(hashName, context.local_app_traffic_secret, label || 'exporter', ctx_hash, length || 32);
    },

    /** Returns the local Finished verify_data (Buffer), or null. */
    getFinished: function(){
      return context.local_finished_data ? Buffer.from(context.local_finished_data) : null;
    },

    /** Returns the peer Finished verify_data (Buffer), or null. */
    getPeerFinished: function(){
      return context.remote_finished_data ? Buffer.from(context.remote_finished_data) : null;
    },

    /** Returns the ECDHE shared secret (Uint8Array), or null. For research/advanced use. */
    getSharedSecret: function(){
      return context.ecdhe_shared_secret ? Buffer.from(context.ecdhe_shared_secret) : null;
    },

    /** Handshake duration in ms, or null if not completed. */
    get handshakeDuration() {
      if (context.handshakeStartTime && context.handshakeEndTime)
        return context.handshakeEndTime - context.handshakeStartTime;
      return null;
    },

    /** Full negotiation result — all selected parameters in one object. */
    getNegotiationResult: function(){
      let cipherInfo = context.selected_cipher_suite ? TLS_CIPHER_SUITES[context.selected_cipher_suite] : null;
      return {
        version: context.selected_version,
        versionName: context.selected_version === 0x0304 ? 'TLSv1.3' : context.selected_version === 0xFEFC ? 'DTLSv1.3' : context.selected_version === 0x0303 ? 'TLSv1.2' : context.selected_version === 0xFEFD ? 'DTLSv1.2' : null,
        cipher: context.selected_cipher_suite,
        cipherName: cipherInfo ? cipherInfo.name : null,
        group: context.selected_group,
        groupName: context.selected_group === 0x001d ? 'X25519' : context.selected_group === 0x0017 ? 'P-256' : context.selected_group === 0x0018 ? 'P-384' : null,
        signatureAlgorithm: context.selected_signature_algorithm,
        alpn: context.selected_alpn,
        sni: context.selected_sni || context.local_sni,
        resumed: context.isResumed,
        helloRetried: context.helloRetried,
        handshakeDuration: context.handshakeEndTime && context.handshakeStartTime ? context.handshakeEndTime - context.handshakeStartTime : null,
      };
    },

    /** Compute JA3 fingerprint from the ClientHello (server-side only).
     *  Returns { hash, raw } or null if no ClientHello available.
     *  JA3 = md5(SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats)
     */
    getJA3: function(){
      if (!context.rawClientHello) return null;
      try {
        let hello = parse_tls_message(context.rawClientHello);

        let version = hello.client_version || 0x0303;
        let ciphers = (hello.cipher_suites || []).filter(c => (c & 0x0F0F) !== 0x0A0A).join('-');
        let extensions = (hello.extensions || []).map(e => e.type).filter(t => t !== 0x0A0A).join('-');
        let curves = (hello.supported_groups || []).filter(g => (g & 0x0F0F) !== 0x0A0A).join('-');
        let pointFormats = (hello.ec_point_formats || [0]).join('-');

        let raw = [version, ciphers, extensions, curves, pointFormats].join(',');
        let hash = crypto.createHash('md5').update(raw).digest('hex');
        return { hash, raw };
      } catch(e) { return null; }
    },

    /** Request a TLS 1.3 Key Update. requestPeer=true means ask the other side to update too. */
    requestKeyUpdate: function(requestPeer){
      if (context.state !== 'connected' || (context.selected_version !== wire.TLS_VERSION.TLS1_3 && context.selected_version !== wire.DTLS_VERSION.DTLS1_3)) return;
      let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
      let hashLen = getHashLen(hashName);

      // Derive new local traffic secret
      let newLocalSecret = hkdf_expand_label(hashName, context.local_app_traffic_secret, 'traffic upd', new Uint8Array(0), hashLen);
      context.local_app_traffic_secret = newLocalSecret;

      // Send KeyUpdate message
      let ku_data = build_tls_message({ type: 'key_update', request_update: requestPeer ? 1 : 0 });
      ev.emit('message', 2, context.message_sent_seq, 'key_update', ku_data);
      context.message_sent_seq++;

      ev.emit('keyUpdate', { direction: 'send', secret: newLocalSecret });
    },
  };

  for (let k in api) if (Object.prototype.hasOwnProperty.call(api,k)) this[k] = api[k];
  // Re-define dynamic getters (the for-in loop flattens them to values)
  Object.defineProperty(this, 'isResumed', { get: function() { return context.isResumed; }, configurable: true, enumerable: true });
  return this;
}

export default TLSSession;

