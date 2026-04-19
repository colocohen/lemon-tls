import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

import {
  TLS_CIPHER_SUITES,
  build_cert_verify_tbs,
  build_cert_verify_tbs_with_hash,
  get_handshake_finished,
  get_handshake_finished_with_hash,
  tls12_prf,
  derive_handshake_traffic_secrets,
  derive_handshake_traffic_secrets_with_hash,
  derive_app_traffic_secrets,
  derive_app_traffic_secrets_with_hash,
  derive_resumption_master_secret,
  derive_resumption_master_secret_with_hash,
  derive_psk,
  derive_binder_key,
  compute_psk_binder,
  derive_handshake_traffic_secrets_psk,
  derive_handshake_traffic_secrets_psk_with_hash,
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
import { encrypt_session_blob, decrypt_session_blob, encode_client_session, decode_client_session } from './session/ticket.js';

// Debug logging — enabled via LEMON_DEBUG=1 env var
const LEMON_DEBUG = typeof process !== 'undefined' && process.env && process.env.LEMON_DEBUG === '1';
function dbg(tag, ...args) { if (LEMON_DEBUG) console.error('[LEMON ' + tag + ']', ...args); }
function hexPreview(buf, max) {
  if (!buf) return 'null';
  let b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  let n = Math.min(b.length, max || 32);
  return b.slice(0, n).toString('hex') + (b.length > n ? `... (${b.length} bytes)` : ` (${b.length} bytes)`);
}


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
    ticketKeys: options.ticketKeys || null, // 48 bytes: [0:16]=key_name, [16:48]=AES-256-GCM key
    ticketLifetime: options.ticketLifetime != null ? (options.ticketLifetime >>> 0) : 7200, // seconds
    sessionTickets: options.sessionTickets !== false, // default true (was noTickets inverted)

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

    // Incremental transcript hash — running crypto.Hash object that we update
    // each time a handshake message is pushed. Replaces the previous pattern of
    // `concatUint8Arrays(transcript)` + `hashFn(...)` on every key-derivation
    // step, which re-hashed and re-allocated the entire transcript each time
    // (~5 times per handshake, several KB each).
    //
    // The array `transcript` is still maintained in parallel for cases that
    // need it (HRR rewind, TLS 1.2 EMS snapshot via transcript.length, logging).
    // Only the HASH path uses this incremental object. Reset on HRR.
    transcriptHash: null,          // crypto.Hash object (lazy init when hashName is known)
    transcriptHashName: null,      // hash algorithm currently tracked ('sha256' / 'sha384')


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
    psk_offered: null,       // client: { identity, psk, cipher } offered in ClientHello
    psk_accepted: false,     // server accepted PSK → abbreviated handshake
    isResumed: false,        // true if PSK was accepted (1.3) or abbreviated handshake (1.2)

    // TLS 1.2 resumption
    tls12_abbreviated: false,         // doing abbreviated handshake (server side)
    tls12_resume_state: null,         // loaded session state (from SessionID or Ticket): { version, cipher, master_secret, extended_master_secret, sni, alpn, timestamp }
    tls12_session_ticket_requested: false,  // client sent SessionTicket extension (empty or with data)
    tls12_session_ticket_offered: null,     // client sent non-empty SessionTicket (raw bytes) — server tries to decrypt
    tls12_newsession_sent: false,           // server sent NewSessionTicket message (TLS 1.2)
    tls12_session_id_for_store: null,       // session_id to emit with 'newSession' (32 bytes, server-generated)
    tls12_session_id_emitted: false,        // 'newSession' event already fired
    tls12_client_session_emitted: false,    // client-side 'session' event fired (TLS 1.2 Session ID or ticket)
    tls12_resume_pending: false,            // waiting for 'resumeSession' async callback
    tls12_client_session: null,             // client: saved session to resume with (parsed sessionData)
  };

  /**
   * Emit NSS SSLKEYLOGFILE lines on 'keylog' event (Node.js TLSSocket compat).
   * Used by Wireshark and similar tools to decrypt TLS traffic.
   *
   * Format: "LABEL <client_random_hex> <secret_hex>\n"
   *   - TLS 1.2: CLIENT_RANDOM <cr> <master_secret>
   *   - TLS 1.3: CLIENT_HANDSHAKE_TRAFFIC_SECRET / SERVER_HANDSHAKE_TRAFFIC_SECRET
   *              CLIENT_TRAFFIC_SECRET_0        / SERVER_TRAFFIC_SECRET_0
   *
   * All three functions are zero-allocation when no 'keylog' listeners are attached
   * (single listenerCount check at entry), so leaving this infrastructure in place
   * has no measurable cost in production.
   */
  function _emitKeylogPair(labelClient, labelServer, secretClient, secretServer) {
    if (ev.listenerCount('keylog') === 0) return;
    let clientRandom = context.isServer ? context.remote_random : context.local_random;
    if (!clientRandom) return;
    // Compute clientRandom hex once — both lines share it
    let crHex = Buffer.from(clientRandom).toString('hex');
    if (secretClient) {
      let line = labelClient + ' ' + crHex + ' ' + Buffer.from(secretClient).toString('hex') + '\n';
      ev.emit('keylog', Buffer.from(line));
    }
    if (secretServer) {
      let line = labelServer + ' ' + crHex + ' ' + Buffer.from(secretServer).toString('hex') + '\n';
      ev.emit('keylog', Buffer.from(line));
    }
  }

  /** TLS 1.3: emit CLIENT_HANDSHAKE_TRAFFIC_SECRET + SERVER_HANDSHAKE_TRAFFIC_SECRET. */
  function _emitHandshakeKeylog() {
    _emitKeylogPair(
      'CLIENT_HANDSHAKE_TRAFFIC_SECRET', 'SERVER_HANDSHAKE_TRAFFIC_SECRET',
      context.isServer ? context.remote_handshake_traffic_secret : context.local_handshake_traffic_secret,
      context.isServer ? context.local_handshake_traffic_secret  : context.remote_handshake_traffic_secret
    );
  }

  /** TLS 1.3: emit CLIENT_TRAFFIC_SECRET_0 + SERVER_TRAFFIC_SECRET_0. */
  function _emitAppKeylog() {
    _emitKeylogPair(
      'CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0',
      context.isServer ? context.remote_app_traffic_secret : context.local_app_traffic_secret,
      context.isServer ? context.local_app_traffic_secret  : context.remote_app_traffic_secret
    );
  }

  /** TLS 1.2: emit CLIENT_RANDOM <client_random> <master_secret>. */
  function _emitKeylog(label, secret) {
    if (ev.listenerCount('keylog') === 0) return;
    let clientRandom = context.isServer ? context.remote_random : context.local_random;
    if (!clientRandom || !secret) return;
    let line = label + ' ' +
      Buffer.from(clientRandom).toString('hex') + ' ' +
      Buffer.from(secret).toString('hex') + '\n';
    ev.emit('keylog', Buffer.from(line));
  }

  /**
   * Push a handshake message to the transcript.
   * If a transcriptHook is set (by DTLSSession), it transforms the data first.
   * This allows DTLS 1.2 to store DTLS-format entries (with reconstruction data)
   * while TLS and DTLS 1.3 store standard TLS-format entries.
   *
   * Also updates the incremental transcript hash if it's been initialized,
   * so subsequent calls to get_transcript_hash() run in O(1) clone+digest time
   * instead of re-hashing the entire transcript.
   */
  function pushTranscript(data) {
    if (context.transcriptHook) {
      data = context.transcriptHook(data);
    }
    context.transcript.push(data);
    if (context.transcriptHash !== null) {
      context.transcriptHash.update(data);
    }
  }

  /**
   * Returns the transcript hash using the incremental running hash object.
   * Initializes the running hash on first call (replaying any pre-existing
   * messages), then uses Hash.copy()+digest() on subsequent calls so the
   * running hash keeps accepting more updates.
   *
   * Perf vs old pattern `getHashFn(h)(concatUint8Arrays(transcript))`:
   *   - Avoids concat — which allocates a buffer holding ALL transcript bytes
   *   - Avoids hashing the entire transcript from scratch every time
   *   - Hash.copy() duplicates only the hash state (~hashLen bytes)
   *
   * For a typical handshake with 6-8 messages of a few KB total and ~5 hash
   * computations during key derivation, this saves ~20KB of allocations and
   * re-hashes the same bytes 4 fewer times.
   */
  function get_transcript_hash(hashName) {
    if (context.transcriptHash !== null && context.transcriptHashName === hashName) {
      return new Uint8Array(context.transcriptHash.copy().digest());
    }
    // Lazy init: create a fresh hash and replay existing transcript into it.
    // After this, pushTranscript() updates the hash incrementally.
    context.transcriptHash = crypto.createHash(hashName);
    context.transcriptHashName = hashName;
    for (let i = 0; i < context.transcript.length; i++) {
      context.transcriptHash.update(context.transcript[i]);
    }
    return new Uint8Array(context.transcriptHash.copy().digest());
  }

  /**
   * Reset the incremental transcript hash. Called after HRR reshape, where the
   * transcript array is replaced with [message_hash(CH1), HRR] and the running
   * hash must be restarted to match.
   */
  function reset_transcript_hash(hashName) {
    context.transcriptHash = crypto.createHash(hashName);
    context.transcriptHashName = hashName;
    for (let i = 0; i < context.transcript.length; i++) {
      context.transcriptHash.update(context.transcript[i]);
    }
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

    let message = parse_tls_message(data, context.selected_version);

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

        dbg('SRV-PSK', 'received identity:', hexPreview(pskIdentity.identity, 24),
            'age:', (pskIdentity.age || 0) >>> 0,
            'received binder:', hexPreview(pskBinder, 16));

        let pskResult = null;
        ev.emit('psk', {
          identity: pskIdentity.identity,
          obfuscatedAge: (pskIdentity.age || 0) >>> 0
        }, function(result) {
          pskResult = result;
        });

        dbg('SRV-PSK', 'pskResult:', pskResult ? `psk=${hexPreview(pskResult.psk, 8)} cipher=0x${pskResult.cipher?.toString(16)}` : 'null (decrypt failed)');

        if (pskResult && pskResult.psk) {
          let pskCipher = pskResult.cipher || 0x1301;
          let hashName = TLS_CIPHER_SUITES[pskCipher] ? TLS_CIPHER_SUITES[pskCipher].hash : 'sha256';
          let binder_key = derive_binder_key(hashName, pskResult.psk, false);

          let hashLen = getHashFn(hashName).outputLen;
          let bindersSize = 2 + 1 + hashLen;
          let truncatedCH = data.slice(0, data.length - bindersSize);
          let expectedBinder = compute_psk_binder(hashName, binder_key, truncatedCH);

          dbg('SRV-PSK', 'hash:', hashName, 'hashLen:', hashLen,
              'truncatedCH len:', truncatedCH.length,
              'full CH len:', data.length);
          dbg('SRV-PSK', 'expected binder:', hexPreview(expectedBinder, 16));
          dbg('SRV-PSK', 'received binder:', hexPreview(pskBinder, 16));

          let binderOk = pskBinder && expectedBinder.length === pskBinder.length;
          if (binderOk) {
            for (let bi = 0; bi < expectedBinder.length; bi++) {
              if (expectedBinder[bi] !== pskBinder[bi]) { binderOk = false; break; }
            }
          }

          dbg('SRV-PSK', binderOk ? '✓ BINDER MATCH — psk_accepted' : '✗ BINDER MISMATCH — full handshake');

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
          dbg('CLI-PSK', '✓ server accepted PSK, selected_identity:', message.pre_shared_key.selected);
          context.psk_accepted = true;
          context.isResumed = true;
        }
      } else if (!context.isServer && context.psk_offered && message.type === 'server_hello') {
        dbg('CLI-PSK', '✗ server did NOT include pre_shared_key in SH — full handshake');
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

        // After HRR, the running hash must be restarted to match the reshaped
        // transcript. If any existing running hash was tracking the old (CH1 + HRR)
        // sequence, it's now stale — we rebuild from the new 2-entry transcript.
        reset_transcript_hash(hashName);

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
              { type: 'EXTENDED_MASTER_SECRET', value: null },
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

      // Server: TLS 1.2 resumption detection (only makes sense from ClientHello).
      // This runs BEFORE set_context's reactive loop picks a version, so we mark state
      // but defer the decision. The reactive loop will check tls12_abbreviated once
      // TLS 1.2 is actually selected.
      if (context.isServer && message.type === 'client_hello') {

        // Was SessionTicket extension present? (empty or with data)
        if (message.session_ticket_supported) {
          context.tls12_session_ticket_requested = true;
        }

        // 1) Try ticket-based resumption (RFC 5077) — stateless, preferred over session_id
        if (message.session_ticket && message.session_ticket.length > 0 && context.ticketKeys && context.sessionTickets) {
          let state = decrypt_session_blob(message.session_ticket, context.ticketKeys);
          if (state && state.v === 12 && state.master_secret) {
            // Honor ticket-based resumption: we'll proceed as abbreviated handshake once TLS 1.2 is selected.
            context.tls12_resume_state = state;
            context.tls12_session_ticket_offered = message.session_ticket;
          }
        }

        // 2) Try Session ID resumption — emit 'resumeSession' event (async-supported).
        //    Only if ticket-based didn't already succeed. Works regardless of sessionTickets
        //    setting: if the user registered a 'resumeSession' listener, they opted into
        //    Session ID-based resumption.
        if (!context.tls12_resume_state && message.session_id && message.session_id.length > 0) {
          // Fire synchronously-first; listener may resolve immediately OR asynchronously.
          // If async, the listener's callback ends up calling set_context via a helper below.
          let offeredId = message.session_id;
          let resolved = false;

          let resumeCb = function(err, sessionData) {
            if (resolved) return;
            resolved = true;
            context.tls12_resume_pending = false;

            if (!err && sessionData) {
              // sessionData may be a structured state (user returned a decoded state)
              // or an encrypted Buffer (user returned what we gave them in 'newSession').
              let state = null;
              if (sessionData instanceof Uint8Array || Buffer.isBuffer(sessionData)) {
                state = decrypt_session_blob(sessionData, context.ticketKeys);
              } else if (typeof sessionData === 'object' && sessionData.master_secret) {
                state = sessionData;
              }
              if (state && state.v === 12 && state.master_secret) {
                set_context({
                  tls12_resume_state: state,
                });
              }
            }
            // If no state resolved → full handshake. Reactive loop continues once pending clears.
          };

          context.tls12_resume_pending = true;
          ev.emit('resumeSession', offeredId, resumeCb);

          // If nobody listened (listenerCount === 0), immediately un-pend.
          if (ev.listenerCount('resumeSession') === 0) {
            resumeCb(null, null);
          }
        }
      }

      // Client: TLS 1.2 resumption detection.
      // Two cases trigger abbreviated handshake:
      //   (a) Session ID-based: server echoes the saved session_id
      //   (b) Ticket-based: per RFC 5077 §3.4, if server accepts the ticket AND the CH
      //       session_id is non-empty, it MUST echo the same session_id. So if our CH
      //       session_id appears back in SH and we offered a ticket, ticket was accepted.
      if (!context.isServer && context.tls12_client_session && message.type === 'server_hello' &&
          message.session_id && message.session_id.length > 0) {

        let abbreviatedDetected = false;
        let savedSid = context.tls12_client_session.session_id;
        let sentSid  = context.local_session_id;
        let hasTicket = context.tls12_client_session.ticket && context.tls12_client_session.ticket.length > 0;

        dbg('CLI-12RESUME', 'saved sid:', hexPreview(savedSid, 16),
            'sent sid:', hexPreview(sentSid, 16),
            'received sid:', hexPreview(message.session_id, 16),
            'hasTicket:', hasTicket);

        // Case (a): server's session_id equals the one we had stored from a prior connection
        if (savedSid && savedSid.length > 0 && uint8Equal(message.session_id, savedSid)) {
          abbreviatedDetected = true;
          dbg('CLI-12RESUME', '✓ case (a) matched: SH echoes saved sid');
        }

        // Case (b): we offered a ticket and server echoed our CH session_id
        if (!abbreviatedDetected && hasTicket && sentSid && sentSid.length > 0 &&
            uint8Equal(message.session_id, sentSid)) {
          abbreviatedDetected = true;
          dbg('CLI-12RESUME', '✓ case (b) matched: SH echoes CH sid after ticket offer');
        }

        if (!abbreviatedDetected) {
          dbg('CLI-12RESUME', '✗ no match — full handshake expected');
        }

        if (abbreviatedDetected) {
          context.tls12_abbreviated = true;
          context.isResumed = true;
          // Load master_secret and EMS flag from saved session
          set_context({
            base_secret: context.tls12_client_session.master_secret,
            use_extended_master_secret: !!context.tls12_client_session.extended_master_secret,
            // Mark as if remote_hello_done arrived — we won't actually receive it in abbreviated flow,
            // but the reactive loop uses this to gate CKE; we're skipping CKE anyway.
            remote_hello_done: true,
            // Pretend key_exchange_sent so Finished logic proceeds without real CKE
            key_exchange_sent: true,
          });
        }
      }

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

      // Client receives NewSessionTicket from server (post-handshake in TLS 1.3, pre-CCS in TLS 1.2)
      if(!context.isServer){
        if ((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) && context.resumption_master_secret) {
          // TLS 1.3: derive PSK from resumption_master_secret + ticket_nonce
          let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
          let psk = derive_psk(hashName, context.resumption_master_secret, message.ticket_nonce);

          dbg('CLI-NST', 'received TLS 1.3 NST — cipher:', '0x' + context.selected_cipher_suite.toString(16),
              'hash:', hashName,
              'transcript len:', concatUint8Arrays(context.transcript).length);
          dbg('CLI-NST', 'ticket_nonce:', hexPreview(message.ticket_nonce, 4),
              'age_add:', message.ticket_age_add,
              'lifetime:', message.ticket_lifetime);
          dbg('CLI-NST', 'resumption_master_secret:', hexPreview(context.resumption_master_secret, 8),
              'derived psk:', hexPreview(psk, 8));

          // Encode opaque client-side session Buffer (JSON — user is responsible for secure storage)
          let session_blob = encode_client_session({
            v: 13,                                    // blob kind: TLS 1.3
            version: context.selected_version,
            cipher: context.selected_cipher_suite,
            ticket: message.ticket,
            psk: psk,
            age_add: message.ticket_age_add,
            lifetime: message.ticket_lifetime,
            sni: context.local_sni || null,
            alpn: context.selected_alpn || null,
            created: Date.now(),
          });

          ev.emit('session', session_blob);
        } else if (context.selected_version === wire.TLS_VERSION.TLS1_2 && context.base_secret) {
          // TLS 1.2: NewSessionTicket is sent BEFORE server's CCS+Finished and is part of the
          // handshake transcript (RFC 5077 §3.3). Server's Finished hash covers this message,
          // so the client MUST include it in its transcript for verification to succeed.
          pushTranscript(data);

          // Save the raw ticket so getTLSTicket() can return it (Node compat).
          context.tls12_received_ticket = message.ticket;

          let session_blob = encode_client_session({
            v: 12,                                    // blob kind: TLS 1.2
            version: context.selected_version,
            cipher: context.selected_cipher_suite,
            master_secret: context.base_secret,
            extended_master_secret: !!context.use_extended_master_secret,
            ticket: message.ticket,
            session_id: context.remote_session_id || null,  // store for Session ID fallback
            lifetime: message.ticket_lifetime_hint || context.ticketLifetime,
            sni: context.local_sni || null,
            alpn: context.selected_alpn || null,
            created: Date.now(),
          });

          ev.emit('session', session_blob);
          context.tls12_client_session_emitted = true;
        }
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

      if('tls12_resume_state' in options){
        if(context.tls12_resume_state !== options.tls12_resume_state){
          context.tls12_resume_state = options.tls12_resume_state;
          has_changed=true;
        }
      }

      if('tls12_abbreviated' in options){
        if(context.tls12_abbreviated !== options.tls12_abbreviated){
          context.tls12_abbreviated = options.tls12_abbreviated;
          has_changed=true;
        }
      }

      if('isResumed' in options){
        if(context.isResumed !== options.isResumed){
          context.isResumed = options.isResumed;
          has_changed=true;
        }
      }

      if('use_extended_master_secret' in options){
        if(context.use_extended_master_secret !== options.use_extended_master_secret){
          context.use_extended_master_secret = options.use_extended_master_secret;
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
          // TLS 1.2: base_secret IS the master_secret. Emit NSS SSLKEYLOGFILE line.
          if (options.base_secret && (context.selected_version === wire.TLS_VERSION.TLS1_2 ||
              context.selected_version === wire.DTLS_VERSION.DTLS1_2)) {
            _emitKeylog('CLIENT_RANDOM', options.base_secret);
          }
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
            _emitHandshakeKeylog();
          }
        }
      }

      if('local_handshake_traffic_secret' in options){
        if(context.local_handshake_traffic_secret==null && options.local_handshake_traffic_secret!==null){
          context.local_handshake_traffic_secret=options.local_handshake_traffic_secret;
          has_changed=true;
          if(context.remote_handshake_traffic_secret!==null){
            ev.emit('handshakeSecrets', context.local_handshake_traffic_secret, context.remote_handshake_traffic_secret);
            _emitHandshakeKeylog();
          }
        }
      }

      if('remote_app_traffic_secret' in options){
        if(context.remote_app_traffic_secret==null && options.remote_app_traffic_secret!==null){
          context.remote_app_traffic_secret=options.remote_app_traffic_secret;
          has_changed=true;
          if(context.local_app_traffic_secret!==null){
            ev.emit('appSecrets', context.local_app_traffic_secret, context.remote_app_traffic_secret);
            _emitAppKeylog();
          }
        }
      }

      if('local_app_traffic_secret' in options){
        if(context.local_app_traffic_secret==null && options.local_app_traffic_secret!==null){
          context.local_app_traffic_secret=options.local_app_traffic_secret;
          has_changed=true;
          if(context.remote_app_traffic_secret!==null){
            ev.emit('appSecrets', context.local_app_traffic_secret, context.remote_app_traffic_secret);
            _emitAppKeylog();
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
        
        // If resuming TLS 1.2, force cipher to match stored state (if client still offers it)
        if (context.isServer && context.tls12_resume_state &&
            context.selected_version !== wire.TLS_VERSION.TLS1_3 &&
            context.selected_version !== wire.DTLS_VERSION.DTLS1_3) {
          let storedCipher = context.tls12_resume_state.cipher | 0;
          if (context.remote_supported_cipher_suites.indexOf(storedCipher) >= 0 &&
              context.local_supported_cipher_suites.indexOf(storedCipher) >= 0) {
            params_to_set['selected_cipher_suite'] = storedCipher;
          } else {
            // Client no longer offers this cipher → can't resume, drop state
            context.tls12_resume_state = null;
          }
        }

        // TLS 1.3 PSK resumption: per RFC 8446 §4.2.11, server MUST select a cipher compatible
        // with the selected PSK (same hash algorithm). Since we accepted the PSK based on its
        // stored cipher's hash (for binder verification), we force the same cipher here.
        if (context.isServer && context.psk_accepted && context.psk_offered && context.psk_offered.cipher &&
            (context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3)) {
          let pskCipher = context.psk_offered.cipher | 0;
          if (context.remote_supported_cipher_suites.indexOf(pskCipher) >= 0 &&
              context.local_supported_cipher_suites.indexOf(pskCipher) >= 0) {
            params_to_set['selected_cipher_suite'] = pskCipher;
          }
          // If client no longer offers this cipher, PSK can't be used — but we already accepted it.
          // This is an edge case; fall through to normal selection and hope for the best.
        }

        if (!('selected_cipher_suite' in params_to_set)) {
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
      }

      // TLS 1.2 abbreviated handshake setup: validate EMS match, seed base_secret, set flags.
      // Runs once when all prerequisites are met (version + cipher selected, resume state present).
      if (context.isServer && context.tls12_resume_state && !context.tls12_abbreviated &&
          params_to_set.selected_cipher_suite != null &&
          (context.selected_version === wire.TLS_VERSION.TLS1_2 || params_to_set.selected_version === wire.TLS_VERSION.TLS1_2)) {

        let storedEMS = !!context.tls12_resume_state.extended_master_secret;
        let clientEMS = !!context.use_extended_master_secret;

        if (storedEMS !== clientEMS) {
          // EMS mismatch: per RFC 7627 can't resume. Fall through to full handshake.
          context.tls12_resume_state = null;
        } else {
          // OK, we can do abbreviated. Use params_to_set for all state flags
          // (triggers has_changed → reactive loop re-runs with new state).
          params_to_set['tls12_abbreviated'] = true;
          params_to_set['isResumed'] = true;
          params_to_set['base_secret'] = context.tls12_resume_state.master_secret;
          // Echo stored session_id if we had one from the client. Otherwise fresh.
          // For ticket-based resume: client's CH session_id is usually non-empty "random" bytes —
          // we echo it back (RFC 5077 §3.4). For ID-based: we already have context.remote_session_id.
          params_to_set['selected_session_id'] = context.remote_session_id || new Uint8Array(0);
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

          // Rebuild the running hash to match the reshaped transcript.
          reset_transcript_hash(hashName);

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
              // Block ServerHello while waiting for async resumeSession decision
              if (!context.tls12_resume_pending) {
                can_send_hello=true;
              }
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
              ext_list.push({ type: 'EXTENDED_MASTER_SECRET', value: null });
            }

            if (context.selected_alpn) {
              // RFC 7301: ServerHello echoes a single selected protocol
              ext_list.push({ type: 'ALPN', value: [ String(context.selected_alpn) ] });
            }

            // SESSION_TICKET: RFC 5077 §3.2 — server echoes empty extension to signal it will
            // send a NewSessionTicket later. Skip for abbreviated handshake (per §3.3).
            // Skip for DTLS — we don't emit NST in DTLS, so MUST NOT echo the ext either (§3.2).
            let isDtls12Here = (context.selected_version === wire.DTLS_VERSION.DTLS1_2);
            if (context.tls12_session_ticket_requested && !context.tls12_abbreviated && context.sessionTickets && !isDtls12Here) {
              ext_list.push({ type: 'SESSION_TICKET', value: new Uint8Array(0) });
            }

            // Session ID: for abbreviated (resumed) handshake, MUST echo client's session_id
            // (RFC 5077 §3.4). For TLS 1.2 full handshake, generate a fresh 32-byte session_id
            // (matches OpenSSL/Node.js behavior for middlebox compatibility).
            // For DTLS 1.2 full handshake: just echo client's session_id (no middlebox concern,
            // and matches original lemon-tls behavior before my TLS 1.2 resumption changes).
            let sid_to_send;
            if (context.tls12_abbreviated) {
              sid_to_send = context.remote_session_id || new Uint8Array(0);
            } else if (context.selected_version === wire.DTLS_VERSION.DTLS1_2) {
              sid_to_send = context.remote_session_id || new Uint8Array(0);
            } else {
              if (!context.tls12_session_id_for_store) {
                context.tls12_session_id_for_store = new Uint8Array(crypto.randomBytes(32));
              }
              sid_to_send = context.tls12_session_id_for_store;
            }

            build_message_params = {
              type: 'server_hello',
              version: context.selected_version,
              random: context.local_random,
              session_id: sid_to_send,
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
          // Use incremental transcript hash — avoids concat+hash of full transcript
          let tx_hash = get_transcript_hash(hashName);
          if (context.psk_accepted && context.psk_offered && context.psk_offered.psk) {
            // PSK + ECDHE key schedule
            result = derive_handshake_traffic_secrets_psk_with_hash(hashName, context.psk_offered.psk, context.ecdhe_shared_secret, tx_hash);
          } else {
            // Standard key schedule (no PSK)
            result = derive_handshake_traffic_secrets_with_hash(hashName, context.ecdhe_shared_secret, tx_hash);
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

      if(context.isServer==true && context.cert_sent==false && context.local_cert_chain!==null && !context.psk_accepted && !context.tls12_abbreviated){
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

          let tbsHashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
          let tbs_data = build_cert_verify_tbs_with_hash(tbsHashName, true, get_transcript_hash(tbsHashName));

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
      
      

      // TLS 1.2 server: send NewSessionTicket (RFC 5077) BEFORE our Finished.
      // Per RFC 5077 §3.3: "sent during the TLS handshake before the ChangeCipherSpec
      // message, after the server has successfully verified the client's Finished message."
      // Must run BEFORE the Finished send block below (which sets finished_sent=true).
      // NOTE: Only for FULL handshake. In abbreviated handshake, we'd need to signal renewal
      // via SESSION_TICKET ext in SH (which we don't add for abbreviated per RFC 5077 §3.2),
      // so sending NST would cause "unexpected message" errors on strict clients (e.g. openssl).
      // Renewal is optional per RFC 5077 §3.3 — safer to skip it in abbreviated.
      // Excluded for DTLS 1.2 — implementations (e.g. openssl s_server -dtls1_2) don't always
      // support it well. Revisit if needed.
      if (context.selected_version === wire.TLS_VERSION.TLS1_2 &&
          context.isServer && !context.tls12_newsession_sent && context.sessionTickets &&
          context.tls12_session_ticket_requested && !context.tls12_abbreviated &&
          context.base_secret) {

        // Full handshake only: send NST after client's Finished verified, before server's Finished.
        let can_send_nst = context.remote_finished_ok && !context.finished_sent;

        if (can_send_nst) {
          context.tls12_newsession_sent = true;

          // Ensure ticketKeys is 48 bytes
          if (!context.ticketKeys || context.ticketKeys.length !== 48) {
            context.ticketKeys = crypto.randomBytes(48);
          }

          // Build session state to encrypt into ticket
          let ticket = encrypt_session_blob({
            v: 12,                                      // blob kind: TLS 1.2
            version: context.selected_version,
            cipher: context.selected_cipher_suite,
            master_secret: context.base_secret,
            extended_master_secret: !!context.use_extended_master_secret,
            sni: context.selected_sni || context.remote_sni || null,
            alpn: context.selected_alpn || null,
            created: Date.now(),
          }, context.ticketKeys);

          let nst_data = build_tls_message({
            type: 'new_session_ticket_tls12',
            ticket_lifetime_hint: context.ticketLifetime,
            ticket: ticket,
          });

          pushTranscript(nst_data);
          // epoch 0 = cleartext (server hasn't sent its CCS yet)
          ev.emit('message', 0, context.message_sent_seq, 'new_session_ticket', nst_data);
          context.message_sent_seq++;

          // Server-side 'session' event for monitoring / backward compat with lemon-tls
          let server_session_blob = encode_client_session({
            v: 12,
            version: context.selected_version,
            cipher: context.selected_cipher_suite,
            master_secret: context.base_secret,
            extended_master_secret: !!context.use_extended_master_secret,
            ticket: ticket,
            session_id: context.remote_session_id || null,
            lifetime: context.ticketLifetime,
            sni: context.selected_sni || context.remote_sni || null,
            alpn: context.selected_alpn || null,
            created: Date.now(),
          });
          ev.emit('session', server_session_blob);
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
          let transcript_hash = get_transcript_hash(hashName);
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

            let finHashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
            let finished_data=get_handshake_finished_with_hash(finHashName,context.local_handshake_traffic_secret,get_transcript_hash(finHashName));
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

          // Finished ordering differs between full and abbreviated handshake:
          //   Full:        client sends first (after CKE), then server (after client's Finished).
          //   Abbreviated: server sends first (after ServerHello), then client (after server's Finished).
          let can_send_finished;
          if (context.tls12_abbreviated) {
            if (context.isServer) {
              can_send_finished = context.hello_sent == true;                // after ServerHello
            } else {
              can_send_finished = context.remote_finished_ok == true;        // after server's Finished
            }
          } else {
            if (context.isServer) {
              can_send_finished = context.remote_finished_ok == true;
            } else {
              can_send_finished = context.key_exchange_sent == true;
            }
          }

          if (can_send_finished) {

            let finishedHashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
            let transcript_hash = get_transcript_hash(finishedHashName);

            let finished_data;
            if(context.isServer==true){
              finished_data=tls12_prf(context.base_secret, "server finished", transcript_hash, 12, finishedHashName);
            }else{
              finished_data=tls12_prf(context.base_secret, "client finished", transcript_hash, 12, finishedHashName);
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

            let appHashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
            let result2 = derive_app_traffic_secrets_with_hash(appHashName, context.base_secret, get_transcript_hash(appHashName));

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

            let remoteFinHashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
            params_to_set['expected_remote_finished']=get_handshake_finished_with_hash(remoteFinHashName,context.remote_handshake_traffic_secret,get_transcript_hash(remoteFinHashName));

          }

        }else if((context.selected_version === wire.TLS_VERSION.TLS1_2 || context.selected_version === wire.DTLS_VERSION.DTLS1_2) && context.base_secret!==null){

          if(context.remote_finished!==null){


            let tls12FinHashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
            let transcript_hash = get_transcript_hash(tls12FinHashName);

            if(context.isServer==true){
              params_to_set['expected_remote_finished']=tls12_prf(context.base_secret, "client finished", transcript_hash, 12, tls12FinHashName);
            }else{
              params_to_set['expected_remote_finished']=tls12_prf(context.base_secret, "server finished", transcript_hash, 12, tls12FinHashName);
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
          context.resumption_master_secret = derive_resumption_master_secret_with_hash(
            hashName, context.tls13_master_secret, get_transcript_hash(hashName)
          );
        }

        // TLS 1.3 server: send NewSessionTicket
        if ((context.selected_version === wire.TLS_VERSION.TLS1_3 || context.selected_version === wire.DTLS_VERSION.DTLS1_3) && context.isServer && !context.session_ticket_sent && context.sessionTickets && context.resumption_master_secret) {
          context.session_ticket_sent = true;

          let hashName = TLS_CIPHER_SUITES[context.selected_cipher_suite].hash;
          let ticket_nonce = new Uint8Array([context.ticket_nonce_counter++]);
          let psk = derive_psk(hashName, context.resumption_master_secret, ticket_nonce);
          let ticket_age_add = crypto.randomBytes(4).readUInt32BE(0);
          let ticket_lifetime = context.ticketLifetime;

          dbg('SRV-NST', 'issuing TLS 1.3 NST — cipher:', '0x' + context.selected_cipher_suite.toString(16),
              'hash:', hashName,
              'transcript len:', concatUint8Arrays(context.transcript).length);
          dbg('SRV-NST', 'ticket_nonce:', hexPreview(ticket_nonce, 4),
              'age_add:', ticket_age_add,
              'lifetime:', ticket_lifetime);
          dbg('SRV-NST', 'resumption_master_secret:', hexPreview(context.resumption_master_secret, 8),
              'derived psk:', hexPreview(psk, 8));

          // Ensure ticketKeys is 48 bytes (key_name + aes_key)
          if (!context.ticketKeys || context.ticketKeys.length !== 48) {
            context.ticketKeys = crypto.randomBytes(48);
          }

          // Encrypt session state into opaque ticket (unified format: key_name(16) | IV(12) | CT | Tag(16))
          let ticket = encrypt_session_blob({
            v: 13,                                      // blob kind: TLS 1.3 PSK
            version: context.selected_version,
            cipher: context.selected_cipher_suite,
            psk: psk,
            age_add: ticket_age_add,
            sni: context.selected_sni || context.remote_sni || null,
            alpn: context.selected_alpn || null,
            created: Date.now(),
          }, context.ticketKeys);

          let nst_data = wire.build_message(wire.TLS_MESSAGE_TYPE.NEW_SESSION_TICKET,
            wire.build_new_session_ticket({
              ticket_lifetime: ticket_lifetime,
              ticket_age_add: ticket_age_add,
              ticket_nonce: ticket_nonce,
              ticket: ticket,
              extensions: []
            })
          );

          ev.emit('message', 2, context.message_sent_seq, 'new_session_ticket', nst_data);
          context.message_sent_seq++;

          // Emit 'session' event on server side too — lets users track when tickets are
          // issued (e.g. for monitoring or metrics). Not part of Node.js API but useful.
          // Emits the same Buffer the client would receive via their 'session' event,
          // so server-side apps could also persist it if they want.
          let server_session_blob = encode_client_session({
            v: 13,
            version: context.selected_version,
            cipher: context.selected_cipher_suite,
            ticket: ticket,
            psk: psk,
            age_add: ticket_age_add,
            lifetime: ticket_lifetime,
            sni: context.selected_sni || context.remote_sni || null,
            alpn: context.selected_alpn || null,
            created: Date.now(),
          });
          ev.emit('session', server_session_blob);
        }

        // TLS 1.2 server: emit 'newSession' for Session ID-based resumption.
        // Fires whenever we generated a session_id for this connection AND didn't issue
        // a NewSessionTicket (so the client can only resume via Session ID — we need the
        // user to store the session state). TLS 1.2 only (DTLS 1.2 excluded for now).
        if (context.selected_version === wire.TLS_VERSION.TLS1_2 &&
            context.isServer && !context.tls12_abbreviated && !context.tls12_newsession_sent &&
            context.tls12_session_id_for_store && !context.tls12_session_id_emitted && context.base_secret &&
            context.remote_finished_ok) {

          context.tls12_session_id_emitted = true;

          // Ensure ticketKeys is 48 bytes (used to encrypt stored session data)
          if (!context.ticketKeys || context.ticketKeys.length !== 48) {
            context.ticketKeys = crypto.randomBytes(48);
          }

          let stored_blob = encrypt_session_blob({
            v: 12,
            version: context.selected_version,
            cipher: context.selected_cipher_suite,
            master_secret: context.base_secret,
            extended_master_secret: !!context.use_extended_master_secret,
            sni: context.selected_sni || context.remote_sni || null,
            alpn: context.selected_alpn || null,
            created: Date.now(),
          }, context.ticketKeys);

          // User stores this; returns it on next handshake via 'resumeSession' callback.
          ev.emit('newSession', context.tls12_session_id_for_store, stored_blob, function() {
            // Callback is advisory — we don't block on it in lemon-tls.
            // (Node.js blocks the handshake until callback is invoked, but our reactive
            // model decouples this: the session is marked for storage and we continue.)
          });
        }

        // TLS 1.2 client: emit 'session' for Session ID-only resumption (no ticket received).
        // Fires at secureConnect when the server gave us a non-empty session_id but no
        // NewSessionTicket — the client's only way to resume is via Session ID, so we must
        // give the user a blob containing session_id + master_secret to pass back later.
        // TLS 1.2 only (DTLS 1.2 excluded for now).
        if (context.selected_version === wire.TLS_VERSION.TLS1_2 &&
            !context.isServer && !context.tls12_abbreviated && !context.tls12_client_session_emitted &&
            context.remote_session_id && context.remote_session_id.length > 0 &&
            context.base_secret && context.remote_finished_ok) {

          context.tls12_client_session_emitted = true;

          let session_blob = encode_client_session({
            v: 12,                                    // blob kind: TLS 1.2
            version: context.selected_version,
            cipher: context.selected_cipher_suite,
            master_secret: context.base_secret,
            extended_master_secret: !!context.use_extended_master_secret,
            ticket: null,                             // no ticket — Session ID only
            session_id: context.remote_session_id,
            sni: context.local_sni || null,
            alpn: context.selected_alpn || null,
            created: Date.now(),
          });
          ev.emit('session', session_blob);
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
        { type: 'EXTENDED_MASTER_SECRET', value: null }
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

      // Resumption: check if session was provided (opaque Buffer) — decode to structured data
      let sessionData = null;
      if (options.session) {
        // options.session may be a Buffer/Uint8Array (Node.js style) or a plain object (legacy)
        if (options.session instanceof Uint8Array || Buffer.isBuffer(options.session)) {
          sessionData = decode_client_session(options.session);
        } else if (typeof options.session === 'object') {
          sessionData = options.session; // legacy: already-structured object
        }
      } else if (options.psk) {
        sessionData = options.psk; // legacy path
      }

      let message_data;

      // TLS 1.3 PSK resumption (sessionData contains psk)
      if (sessionData && sessionData.psk && sessionData.ticket && sessionData.cipher) {
        // Add PSK key exchange modes (psk_dhe_ke = 1)
        extensions.push({ type: 'PSK_KEY_EXCHANGE_MODES', value: [1] });

        // Save PSK for later verification
        context.psk_offered = {
          identity: sessionData.ticket,
          psk: sessionData.psk instanceof Uint8Array ? sessionData.psk : new Uint8Array(sessionData.psk),
          cipher: sessionData.cipher,
          age_add: sessionData.age_add || 0,
        };

        // Compute obfuscated ticket age
        let ticketAge = sessionData.lifetime ? Math.min((Date.now() - (sessionData.created || Date.now())) / 1000, sessionData.lifetime) * 1000 : 0;
        let obfuscatedAge = ((ticketAge + (sessionData.age_add || 0)) & 0xFFFFFFFF) >>> 0;

        // Build ClientHello with placeholder binder to compute truncated hash
        let hashName = TLS_CIPHER_SUITES[sessionData.cipher] ? TLS_CIPHER_SUITES[sessionData.cipher].hash : 'sha256';
        let hashLen = getHashFn(hashName).outputLen;
        let placeholderBinder = new Uint8Array(hashLen);

        let pskExt = {
          type: 'PRE_SHARED_KEY',
          value: {
            identities: [{ identity: sessionData.ticket, age: obfuscatedAge }],
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

        dbg('CLI-PSK', 'ticket:', hexPreview(sessionData.ticket, 24),
            'cipher:', '0x' + sessionData.cipher.toString(16),
            'hash:', hashName);
        dbg('CLI-PSK', 'psk:', hexPreview(sessionData.psk, 8),
            'age_add:', sessionData.age_add,
            'lifetime:', sessionData.lifetime,
            'ticketAge (ms):', ticketAge,
            'obfuscatedAge:', obfuscatedAge);
        dbg('CLI-PSK', 'truncatedMessage len:', truncatedMessage.length,
            'full CH len (after real binder):', 'see next');
        dbg('CLI-PSK', 'sent binder:', hexPreview(binder, 16));

        // Rebuild with real binder
        pskExt.value.binders = [binder];
        message_data = build_tls_message(build_message_params);

      } else if (sessionData && sessionData.v === 12 && sessionData.master_secret) {
        // TLS 1.2 resumption: session ID and/or SessionTicket
        // Save for later verification when ServerHello arrives
        context.tls12_client_session = sessionData;

        // Only advertise SESSION_TICKET ext if we actually have a ticket to present.
        // If we only have a session_id (no ticket), don't include empty SESSION_TICKET ext:
        // servers with SSL_OP_NO_TICKET can behave inconsistently when the extension appears
        // alongside a session_id resumption attempt — they may skip the session_id lookup.
        if (sessionData.ticket && sessionData.ticket.length > 0) {
          extensions.push({ type: 'SESSION_TICKET', value: sessionData.ticket });
        }

        // If we have a session_id → put it in ClientHello.session_id (overrides the random one)
        let sid = context.local_session_id;
        if (sessionData.session_id && sessionData.session_id.length > 0) {
          sid = sessionData.session_id;
          context.local_session_id = sid;
        }

        let build_message_params = {
          type: 'client_hello',
          version: 0x0303,
          random: context.local_random,
          session_id: sid,
          cookie: context.dtls_cookie,
          cipher_suite: context.local_supported_cipher_suites,
          extensions: extensions
        };
        message_data = build_tls_message(build_message_params);

      } else {
        // No resumption — advertise empty SessionTicket extension to offer support.
        // Skip for DTLS (DTLS clients/servers often don't implement RFC 5077 fully,
        // and adding it caused interop issues with openssl s_server -dtls1_2).
        let isDtls = context.local_supported_versions && context.local_supported_versions.some(v => (v & 0xFF00) === 0xFE00);
        if (!isDtls && context.sessionTickets) {
          extensions.push({ type: 'SESSION_TICKET', value: new Uint8Array(0) });
        }

        // Standard ClientHello
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
      return context.selected_alpn || null;
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

