/**
 * dtls_session.js — DTLS 1.2 + 1.3 session (client + server).
 *
 * Wraps TLSSession (composition) and adds:
 *   - DTLS record layer (plaintext + encrypted via record.js)
 *   - Reconstruction headers (add on output, strip on input)
 *   - Fragmentation and reassembly
 *   - Flight-based retransmission
 *   - HelloVerifyRequest (DTLS 1.2)
 *   - ACK records (DTLS 1.3)
 *   - Epoch + key management
 *   - Version mapping (TLSSession works internally, DTLS on the wire)
 *
 * Events emitted:
 *   'packet'  (Uint8Array)  — DTLS datagram ready to send via UDP
 *   'connect' ()            — handshake complete
 *   'data'    (Uint8Array)  — decrypted application data received
 *   'error'   (Error)
 *   'close'   ()
 *
 * Usage:
 *   let dtls = new DTLSSession({ isServer: false, servername: 'example.com' });
 *   dtls.on('packet', (data) => udpSocket.send(data, remotePort, remoteAddr));
 *   dtls.on('connect', () => dtls.send(new TextEncoder().encode('hello')));
 *   dtls.on('data', (data) => console.log('received:', data));
 *   dtls.feedDatagram(incomingUdpPayload);
 */

import { EventEmitter } from 'node:events';
import crypto from 'node:crypto';

import TLSSession from './tls_session.js';
import createSecureContext from './secure_context.js';

import {
  DTLS_VERSION,
  build_dtls_handshake,
  parse_dtls_handshake,
  build_message,
  build_hello_verify_request,
  parse_hello_verify_request,
  parse_hello,
} from './wire.js';

import {
  TLS_CIPHER_SUITES,
  hkdf_expand_label,
  derive_sn_key,
} from './crypto.js';

import {
  CT,
  getAeadAlgo,
  deriveKeys12,
  decryptDtls12,
  buildDtlsPlaintext,
  buildEncryptedDtls12,
  buildEncryptedDtls13,
  parseDtlsDatagram,
  buildDtlsAck,
  parseDtlsAck,
} from './record.js';

import { timingSafeEqualU8 } from './utils.js';


// ============================================================
//  Helpers
// ============================================================

// ============================================================
//  DTLSSession
// ============================================================

/**
 * Insert a DTLS cookie into a ClientHello TLS message.
 * CH1 format: type(1) + length(3) + version(2) + random(32) + sid_len(1) + sid + cookie_len(1) + cookie(0) + ...
 * Returns new Uint8Array with cookie inserted.
 */
function insertCookieIntoClientHello(ch1, cookie) {
  let off = 4; // skip type(1)+length(3)
  off += 2;    // version
  off += 32;   // random
  let sidLen = ch1[off];
  off += 1 + sidLen; // session_id

  // Now at cookie_len position
  let oldCookieLen = ch1[off];
  let cookiePos = off;

  // Build CH2: [before cookie_len] + [new cookie_len + cookie] + [after old cookie]
  let before = ch1.subarray(0, cookiePos);
  let after  = ch1.subarray(cookiePos + 1 + oldCookieLen);

  let ch2 = new Uint8Array(before.length + 1 + cookie.length + after.length);
  ch2.set(before, 0);
  ch2[before.length] = cookie.length;
  ch2.set(cookie, before.length + 1);
  ch2.set(after, before.length + 1 + cookie.length);

  // Update handshake length field (bytes 1-3)
  let newBodyLen = ch2.length - 4;
  ch2[1] = (newBodyLen >> 16) & 0xff;
  ch2[2] = (newBodyLen >> 8) & 0xff;
  ch2[3] = newBodyLen & 0xff;

  return ch2;
}

// Handshake diagnostics — off by default; enabled via LEMON_DEBUG=1 (or
// WEBRTC_DEBUG=1 so one flag lights up the whole webrtc-server stack).
// Interop failures in DTLS are notoriously silent (a record that fails
// decryption or ordering simply vanishes); these logs make every inbound
// record, ordering decision, and completion visible without a packet dump.
var LEMON_DEBUG = typeof process !== 'undefined' && process.env &&
  (process.env.LEMON_DEBUG === '1' || process.env.WEBRTC_DEBUG === '1');
function _ldbg() {
  if (!LEMON_DEBUG) return;
  if (typeof console !== 'undefined' && console.log) {
    console.log.apply(console, ['[lemon-dtls]'].concat([].slice.call(arguments)));
  }
}

function DTLSSession(options) {
  if (!(this instanceof DTLSSession)) return new DTLSSession(options);
  options = options || {};

  let ev = new EventEmitter();
  let isServer = !!options.isServer;

  // ---- Internal TLSSession ----
  let tls = new TLSSession({
    isServer: isServer,
    // RFC 9147 §5.3: the DTLS ClientHello's legacy_session_id "MUST be
    // set to a zero-length vector" — the 32-byte compatibility sid is a
    // TLS-over-TCP middlebox trick (RFC 8446 §4.1.2) that DTLS excludes
    // (8446 appendix D.4: no compatibility mode over DTLS). The TLS
    // engine generates the compat sid when none is supplied, so pin it
    // empty for DTLS, both 1.2 and 1.3 profiles. (Also sidesteps a
    // deployed-parser landmine: webrtc-dtls ≤0.7 reads the sid LENGTH
    // byte and never the body, so any non-empty sid shears its whole
    // ClientHello parse.)
    sessionId: new Uint8Array(0),
    servername: options.servername,
    SNICallback: options.SNICallback,
    rejectUnauthorized: options.rejectUnauthorized,
    ca: options.ca,
    noTickets: options.noTickets,
    requestCert: options.requestCert,
    cert: options.cert,
    key: options.key,
    ticketKeys: options.ticketKeys,
  });

  // ---- DTLS context ----
  let ctx = {
    state: 'idle',         // idle → handshaking → connected → closed
    isServer: isServer,
    mtu: options.mtu || 1200,

    // Upper bound on a single reassembled handshake message. The DTLS handshake
    // header carries a 24-bit length (up to 16MB), which is attacker-controlled
    // on the very first fragment. Without a cap, a peer could send one fragment
    // claiming length 0xFFFFFF for several msg_seqs and force large allocations
    // before anything is authenticated. 256KB comfortably fits a real
    // certificate-chain flight while bounding the damage. Configurable via
    // options.maxHandshakeMessageSize.
    maxHandshakeMessageSize: options.maxHandshakeMessageSize || (256 * 1024),

    // Version (determined after negotiation)
    selectedVersion: null,  // DTLS version (0xFEFC or 0xFEFD)

    // Keys by DTLS epoch
    // epoch 0: cleartext
    // DTLS 1.2: epoch 1 = after CCS
    // DTLS 1.3: epoch 2 = handshake, epoch 3 = application
    keys: {},

    // Record sequence numbers (per epoch, for sending)
    writeSeq: {},

    // Cipher info (set when handshake secrets arrive)
    cipherSuite: null,
    hashName: null,

    // Fragment reassembly: msg_seq → { totalLength, type, chunks:[{off,end,body}], covered }
    fragments: {},

    // Incoming handshake msg_seq tracking
    nextReadMsgSeq: 0,

    // Out-of-order handshake buffering (RFC 6347 §4.2.4 / RFC 9147 §5.2):
    // complete messages that arrive ahead of nextReadMsgSeq are held here,
    // keyed by msg_seq, and drained in order once the gap is filled.
    pendingMessages: {},   // msg_seq → { type, body }

    // Flight tracking for retransmission
    currentFlight: [],     // array of { epoch, data: Uint8Array (complete datagram) }
    // RFC 6347 §4.2.4 flight discipline: a NEW flight begins with the first
    // record we send after having accepted new handshake data from the peer.
    // Set when inbound processing advances state; consumed (and reset) by
    // the outgoing path, which then starts a fresh currentFlight. Without
    // this boundary, flights ACCUMULATED: after the HVR exchange the client's
    // flight 5 (CKE/CCS/Finished) was appended onto the CH2 still sitting in
    // currentFlight, so a flight-5 retransmission replayed the ClientHello
    // too — which a connected werift server answers with renegotiation(),
    // destroying the session instead of recovering it.
    newFlightPending: false,
    retransmitTimer: null,
    retransmitCount: 0,
    retransmitTimeout: 1000,
    maxRetransmits: 6,

    // DTLS 1.2: CCS tracking
    localCcsSent: false,
    remoteCcsSeen: false,

    // HelloVerifyRequest (DTLS 1.2 server)
    hvrCookie: null,       // cookie sent in HVR
    hvrDone: false,        // true after HVR exchange complete
  };


  // ============================================================
  //  Setup TLSSession for DTLS
  // ============================================================

  // Set DTLS versions and cookie (triggers DTLS format in build_hello)
  let versions = [];
  let minVer = options.minVersion || 'DTLSv1.2';
  let maxVer = options.maxVersion || 'DTLSv1.3';
  if (maxVer === 'DTLSv1.3' || maxVer === 'TLSv1.3') versions.push(DTLS_VERSION.DTLS1_3);
  if (minVer === 'DTLSv1.2' || minVer === 'TLSv1.2' || maxVer === 'DTLSv1.2') versions.push(DTLS_VERSION.DTLS1_2);
  if (versions.length === 0) versions = [DTLS_VERSION.DTLS1_3, DTLS_VERSION.DTLS1_2];

  let tlsSetup = {
    local_supported_versions: versions,
    dtls_cookie: new Uint8Array(0),  // empty cookie — triggers DTLS format
  };

  // Pass through cipher/group/alpn preferences
  if (options.cipherSuites) tlsSetup.local_supported_cipher_suites = options.cipherSuites;

  // Client cipher defaults: TLSSession auto-populates both TLS 1.3+1.2 ciphers,
  // but if we only support DTLS 1.2, we must not offer TLS 1.3 ciphers
  // (the server might erroneously select one for a 1.2 connection).
  if (!isServer && !options.cipherSuites && versions.indexOf(DTLS_VERSION.DTLS1_3) < 0) {
    tlsSetup.local_supported_cipher_suites = [0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8];
  }
  if (options.groups) tlsSetup.local_supported_groups = options.groups;
  if (options.alpnProtocols) tlsSetup.local_supported_alpns = options.alpnProtocols;

  // Server defaults — TLSSession client auto-populates these, but server expects them set externally
  if (isServer) {
    if (!tlsSetup.local_supported_cipher_suites) {
      let ciphers = [];
      if (versions.indexOf(DTLS_VERSION.DTLS1_3) >= 0) {
        ciphers.push(0x1301, 0x1302, 0x1303); // TLS 1.3 AEAD ciphers
      }
      if (versions.indexOf(DTLS_VERSION.DTLS1_2) >= 0) {
        ciphers.push(0xC02F, 0xC030, 0xC02B, 0xC02C); // TLS 1.2 ECDHE ciphers
      }
      tlsSetup.local_supported_cipher_suites = ciphers;
    }
    if (!tlsSetup.local_supported_groups) {
      tlsSetup.local_supported_groups = [0x001d, 0x0017, 0x0018];
    }
    tlsSetup.local_supported_signature_algorithms = [
      0x0804, 0x0805, 0x0806,  // RSA-PSS
      0x0403, 0x0503, 0x0603,  // ECDSA
      0x0807, 0x0808,          // EdDSA
      0x0401, 0x0501, 0x0601,  // PKCS#1
    ];
  }

  // Server cert/key
  if (options.cert && options.key) {
    let sctx = createSecureContext({ key: options.key, cert: options.cert });
    tlsSetup.local_cert_chain = sctx.certificateChain;
    tlsSetup.cert_private_key = sctx.privateKey;
  }

  tls.set_context(tlsSetup);


  // ============================================================
  //  DTLS 1.2 transcript hook (RFC 6347 §4.2.6)
  //
  //  DTLS 1.2 requires the handshake hash to include DTLS-specific
  //  reconstruction data (msg_seq + frag_offset + frag_length).
  //  We hook into TLSSession's transcript to transparently convert
  //  TLS-format entries to DTLS-format when the version is DTLS 1.2.
  //
  //  For DTLS 1.3 and TLS, the transcript uses standard TLS format.
  // ============================================================

  let transcriptMsgSeqs = [];  // parallel array: msg_seq for each transcript entry

  tls.context.transcriptHook = function(data) {
    // Determine msg_seq: incoming uses _incomingMsgSeq (set by deliverHandshakeMessage),
    // outgoing uses message_sent_seq (TLSSession's counter).
    let msgSeq;
    if (ctx._incomingMsgSeq !== undefined) {
      msgSeq = ctx._incomingMsgSeq;
      ctx._incomingMsgSeq = undefined; // one-shot: only applies to the first push
    } else {
      msgSeq = tls.context.message_sent_seq;
    }
    transcriptMsgSeqs.push(msgSeq);

    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_2) {
      return build_dtls_handshake(data, msgSeq);
    }
    return data; // TLS format for DTLS 1.3 or unknown version
  };

  /**
   * Called when selectedVersion is first determined as DTLS 1.2.
   * Retroactively converts all existing transcript entries to DTLS format.
   */
  function fixTranscriptForDtls12() {
    let t = tls.context.transcript;
    for (let i = 0; i < t.length; i++) {
      if (i < transcriptMsgSeqs.length) {
        t[i] = build_dtls_handshake(t[i], transcriptMsgSeqs[i]);
      }
    }
  }


  // ============================================================
  //  Key derivation
  // ============================================================

  function deriveEpochKeys(secret) {
    let cs = TLS_CIPHER_SUITES[ctx.cipherSuite];
    let empty = new Uint8Array(0);
    let key = hkdf_expand_label(cs.hash, secret, 'key', empty, cs.keylen);
    let iv = hkdf_expand_label(cs.hash, secret, 'iv', empty, 12);

    let result = { key, iv };

    // DTLS 1.3: derive sn_key for record number encryption
    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3) {
      result.snKey = derive_sn_key(cs.hash, secret, ctx.cipherSuite);
      result.algo = getAeadAlgo(ctx.cipherSuite);
    }

    return result;
  }

  tls.on('handshakeSecrets', function(localSecret, remoteSecret) {
    // Ensure version is detected before key derivation
    if (ctx.selectedVersion === null) ctx.selectedVersion = tls.context.selected_version;
    ctx.cipherSuite = tls.getCipher();
    ctx.hashName = TLS_CIPHER_SUITES[ctx.cipherSuite].hash;

    let dtlsEpoch = ctx.selectedVersion === DTLS_VERSION.DTLS1_3 ? 2 : 1;

    ctx.keys[dtlsEpoch] = {
      write: deriveEpochKeys(localSecret),
      read: deriveEpochKeys(remoteSecret),
    };
    ctx.writeSeq[dtlsEpoch] = 0;
  });

  tls.on('appSecrets', function(localSecret, remoteSecret) {
    let dtlsEpoch = ctx.selectedVersion === DTLS_VERSION.DTLS1_3 ? 3 : 1;

    ctx.keys[dtlsEpoch] = {
      write: deriveEpochKeys(localSecret),
      read: deriveEpochKeys(remoteSecret),
    };
    ctx.writeSeq[dtlsEpoch] = 0;
  });


  // ============================================================
  //  Outgoing: TLSSession message → DTLS datagram
  // ============================================================

  tls.on('message', function(tlsEpoch, seq, type, data) {
    // Ensure version is detected
    if (ctx.selectedVersion === null && tls.context.selected_version) {
      ctx.selectedVersion = tls.context.selected_version;
      // If just determined as DTLS 1.2, retroactively fix transcript entries
      // that were pushed before the version was known.
      if (ctx.selectedVersion === DTLS_VERSION.DTLS1_2) {
        fixTranscriptForDtls12();
      }
    }

    // Save client's CH1 for potential HVR retry
    if (type === 'hello' && !isServer) {
      ctx.savedClientHello = data;
    }

    // Map TLS epoch → DTLS epoch
    let dtlsEpoch;
    if (tlsEpoch === 0) {
      dtlsEpoch = 0;
    } else if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3) {
      dtlsEpoch = tlsEpoch === 1 ? 2 : 3;  // epoch 2=handshake, 3=app
    } else {
      dtlsEpoch = 1;  // DTLS 1.2: epoch 1 for all encrypted
    }

    if (type === 'alert') {
      sendAlertRecord(dtlsEpoch, data);
      return;
    }

    // DTLS 1.2: derive keys before first encrypted message
    if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3 && tlsEpoch === 1 && !ctx.keys[1]) {
      let ts = tls.getTrafficSecrets();
      if (ts.masterSecret) {
        let d12 = deriveKeys12(ts.masterSecret, ts.localRandom, ts.remoteRandom, tls.getCipher(), isServer);
        ctx.keys[1] = {
          write: { key: d12.writeKey, iv: d12.writeIv },
          read:  { key: d12.readKey,  iv: d12.readIv },
        };
        ctx.writeSeq[1] = 0;
      }
    }

    // Flight boundary: first outgoing record after accepting peer data
    // starts a fresh flight (clears the previous flight's records and
    // resets the retransmit budget — RFC 6347 §4.2.4).
    if (ctx.newFlightPending) {
      ctx.newFlightPending = false;
      startNewFlight();
    }

    // DTLS 1.2: send CCS before first encrypted message (Finished)
    if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3 && tlsEpoch === 1 && !ctx.localCcsSent) {
      sendCCS();
    }

    // Convert TLS handshake message → DTLS handshake message (add reconstruction header)
    let dtlsMsg = build_dtls_handshake(data, seq);

    // Fragment if needed
    let frags = fragmentMessage(dtlsMsg, data, seq);

    // Build DTLS records and emit
    for (let i = 0; i < frags.length; i++) {
      let record = buildRecord(dtlsEpoch, CT.HANDSHAKE, frags[i]);
      ctx.currentFlight.push(record);
      ev.emit('packet', record);
    }

    // Start retransmit timer after sending flight messages.
    //
    // BUGFIX (one-shot initial ClientHello): ctx.state only left 'idle'
    // inside feedDatagram — i.e. on the first INBOUND datagram. A
    // client's first flight is sent before anything has been received,
    // so the 'handshaking'-only guard below never armed the retransmit
    // timer for flight 1. A lost or early-dropped ClientHello — e.g. one
    // arriving while the peer's ICE layer still discards non-STUN
    // traffic, a routine race right after nomination — was therefore
    // never retransmitted, and the handshake hung silently forever
    // (surfacing as connectionState stuck at 'connecting'). RFC 6347
    // §4.2.4's flight state machine has no unguarded flights: every
    // flight except the handshake-final one must sit under a retransmit
    // timer. Sending a handshake flight IS handshaking — reflect that in
    // the state before consulting it.
    if (ctx.state === 'idle') ctx.state = 'handshaking';
    if (ctx.state === 'handshaking') {
      startRetransmitTimer();
    }
  });

  /**
   * Build a DTLS record (plaintext or encrypted depending on epoch and key availability).
   */
  function buildRecord(epoch, contentType, payload) {
    let epochKeys = ctx.keys[epoch];

    if (!epochKeys) {
      // No keys → plaintext record
      return buildDtlsPlaintext(contentType, epoch, nextWriteSeq(epoch), payload);
    }

    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3) {
      // DTLS 1.3 encrypted (unified header)
      return buildEncryptedDtls13(contentType, payload, nextWriteSeq(epoch), epoch, epochKeys.write);
    } else {
      // DTLS 1.2 encrypted (classic header)
      return buildEncryptedDtls12(contentType, epoch, nextWriteSeq(epoch), payload, epochKeys.write);
    }
  }

  function nextWriteSeq(epoch) {
    if (!(epoch in ctx.writeSeq)) ctx.writeSeq[epoch] = 0;
    return ctx.writeSeq[epoch]++;
  }

  /**
   * Fragment a DTLS handshake message if it exceeds MTU.
   * Returns array of DTLS handshake message fragments (each with reconstruction header).
   */
  function fragmentMessage(dtlsMsg, tlsMsg, msgSeq) {
    // Record-layer overhead we must leave room for inside one datagram/MTU:
    //   DTLS 1.2: 13-byte classic record header + 16-byte AEAD tag (+8 explicit
    //             nonce for GCM, but that lives inside the encrypted payload the
    //             record layer builds, so we keep a small safety margin).
    //   DTLS 1.3: 5-byte unified header (2-byte seq + length) + 16-byte AEAD tag.
    // Using the correct, smaller 1.3 overhead avoids over-fragmenting.
    let isDtls13 = ctx.selectedVersion === DTLS_VERSION.DTLS1_3;
    let recordOverhead = isDtls13 ? (5 + 16) : (13 + 16 + 8);
    let maxFragment = ctx.mtu - recordOverhead;

    // The DTLS handshake message header is 12 bytes; the body is what we chunk.
    const HS_HDR = 12;
    if (dtlsMsg.length <= maxFragment) return [dtlsMsg];

    // Need to fragment: split the TLS body into chunks
    let body = tlsMsg.subarray(4); // skip TLS header (type+length)
    let totalLength = body.length;
    let fragments = [];
    let offset = 0;

    // Each fragment carries its own 12-byte handshake header, so the payload
    // budget per fragment is maxFragment - HS_HDR.
    let maxChunk = Math.max(1, maxFragment - HS_HDR);
    while (offset < totalLength) {
      let chunkLen = Math.min(maxChunk, totalLength - offset);
      let frag = build_dtls_handshake(tlsMsg, msgSeq, offset, chunkLen);
      fragments.push(frag);
      offset += chunkLen;
    }

    return fragments;
  }

  /**
   * Send an alert record.
   */
  function sendAlertRecord(epoch, alertData) {
    let record = buildRecord(epoch, CT.ALERT, alertData);
    ev.emit('packet', record);
  }

  /**
   * Send CCS record (DTLS 1.2 only).
   */
  function sendCCS() {
    if (ctx.localCcsSent) return;
    ctx.localCcsSent = true;
    // The server's final flight OPENS with CCS — honor the flight boundary
    // here too, before this record is captured.
    if (ctx.newFlightPending) {
      ctx.newFlightPending = false;
      startNewFlight();
    }
    let record = buildDtlsPlaintext(CT.CHANGE_CIPHER_SPEC, 0, nextWriteSeq(0), new Uint8Array([1]));
    // RFC 6347 §4.2.4: the CCS is part of the flight and MUST be included
    // when the flight is retransmitted. Previously it was emitted but never
    // captured, so a retransmitted final flight arrived WITHOUT the cipher-
    // spec change and the peer could never decrypt the accompanying
    // Finished — an unrecoverable stall under single-datagram loss.
    ctx.currentFlight.push(record);
    ev.emit('packet', record);
  }


  // ============================================================
  //  Incoming: UDP datagram → parse → feed TLSSession
  // ============================================================

  function feedDatagram(data) {
    if (ctx.state === 'closed') return;
    if (ctx.state === 'idle') ctx.state = 'handshaking';

    // Build key lookup for decryption
    let keysByEpoch = {};
    for (let ep in ctx.keys) {
      if (ctx.keys[ep] && ctx.keys[ep].read) {
        keysByEpoch[Number(ep)] = ctx.keys[ep].read;
      }
    }

    let records = parseDtlsDatagram(data, keysByEpoch);

    if (LEMON_DEBUG) {
      var _summ = [];
      for (var _ri = 0; _ri < records.length; _ri++) {
        var _r = records[_ri];
        _summ.push('type=' + _r.type + ' epoch=' + _r.epoch + ' seq=' + _r.seq +
          (_r.epoch > 0 && !_r.encrypted ? ' UNDECRYPTED' : ''));
      }
      _ldbg('rx datagram len=' + data.length + ' state=' + ctx.state +
        ' records: [' + _summ.join(' | ') + ']');
    }

    // RFC 9147 §7: collect the record numbers of handshake records we received
    // in this datagram so we can ACK them once, after processing. Only for
    // DTLS 1.3, and only while we're still handshaking (post-handshake ACKs of
    // NewSessionTicket etc. are optional and skipped here for simplicity).
    let ackable = [];

    for (let i = 0; i < records.length; i++) {
      if (records[i].type === CT.HANDSHAKE &&
          ctx.selectedVersion === DTLS_VERSION.DTLS1_3) {
        ackable.push({ epoch: records[i].epoch, seq: records[i].seq });
      }

      processRecord(records[i]);

      // After CCS, keys are newly available — re-decrypt remaining epoch>0 records
      if (records[i].type === CT.CHANGE_CIPHER_SPEC && ctx.keys[1]) {
        let readKeys = ctx.keys[1].read;
        for (let j = i + 1; j < records.length; j++) {
          if (!records[j].encrypted && records[j].epoch > 0 && readKeys) {
            try {
              records[j].content = decryptDtls12(records[j].content, readKeys.key, readKeys.iv, records[j].epoch, records[j].seq, records[j].type);
              records[j].encrypted = true;
            } catch(e) {
            }
          }
        }
      }
    }

    // Send a single ACK covering all handshake records received in this datagram.
    // We ACK from the highest epoch for which we already have write keys (so the
    // ACK itself is protected once handshake keys exist; epoch 0 before that).
    if (ackable.length > 0) {
      let ackEpoch = ctx.keys[3] ? 3 : (ctx.keys[2] ? 2 : 0);
      sendAck(ackEpoch, ackable);
    }
  }

  function processRecord(record) {
    if (record.type === CT.HANDSHAKE) {
      // An epoch>0 record that could not be decrypted (keys not yet
      // installed, AEAD failure) must NOT be fed to the handshake
      // parser: its content is ciphertext, and parsing it yields a
      // garbage "message" with attacker-controllable type/length fields.
      // Drop it — DTLS is loss-tolerant by design, and the peer's (or
      // our own flight-elicited) retransmission delivers a fresh copy
      // once it can be decrypted.
      if (record.epoch > 0 && !record.encrypted) {
        _ldbg('skip undecrypted epoch=' + record.epoch + ' seq=' + record.seq +
          ' len=' + (record.content ? record.content.length : 0));
        return;
      }
      processHandshakeRecord(record.content, record.epoch, record.encrypted);
    } else if (record.type === CT.APPLICATION_DATA) {
      if (ctx.state === 'connected') {
        ev.emit('data', record.content);
      }
    } else if (record.type === CT.CHANGE_CIPHER_SPEC) {
      // DTLS 1.2: peer sent CCS — derive keys if not yet done
      ctx.remoteCcsSeen = true;
      if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3 && !ctx.keys[1]) {
        let ts = tls.getTrafficSecrets();
        if (ts.masterSecret) {
          let d12 = deriveKeys12(ts.masterSecret, ts.localRandom, ts.remoteRandom, tls.getCipher(), isServer);
          ctx.keys[1] = {
            write: { key: d12.writeKey, iv: d12.writeIv },
            read:  { key: d12.readKey,  iv: d12.readIv },
          };
          ctx.writeSeq[1] = 0;
        }
      }
    } else if (record.type === CT.ACK) {
      processAck(record.content);
    } else if (record.type === CT.ALERT) {
      let level = record.content[0];
      let desc = record.content[1];
      if (desc === 0) {
        // close_notify
        ctx.state = 'closed';
        ev.emit('close');
      } else {
        ev.emit('error', new Error('DTLS alert: level=' + level + ' desc=' + desc));
      }
    }
  }

  /**
   * Process a handshake record. Handles reassembly and feeds to TLSSession.
   */
  function processHandshakeRecord(data, epoch, encrypted) {
    // A handshake record may contain multiple handshake messages
    let off = 0;
    let sawMessage = false;   // record contained ≥1 parseable handshake message
    let anyNew = false;       // ≥1 message advanced our state (not a duplicate)
    while (off + 12 <= data.length) {
      let parsed = parse_dtls_handshake(data.subarray(off));

      let msgSeq = parsed.msg_seq;
      let totalLen = parsed.length;
      let fragOffset = parsed.frag_offset;
      let fragLen = parsed.frag_length;
      sawMessage = true;
      _ldbg('hs msg: type=' + parsed.type + ' msgSeq=' + msgSeq +
        ' len=' + totalLen + ' frag=' + fragOffset + '+' + fragLen +
        ' nextReadMsgSeq=' + ctx.nextReadMsgSeq);

      // Is this a complete message or a fragment?
      if (fragOffset === 0 && fragLen === totalLen) {
        // Complete message — feed directly
        if (deliverHandshakeMessage(parsed.type, parsed.body, msgSeq)) anyNew = true;
      } else {
        // Fragment — reassemble
        if (reassembleFragment(parsed)) anyNew = true;
      }

      off += 12 + fragLen;
    }

    // ── Implicit-ACK discipline (RFC 6347 §4.2.4) ──
    // Receiving a message from the peer's NEXT flight is the implicit ACK
    // of ours — only then may our retransmit timer be cancelled. The
    // previous unconditional cancelRetransmit() here also fired on pure
    // RETRANSMISSIONS of the peer's PREVIOUS flight, which mean the exact
    // opposite: our reply was lost. Two concrete deadlocks that caused:
    //   1. Our cookie-bearing CH2 is lost → server retransmits its HVR
    //      (seq 0, discarded as a duplicate) → cancel killed the CH2
    //      timer → CH2 never resent → handshake dead.
    //   2. Our final flight (CKE/CCS/Finished) is lost → server
    //      retransmits its flight (all seqs below nextReadMsgSeq,
    //      discarded) → cancel killed the flight timer → dead.
    // NOTE: the implicit-ACK cancel deliberately does NOT live here.
    // Everything in this function runs AFTER deliverHandshakeMessage,
    // and TLS produces our response flight synchronously inside the
    // feed — so a cancel at this point lands on the freshly-armed timer
    // of the flight we JUST sent, not on the acknowledged one. The
    // cancel happens at the acceptance points inside
    // deliverHandshakeMessage instead, before the feed.
    if (anyNew) {
      // handled at acceptance time
    } else if (sawMessage && ctx.currentFlight.length > 0 &&
               ctx.state !== 'connected' &&
               ctx.selectedVersion !== DTLS_VERSION.DTLS1_3 &&
               // Damping: a peer retransmits its flight as SEVERAL
               // datagrams; without a guard, EACH duplicate datagram
               // elicited a full resend of our flight — a ×N
               // amplification burst that itself increased loss
               // pressure. One resend per 250ms answers the peer's
               // whole retransmitted flight exactly once.
               (Date.now() - (ctx._lastDupElicitedResend || 0)) >= 250) {
      ctx._lastDupElicitedResend = Date.now();
      // Pure duplicate of a previous peer flight while we still have an
      // outstanding flight of our own: the peer is telling us it never
      // got our reply. Resend it immediately (RFC 6347 §4.2.4 responder
      // behavior) rather than waiting out our own backoff. The regular
      // timer keeps running unchanged, so the retransmit budget still
      // bounds the total effort; the resend rate is naturally bounded by
      // the peer's own retransmission schedule. DTLS 1.3 is excluded —
      // it uses explicit ACKs (RFC 9147 §7) instead of flight inference.
      for (let f = 0; f < ctx.currentFlight.length; f++) {
        ev.emit('packet', ctx.currentFlight[f]);
      }
    }
  }

  /**
   * Reassemble a (possibly fragmented) handshake message.
   *
   * RFC 6347 §4.2.3 / RFC 9147 §5.5: fragments may overlap and arrive out of
   * order, because a retransmission can re-fragment the same message with
   * different boundaries (e.g. after a PMTU change). We therefore copy each
   * fragment's bytes into a full-length buffer and track coverage as a set of
   * merged byte-ranges, rather than requiring each fragment to start exactly
   * where the previous one ended.
   */
  function reassembleFragment(parsed) {
    let key = parsed.msg_seq;

    // Ignore fragments for messages we've already delivered.
    if (key < ctx.nextReadMsgSeq) return false;

    // DoS guard: the 24-bit `length` is attacker-controlled on the first
    // fragment. Reject anything claiming more than our cap BEFORE allocating,
    // so a peer can't force huge buffers with a single unauthenticated packet.
    if (parsed.length > ctx.maxHandshakeMessageSize) {
      ev.emit('error', new Error('DTLS handshake message exceeds maxHandshakeMessageSize (' +
        parsed.length + ' > ' + ctx.maxHandshakeMessageSize + ')'));
      return false;
    }

    let frag = ctx.fragments[key];
    if (!frag) {
      frag = ctx.fragments[key] = {
        totalLength: parsed.length,
        type: parsed.type,
        buf: new Uint8Array(parsed.length),
        ranges: [],   // sorted, merged [start, end) covered ranges
      };
    }

    let start = parsed.frag_offset;
    let end = parsed.frag_offset + parsed.frag_length;

    // Bounds guard against a malformed fragment claiming to exceed totalLength.
    if (end > frag.totalLength) return false;

    // Coverage before this fragment — used to decide whether it contributed
    // anything new (a retransmitted fragment that only re-covers known bytes
    // is a duplicate for implicit-ACK purposes).
    let coveredBefore = 0;
    for (let cr = 0; cr < frag.ranges.length; cr++) {
      coveredBefore += frag.ranges[cr][1] - frag.ranges[cr][0];
    }

    // Copy the fragment bytes in (overlaps simply overwrite with identical data).
    frag.buf.set(parsed.body.subarray(0, parsed.frag_length), start);

    // Merge [start, end) into the covered-range set.
    frag.ranges.push([start, end]);
    frag.ranges.sort((a, b) => a[0] - b[0]);
    let merged = [];
    for (let r of frag.ranges) {
      if (merged.length && r[0] <= merged[merged.length - 1][1]) {
        // Overlapping/adjacent → extend the previous range.
        if (r[1] > merged[merged.length - 1][1]) merged[merged.length - 1][1] = r[1];
      } else {
        merged.push([r[0], r[1]]);
      }
    }
    frag.ranges = merged;

    let coveredAfter = 0;
    for (let ca = 0; ca < merged.length; ca++) {
      coveredAfter += merged[ca][1] - merged[ca][0];
    }

    // Complete when a single range covers [0, totalLength).
    if (merged.length === 1 && merged[0][0] === 0 && merged[0][1] === frag.totalLength) {
      delete ctx.fragments[key];
      return deliverHandshakeMessage(frag.type, frag.buf, key);
    }
    return coveredAfter > coveredBefore;
  }

  /**
   * Deliver a complete handshake message to TLSSession.
   * Strips DTLS reconstruction → builds TLS format.
   *
   * @returns {boolean} true if the message advanced our handshake state
   *   (delivered in-order, buffered out-of-order, or consumed as a valid
   *   HVR / cookie-exchange step); false if it was a duplicate or was
   *   dropped. processHandshakeRecord uses this for the implicit-ACK
   *   decision — only genuinely new data may cancel our retransmit timer.
   */
  function deliverHandshakeMessage(type, body, msgSeq) {
    // Skip if we've already processed this msg_seq (duplicate / retransmit).
    if (msgSeq < ctx.nextReadMsgSeq) return false;

    // Check for HelloVerifyRequest (DTLS 1.2 server→client, type=3)
    if (type === 3 && !isServer) {
      ctx.nextReadMsgSeq = msgSeq + 1;
      // The HVR acknowledges CH1 (implicit ACK, RFC 6347 §4.2.4). No
      // explicit cancel is needed: triggerClientHelloWithCookie arms the
      // CH2 flight's own timer, and startRetransmitTimer clears any
      // previous timer as its first step.
      let hvr = parse_hello_verify_request(body);
      triggerClientHelloWithCookie(hvr.cookie);
      return true;
    }

    // ---- Server-side HelloVerifyRequest cookie exchange (RFC 6347 §4.2.1) ----
    // For DTLS 1.2 with cookies enabled, the first ClientHello carries no cookie
    // (or an empty one). We answer with a HelloVerifyRequest and do NOT process
    // the ClientHello — that proves return-routability (the client must be at the
    // address it claims before we allocate any handshake state). Only a second
    // ClientHello echoing the correct cookie is processed.
    //
    // Note: msg_seq is NOT advanced for a rejected/HVR-triggering ClientHello, so
    // the client's retried CH (which reuses msg_seq per RFC 6347) is still accepted.
    if (type === 1 && isServer && options.useCookies === true &&
        ctx.selectedVersion !== DTLS_VERSION.DTLS1_3) {

      let ch = null;
      try { ch = parse_hello({ kind: 'client', body: body }); } catch (e) { ch = null; }
      let incomingCookie = (ch && ch.dtls_cookie) ? ch.dtls_cookie : new Uint8Array(0);

      if (incomingCookie.length === 0) {
        // First ClientHello → send HVR with a fresh cookie. Don't process the CH,
        // don't advance msg_seq (the retry reuses the same msg_seq).
        // Counts as progress: a retransmitted cookieless CH means the client
        // never got our HVR — resending it here IS the correct response.
        sendHelloVerifyRequest();
        return true;
      }

      // Second ClientHello: the cookie MUST match what we issued.
      if (!ctx.hvrCookie || !timingSafeEqualU8(incomingCookie, ctx.hvrCookie)) {
        // Cookie mismatch → silently drop (RFC 6347: server discards). Don't
        // advance msg_seq; a correct retry can still arrive.
        return false;
      }
      // Cookie verified → accept this ClientHello as the handshake anchor.
      //
      // Strict RFC 6347 §4.2.2 (see the figure in the RFC): the cookie-
      // bearing CH2 arrives with message_seq 1, and our ServerHello must
      // be numbered 1 as well. The previous code assumed the retried CH
      // "reuses msg_seq" 0 — that is only true for a pure retransmission
      // of CH1 (HVR lost), not for the cookie-bearing CH2, so RFC-
      // compliant clients (pion, OpenSSL, fixed lemon-tls) had their CH2
      // buffered as "out of order" forever and the handshake deadlocked.
      //
      // Set the read cursor and the outgoing counter to 1; the in-order
      // check below then accepts exactly a seq-1 CH2 and rejects anything
      // else (including seq-0 CH2s from pre-fix lemon-tls clients — non-
      // compliant numbering is intentionally not accommodated). The
      // transcript stays consistent on both sides because
      // feedHandshakeToTls records the incoming wire seq and outgoing
      // messages record message_sent_seq at emission — which is exactly
      // what the Finished MAC hashes (RFC 6347 §4.2.6).
      ctx.nextReadMsgSeq = 1;
      tls.context.message_sent_seq = 1;
      // Fall through and process the ClientHello normally.
    }

    // ---- In-order delivery (RFC 6347 §4.2.4 / RFC 9147 §5.2) ----
    // DTLS handshake messages must be handed to the TLS state machine strictly
    // in msg_seq order. If this message is ahead of what we expect, buffer it
    // and wait for the gap to fill. If it's the next expected one, feed it, then
    // drain any consecutive messages that were buffered earlier.
    if (msgSeq > ctx.nextReadMsgSeq) {
      // Out of order — hold it (ignore a duplicate already buffered).
      if (!(msgSeq in ctx.pendingMessages)) {
        ctx.pendingMessages[msgSeq] = { type: type, body: body };
        return true;    // new information, even if not yet deliverable
      }
      return false;     // duplicate of an already-buffered message
    }

    // msgSeq === nextReadMsgSeq → accept. Timer discipline, per the
    // RFC 6347 §4.2.4 state machine, in two halves:
    //
    //  1. A message from the peer's next flight is the implicit ACK of
    //     ours — but it must RE-ARM the timer, not cancel it. While we
    //     are in WAITING (peer's flight only partially received — e.g.
    //     one datagram of the server's SH..SHD flight lost), timer
    //     expiry retransmits OUR last flight, which elicits a full
    //     retransmission of the peer's flight (a cookie-valid duplicate
    //     CH2 makes werift resend flight 4, a duplicate Finished makes
    //     it resend flight 6). An earlier revision cancelled here: one
    //     lost datagram inside the peer's flight then left BOTH sides
    //     timer-less and deadlocked — ~50% handshake failure at just 5%
    //     random loss.
    //
    //  2. The re-arm must happen BEFORE feeding TLS: the feed can
    //     synchronously produce our entire next flight, whose fresh
    //     timer must not be clobbered afterwards (the original code
    //     cancelled at the end of processHandshakeRecord — after the
    //     response — so no responder flight was EVER protected by
    //     retransmission).
    //
    //     When the feed does respond, the flight boundary (newFlightPending
    //     → startNewFlight) resets the retransmit budget and the outgoing
    //     path arms the new flight's timer, superseding this re-arm.
    startRetransmitTimer();
    ctx.newFlightPending = true;
    feedHandshakeToTls(type, body, msgSeq);
    ctx.nextReadMsgSeq = msgSeq + 1;

    // Drain consecutively-numbered buffered messages. Same pre-feed
    // ordering applies; for a timer armed by an earlier feed in this very
    // drain, cancelling here would be wrong — but a mid-flight response
    // does not occur in TLS flows (a flight is answered only after its
    // final message), so each pre-feed cancel can only ever hit an
    // already-acknowledged flight's timer (usually already null).
    while (ctx.nextReadMsgSeq in ctx.pendingMessages) {
      let next = ctx.pendingMessages[ctx.nextReadMsgSeq];
      delete ctx.pendingMessages[ctx.nextReadMsgSeq];
      startRetransmitTimer();
      ctx.newFlightPending = true;
      feedHandshakeToTls(next.type, next.body, ctx.nextReadMsgSeq);
      ctx.nextReadMsgSeq++;
    }
    return true;
  }

  /**
   * Feed one in-order handshake message to the TLSSession, converting from DTLS
   * to TLS wire format and driving version detection.
   */
  function feedHandshakeToTls(type, body, msgSeq) {
    // Build TLS-format message: type(1) + length(3) + body
    let tlsMsg = build_message(type, body);

    // Set incoming msg_seq for the transcriptHook (one-shot — cleared after first push)
    ctx._incomingMsgSeq = msgSeq;

    // Feed to TLSSession (transcriptHook will convert to DTLS format if needed)
    tls.message(tlsMsg);

    // Update selectedVersion if just negotiated
    if (ctx.selectedVersion === null && tls.context.selected_version) {
      ctx.selectedVersion = tls.context.selected_version;
      if (ctx.selectedVersion === DTLS_VERSION.DTLS1_2) {
        fixTranscriptForDtls12();
      }
    }
  }

  /**
   * Server: build and send a HelloVerifyRequest with a fresh cookie (DTLS 1.2).
   * The cookie is a CSPRNG value stored on the context; a matching cookie must
   * come back in the client's second ClientHello (verified in
   * deliverHandshakeMessage) before we process the handshake.
   */
  function sendHelloVerifyRequest() {
    let cookie = new Uint8Array(crypto.randomBytes(32));
    ctx.hvrCookie = cookie;
    ctx.hvrDone = true;

    // HVR always uses msg_seq 0 and is sent in the clear (epoch 0).
    let hvrMsg = build_dtls_handshake(build_message(3, build_hello_verify_request({ cookie: cookie })), 0);
    let record = buildDtlsPlaintext(CT.HANDSHAKE, 0, nextWriteSeq(0), hvrMsg);
    ev.emit('packet', record);
  }

  /**
   * Trigger a new ClientHello with cookie (DTLS 1.2 HVR response).
   */
  function triggerClientHelloWithCookie(cookie) {
    if (!ctx.savedClientHello) return;

    // Build CH2 by inserting cookie into saved CH1
    // RFC 6347: "the client MUST use the same parameter values"
    let ch2 = insertCookieIntoClientHello(ctx.savedClientHello, cookie);

    // Reset state for the post-HVR handshake restart.
    //
    // RFC 6347 §4.2.1: the handshake transcript restarts at CH2 — the
    // cookieless CH1 and the HelloVerifyRequest are NOT included in the
    // handshake hash. Resetting the transcript is therefore correct.
    //
    // RFC 6347 §4.2.2, however, is explicit (see the figure in the RFC)
    // that message_seq does NOT restart:
    //
    //       ClientHello (seq=1)  ------>       ← CH2 carries seq 1
    //       (with cookie)
    //                            <------ ServerHello (seq=1)
    //
    // The previous code reset BOTH directions of the counter to 0: it
    // sent CH2 with msg_seq=0 and reset nextReadMsgSeq to 0. Against a
    // spec-compliant server (pion, werift, OpenSSL — all send an HVR and
    // then number ServerHello=1), the entire server flight (seq 1..N)
    // landed in pendingMessages waiting forever for a seq-0 message that
    // never comes: the handshake stalled silently — no error, no alert.
    // It only ever worked lemon-tls↔lemon-tls because our own server
    // sends an HVR only when options.useCookies is set, so the broken
    // path was never exercised same-stack.
    //
    // nextReadMsgSeq is deliberately NOT touched here: the HVR branch in
    // deliverHandshakeMessage already advanced it to 1, which is exactly
    // where the server's ServerHello will arrive.
    tls.context.transcript = [];
    tls.context.hello_sent = true;
    tls.context.dtls_cookie = cookie;
    // CH2 is message_seq 1. Set message_sent_seq BEFORE the transcript
    // push so transcriptHook / transcriptMsgSeqs record seq 1 for CH2 —
    // the Finished MAC hashes the DTLS reconstruction data including
    // message_seq (RFC 6347 §4.2.6), so a transcript recording seq 0 for
    // a wire message sent with seq 1 would fail Finished verification.
    tls.context.message_sent_seq = 1;
    ctx.currentFlight = [];
    ctx.fragments = {};          // discard any partial reassembly from CH1 flight
    ctx.pendingMessages = {};    // discard any out-of-order buffer from CH1 flight
    transcriptMsgSeqs = [];

    // Push CH2 to transcript (transcriptHook will store TLS format for now,
    // and fixTranscriptForDtls12() will convert when version is determined)
    ctx._incomingMsgSeq = undefined; // not incoming — use message_sent_seq
    tls.context.transcript.push(
      tls.context.transcriptHook ? tls.context.transcriptHook(ch2) : ch2
    );

    // Build DTLS message and send — msg_seq 1 per the RFC figure above.
    let dtlsMsg = build_dtls_handshake(ch2, 1);
    let record = buildRecord(0, CT.HANDSHAKE, dtlsMsg);
    ctx.currentFlight = [record];
    ev.emit('packet', record);

    tls.context.message_sent_seq = 2;
    startRetransmitTimer();
  }


  // ============================================================
  //  Flight tracking + retransmission
  // ============================================================

  function startRetransmitTimer() {
    cancelRetransmit();
    ctx.retransmitTimer = setTimeout(function() {
      if (ctx.retransmitCount >= ctx.maxRetransmits) {
        ev.emit('error', new Error('DTLS handshake timeout — max retransmits exceeded'));
        ctx.state = 'closed';
        ev.emit('close');
        return;
      }

      // Retransmit entire current flight
      for (let i = 0; i < ctx.currentFlight.length; i++) {
        ev.emit('packet', ctx.currentFlight[i]);
      }

      ctx.retransmitCount++;
      ctx.retransmitTimeout = Math.min(ctx.retransmitTimeout * 2, 60000);
      startRetransmitTimer();
    }, ctx.retransmitTimeout);

    if (ctx.retransmitTimer.unref) ctx.retransmitTimer.unref();
  }

  function cancelRetransmit() {
    if (ctx.retransmitTimer !== null) {
      clearTimeout(ctx.retransmitTimer);
      ctx.retransmitTimer = null;
    }
  }

  function startNewFlight() {
    ctx.currentFlight = [];
    ctx.retransmitCount = 0;
    ctx.retransmitTimeout = 1000;
  }


  // ============================================================
  //  ACK (DTLS 1.3)
  // ============================================================

  function processAck(content) {
    let acks = parseDtlsAck(content);
    // ACK received — flight was acknowledged
    cancelRetransmit();
    startNewFlight();
  }

  function sendAck(epoch, recordsToAck) {
    if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3) return;
    let payload = buildDtlsAck(recordsToAck);
    let record = buildRecord(epoch, CT.ACK, payload);
    ev.emit('packet', record);
  }


  // ============================================================
  //  Handshake completion
  // ============================================================

  // Forward 'clienthello' so server-side callers can inspect the peer's
  // offered extensions (tls.getRemoteExtension / message.extensions) and
  // set answering extensions via set_context({ local_extensions }) BEFORE
  // the ServerHello is built — the emit is synchronous within ClientHello
  // processing, ahead of hello construction. This is how DTLS-SRTP's
  // use_srtp answer (RFC 5764 §4.1) gets negotiated generically.
  tls.on('clienthello', function(data, message) {
    ev.emit('clienthello', data, message);
  });

  tls.on('secureConnect', function() {
    _ldbg('handshake complete — secureConnect (version=0x' +
      ((ctx.selectedVersion || tls.context.selected_version || 0).toString(16)) + ')');
    ctx.state = 'connected';
    cancelRetransmit();
    startNewFlight();
    ev.emit('connect');
  });

  tls.on('error', function(e) {
    ev.emit('error', e);
  });

  tls.on('session', function(ticket) {
    ev.emit('session', ticket);
  });


  // ============================================================
  //  Application data
  // ============================================================

  function send(data) {
    if (ctx.state !== 'connected') {
      ev.emit('error', new Error('Cannot send before handshake complete'));
      return;
    }
    if (typeof data === 'string') data = new TextEncoder().encode(data);

    let epoch = ctx.selectedVersion === DTLS_VERSION.DTLS1_3 ? 3 : 1;
    let record = buildRecord(epoch, CT.APPLICATION_DATA, data);
    ev.emit('packet', record);
  }


  // ============================================================
  //  Close
  // ============================================================

  function close() {
    if (ctx.state === 'closed') return;
    let epoch = ctx.state === 'connected' ? (ctx.selectedVersion === DTLS_VERSION.DTLS1_3 ? 3 : 1) : 0;
    sendAlertRecord(epoch, new Uint8Array([1, 0])); // warning, close_notify
    ctx.state = 'closed';
    cancelRetransmit();
    ev.emit('close');
  }


  // ============================================================
  //  Server: HelloVerifyRequest (DTLS 1.2)
  // ============================================================

  tls.on('hello', function() {
    // Version is detected lazily in handshakeSecrets and message handlers.
    //
    // Note: DTLS 1.2 HelloVerifyRequest is handled earlier, in
    // deliverHandshakeMessage — the first (cookieless) ClientHello never reaches
    // TLSSession, so by the time 'hello' fires here the cookie has already been
    // verified. Nothing to do for HVR at this point.
  });


  // ============================================================
  //  Public API
  // ============================================================

  let api = {
    /** Feed an incoming UDP datagram. */
    feedDatagram: feedDatagram,

    /** Send application data (after connect). */
    send: send,

    /** Close the DTLS session. */
    close: close,

    /** Configure the session (passes through to TLSSession). */
    set_context: function(opts) { tls.set_context(opts); },

    /** Register event listener. */
    on: function(name, fn) { ev.on(name, fn); },
    off: function(name, fn) { ev.off(name, fn); },

    /** Access to internal TLSSession (for advanced use). */
    get tls() { return tls; },

    /**
     * Export keying material (RFC 5705 / RFC 8446 §7.5).
     * DTLS-SRTP: exportKeyingMaterial(len, 'EXTRACTOR-dtls_srtp') — no context.
     * Returns Buffer, or null before secrets are available.
     */
    exportKeyingMaterial: function(length, label, context_value) {
      return tls.exportKeyingMaterial(length, label, context_value);
    },

    /** Peer's hello extensions: [{ type, name, data, value }]. */
    getRemoteExtensions: function() { return tls.getRemoteExtensions(); },

    /** One peer extension by numeric type (e.g. 14 = use_srtp), or null. */
    getRemoteExtension: function(type) { return tls.getRemoteExtension(type); },

    /** Current DTLS state. */
    get state() { return ctx.state; },

    /** Selected DTLS version (0xFEFC or 0xFEFD). */
    get version() { return ctx.selectedVersion; },

    /** Whether handshake is complete. */
    get connected() { return ctx.state === 'connected'; },

    /** Full negotiation result. */
    getNegotiationResult: function() { return tls.getNegotiationResult(); },

    /** Negotiated ALPN. */
    getALPN: function() { return tls.getALPN(); },

    /** Peer certificate. */
    getPeerCertificate: function() { return tls.getPeerCertificate(); },
  };

  for (let k in api) {
    if (Object.prototype.hasOwnProperty.call(api, k)) {
      if (typeof Object.getOwnPropertyDescriptor(api, k).get === 'function') {
        Object.defineProperty(this, k, Object.getOwnPropertyDescriptor(api, k));
      } else {
        this[k] = api[k];
      }
    }
  }

  return this;
}

export default DTLSSession;