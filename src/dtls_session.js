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

import TLSSession from './tls_session.js';
import createSecureContext from './secure_context.js';

import {
  DTLS_VERSION,
  build_dtls_handshake,
  parse_dtls_handshake,
  build_message,
  build_hello_verify_request,
  parse_hello_verify_request,
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

function DTLSSession(options) {
  if (!(this instanceof DTLSSession)) return new DTLSSession(options);
  options = options || {};

  let ev = new EventEmitter();
  let isServer = !!options.isServer;

  // ---- Internal TLSSession ----
  let tls = new TLSSession({
    isServer: isServer,
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

    // Fragment reassembly: msg_seq → { totalLength, parts: { offset: Uint8Array } }
    fragments: {},

    // Incoming handshake msg_seq tracking
    nextReadMsgSeq: 0,

    // Flight tracking for retransmission
    currentFlight: [],     // array of { epoch, data: Uint8Array (complete datagram) }
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

    // Start retransmit timer after sending flight messages
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
    let overhead = 13 + 16; // record header + AEAD tag (approximate)
    let maxFragment = ctx.mtu - overhead;

    if (dtlsMsg.length <= maxFragment) return [dtlsMsg];

    // Need to fragment: split the TLS body into chunks
    let body = tlsMsg.subarray(4); // skip TLS header (type+length)
    let totalLength = body.length;
    let fragments = [];
    let offset = 0;

    while (offset < totalLength) {
      let chunkLen = Math.min(maxFragment - 12, totalLength - offset); // 12 = DTLS handshake header
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
    let record = buildDtlsPlaintext(CT.CHANGE_CIPHER_SPEC, 0, nextWriteSeq(0), new Uint8Array([1]));
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

    for (let i = 0; i < records.length; i++) {
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
  }

  function processRecord(record) {
    if (record.type === CT.HANDSHAKE) {
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
    while (off + 12 <= data.length) {
      let parsed = parse_dtls_handshake(data.subarray(off));

      let msgSeq = parsed.msg_seq;
      let totalLen = parsed.length;
      let fragOffset = parsed.frag_offset;
      let fragLen = parsed.frag_length;

      // Is this a complete message or a fragment?
      if (fragOffset === 0 && fragLen === totalLen) {
        // Complete message — feed directly
        deliverHandshakeMessage(parsed.type, parsed.body, msgSeq);
      } else {
        // Fragment — reassemble
        reassembleFragment(parsed);
      }

      off += 12 + fragLen;
    }

    // Received handshake data → cancel retransmit (implicit ACK)
    cancelRetransmit();
  }

  /**
   * Reassemble a fragmented handshake message.
   */
  function reassembleFragment(parsed) {
    let key = parsed.msg_seq;
    if (!(key in ctx.fragments)) {
      ctx.fragments[key] = { totalLength: parsed.length, type: parsed.type, parts: {} };
    }
    let frag = ctx.fragments[key];
    frag.parts[parsed.frag_offset] = parsed.body;

    // Check if complete
    let assembled = new Uint8Array(frag.totalLength);
    let filled = 0;
    let offsets = Object.keys(frag.parts).map(Number).sort((a, b) => a - b);

    for (let i = 0; i < offsets.length; i++) {
      let part = frag.parts[offsets[i]];
      if (offsets[i] !== filled) return; // gap — not complete yet
      assembled.set(part, offsets[i]);
      filled = offsets[i] + part.length;
    }

    if (filled < frag.totalLength) return; // not complete

    // Complete — deliver
    delete ctx.fragments[key];
    deliverHandshakeMessage(frag.type, assembled, key);
  }

  /**
   * Deliver a complete handshake message to TLSSession.
   * Strips DTLS reconstruction → builds TLS format.
   */
  function deliverHandshakeMessage(type, body, msgSeq) {
    // Skip if we've already processed this msg_seq
    if (msgSeq < ctx.nextReadMsgSeq) return;
    ctx.nextReadMsgSeq = msgSeq + 1;


    // Check for HelloVerifyRequest (DTLS 1.2 server→client, type=3)
    if (type === 3 && !isServer) {
      let hvr = parse_hello_verify_request(body);
      triggerClientHelloWithCookie(hvr.cookie);
      return;
    }

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
   * Trigger a new ClientHello with cookie (DTLS 1.2 HVR response).
   */
  function triggerClientHelloWithCookie(cookie) {
    if (!ctx.savedClientHello) return;

    // Build CH2 by inserting cookie into saved CH1
    // RFC 6347: "the client MUST use the same parameter values"
    let ch2 = insertCookieIntoClientHello(ctx.savedClientHello, cookie);

    // Reset state
    tls.context.transcript = [];
    tls.context.hello_sent = true;
    tls.context.dtls_cookie = cookie;
    tls.context.message_sent_seq = 0;
    ctx.nextReadMsgSeq = 0;
    ctx.currentFlight = [];
    transcriptMsgSeqs = [];

    // Push CH2 to transcript (transcriptHook will store TLS format for now,
    // and fixTranscriptForDtls12() will convert when version is determined)
    ctx._incomingMsgSeq = undefined; // not incoming — use message_sent_seq
    tls.context.transcript.push(
      tls.context.transcriptHook ? tls.context.transcriptHook(ch2) : ch2
    );

    // Build DTLS message and send
    let dtlsMsg = build_dtls_handshake(ch2, 0);
    let record = buildRecord(0, CT.HANDSHAKE, dtlsMsg);
    ctx.currentFlight = [record];
    ev.emit('packet', record);

    tls.context.message_sent_seq = 1;
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

  tls.on('secureConnect', function() {
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
    // Version is detected lazily in handshakeSecrets and message handlers

    // DTLS 1.2 server: optionally send HelloVerifyRequest
    if (isServer && ctx.selectedVersion !== DTLS_VERSION.DTLS1_3 && !ctx.hvrDone && options.useCookies === true) {
      ctx.hvrDone = true;
      let cookie = new Uint8Array(32);
      for (let i = 0; i < 32; i++) cookie[i] = Math.floor(Math.random() * 256);
      ctx.hvrCookie = cookie;

      let hvrBody = build_hello_verify_request({ cookie: cookie });
      let hvrMsg = build_dtls_handshake(
        build_message(3, hvrBody),
        0
      );
      let record = buildDtlsPlaintext(CT.HANDSHAKE, 0, nextWriteSeq(0), hvrMsg);
      ev.emit('packet', record);
    }
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
