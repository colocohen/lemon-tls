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
  default_cipher_suites,
  hkdf_expand_label,
  derive_sn_key,
  LABEL_PREFIX_TLS13,
  LABEL_PREFIX_DTLS13,
} from './crypto.js';

import {
  CT,
  getAeadAlgo,
  deriveKeys,
  deriveKeys12,
  decryptDtls12,
  buildDtlsPlaintext,
  buildEncryptedDtls12,
  buildEncryptedDtls13,
  parseDtlsDatagram,
  buildDtlsAck,
  parseDtlsAck,
  decryptEncryptedDtls13,
} from './record.js';

import { timingSafeEqualU8 } from './utils.js';
import { SUPPORTED_GROUPS as ECDH_SUPPORTED_GROUPS } from './session/ecdh.js';
import { default_signature_schemes } from './session/signing.js';


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

/**
 * Log an OUTBOUND record. The existing _ldbg traces only what arrives —
 * which is half the picture when a peer rejects something WE sent, and
 * that is precisely the DTLS 1.3 interop case: BoringSSL reads our
 * flight, dislikes it, and closes. Decoding the record header here
 * (content type, epoch, sequence, and the handshake message type when
 * the record is still in the clear) shows exactly what left the socket.
 */
function _ldbgTx(record, whereFrom) {
  if (!LEMON_DEBUG || !record || !record.length) return;
  try {
    var ct = record[0];
    // DTLS 1.3 UNIFIED HEADER (RFC 9147 4.1): an encrypted record starts
    // with 001CSLEE — first byte in 0x20..0x3F — instead of the classic
    // content-type/version/epoch/sequence header. Its epoch is the low
    // two bits and the body is ciphertext, so all we can honestly report
    // is that one went out and how big it was. Reading it as a classic
    // header produced nonsense like "ct46 epoch=323".
    if (ct >= 0x20 && ct <= 0x3F) {
      _ldbg('TX [1.3 encrypted] epoch=' + (ct & 0x03) + ' len=' + record.length +
            (whereFrom ? ' <' + whereFrom + '>' : ''));
      return;
    }
    var epoch = (record[3] << 8) | record[4];
    var names = { 20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake',
                  23: 'ApplicationData', 25: 'Heartbeat', 26: 'ACK' };
    var hsNames = { 1:'ClientHello', 2:'ServerHello', 4:'NewSessionTicket',
                    8:'EncryptedExtensions', 11:'Certificate',
                    13:'CertificateRequest', 15:'CertificateVerify',
                    20:'Finished', 24:'KeyUpdate' };
    var extra = '';
    if (ct === 22 && record.length > 13) {
      extra = ' hs=' + (hsNames[record[13]] || ('type' + record[13]));
    }
    if (ct === 21 && record.length >= 15) {
      extra = ' alert level=' + record[13] + ' desc=' + record[14];
    }
    _ldbg('TX ' + (names[ct] || ('ct' + ct)) + ' epoch=' + epoch +
          ' len=' + record.length + extra + (whereFrom ? ' <' + whereFrom + '>' : ''));
  } catch (e) {}
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
    srtpProfiles: options.srtpProfiles,
    servername: options.servername,
    SNICallback: options.SNICallback,
    rejectUnauthorized: options.rejectUnauthorized,
    checkServerIdentity: options.checkServerIdentity,
    // DTLS peers in WebRTC present self-signed certificates by design and are
    // authenticated by the SDP fingerprint, not by a CA chain. Falling back to
    // the platform trust store here would mark every such peer unauthorized.
    useDefaultCA: options.useDefaultCA === true,
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

    // Flight tracking for retransmission.
    //
    // Stores PRE-ENCRYPTION descriptors — { epoch, contentType, payload } —
    // never built records. Rebuilding at retransmit time (resendFlight) gives
    // every retransmitted record a FRESH record sequence number, which is not
    // an optimization but a hard requirement on two independent grounds:
    //   1. DTLS 1.3 (RFC 9147 §4.2.1): the AEAD nonce is derived from the
    //      record seq. Re-emitting a stored ciphertext repeats (key, nonce) —
    //      catastrophic for GCM (key-stream reuse reveals plaintext XOR and
    //      enables tag forgery). The old code stored fully-built records and
    //      replayed the exact bytes.
    //   2. Receivers reconstruct the full seq from its truncated wire form
    //      relative to the highest seq seen (and BoGo outright requires
    //      monotonic seqs from the shim) — a replayed old seq reconstructs to
    //      a wrong full value and fails deprotection as "bad record MAC".
    currentFlight: [],     // array of { epoch, contentType, payload: Uint8Array }
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

    // ---- Epoch tracking (RFC 9147 §6.1) ----
    // Sending and receiving epochs advance INDEPENDENTLY: a KeyUpdate rekeys
    // one direction only. Until KeyUpdate existed both directions moved
    // together through 0 -> 2 -> 3, so a single number sufficed; it does not
    // any more. ctx.keys[e] therefore holds .write and .read for possibly
    // different generations, and each half is installed on its own.
    writeEpoch: null,          // epoch we currently PROTECT outgoing records with
    readEpoch: null,           // highest epoch we hold READ keys for
    // A KeyUpdate we have sent whose ACK has not come back. RFC 9147 §8:
    // "implementations MUST NOT send records with the new keys or send a new
    // KeyUpdate until the previous KeyUpdate has been acknowledged". So the
    // new write keys are installed immediately but stay dormant here until
    // the ACK arrives.
    pendingWriteEpoch: null,
    keyUpdateFlight: null,     // { payload, epoch, timer, attempts, timeout }

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
      // crypto.js owns the default suite list (see default_cipher_suites).
      tlsSetup.local_supported_cipher_suites = default_cipher_suites(
        versions.indexOf(DTLS_VERSION.DTLS1_3) >= 0,
        versions.indexOf(DTLS_VERSION.DTLS1_2) >= 0
      );
    }
    if (!tlsSetup.local_supported_groups) {
      tlsSetup.local_supported_groups = ECDH_SUPPORTED_GROUPS.slice(); // whatever ecdh.js implements
    }
    // signing.js owns the scheme list; DTLS spans 1.2+1.3 so include PKCS#1.
    tlsSetup.local_supported_signature_algorithms = default_signature_schemes();
  }

  // Server cert/key.
  //
  // The whole options object goes in, not just key+cert: createSecureContext
  // also reads passphrase, ca, ciphers, sigalgs, ecdhCurve, honorCipherOrder,
  // pfx and ocsp, and picking out two fields silently dropped all of them —
  // an encrypted private key could never be decrypted here no matter what the
  // caller passed. Same defect the TLS paths carried.
  if (options.cert && options.key) {
    let sctx = createSecureContext(options);
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

    // RFC 9147 §5.9, verbatim: "Hash calculations include entire handshake
    // messages, including DTLS-specific fields: message_seq,
    // fragment_offset, and fragment_length. However, in order to remove
    // sensitivity to handshake message fragmentation, the CertificateVerify
    // and Finished messages MUST be computed as if each handshake message
    // had been sent as a single fragment."
    //
    // So DTLS 1.3 keeps the 12-byte DTLS header in the transcript, exactly
    // like DTLS 1.2 (RFC 6347 §4.2.6) — with fragment_offset 0 and
    // fragment_length equal to the whole body, which is what
    // build_dtls_handshake produces by default.
    //
    // This code did the OPPOSITE for 1.3 and stored TLS-format messages,
    // citing a section number that says the reverse of what it does. The
    // effect is invisible between two copies of this library — both make
    // the same choice and their MACs agree — and only shows up against a
    // conforming peer, where every message parses cleanly and then the
    // Finished MAC fails: "Finished verify_data mismatch" against Chrome,
    // with a transcript whose entries were each 8 bytes short.
    // MEASURED AGAINST CHROME, and it contradicts the plain reading of
    // RFC 9147 §5.9 ("Hash calculations include entire handshake
    // messages, including DTLS-specific fields"):
    //   • TLS-format transcript  -> Chrome's CertificateVerify VERIFIES,
    //                               Finished MAC mismatches;
    //   • DTLS-format transcript -> Chrome's CertificateVerify FAILS.
    // So BoringSSL signs CertificateVerify over the TLS-format transcript.
    // Since CertificateVerify is the one we can check against a real peer
    // and it passes this way, TLS format stays for 1.3 — the Finished
    // difference is something else and must be found without breaking a
    // signature that demonstrably verifies.
    let entry = (ctx.selectedVersion === DTLS_VERSION.DTLS1_2)
      ? build_dtls_handshake(data, msgSeq)
      : data;


    return entry;
  };

  /**
   * Called when selectedVersion is first determined as DTLS 1.2.
   * Retroactively converts all existing transcript entries to DTLS format.
   */
  /**
   * Convert transcript entries recorded BEFORE the version was known into
   * DTLS handshake format.
   *
   * Both DTLS 1.2 (RFC 6347 §4.2.6) and DTLS 1.3 (RFC 9147 §5.9) hash the
   * 12-byte DTLS handshake header, but the first messages — our ClientHello
   * and the peer's ServerHello — are pushed while selectedVersion is still
   * null, so they land in TLS format and have to be rewritten once the
   * negotiation resolves. Entries already in DTLS format are left alone:
   * a second conversion would wrap a 12-byte header around one that is
   * already there.
   */
  function fixTranscriptForDtls() {
    let t = tls.context.transcript;
    for (let i = 0; i < t.length; i++) {
      if (i >= transcriptMsgSeqs.length) continue;
      let e = t[i];
      if (!e || e.length < 4) continue;
      // A DTLS entry is 12 + body; a TLS entry is 4 + body. The declared
      // length lives in the same place in both, so comparing it against the
      // actual size tells them apart without guessing.
      let declared = (e[1] << 16) | (e[2] << 8) | e[3];
      if (e.length === declared + 12) continue;   // already DTLS format
      t[i] = build_dtls_handshake(e, transcriptMsgSeqs[i]);
    }
  }

  // Kept for callers that still use the old name.
  function fixTranscriptForDtls12() { fixTranscriptForDtls(); }


  // ============================================================
  //  Key derivation
  // ============================================================

  /**
   * RFC 9147 §5.9: DTLS 1.3 derives with the "dtls13" label prefix (no trailing
   * space), NOT TLS 1.3's "tls13 ". Using the TLS prefix yields a handshake in
   * which every message parses and the transcripts match on both sides, and
   * only the keys differ — the peer reports "bad record MAC" and nothing else.
   * DTLS 1.2 does not use HKDF-Expand-Label at all (it uses the 1.2 PRF), so
   * the branch only has to distinguish 1.3.
   */
  function dtlsLabelPrefix() {
    return ctx.selectedVersion === DTLS_VERSION.DTLS1_3
      ? LABEL_PREFIX_DTLS13
      : LABEL_PREFIX_TLS13;
  }

  function deriveEpochKeys(secret) {
    let lp = dtlsLabelPrefix();
    // record.js owns "traffic secret -> key + iv" and already exports it. This
    // function used to re-derive both inline, which is the same two HKDF calls
    // with the same arguments in a second place — precisely the shape of the
    // label-prefix bug, where one copy of a derivation was fixed and another
    // was not. Only the DTLS-specific extras belong here.
    let result = deriveKeys(secret, ctx.cipherSuite, lp);

    // DTLS 1.3: derive sn_key for record number encryption
    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3) {
      result.snKey = derive_sn_key(TLS_CIPHER_SUITES[ctx.cipherSuite].hash, secret,
                                   ctx.cipherSuite, lp);
      result.algo = getAeadAlgo(ctx.cipherSuite);
    }

    return result;
  }

  /**
   * The DTLS epoch a given key generation belongs to.
   *
   * DTLS 1.3 (RFC 9147 §6.1) numbers epochs 0=plaintext, 1=early data,
   * 2=handshake, 3=application. DTLS 1.2 uses a single encrypted epoch 1.
   * Which numbering applies depends on the negotiated version, so this must
   * resolve the version FIRST and never assume a previous sync happened.
   *
   * The two callers used to differ: the handshake-secrets handler synced the
   * version from the TLS session, the application-secrets handler did not sync
   * at all. That asymmetry is only harmless while the version happens to be
   * committed by the time each event fires. When it is not — the TLS engine
   * commits negotiated values at the END of a reactive pass, and these events
   * are emitted DURING one — the keys are filed under epoch 1 while records are
   * later built for epoch 2/3. buildRecord then finds no keys, returns null,
   * and the record is dropped silently: the peer sees nothing at all and times
   * out. One helper, so both generations decide the same way.
   */
  function dtlsEpochForSecrets(isApplication) {
    if (ctx.selectedVersion === null && tls.context.selected_version) {
      ctx.selectedVersion = tls.context.selected_version;
      // Both DTLS versions hash the DTLS handshake header (RFC 6347 §4.2.6,
      // RFC 9147 §5.9), so the early TLS-format entries must be rewritten
      // whichever version was negotiated.
      if (ctx.selectedVersion === DTLS_VERSION.DTLS1_2) fixTranscriptForDtls();
    }
    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3) return isApplication ? 3 : 2;
    return 1;
  }

  tls.on('handshakeSecrets', function(localSecret, remoteSecret) {
    let dtlsEpoch = dtlsEpochForSecrets(false);
    ctx.cipherSuite = tls.getCipher();
    ctx.hashName = TLS_CIPHER_SUITES[ctx.cipherSuite].hash;

    ctx.keys[dtlsEpoch] = {
      write: deriveEpochKeys(localSecret),
      read: deriveEpochKeys(remoteSecret),
    };
    ctx.writeSeq[dtlsEpoch] = 0;
  });

  tls.on('appSecrets', function(localSecret, remoteSecret) {
    let dtlsEpoch = dtlsEpochForSecrets(true);

    ctx.keys[dtlsEpoch] = {
      write: deriveEpochKeys(localSecret),
      read: deriveEpochKeys(remoteSecret),
    };
    ctx.writeSeq[dtlsEpoch] = 0;

    // Baseline for KeyUpdate. Everything after this point counts up from here,
    // per direction.
    ctx.writeEpoch = dtlsEpoch;
    ctx.readEpoch = dtlsEpoch;
  });


  // ============================================================
  //  KeyUpdate (RFC 9147 §8)
  // ============================================================
  //
  // TLSSession derives the new traffic secret and emits 'keyUpdate'; the DTLS
  // layer owns everything the epoch implies. Nothing consumed this event
  // before, so a KeyUpdate updated the session's notion of the traffic secret
  // while the record layer kept protecting and deprotecting with the old keys.
  // That is worse than not implementing it: on DTLS an undeprotectable record
  // is silently discarded (§4.5.2), so the symptom is a connection that simply
  // stops carrying data, with no alert and no error anywhere.

  tls.on('keyUpdate', function(info) {
    // DTLS 1.2 has no KeyUpdate; the TLS session only emits this for 1.3, but
    // the guard keeps the epoch arithmetic below unreachable on the 1.2 path.
    if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3) return;
    if (!info || !info.secret) return;
    if (ctx.writeEpoch === null || ctx.readEpoch === null) return;

    if (info.direction === 'send') {
      // §8: only one KeyUpdate may be in flight. requestKeyUpdate() below
      // refuses up front; reaching here with one pending means the TLS session
      // rotated its secret anyway (e.g. an auto-response to the peer's
      // update_requested while ours was still unacknowledged), which would
      // strand an epoch. Say so rather than silently losing the connection.
      if (ctx.pendingWriteEpoch !== null) {
        ev.emit('error', new Error(
          'DTLS: a KeyUpdate is already awaiting acknowledgement (RFC 9147 §8)'));
        return;
      }
      let next = ctx.writeEpoch + 1;
      // Install the new write keys, but keep protecting with the old epoch
      // until the peer ACKs (§8). ctx.keys[next] may already carry a .read
      // half from the peer's own update — merge, never overwrite.
      ctx.keys[next] = Object.assign({}, ctx.keys[next], { write: deriveEpochKeys(info.secret) });
      ctx.writeSeq[next] = 0;
      ctx.pendingWriteEpoch = next;

    } else if (info.direction === 'receive') {
      let next = ctx.readEpoch + 1;
      ctx.keys[next] = Object.assign({}, ctx.keys[next], { read: deriveEpochKeys(info.secret) });
      ctx.readEpoch = next;
      // The previous epoch's read keys are deliberately RETAINED. §8: records
      // already in flight under the old epoch must still deprotect, and our
      // ACK may be lost, so the peer may retransmit under the old keys.
    }
  });

  /** Arm the post-handshake retransmit for an unacknowledged KeyUpdate. */
  function armKeyUpdateRetransmit(payload, epoch) {
    cancelKeyUpdateRetransmit();
    ctx.keyUpdateFlight = {
      payload: payload, epoch: epoch,
      attempts: 0, timeout: ctx.retransmitTimeout, timer: null,
    };
    scheduleKeyUpdateRetransmit();
  }

  function scheduleKeyUpdateRetransmit() {
    let f = ctx.keyUpdateFlight;
    if (!f) return;
    f.timer = setTimeout(function () {
      if (!ctx.keyUpdateFlight) return;
      if (f.attempts >= ctx.maxRetransmits) {
        ev.emit('error', new Error('DTLS: KeyUpdate was never acknowledged'));
        cancelKeyUpdateRetransmit();
        return;
      }
      f.attempts++;
      // Rebuild rather than replay: a retransmission is a NEW record and needs
      // a fresh sequence number, or the peer's replay window rejects it.
      let record = buildRecord(f.epoch, CT.HANDSHAKE, f.payload);
      if (record) { _ldbgTx(record, 'keyupdate-rtx'); ev.emit('packet', record); }
      f.timeout = Math.min(f.timeout * 2, 60000);
      scheduleKeyUpdateRetransmit();
    }, f.timeout);
    if (f.timer && typeof f.timer.unref === 'function') f.timer.unref();
  }

  function cancelKeyUpdateRetransmit() {
    if (ctx.keyUpdateFlight && ctx.keyUpdateFlight.timer) clearTimeout(ctx.keyUpdateFlight.timer);
    ctx.keyUpdateFlight = null;
  }


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
      // epoch 2 = handshake. Anything above rides the CURRENT application
      // epoch, which is 3 until a KeyUpdate moves it to 4, 5, ... Hardcoding 3
      // meant every post-handshake message stayed on the pre-rekey epoch.
      dtlsEpoch = (tlsEpoch === 1) ? 2
                : (ctx.writeEpoch !== null ? ctx.writeEpoch : 3);
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
    // RFC 9147 §5.8.4: post-handshake messages do NOT belong to the handshake
    // flight. Each category gets an independent state machine; folding a
    // KeyUpdate into currentFlight would make a handshake retransmission
    // replay it, and a KeyUpdate ACK cancel the handshake's timer.
    let isPostHandshakeKU = (type === 'key_update' &&
                             ctx.selectedVersion === DTLS_VERSION.DTLS1_3);
    if (isPostHandshakeKU) {
      for (let i = 0; i < frags.length; i++) {
        let kuRecord = buildRecord(dtlsEpoch, CT.HANDSHAKE, frags[i]);
        if (kuRecord) { _ldbgTx(kuRecord, 'keyupdate'); ev.emit('packet', kuRecord); }
      }
      // KeyUpdate must be acknowledged (§8), so it is retransmitted on its own
      // timer until an ACK arrives. Only the last fragment is tracked; a
      // KeyUpdate body is 1 byte and never fragments in practice.
      armKeyUpdateRetransmit(frags[frags.length - 1], dtlsEpoch);
      return;
    }

    for (let i = 0; i < frags.length; i++) {
      let record = buildRecord(dtlsEpoch, CT.HANDSHAKE, frags[i]);
      // The flight captures the fragment, not the record — see currentFlight.
      ctx.currentFlight.push({ epoch: dtlsEpoch, contentType: CT.HANDSHAKE, payload: frags[i] });
      if (record) {
        _ldbgTx(record, 'L543'); ev.emit('packet', record);
      } else {
        // buildRecord refused to build (no keys for an encrypted epoch).
        // Dropping the record here without a word is how a key-epoch mismatch
        // turns into an unexplained peer timeout instead of a diagnosable
        // failure: nothing reaches the wire and nothing is reported. Surface
        // it — the handshake cannot proceed either way.
        ev.emit('error', new Error(
          'DTLS: could not build outgoing handshake record for epoch ' + dtlsEpoch +
          ' — no keys installed for that epoch'));
        return;
      }
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
      // DTLS 1.3 epochs 2 (handshake) and 3 (application) are ALWAYS
      // encrypted — they carry the unified header (first byte 0x2c–0x2f). If
      // we reach here without keys for such an epoch, emitting a classic
      // 13-byte plaintext header (first byte = content type, e.g. 0x16/0x1a)
      // would make the peer reject the record as "bad type byte" (RFC 9147
      // §4). That only happens on a caller ordering bug (record built before
      // its epoch's keys were installed); surface it instead of putting a
      // malformed record on the wire. Epoch 0 is legitimately plaintext.
      if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3 && epoch >= 2) {
        ev.emit('error', new Error('DTLS 1.3: attempted to build epoch ' + epoch + ' record before keys installed'));
        return null;
      }
      // No keys → plaintext record (epoch 0, or DTLS 1.2 pre-CCS)
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
    // buildRecord returns null when it refuses to emit a malformed record
    // (DTLS 1.3 epoch >= 2 with no keys installed). Emitting that null as a
    // packet pushes `null` into the transport; drop it instead — we already
    // surfaced the reason through 'error'.
    if (!record) return;
    _ldbgTx(record, 'L664'); ev.emit('packet', record);
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
    // when the flight is retransmitted. Captured as a descriptor (epoch 0,
    // plaintext), so resendFlight rebuilds it with a fresh seq like every
    // other record. Previously it was emitted but never captured, so a
    // retransmitted final flight arrived WITHOUT the cipher-spec change and
    // the peer could never decrypt the accompanying Finished — an
    // unrecoverable stall under single-datagram loss.
    ctx.currentFlight.push({ epoch: 0, contentType: CT.CHANGE_CIPHER_SPEC, payload: new Uint8Array([1]) });
    _ldbgTx(record, 'L688'); ev.emit('packet', record);
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

    // Whether these records arrived AFTER the handshake must be decided here,
    // before the loop — not after it. The datagram that completes the
    // handshake flips ctx.state to 'connected' partway through, so reading the
    // state afterwards misclassifies the handshake's own epoch-2 records as
    // post-handshake and ACKs them inside the application-data epoch. That is
    // the spurious epoch-3 ACK that makes a peer answer decode_error on the
    // NEXT record — so a perfectly good SCTP COOKIE_ECHO takes the blame.
    let wasConnectedOnEntry = (ctx.state === 'connected');

    for (let i = 0; i < records.length; i++) {
      // A record we could not decrypt when the datagram was parsed. Keys may
      // have arrived since — processing an earlier record in THIS datagram
      // (the ServerHello) is exactly what installs them. Retry now, in order,
      // so a peer that packs its whole flight into one datagram is handled
      // without waiting for a retransmit.
      if (records[i].deferred) {
        let epochKeys = ctx.keys[records[i].epoch];
        let readKeys = epochKeys ? epochKeys.read : null;
        if (!readKeys) continue;                 // still unreadable — let the peer retransmit
        let dec = null;
        try { dec = decryptEncryptedDtls13(records[i].raw, readKeys); } catch (e) { dec = null; }
        if (!dec) continue;
        records[i] = {
          type: dec.type, epoch: dec.epoch, seq: dec.seq,
          content: dec.content, encrypted: true, deferred: false,
        };
      }

      // NEVER ACK THE FIRST FLIGHT (RFC 9147 §7.1): "ACKs MUST NOT be
      // sent for the ClientHello". The first flight is acknowledged by
      // the RESPONSE to it — the ServerHello — and a peer that receives
      // an ACK where none belongs answers decode_error.
      // Epoch 0 records are exactly that first flight: everything later
      // is protected under epoch 2 or above. This only bites when the
      // ClientHello is large enough to FRAGMENT, because a single-record
      // flight is consumed before any ACK decision is made — which is
      // why a two-way call worked and an SFU, whose extra transceivers
      // push the ClientHello past the MTU, did not.
      if (records[i].type === CT.HANDSHAKE &&
          ctx.selectedVersion === DTLS_VERSION.DTLS1_3 &&
          records[i].epoch > 0) {
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
      // ACKs RIDE THE HANDSHAKE EPOCH (RFC 9147 §7): they acknowledge
      // handshake records, so epoch 2 once handshake keys exist and
      // epoch 0 before that — never epoch 3. Picking "the highest epoch
      // we have keys for" sent them under APPLICATION-DATA protection,
      // where the peer decrypts with app keys and finds a content type
      // that does not belong. Chrome answers decode_error.
      // This shows up the moment a ClientHello is large enough to be
      // FRAGMENTED — an SFU with several transceivers crosses the MTU
      // and a two-way call does not, which is exactly why bidirectional
      // worked and party mode did not.
      // Post-handshake (§7.1: "For post-handshake messages, ACKs SHOULD be
      // sent once for each received and processed handshake record") the
      // handshake epoch is gone and §7 requires the HIGHEST available sending
      // epoch. During the handshake it is still epoch 2, or 0 before keys.
      // RFC 9147 §7.1 lists the flights that are IMPLICITLY acknowledged by
      // the responding flight, and the client's final flight is pointedly not
      // among them: "In general, flights MUST be ACKed unless they are
      // implicitly acknowledged", excepting "handshake flights other than the
      // client's final flight of the main handshake".
      //
      // So the two roles need opposite answers here, which is why a
      // state-only test could not get both right:
      //   client — the server's flight is implicitly acked by our own final
      //            flight, so an explicit ACK is both redundant and (at the
      //            application epoch) actively harmful;
      //   server — the client's final flight has no responding flight, so
      //            without an explicit ACK the client retransmits it forever.
      // §7 then fixes the epoch: after the handshake, the highest available
      // sending epoch.
      let justCompleted = (!wasConnectedOnEntry && ctx.state === 'connected');
      let finalFlightAck = isServer && justCompleted;
      let atAppEpoch = wasConnectedOnEntry || finalFlightAck;

      let ackEpoch = atAppEpoch
        ? (ctx.writeEpoch !== null ? ctx.writeEpoch : 3)
        : (ctx.keys[2] ? 2 : 0);
      sendAck(ackEpoch, ackable, atAppEpoch);
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
      // Name the alert either way. A close_notify is a CLEAN shutdown and
      // a failure is not, but both present to the application as "the
      // connection ended" — and telling them apart is the difference
      // between "the peer hung up" and "the peer rejected us".
      _ldbg('RX Alert level=' + level + ' desc=' + desc +
            (desc === 0 ? ' (close_notify — clean shutdown)' : ' (failure)'));
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
      resendFlight();
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
    if (type === 1 && isServer) {
      let ch = null;
      try { ch = parse_hello({ kind: 'client', body: body }); } catch (e) { ch = null; }

      // Does this ClientHello offer DTLS 1.3?
      //
      // RULE: a decision derived from an incoming message is read from that
      // message, never from state the message itself is about to establish.
      // (Stated in full next to params_to_set in tls_session.js; this is the
      // fourth bug it has caused.) Read it from the MESSAGE, never
      // from ctx.selectedVersion — when the first ClientHello arrives nothing
      // has been negotiated yet, so a state-based test reads null and fails
      // OPEN. That matters because the two rules below are MUST-level and
      // version-specific.
      let offersDtls13 = false;
      if (ch && Array.isArray(ch.supported_versions)) {
        offersDtls13 = ch.supported_versions.indexOf(DTLS_VERSION.DTLS1_3) >= 0;
      }

      // RFC 9147 §5.3: "A DTLS 1.3-only client MUST set the legacy_cookie field
      // to zero length. If a DTLS 1.3 ClientHello is received with any other
      // value in this field, the server MUST abort the handshake with an
      // 'illegal_parameter' alert." DTLS 1.3 carries cookies in the `cookie`
      // EXTENSION; the legacy body field is vestigial and must stay empty.
      if (offersDtls13 && ch && ch.dtls_cookie && ch.dtls_cookie.length > 0) {
        tls.sendAlert(2, 47); // fatal, illegal_parameter
        ev.emit('error', new Error(
          'DTLS 1.3 ClientHello carries a non-empty legacy_cookie (' +
          ch.dtls_cookie.length + ' bytes) — RFC 9147 §5.3 requires zero length'));
        return false;
      }

      // RFC 9147 §5.1: "DTLS 1.3-compliant implementations MUST NOT use the
      // HelloVerifyRequest to execute a return-routability check." DTLS 1.3
      // does return-routability with HelloRetryRequest + the cookie extension
      // instead. The old guard tested ctx.selectedVersion, which is null here,
      // so a DTLS 1.3 handshake could still be answered with an HVR.
      if (options.useCookies === true && !offersDtls13) {

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
    _ldbgTx(record, 'L1194'); ev.emit('packet', record);
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
    ctx.currentFlight = [{ epoch: 0, contentType: CT.HANDSHAKE, payload: dtlsMsg }];
    if (record) { _ldbgTx(record, 'L1258'); ev.emit('packet', record); }

    tls.context.message_sent_seq = 2;
    startRetransmitTimer();
  }


  // ============================================================
  //  Flight tracking + retransmission
  // ============================================================

  /**
   * Rebuild and re-emit the current flight with FRESH record sequence numbers.
   * See currentFlight's comment for why re-encryption (not byte replay) is
   * mandatory. Each descriptor goes back through buildRecord, which pulls the
   * next write seq for its epoch — so a retransmitted DTLS 1.3 record gets a
   * new nonce, and a monotonic seq the receiver can reconstruct.
   */
  function resendFlight() {
    // NEVER AFTER THE HANDSHAKE COMPLETES. Once we are connected the
    // handshake flight is finished by definition, and re-emitting it
    // sends HANDSHAKE content inside an APPLICATION-DATA epoch — the
    // peer decrypts a record with its app-data keys and finds a message
    // it cannot place. Chrome tolerated one and then answered
    // decode_error on the next SCTP record, which read as an SCTP
    // problem for several rounds and was not one: the giveaway is a
    // record in the log with no matching sctp->dtls line, because the
    // payload never came from the application at all.
    // RFC 9147 §5.8: retransmission is bounded by the handshake; after
    // it, ACKs are the mechanism, not a timer.
    if (ctx.state === 'connected' || ctx.state === 'closed') {
      cancelRetransmit();
      return;
    }
    for (let i = 0; i < ctx.currentFlight.length; i++) {
      let f = ctx.currentFlight[i];
      let record = buildRecord(f.epoch, f.contentType, f.payload);
      if (record) { _ldbgTx(record, 'L1280'); ev.emit('packet', record); }
    }
  }

  function startRetransmitTimer() {
    cancelRetransmit();
    // ONE GATE, AT THE SOURCE. Four call sites arm this timer and only
    // one of them checks the state, so a timer armed while the handshake
    // was still running could fire after it finished and re-emit the
    // flight into the application-data epoch. Refusing to arm once
    // connected (or closed) covers every caller, including any added
    // later, without each having to remember the rule.
    if (ctx.state === 'connected' || ctx.state === 'closed') return;
    ctx.retransmitTimer = setTimeout(function() {
      if (ctx.retransmitCount >= ctx.maxRetransmits) {
        ev.emit('error', new Error('DTLS handshake timeout — max retransmits exceeded'));
        ctx.state = 'closed';
        ev.emit('close');
        return;
      }

      // Retransmit entire current flight with fresh record seqs.
      resendFlight();

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

    // An outstanding KeyUpdate is what this ACK is for: §8 forbids protecting
    // anything with the new keys until it arrives, so THIS is the moment the
    // new epoch becomes live. Keys were installed when the KeyUpdate was sent;
    // only the switch happens here.
    if (ctx.pendingWriteEpoch !== null) {
      ctx.writeEpoch = ctx.pendingWriteEpoch;
      ctx.pendingWriteEpoch = null;
      cancelKeyUpdateRetransmit();
      ev.emit('keyUpdate', { direction: 'send', epoch: ctx.writeEpoch });
      return;
    }

    // Everything else keeps the original behaviour verbatim. In particular the
    // ACK for the client's final flight (which RFC 9147 §7.1 requires the peer
    // to send explicitly, and which arrives at the application epoch) must
    // still cancel that flight's retransmit timer.
    cancelRetransmit();
    startNewFlight();
  }

  function sendAck(epoch, recordsToAck, postHandshake) {
    if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3) return;
    // ACKs BELONG TO THE HANDSHAKE (RFC 9147 §7). They acknowledge
    // handshake records, and once the handshake is complete there is
    // nothing left to acknowledge — but this kept firing afterwards and
    // put an ACK record inside the APPLICATION-DATA epoch. The peer
    // decrypts it with app-data keys, finds a content type that has no
    // business there, and the stream is poisoned: Chrome tolerated it
    // and then answered decode_error on the next record, which made a
    // perfectly good SCTP COOKIE_ECHO look like the culprit for several
    // rounds. The giveaway in the log is a record with no matching
    // sctp->dtls line — the payload never came from the application.
    // ...that reasoning applies to HANDSHAKE flights. Post-handshake messages
    // are a separate case the original guard swept up with them: KeyUpdate,
    // NewSessionTicket and friends have no responding flight to acknowledge
    // them implicitly, so §7.1 requires an explicit ACK — without one the peer
    // retransmits its KeyUpdate forever and never activates its new keys.
    // `postHandshake` is set only for records actually received and processed
    // after the handshake, so the spurious-ACK bug this guard was written for
    // cannot return through it.
    if (!postHandshake && (ctx.state === 'connected' || ctx.state === 'closed')) return;
    if (ctx.state === 'closed') return;
    let payload = buildDtlsAck(recordsToAck);
    let record = buildRecord(epoch, CT.ACK, payload);
    _ldbgTx(record, 'L1334'); ev.emit('packet', record);
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
    // The peer's REASON, spelled out. When BoringSSL rejects part of our
    // flight it sends an alert and closes; without printing it here the
    // only symptom is a connection that dies after a handshake that
    // looked complete, which is exactly the DTLS 1.3 interop case.
    _ldbg('ERROR ' + (e && e.message ? e.message : e) +
          (e && e.alertDescription != null ? ' alertDesc=' + e.alertDescription : '') +
          (e && e.code ? ' code=' + e.code : ''));
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

    let epoch = ctx.selectedVersion === DTLS_VERSION.DTLS1_3
      ? (ctx.writeEpoch !== null ? ctx.writeEpoch : 3)
      : 1;
    let record = buildRecord(epoch, CT.APPLICATION_DATA, data);
    _ldbgTx(record, 'L1383'); ev.emit('packet', record);
  }


  // ============================================================
  //  Close
  // ============================================================

  function close() {
    if (ctx.state === 'closed') return;
    // Choose the epoch by what the PEER can read, not by whether WE consider
    // the handshake finished — the same rule the TLS branch uses for alerts.
    //
    // "not connected yet" does not mean "no keys": once handshake keys exist
    // the peer has switched to reading protected records, and a plaintext
    // close_notify arrives with a classic DTLSPlaintext header where the peer
    // requires the RFC 9147 §4 unified header. It then reports a bad record
    // type instead of a clean shutdown. Mirror the ACK path, which already
    // picks the highest epoch we hold write keys for.
    let epoch;
    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3) {
      // After a KeyUpdate the live epoch is 4, 5, ... — the peer has moved on
      // and no longer reads epoch 3, so a close_notify sent there is dropped
      // and the shutdown looks like a timeout instead of a clean close.
      epoch = (ctx.writeEpoch !== null && ctx.keys[ctx.writeEpoch])
        ? ctx.writeEpoch
        : (ctx.keys[3] ? 3 : (ctx.keys[2] ? 2 : 0));
    } else {
      epoch = ctx.keys[1] ? 1 : 0;
    }
    sendAlertRecord(epoch, new Uint8Array([1, 0])); // warning, close_notify
    ctx.state = 'closed';
    cancelRetransmit();
    cancelKeyUpdateRetransmit();
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

    /**
     * Request a TLS 1.3 KeyUpdate (RFC 9147 §8).
     *
     * Returns false without doing anything if the session is not a connected
     * DTLS 1.3 association, or if an earlier KeyUpdate has not been
     * acknowledged yet — §8 permits only one in flight. The new epoch does not
     * become active on send; it activates when the peer's ACK arrives.
     *
     * @param {boolean} [requestPeer] also ask the peer to update its own keys
     * @returns {boolean} whether the update was initiated
     */
    requestKeyUpdate: function(requestPeer) {
      if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3) return false;
      if (ctx.state !== 'connected') return false;
      if (ctx.pendingWriteEpoch !== null) return false;
      tls.requestKeyUpdate(!!requestPeer);
      return true;
    },

    /** Current epoch used to protect outgoing records (null before connect). */
    getWriteEpoch: function() { return ctx.writeEpoch; },

    /** Highest epoch for which read keys are installed (null before connect). */
    getReadEpoch: function() { return ctx.readEpoch; },

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

    /**
     * The negotiated DTLS-SRTP protection profile (RFC 5764), or null.
     * Surfaced here because DTLS-SRTP is the reason the exporter exists for
     * this transport — a caller that can export keying material must also be
     * able to learn which profile those keys are for.
     */
    getSelectedSrtpProfile: function() {
      return tls.getSelectedSrtpProfile();
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

    /** Every fingerprint of this connection: { ja3, ja4, ja3s, ja4s, ja4x }.
     *  The transport character resolves to 'd' on its own — the inner
     *  TLSSession reads the 0xFE high byte off the hello's legacy_version —
     *  so no `protocol` override is needed for plain DTLS. */
    getFingerprints: function(opts) { return tls.getFingerprints(opts); },

    /** JA3 of the connection's ClientHello. Shorthand for getFingerprints().ja3. */
    getJA3: function() { return tls.getJA3(); },

    /** Set the key and certificate for this connection (Node parity). */
    setKeyCert: function(ctxOrOpts) { return tls.setKeyCert(ctxOrOpts); },

    /** Finished verify_data, ours and the peer's (RFC 5929 channel binding). */
    getFinished: function() { return tls.getFinished(); },
    getPeerFinished: function() { return tls.getPeerFinished(); },

    /** Whether this connection resumed an earlier session. */
    isSessionReused: function() { return !!tls.isResumed; },
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