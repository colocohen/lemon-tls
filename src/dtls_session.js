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
  build_dtls_fragment,
  parse_dtls_handshake,
  build_message,
  build_hello_verify_request,
  parse_hello_verify_request,
  parse_hello,
  peer_alert_error,
  local_alert_error,
  read_peer_alert,
  MAX_WARNING_ALERTS,
  MAX_RECORD_PLAINTEXT,
  TLS_ALERT,
  TLS_MESSAGE_TYPE,
  parseError,
} from './wire.js';

import {
  TLS_CIPHER_SUITES,
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
  openDtls12,
  acceptRecordSeq,
  buildDtlsPlaintext,
  buildEncryptedDtls12,
  buildEncryptedDtls13,
  parseDtlsDatagram,
  buildDtlsAck,
  parseDtlsAck,
  decryptEncryptedDtls13,
} from './record.js';

import { timingSafeEqualU8, concatUint8Arrays } from './utils.js';
import { versionsInRange, localLists } from './node_options.js';


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
// The two settable link parameters, checked where they are set (option or
// setter): a wrong value is a programming error, thrown at once.
// The connectionId option (RFC 9146, RFC 9147 §9): the CID this side asks
// for. true — a server, SERVER_CID_LEN random bytes (createDTLSServer finds
// its connections by them); a client, an empty one (it needs none: the server
// does not move) —, or the CID itself. TLSSession negotiates whatever it is.
const SERVER_CID_LEN = 8;
function connectionIdOption(v, isServer) {
  if (v === true) return isServer ? new Uint8Array(crypto.randomBytes(SERVER_CID_LEN)) : new Uint8Array(0);
  return v;
}

function checkedMtu(v, dflt) {
  if (v === undefined || v === null) {
    if (dflt !== undefined) return dflt;
    throw new TypeError('DTLS mtu: a number of bytes is required');
  }
  if (!Number.isInteger(v) || v < 128 || v > 65507) throw new RangeError('DTLS mtu must be an integer in [128, 65507], got ' + v);
  return v;
}
// The least a timer from a round-trip estimate starts at (currentRto).
const RTO_MIN_MS = 100;
function checkedRetransmitTimeout(v, dflt) {
  if (v === undefined || v === null) {
    if (dflt !== undefined) return dflt;
    throw new TypeError('DTLS initialRetransmitTimeout: a number of milliseconds is required');
  }
  if (!Number.isInteger(v) || v < 10 || v > 60000) throw new RangeError('DTLS initialRetransmitTimeout must be an integer in [10, 60000] ms, got ' + v);
  return v;
}

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
  // Every option goes on to the TLS session as the caller gave it — the
  // TLS options (customExtensions, ALPNCallback, ticketData, signature and
  // group choices, ...) mean the same over DTLS — and DTLS sets only these.
  // A hand-picked list here left out whatever it did not name, as
  // createDTLSServer's did (r96, A6).
  let tls = new TLSSession(Object.assign({}, options, {
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
    // DTLS peers in WebRTC present self-signed certificates by design and are
    // authenticated by the SDP fingerprint, not by a CA chain. Falling back to
    // the platform trust store here would mark every such peer unauthorized.
    useDefaultCA: options.useDefaultCA === true,
    // Resumption, as over TCP (TLSSocket): a 'session' Buffer from an
    // earlier connection — a DTLS 1.3 PSK ticket, or a DTLS 1.2 RFC 5077
    // ticket — and whether this side issues / asks for tickets (default
    // true; noTickets: true is the older spelling of sessionTickets: false).
    session: options.session || null,
    sessionTickets: options.sessionTickets !== undefined ? options.sessionTickets !== false
                                                         : options.noTickets !== true,
    // No 0-RTT over DTLS here: early data has no DTLS record path.
    earlyData: false,
    connectionId: connectionIdOption(options.connectionId, isServer),
  }));

  // ---- DTLS context ----
  let ctx = {
    state: 'idle',         // idle → handshaking → connected → closed
    // Connection IDs (RFC 9146, RFC 9147 §9): { local, peer } once
    // negotiated ('connectionId'), the peer's as NewConnectionId moves it;
    // and the newest record number authenticated (noteNewest), the one
    // a peer's new address may be taken from.
    cid: null,
    rxNewest: null,
    consecutiveWarnings: 0,   // warning alerts with nothing else between them
    // DTLS 1.3 ACK state (RFC 9147 §7.1), for the peer's flight in progress:
    // the handshake records of it received so far, a timer for the ACK when
    // the rest does not follow, and whether this datagram showed a gap.
    lastFlight12: null,       // DTLS 1.2: our last flight, kept for the peer's retransmissions
    dgAnyNew: false,          // this datagram: a handshake message not taken before
    dgDuplicate: false,       // this datagram: a handshake message already taken
    dgNewest: false,          // this datagram: a protected record newer than any before
    pendingAcks: [],
    ackTimer: null,
    postAcks: [],             // post-handshake records received, to ACK together
    postAckTimer: null,
    ackDisruption: false,
    flightMessagesQueued: 0,   // flight messages queued, ever (did this datagram answer with one?)
    isServer: isServer,
    mtu: checkedMtu(options.mtu, 1200),

    // Upper bound on a single reassembled handshake message. The DTLS handshake
    // header carries a 24-bit length (up to 16MB), which is attacker-controlled
    // on the very first fragment. Without a cap, a peer could send one fragment
    // claiming length 0xFFFFFF for several msg_seqs and force large allocations
    // before anything is authenticated. TLS over TCP's limit
    // (tls.handshakeMessageLimit(): 128 KB, or maxHandshakeSize) — it was a
    // limit of DTLS's own, 256 KB. maxHandshakeMessageSize, its older
    // option, is still taken (never past the same 128 KB).
    maxHandshakeMessageSize: options.maxHandshakeMessageSize > 0 ? Math.min(options.maxHandshakeMessageSize, tls.handshakeMessageLimit()) : tls.handshakeMessageLimit(),

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
    postHandshake: [],         // DTLS 1.3 post-handshake messages awaiting their ACK
    deferredKeyUpdate: null,   // DTLS 1.3: our KeyUpdate held back while one is unACKed (§8)
    feeding: 0,                // inside feedDatagram: post-handshake messages wait for its end
    seenPlainSeqs: [],         // the last epoch-0 record numbers received (duplicates dropped)
    out: [],                   // what is to be sent, packed at the end of the pass (flushOut)
    flightQueued: 0,           // messages of the current flight queued (haveFlight)
    outScheduled: false,
    heldPostHandshake: [],     // ...these (sendPostHandshake)
    lastAckResend: 0,          // when an ACK that confirmed nothing new last caused a resend
    finalFlightPending: false, // DTLS 1.3 client: final flight not yet confirmed (see secureConnect)

    retransmitTimer: null,
    retransmitCount: 0,
    retransmitTimeout: checkedRetransmitTimeout(options.initialRetransmitTimeout, 1000),
    initialRetransmitTimeout: checkedRetransmitTimeout(options.initialRetransmitTimeout, 1000),   // where each flight's timer starts (RFC 9147 §5.8.2: 1 s)
    // Given, the schedule is the caller's: no round-trip estimate moves it.
    fixedRto: options.initialRetransmitTimeout !== undefined && options.initialRetransmitTimeout !== null,
    lastSession: undefined,   // the last 'session' Buffer (getSession)
    // Giving up (RFC 9147 §5.8.2 leaves it to us): after at least this many
    // retransmissions AND this much time since the flight first went out.
    // A count alone was 6 tries: about a minute from a 1 s timer, but 6 s from
    // a 100 ms one (as WebRTC stacks start), too soon on a lossy path.
    maxRetransmits: 6,
    giveUpAfter: 60000,
    // Round-trip estimate (RFC 6298's, as RFC 9147 §5.8.2 invites: "the
    // retransmit timer [...] SHOULD be adjusted from RTT samples"): from a
    // flight sent once to the first new message of the answer (Karn: never
    // from one retransmitted). Later flights' timers start from it.
    srtt: null, rttvar: null,
    flightBegan: null,         // when the current flight first went out (giving up)
    rttStart: null,            // ...the same, until its answer is sampled (RTT)
    flightResent: false,       // whether it has been resent

    // DTLS 1.2: CCS tracking
    localCcsSent: false,

    // HelloVerifyRequest (DTLS 1.2 server)
    hvrCookie: null,       // cookie sent in HVR
    hvrDone: false,        // true after HVR exchange complete
  };


  // ============================================================
  //  Setup TLSSession for DTLS
  // ============================================================

  // Set DTLS versions and cookie (triggers DTLS format in build_hello)
  // node_options.js: the same reading as TLS over TCP. Inline compares took
  // an unknown name silently.
  let versions = versionsInRange(options.minVersion, options.maxVersion, true);

  // The lists from the options (node_options.js localLists, as TLS over TCP
  // builds them: the same names, cipherSuites and alpnProtocols as aliases);
  // TLSSession fills what they leave out, by role (fill_default_lists). A
  // DTLS server took no signatureAlgorithms nor prioritizeChaCha before, and
  // a DTLS client offered every post-quantum group a server takes.
  let tlsSetup = Object.assign(localLists(options, versions), {
    dtls_cookie: new Uint8Array(0),  // empty cookie — triggers DTLS format
  });

  // Server cert/key.
  //
  // The whole options object goes in, not just key+cert: createSecureContext
  // also reads passphrase, ca, ciphers, sigalgs, ecdhCurve, honorCipherOrder,
  // pfx and ocsp, and picking out two fields silently dropped all of them —
  // an encrypted private key could never be decrypted here no matter what the
  // caller passed. Same defect the TLS paths carried.
  // Through TLSSession's setKeyCert, as an SNICallback's context goes in:
  // the key/certificate pairs — several (key: [...], cert: [...]), the one
  // the client can verify chosen per handshake — not only the first.
  tls.set_context(tlsSetup);
  if (options.cert && options.key) tls.setKeyCert(createSecureContext(options));


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
      // §8: only one KeyUpdate may be in flight. requestKeyUpdate() refuses
      // up front; the TLS session's answer to the peer's update_requested
      // is held back (deferredKeyUpdate). Anything else reaching here with
      // one pending would strand an epoch: said, not lost in silence.
      if (ctx.pendingWriteEpoch !== null) {
        // The secret of a KeyUpdate held back (deferredKeyUpdate): it takes
        // effect when that one goes.
        if (ctx.deferredKeyUpdate && ctx.deferredKeyUpdate.secret === null) {
          ctx.deferredKeyUpdate.secret = info.secret;
          return;
        }
        ev.emit('error', new Error(
          'DTLS: a KeyUpdate is already awaiting acknowledgement (RFC 9147 §8)'));
        return;
      }
      installWriteUpdate(info.secret);
    } else if (info.direction === 'receive') {
      let next = ctx.readEpoch + 1;
      ctx.keys[next] = Object.assign({}, ctx.keys[next], { read: deriveEpochKeys(info.secret) });
      ctx.readEpoch = next;
      // The previous epoch's read keys are deliberately RETAINED. §8: records
      // already in flight under the old epoch must still deprotect, and our
      // ACK may be lost, so the peer may retransmit under the old keys.
    }
  });

  // ── Datagrams ──
  // Everything this side sends goes through one queue (ctx.out), and leaves
  // it packed (flushOut): handshake messages of one epoch share a record —
  // a message is cut where the space runs out, and the next goes on in the
  // same record (RFC 6347 §4.2.3, RFC 9147 §5.5: several handshake messages
  // or fragments to a record); records share a datagram, up to the MTU, each
  // with its length (the DTLS 1.3 unified header's L bit is always set here:
  // RFC 9147 §4.3, RFC 6347 §4.1.1). One record per message and one datagram
  // per record left room unused (BoGo MTU-DTLS13: "previous packet had 212
  // bytes available"); records alone packed into a datagram left room in the
  // record (BoGo: "previous handshake record had 1107 bytes available, but
  // shim did not fit another fragment in it"). Retransmissions are packed the
  // same way: what is still unACKed, cut again to fill.
  //   Items: { kind: 'msg', tlsMsg, msgSeq, epoch, list } — a whole handshake
  //   message, fragmented here; each fragment becomes an entry of `list` (the
  //   flight, a post-handshake message), what ACKs and retransmission act on;
  //   { kind: 'entry', entry } — one of those, (re)sent; { kind: 'raw', epoch,
  //   contentType, payload } — a record of its own (ACK, application data,
  //   HelloVerifyRequest).
  // A pass ends at the next microtask; at once before an alert (its own
  // datagram: wolfSSL took a Finished and a close_notify packed together for
  // a failed handshake) and when the session ends, so its last word is out
  // before 'close'.
  function queueOut(item) {
    ctx.out.push(item);
    if (!ctx.outScheduled) { ctx.outScheduled = true; queueMicrotask(function () { ctx.outScheduled = false; flushOut(); }); }
  }
  function queueMessage(tlsMsg, msgSeq, epoch, list, label) {
    queueOut({ kind: 'msg', tlsMsg: tlsMsg, msgSeq: msgSeq, epoch: epoch, list: list, label: label });
  }

  // A handshake fragment entry cut in two: its first `n` body bytes stay, the
  // rest becomes a new entry right after it in the same list.
  function splitEntry(e, n) {
    let p = e.payload, type = p[0], total = (p[1] << 16) | (p[2] << 8) | p[3];
    let msgSeq = (p[4] << 8) | p[5], off = (p[6] << 16) | (p[7] << 8) | p[8];
    let body = p.subarray(12);
    let frag = function (o, b) { return build_dtls_fragment(type, total, msgSeq, o, b); };
    let rest = { epoch: e.epoch, contentType: e.contentType, payload: frag(off + n, body.subarray(n)), list: e.list };
    e.payload = frag(off, body.subarray(0, n));
    if (e.list) { let i = e.list.indexOf(e); if (i >= 0) e.list.splice(i + 1, 0, rest); }
    return rest;
  }

  // The most a record of ours carries: 2^14, or the peer's
  // record_size_limit (RFC 8449) once negotiated — as TLSSocket's.
  function flushOut() {
    if (ctx.out.length === 0) return;
    let queue = ctx.out;
    ctx.out = [];
    let parts = [], used = 0, rec = null, failed = false;
    // Room left: in the datagram (the MTU), and in the record (2^14, or the
    // peer's record_size_limit — RFC 8449).
    let cap = tls.recordSendLimit();
    let left = function () {
      return Math.min(ctx.mtu - used - (rec ? recordOverhead(rec.epoch) + rec.len : 0), cap - (rec ? rec.len : 0));
    };
    let open = function (epoch, contentType, label) {
      rec = { epoch: epoch, contentType: contentType, parts: [], entries: [], len: 0, label: label };
    };
    let closeRec = function () {
      if (!rec) return;
      let r = rec; rec = null;
      let seq = (r.epoch in ctx.writeSeq) ? ctx.writeSeq[r.epoch] : 0;
      let payload = r.parts.length === 1 ? r.parts[0] : concatUint8Arrays(r.parts);
      let record = buildRecord(r.epoch, r.contentType, payload);
      if (!record) {
        // buildRecord refused (no keys for an encrypted epoch): said, not
        // dropped in silence — the handshake cannot go on either way.
        failed = true;
        fail(new Error('DTLS: could not build outgoing record for epoch ' + r.epoch + ' — no keys installed for that epoch'), TLS_ALERT.INTERNAL_ERROR);
        return;
      }
      let rn = recordNumber(r.epoch, seq);
      for (let i = 0; i < r.entries.length; i++) (r.entries[i].sent || (r.entries[i].sent = [])).push(rn);
      _ldbgTx(record, r.label || 'out');
      parts.push(record); used += record.length;
    };
    let endDatagram = function () {
      closeRec();
      if (parts.length === 0) return;
      let dg = parts.length === 1 ? parts[0] : concatUint8Arrays(parts);
      parts = []; used = 0;
      ev.emit('packet', dg);
    };
    // A record of `epoch` with at least `need` payload bytes: in this
    // datagram if it fits, else the next.
    let room = function (epoch, need) {
      if (used > 0 && ctx.mtu - used < recordOverhead(epoch) + need) endDatagram();
    };
    // Into the open handshake record of `epoch`, or a new one.
    let intoHandshake = function (epoch, need, label) {
      if (rec && (rec.epoch !== epoch || rec.contentType !== CT.HANDSHAKE || left() < need)) closeRec();
      if (!rec) { room(epoch, need); open(epoch, CT.HANDSHAKE, label); }
    };

    for (let qi = 0; qi < queue.length && !failed; qi++) {
      let item = queue[qi];
      if (item.kind === 'msg') {
        let body = item.tlsMsg.subarray(4), total = body.length, off = 0;
        do {
          intoHandshake(item.epoch, 12 + Math.min(total - off, 1), item.label);
          let take = Math.max(0, Math.min(total - off, left() - 12));
          let frag = build_dtls_handshake(item.tlsMsg, item.msgSeq, off, take);
          let entry = { epoch: item.epoch, contentType: CT.HANDSHAKE, payload: frag, list: item.list };
          item.list.push(entry);
          rec.parts.push(frag); rec.entries.push(entry); rec.len += frag.length;
          off += take;
        } while (off < total && !failed);
      } else if (item.kind === 'entry' && item.entry.contentType === CT.HANDSHAKE) {
        let e = item.entry;
        if (e.acked) continue;
        intoHandshake(e.epoch, Math.min(e.payload.length, 13), item.label);
        // Too long for what is left: cut to fill (a fragment's body only).
        if (e.payload.length > left() && e.payload.length > 13 && left() >= 13) {
          let rest = splitEntry(e, left() - 12);
          queue.splice(qi + 1, 0, { kind: 'entry', entry: rest, label: item.label });
        }
        rec.parts.push(e.payload); rec.entries.push(e); rec.len += e.payload.length;
      } else {
        // A record of its own: a ChangeCipherSpec (an entry of the flight),
        // an ACK, application data, a HelloVerifyRequest.
        let e = item.kind === 'entry' ? item.entry : null;
        if (e && e.acked) continue;
        // A new entry (sendCCS): it joins its list here, in sending order.
        if (e && item.join && e.list) e.list.push(e);
        let epoch = e ? e.epoch : item.epoch, contentType = e ? e.contentType : item.contentType;
        let payload = e ? e.payload : item.payload;
        closeRec();
        room(epoch, payload.length);
        open(epoch, contentType, item.label);
        rec.parts.push(payload); rec.len += payload.length;
        if (e) rec.entries.push(e);
        closeRec();
      }
    }
    if (!failed) endDatagram();
  }

  // Our next write epoch's keys, from a KeyUpdate we sent: installed now, used
  // from its ACK on (§8). ctx.keys[next] may already carry a .read half from
  // the peer's own update — merge, never overwrite.
  function installWriteUpdate(secret) {
    let next = ctx.writeEpoch + 1;
    ctx.keys[next] = Object.assign({}, ctx.keys[next], { write: deriveEpochKeys(secret) });
    ctx.writeSeq[next] = 0;
    ctx.pendingWriteEpoch = next;
  }

  // ── Post-handshake messages (RFC 9147 §5.8.4, §7.1) ──
  // NewSessionTicket and KeyUpdate have no answering flight: each is
  // resent on its own timer until the peer ACKs it — independently of the
  // handshake flight and of each other. Only KeyUpdate was; a lost
  // NewSessionTicket was simply lost (BoGo DTLS-Retransmit-*NewSessionTicket*).
  // KeyUpdate's ACK also switches our write epoch (§8) — on the ACK that
  // covers it, not on any ACK, as before.
  // One made while a datagram is being taken in (feedDatagram) waits for its
  // end — for the ACK that datagram may call for (§7.1). The server's
  // NewSessionTickets come of the client's Finished: they went out ahead of
  // its ACK, and a peer that waits for the ACK first (BoringSSL's runner)
  // read the first ticket as renegotiation and the second as out of order
  // (BoGo N1). A KeyUpdate answering the peer's follows its ACK the same way.
  function sendPostHandshake(kind, tlsMsg, msgSeq, epoch) {
    let item = { kind: kind, msg: { tlsMsg: tlsMsg, msgSeq: msgSeq, epoch: epoch }, entries: [],
                 attempts: 0, timeout: currentRto(), timer: null, began: Date.now() };
    ctx.postHandshake.push(item);
    if (ctx.feeding > 0) { ctx.heldPostHandshake.push(item); return; }
    transmitPostHandshake(item);
  }
  function transmitPostHandshake(item) {
    queueMessage(item.msg.tlsMsg, item.msg.msgSeq, item.msg.epoch, item.entries, item.kind);
    schedulePostHandshake(item);
  }
  function flushHeldPostHandshake() {
    let held = ctx.heldPostHandshake;
    ctx.heldPostHandshake = [];
    for (let i = 0; i < held.length; i++) {
      if (ctx.state === 'closed' || ctx.postHandshake.indexOf(held[i]) < 0) continue;
      transmitPostHandshake(held[i]);
    }
  }

  function schedulePostHandshake(item) {
    item.timer = setTimeout(function () {
      item.timer = null;
      if (ctx.postHandshake.indexOf(item) < 0 || ctx.state === 'closed') return;
      if (exhausted(item.attempts, item.began)) {
        removePostHandshake(item);
        // An unacknowledged KeyUpdate leaves the next epoch unusable; a
        // ticket is an offer, and the connection is fine without it.
        if (item.kind === 'key_update') ev.emit('error', new Error('DTLS: KeyUpdate was never acknowledged'));
        return;
      }
      item.attempts++;
      // Rebuilt, not replayed: each retransmission is a new record with a
      // fresh sequence number, or the peer's replay window drops it.
      transmitUnacked(item.entries, item.kind + '-rtx', false);
      item.timeout = Math.min(item.timeout * 2, 60000);
      schedulePostHandshake(item);
    }, item.timeout);
    if (item.timer && typeof item.timer.unref === 'function') item.timer.unref();
  }

  function removePostHandshake(item) {
    if (item.timer) clearTimeout(item.timer);
    let i = ctx.postHandshake.indexOf(item);
    if (i >= 0) ctx.postHandshake.splice(i, 1);
  }

  // The session is over: every timer it runs stops with it.
  function shutDown() {
    flushOut();
    ctx.state = 'closed';
    cancelRetransmit();
    cancelPostHandshake();
    clearPendingAcks();
  }

  function cancelPostHandshake() {
    for (let i = 0; i < ctx.postHandshake.length; i++) {
      if (ctx.postHandshake[i].timer) clearTimeout(ctx.postHandshake[i].timer);
    }
    ctx.postHandshake = [];
    ctx.heldPostHandshake = [];
    ctx.deferredKeyUpdate = null;
  }

  // The post-handshake messages an ACK covers (by record number): done.
  // A second ACK of them finds nothing left, and changes nothing
  // (BoGo ACKPostHandshakeTwice).
  function ackPostHandshake(got) {
    for (let i = ctx.postHandshake.length - 1; i >= 0; i--) {
      let item = ctx.postHandshake[i];
      if (item.entries.length === 0) continue;   // not out yet
      markAcked(item.entries, got);
      if (item.entries.some(function (e) { return !e.acked; })) continue;
      removePostHandshake(item);
      if (item.kind === 'key_update' && ctx.pendingWriteEpoch !== null) {
        // §8: the new epoch becomes live on the ACK of the KeyUpdate.
        ctx.writeEpoch = ctx.pendingWriteEpoch;
        ctx.pendingWriteEpoch = null;
        ev.emit('keyUpdate', { direction: 'send', epoch: ctx.writeEpoch });
        if (ctx.state === 'closed') return;   // a listener closed it
        // The KeyUpdate held back for this one (§8): now, under the epoch
        // just made live — the one it replaces.
        let held = ctx.deferredKeyUpdate;
        if (held && held.secret !== null) {
          ctx.deferredKeyUpdate = null;
          sendPostHandshake('key_update', held.tlsMsg, held.msgSeq, ctx.writeEpoch);
          installWriteUpdate(held.secret);
        }
      }
    }
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
                : appEpoch();
    } else {
      dtlsEpoch = 1;  // DTLS 1.2: epoch 1 for all encrypted
    }

    if (type === 'alert') {
      // TLSSession names the epoch the PEER reads at (sendAlert); this layer
      // holds the keys. Its choice when we hold write keys for it, else the
      // highest epoch we do (alertEpoch) — never a record for an epoch we
      // have no keys for, which a DTLS 1.3 alert before any keys could
      // become: a unified header the peer could not even parse ("bad type
      // byte"; BoGo FragmentMessage*Mismatch).
      let ae = (dtlsEpoch === 0 || (ctx.keys[dtlsEpoch] && ctx.keys[dtlsEpoch].write)) ? dtlsEpoch : alertEpoch();
      sendAlertRecord(ae, data);
      return;
    }

    // DTLS 1.2: keys before the first encrypted message
    if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3 && tlsEpoch === 1) installKeys12();

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

    // Out as a DTLS handshake message — fragmented as it is packed (flushOut).
    // RFC 9147 §5.8.4: post-handshake messages do NOT belong to the handshake
    // flight. Each category gets an independent state machine; folding a
    // KeyUpdate into currentFlight would make a handshake retransmission
    // replay it, and a KeyUpdate ACK cancel the handshake's timer.
    // DTLS 1.3, after the handshake: KeyUpdate, NewSessionTicket — each on
    // its own retransmission until ACKed (sendPostHandshake).
    // (A TLS 1.3 NewSessionTicket is post-handshake whenever it goes — the
    // server sends its first one just before it reports the handshake done.)
    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3 &&
        (type === 'new_session_ticket' || (type === 'key_update' && ctx.state === 'connected'))) {
      // §8: one KeyUpdate at a time — "until the KeyUpdate message has been
      // acknowledged" no other. Ours answering the peer's update_requested
      // while our own is unACKed waits for that ACK (ackPostHandshake), then
      // goes under the epoch it replaces. Sent at once, the next one's keys
      // found an epoch still pending and the connection failed (BoringSSL,
      // which delays its ACKs: every time).
      if (type === 'key_update' && ctx.pendingWriteEpoch !== null) {
        ctx.deferredKeyUpdate = { tlsMsg: data, msgSeq: seq, secret: null };
        return;
      }
      sendPostHandshake(type, data, seq, dtlsEpoch);
      return;
    }

    queueFlightMessage(data, seq, dtlsEpoch);

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
      return buildEncryptedDtls13(contentType, payload, nextWriteSeq(epoch), epoch, epochKeys.write, peerCid());
    } else {
      // DTLS 1.2 encrypted (classic header)
      return buildEncryptedDtls12(contentType, epoch, nextWriteSeq(epoch), payload, epochKeys.write, peerCid());
    }
  }

  // The CID the peer asked for, in every protected record we send (null:
  // none). Ours, that the peer's carry: from the moment we ask for it — a
  // record with it can come in the datagram that agrees to it (a resumed
  // DTLS 1.2 server's Finished, behind its ServerHello) — and required once
  // agreed to.
  function peerCid() { return ctx.cid && ctx.cid.peer.length > 0 ? ctx.cid.peer : null; }
  function localCid() { let c = tls.context.local_cid; return c && c.length > 0 ? c : null; }
  function localCidRequired() { return !!(ctx.cid && ctx.cid.local.length > 0); }

  function nextWriteSeq(epoch) {
    if (!(epoch in ctx.writeSeq)) ctx.writeSeq[epoch] = 0;
    return ctx.writeSeq[epoch]++;
  }

  /**
   * The one way a handshake message of a flight goes out: queued, to be cut
   * and packed (flushOut) into entries of the current flight — kept for
   * retransmission — and counted as our answer (the implicit ACK, RFC 9147
   * §7.1). The cookie-bearing ClientHello goes the same way.
   */
  function queueFlightMessage(tlsMsg, msgSeq, dtlsEpoch) {
    ctx.flightMessagesQueued++;
    ctx.flightQueued++;
    if (ctx.flightBegan === null) ctx.flightBegan = Date.now();
    if (ctx.rttStart === null && ctx.currentFlight.length === 0 && ctx.flightQueued === 1) ctx.rttStart = Date.now();
    queueMessage(tlsMsg, msgSeq, dtlsEpoch, ctx.currentFlight, 'flight');
  }

  // What one record adds around its payload, by the epoch it goes out in
  // (flushOut fills datagrams to the MTU with it):
  //   unprotected (epoch 0, and DTLS 1.2 before the CCS): the 13-byte
  //     DTLSPlaintext header, nothing else;
  //   DTLS 1.3 protected: the unified header (1 + 2-byte sequence number +
  //     2-byte length), the inner content-type byte, the 16-byte tag;
  //   DTLS 1.2 protected: 13 + the 16-byte tag + the 8-byte explicit nonce
  //     of AES-GCM / CCM (ChaCha20-Poly1305 has none, RFC 7905 §2);
  //   and, with the peer's CID, the CID — and in 1.2 the inner type byte.
  // A single figure for all — 37, or 21 for 1.3 — left 24 bytes unused in
  // every plaintext fragment (the whole DTLS 1.2 certificate flight), and
  // was a byte short for 1.3, which forgot the content type.
  function recordOverhead(epoch) {
    if (!ctx.keys[epoch] || !ctx.keys[epoch].write) return 13;
    let cid = peerCid(), cidLen = cid ? cid.length : 0;
    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3) return 5 + cidLen + 1 + 16;
    // The explicit nonce, as the suite table has it (record_ivlen).
    let meta = TLS_CIPHER_SUITES[tls.getCipher()];
    return 13 + (cid ? cidLen + 1 : 0) + 16 + (meta && meta.record_ivlen ? meta.record_ivlen : 0);
  }

  // DTLS 1.2, a ticket offered with no session_id (a hello offering DTLS
  // 1.3 too): an epoch-1 record before any keys is the resumed server's
  // ChangeCipherSpec or Finished — a full handshake has none before our
  // flight. Tried under the keys the saved session gives; one that opens
  // takes the resumption (tls.commitResume12), and the keys are installed.
  // One that does not — anyone may send a datagram — changes nothing.
  function tryResumedKeys12(record) {
    let ms = tls.resumeCandidate12();
    if (!ms) return;
    let d12;
    try { d12 = keys12(ms); } catch (e) { return; }
    let opened;
    try { opened = openDtls12(record.content, { key: d12.readKey, iv: d12.readIv }, record.epoch, record.seq, record.type, localCid()); }
    catch (e) { return; }
    if (!tls.commitResume12() || !installKeys12()) return;
    open12(record, ctx.keys[1].read, opened);
  }

  // A DTLS 1.2 record of an epoch whose keys came after the datagram was
  // parsed, opened now (or `opened` already: { type, content }), and through
  // the replay window, as the datagram parser does. False when it does not
  // open; one that opens and is malformed inside is the peer's (alertDesc).
  function open12(record, readKeys, opened) {
    try {
      opened = opened || openDtls12(record.content, readKeys, record.epoch, record.seq, record.type, localCid());
    } catch (e) { if (e && e.alertDesc) throw e; return false; }
    record.type = opened.type;
    record.content = opened.content;
    record.encrypted = true;
    if (!acceptRecordSeq(readKeys, record.seq)) record.replayed = true;
    return true;
  }

  // DTLS 1.2: epoch 1's keys, from a master secret — the session's, once
  // there is one, or a candidate's (tryResumedKeys12). One place: they were
  // derived in three.
  function keys12(masterSecret) {
    let ts = tls.getTrafficSecrets();
    return deriveKeys12(masterSecret, ts.localRandom, ts.remoteRandom, tls.getCipher(), isServer);
  }
  // …installed, once there is a master secret to make them of. True when
  // they are there.
  function installKeys12() {
    if (ctx.keys[1]) return true;
    let ts = tls.getTrafficSecrets();
    if (!ts.masterSecret) return false;
    let d12 = keys12(ts.masterSecret);
    ctx.keys[1] = {
      write: { key: d12.writeKey, iv: d12.writeIv },
      read:  { key: d12.readKey,  iv: d12.readIv },
    };
    ctx.writeSeq[1] = 0;
    return true;
  }

  // DTLS 1.3: the application epoch we write — 3 until a KeyUpdate moves it on.
  function appEpoch() { return ctx.writeEpoch !== null ? ctx.writeEpoch : 3; }

  /**
   * The epoch our alerts (and close_notify) go out in: the highest one we
   * hold write keys for and the peer reads. DTLS 1.3: the live application
   * epoch once connected — after a KeyUpdate that is 4, 5, ..., and the peer
   * no longer reads 3 — else the handshake epoch once its keys exist, else 0
   * (a DTLSPlaintext record). DTLS 1.2: epoch 1 once our ChangeCipherSpec
   * has gone, else 0.
   */
  function alertEpoch() {
    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3) {
      if (ctx.state === 'connected' && ctx.writeEpoch !== null && ctx.keys[ctx.writeEpoch] && ctx.keys[ctx.writeEpoch].write) return ctx.writeEpoch;
      if (ctx.keys[2] && ctx.keys[2].write) return 2;
      return 0;
    }
    return (ctx.localCcsSent && ctx.keys[1] && ctx.keys[1].write) ? 1 : 0;
  }

  /**
   * Send an alert record.
   */
  function sendAlertRecord(epoch, alertData) {
    // What is queued goes first, the alert in a datagram of its own (see
    // flushOut).
    flushOut();
    let record = buildRecord(epoch, CT.ALERT, alertData);
    // buildRecord returns null when it refuses to emit a malformed record
    // (DTLS 1.3 epoch >= 2 with no keys installed). Emitting that null as a
    // packet pushes `null` into the transport; drop it instead — we already
    // surfaced the reason through 'error'.
    if (!record) return;
    _ldbgTx(record, 'alert'); ev.emit('packet', record);
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
    // RFC 6347 §4.2.4: the CCS is part of the flight and MUST be included
    // when the flight is retransmitted. Captured as a descriptor (epoch 0,
    // plaintext), so resendFlight rebuilds it with a fresh seq like every
    // other record. Previously it was emitted but never captured, so a
    // retransmitted final flight arrived WITHOUT the cipher-spec change and
    // the peer could never decrypt the accompanying Finished — an
    // unrecoverable stall under single-datagram loss.
    //
    // Into the flight where it goes out, as the messages' fragments are
    // (flushOut): the messages queued before it — the ClientKeyExchange, a
    // Certificate — are cut into entries only then, and a CCS put in the
    // list here, at once, went ahead of them. Every retransmission then
    // opened with the CCS (BoGo DTLS-RetransmitFinished-Fragmented: "record
    // of type 20 in retransmit, but expected 22"); a peer that reads in
    // order takes it before the key exchange it follows.
    let ccs = { epoch: 0, contentType: CT.CHANGE_CIPHER_SPEC, payload: new Uint8Array([1]), list: ctx.currentFlight };
    queueOut({ kind: 'entry', entry: ccs, label: 'ccs', join: true });
  }


  // ============================================================
  //  Incoming: UDP datagram → parse → feed TLSSession
  // ============================================================

  /**
   * The one way a DTLS session ends in failure: our alert (when there is one
   * to send — none when the peer's alert or TLSSession's own already went),
   * the session closed (no more input, no retransmission), 'error', then
   * 'close'. 'close' is what DTLSServer drops the connection on: a session
   * that only emitted 'error' stayed in its table, deaf, and the address
   * could not start a new handshake.
   */
  function fail(err, alertDesc) {
    if (ctx.state === 'closed') return;
    if (alertDesc !== undefined && alertDesc !== null) {
      try { tls.sendAlert(2, alertDesc); } catch (e) {}
      err = local_alert_error(alertDesc, err);
    }
    shutDown();
    ev.emit('error', err);
    ev.emit('close');
  }

  /**
   * The input boundary: nothing a peer sends may throw out of this session
   * (a single UDP datagram, spoofable by anyone, took the process down —
   * BoGo). What cannot be read as a record is dropped where it is read, as
   * RFC 9147 §4.5.2 / RFC 6347 §4.1.2.7 ask ("invalid records SHOULD be
   * silently discarded"); what is left to throw here comes from a record
   * that WAS read, or from a bug, and ends the session — the error's own
   * alert (alertDesc), internal_error otherwise. TLSSession has the same
   * boundary for what reaches it (run_guarded).
   */
  //
  // Returns whether the datagram held a record that authenticated and is
  // the newest yet (by epoch, then sequence number) — RFC 9146 §6 / RFC
  // 9147 §9's condition for taking a new peer address, which the layer
  // above decides.
  function feedDatagram(data) {
    ctx.dgNewest = false;
    try {
      feedDatagramUnguarded(data);
    } catch (e) {
      let err = e instanceof Error ? e : new Error(String(e));
      fail(err, (e && e.alertDesc) || TLS_ALERT.INTERNAL_ERROR);
      return false;
    }
    return ctx.dgNewest;
  }

  // A protected record taken: the newest so far?
  function noteNewest(record) {
    let n = ctx.rxNewest;
    if (n && (record.epoch < n.epoch || (record.epoch === n.epoch && record.seq <= n.seq))) return;
    ctx.rxNewest = { epoch: record.epoch, seq: record.seq };
    ctx.dgNewest = true;
  }

  function feedDatagramUnguarded(data) {
    ctx.feeding++;
    try { takeDatagram(data); }
    finally { if (--ctx.feeding === 0) flushHeldPostHandshake(); }
  }

  function takeDatagram(data) {
    if (ctx.state === 'closed') return;
    if (ctx.state === 'idle') ctx.state = 'handshaking';

    // Build key lookup for decryption
    let keysByEpoch = {};
    for (let ep in ctx.keys) {
      if (ctx.keys[ep] && ctx.keys[ep].read) {
        keysByEpoch[Number(ep)] = ctx.keys[ep].read;
      }
    }

    let records = parseDtlsDatagram(data, keysByEpoch, localCid(), localCidRequired());

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
    // in this datagram so we can ACK them once, after processing (DTLS 1.3):
    // a flight's at once or a quarter-timer later, post-handshake ones
    // together, delayed (see "ACKs" below).
    let ackable = [];

    // Whether these records arrived AFTER the handshake must be decided here,
    // before the loop — not after it. The datagram that completes the
    // handshake flips ctx.state to 'connected' partway through, so reading the
    // state afterwards misclassifies the handshake's own epoch-2 records as
    // post-handshake and ACKs them inside the application-data epoch. That is
    // the spurious epoch-3 ACK that makes a peer answer decode_error on the
    // NEXT record — so a perfectly good SCTP COOKIE_ECHO takes the blame.
    let wasConnectedOnEntry = (ctx.state === 'connected');
    let sentBefore = ctx.flightMessagesQueued;
    ctx.ackDisruption = false;
    ctx.dgAnyNew = false;
    ctx.dgDuplicate = false;
    ctx.dgNewest = false;

    for (let i = 0; i < records.length; i++) {
      // An unprotected record received before — same epoch-0 sequence number
      // — is the same record again (replayed, or duplicated on the way), not
      // the peer retransmitting: a retransmission is a new record, with a new
      // number. Taken as one, it had us resend our flight (BoGo
      // DTLS-Replay-TLS12). Not a sliding window, as for protected records
      // (acceptRecordSeq): an unauthenticated number must not move one — a
      // forged high one would make every real record "too old". Just the
      // last numbers seen.
      if (records[i].epoch === 0 && !records[i].encrypted) {
        if (ctx.seenPlainSeqs.indexOf(records[i].seq) >= 0) continue;
        ctx.seenPlainSeqs.push(records[i].seq);
        if (ctx.seenPlainSeqs.length > 64) ctx.seenPlainSeqs.shift();
      }
      if (records[i].replayed) continue;
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
        // A record that opened but is malformed inside (alertDesc) is the
        // peer's: to the boundary. Anything else: it did not open, dropped.
        try { dec = decryptEncryptedDtls13(records[i].raw, readKeys, records[i].epoch, localCid(), localCidRequired()); } catch (e) { if (e && e.alertDesc) throw e; dec = null; }
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

      let hadKeys12 = !!ctx.keys[1];
      if (!hadKeys12 && ctx.selectedVersion === DTLS_VERSION.DTLS1_2 && records[i].epoch === 1 && !records[i].encrypted) {
        tryResumedKeys12(records[i]);
      }
      processRecord(records[i]);
      if (ctx.state === 'closed') break;
      if (records[i].encrypted) noteNewest(records[i]);
      if (ctx.selectedVersion === DTLS_VERSION.DTLS1_2 && !ctx.keys[1]) installKeys12();

      // DTLS 1.2 keys just installed: what of this datagram came protected
      // under them can be read now.
      if (!hadKeys12 && ctx.keys[1]) {
        let readKeys = ctx.keys[1].read;
        for (let j = i + 1; j < records.length; j++) {
          if (!records[j].encrypted && records[j].epoch > 0 && readKeys) open12(records[j], readKeys);
        }
      }
    }

    dtls12AnswerRetransmission();

    // ── ACKs (RFC 9147 §7.1) ──
    // Post-handshake records (NewSessionTicket, KeyUpdate, or the client's
    // final flight again, its ACK lost): nothing answers them, so they are
    // ACKed — at the highest sending epoch (§7) — but not each at once: one
    // ACK a quarter of the timer later covers all that came meanwhile (§7.1,
    // "implementations SHOULD [...] delay sending ACKs"; a server's two
    // tickets, two records each, were four ACKs).
    if (wasConnectedOnEntry) {
      for (let ai = 0; ai < ackable.length; ai++) noteAck(ctx.postAcks, ackable[ai]);
      if (ctx.postAcks.length > 0 && ctx.postAckTimer === null) {
        ctx.postAckTimer = setTimeout(function () {
          ctx.postAckTimer = null;
          if (ctx.state === 'closed' || ctx.postAcks.length === 0) return;
          let all = ctx.postAcks; ctx.postAcks = [];
          sendAck(appEpoch(), all, true);
        }, ackDelay(currentRto()));
        if (ctx.postAckTimer.unref) ctx.postAckTimer.unref();
      }
      return;
    }
    for (let ai = 0; ai < ackable.length; ai++) noteAck(ctx.pendingAcks, ackable[ai]);
    if (ctx.pendingAcks.length === 0) return;

    // The client's final flight, now complete (the handshake is): nothing of
    // ours answers it (a NewSessionTicket that follows is no answer — it is
    // checked first for that reason), so it is ACKed explicitly, at once — §7.1 "MUST send
    // ACKs upon receiving all of any flight which they do not respond to" —
    // at the highest sending epoch, now the application one (§7).
    if (isServer && ctx.state === 'connected') {
      let all = ctx.pendingAcks; clearPendingAcks();
      sendAck(appEpoch(), all, true);
      return;
    }
    // The flight is complete and we answered it: our flight is the ACK
    // (implicit). Sending one as well is what the RFC asks us not to do —
    // "ACKs SHOULD NOT be sent for these complete flights" — and what BoGo
    // saw: an ACK for every datagram of a flight, landing where the peer
    // does not expect one.
    if (ctx.flightMessagesQueued > sentBefore) { clearPendingAcks(); return; }

    if (ctx.state !== 'handshaking') { clearPendingAcks(); return; }

    // Part of a flight. A sign it is disrupted — a message or fragment out
    // of order — is ACKed now, so the peer resends only what is missing;
    // otherwise a timer of a quarter of the retransmit timeout (§7.1's
    // suggestion) gives the rest of the flight time to arrive.
    if (ctx.ackDisruption) {
      cancelAckTimer();
      sendHandshakeAck();
    } else if (ctx.ackTimer === null) {
      ctx.ackTimer = setTimeout(function () {
        ctx.ackTimer = null;
        if (ctx.state === 'handshaking' && ctx.pendingAcks.length > 0) sendHandshakeAck();
      // A quarter of the retransmit timer (§7.1) — its initial value: the
      // timer's backoff counts losses of OUR earlier flight (a ClientHello
      // resent until the ServerHello came), which say nothing about how long
      // the rest of the peer's flight may take. Read off the backed-off timer
      // it was 2 s after three lost ClientHellos.
      }, ackDelay(Math.min(ctx.retransmitTimeout, currentRto())));
      if (ctx.ackTimer.unref) ctx.ackTimer.unref();
    }
  }

  // How long an ACK waits: a quarter of the retransmit timer (§7.1's
  // suggestion), a millisecond at least.
  function ackDelay(rto) { return Math.max(1, Math.floor(rto / 4)); }
  // A record to ACK, kept in `list`: the records of the peer's flight in
  // progress (pendingAcks), ACKed cumulatively — each ACK lists all of them
  // received so far (§7.1 "the messages from that flight which it has
  // received and processed so far") — or post-handshake ones (postAcks);
  // either way, up to what fits in one ACK record: its header (13), the
  // record numbers' length (2) and an AEAD tag's worth (22) out of the MTU,
  // 16 bytes a record number (RFC 9147 §7).
  function noteAck(list, rn) {
    for (let i = 0; i < list.length; i++) {
      if (list[i].epoch === rn.epoch && list[i].seq === rn.seq) return;
    }
    list.push(rn);
    let room = Math.max(1, Math.floor((ctx.mtu - 13 - 22 - 2) / 16));
    if (list.length > room) list.splice(0, list.length - room);
  }
  function cancelAckTimer() {
    if (ctx.ackTimer !== null) { clearTimeout(ctx.ackTimer); ctx.ackTimer = null; }
  }
  function clearPendingAcks() {
    cancelAckTimer();
    ctx.pendingAcks = [];
    if (ctx.postAckTimer !== null) { clearTimeout(ctx.postAckTimer); ctx.postAckTimer = null; }
    ctx.postAcks = [];
  }
  // During the handshake: the handshake epoch (2), never 0 — only protected
  // records are ever ACKed (the first flight never is).
  function sendHandshakeAck() {
    if (!ctx.keys[2]) return;
    sendAck(2, ctx.pendingAcks.slice(), false);
  }

  function processRecord(record) {
    // A record in an epoch above 0 that did not decrypt is not the peer's
    // (forged, corrupted, or a late packet from a previous session on the
    // same address) — RFC 6347 §4.1.2.7 / RFC 9147 §4.5.2: discard it
    // silently. Its content is still ciphertext: as an ALERT its second byte
    // is random, which emitted 'error' and failed the whole connection; as
    // APPLICATION_DATA it went up to SCTP as data.
    if (record.epoch > 0 && !record.encrypted) return;
    // Once connected, everything the peer sends is protected. A plaintext
    // (epoch 0) alert or application data at that point is unauthenticated —
    // anyone able to send a UDP packet from the peer's address could close
    // the connection with a one-record close_notify, or inject data.
    if (ctx.state === 'connected' && !record.encrypted &&
        (record.type === CT.ALERT || record.type === CT.APPLICATION_DATA)) return;

    if (record.type !== CT.ALERT) ctx.consecutiveWarnings = 0;

    // A record that opened under its keys is the peer's: more plaintext
    // than a record may carry — 2^14 (RFC 8446 §5.1, RFC 5246 §6.2.1), or
    // our record_size_limit once negotiated (RFC 8449 §4) — is
    // record_overflow, as in TLS. Without a limit agreed, nothing was
    // checked at all (BoGo LargePlaintext-DTLS). An unprotected one is
    // anyone's: what arrives too long is dropped as the datagram is parsed
    // (record.js).
    if (record.encrypted && record.content) {
      let rsl = tls.getRecordSizeLimit(), max = rsl ? rsl.receive : MAX_RECORD_PLAINTEXT;
      if (record.content.length > max) {
        throw parseError('DTLS record of ' + record.content.length + ' bytes, more than ' +
          (rsl ? 'our record_size_limit (' + max + ')' : '2^14'), TLS_ALERT.RECORD_OVERFLOW);
      }
    }

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
        // DTLS 1.2: protected data from the peer means it has our final
        // flight — nothing more to answer its retransmissions with.
        //
        // NOT DTLS 1.3's final flight (finalFlightPending): that one is
        // acknowledged by an ACK alone (RFC 9147 §7.1: it is the one flight
        // not implicitly acknowledged, and "flights MUST be ACKed unless
        // they are implicitly acknowledged"). A server sends data before it
        // has our Finished — half-RTT data, its tickets — so its data said
        // nothing of our Finished, and taken for it, a lost Finished was
        // never resent: the server's handshake never ended (BoGo
        // DTLS-Retransmit-Client-NoImplictACKFinished). A peer that never
        // ACKs costs only the retransmissions: when they run out the flight
        // is let go, the connection kept (startRetransmitTimer).
        ctx.lastFlight12 = null;
        // A Buffer, as node:tls gives (and every other buffer this API hands
        // out): a view of the decrypted record, not a copy.
        let c = record.content;
        ev.emit('data', Buffer.isBuffer(c) ? c : Buffer.from(c.buffer, c.byteOffset, c.byteLength));
      }
    } else if (record.type === CT.CHANGE_CIPHER_SPEC) {
      // One byte, 1 (RFC 6347 §4.1, RFC 5246 §7.1), and DTLS 1.2 only — DTLS
      // 1.3 has none (RFC 9147 §5: not sent, and none is a key change here).
      // Anything else changed our read state all the same. It is an
      // unprotected record that does not read as one: dropped (§4.1.2.7).
      if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3) return;
      if (!record.content || record.content.length !== 1 || record.content[0] !== 1) return;
      // DTLS 1.2: the peer's key change. The keys come of the master
      // secret, and are installed when it exists (installKeys12, after each
      // record) — a CCS ahead of the key exchange (reordered: RFC 6347 §4.1),
      // or one lost, changes nothing: no alert that would end a good
      // handshake on one reordered datagram, and no flight resent for it
      // either (DTLS-Fuzzer D5). A Finished must still come protected
      // (epochFitsHandshake): the key change is proved by it, not by this.
      installKeys12();
    } else if (record.type === CT.ACK) {
      // DTLS 1.3 only (RFC 9147 §7). One that does not parse: protected, the
      // peer's (decode_error, thrown to the boundary); unprotected, dropped.
      if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3) return;
      let acks;
      try { acks = parseDtlsAck(record.content); }
      catch (e) { if (!record.encrypted) return; throw e; }
      processAck(acks);
    } else if (record.type === CT.ALERT) {
      // As TLS over TCP reads it (wire.read_peer_alert). A malformed one:
      // protected, the alert for it; unprotected — anyone can send a
      // datagram — dropped.
      let a = read_peer_alert(record.content, ctx.selectedVersion === DTLS_VERSION.DTLS1_3);
      if (a.error) {
        if (!record.encrypted) return;
        throw parseError('DTLS ' + a.error.message, a.error.alert);
      }
      let desc = a.desc;
      // Name the alert either way. A close_notify is a CLEAN shutdown and
      // a failure is not, but both present to the application as "the
      // connection ended" — and telling them apart is the difference
      // between "the peer hung up" and "the peer rejected us".
      _ldbg('RX Alert level=' + a.level + ' desc=' + desc +
            (desc === TLS_ALERT.CLOSE_NOTIFY ? ' (close_notify — clean shutdown)' : ' (failure)'));
      ev.emit('alert', { level: a.level, description: desc });
      if (desc === TLS_ALERT.CLOSE_NOTIFY) {
        // close_notify — answered with ours (RFC 5246 §7.2.1: "The other
        // party MUST respond with a close_notify alert of its own"; RFC 8446
        // §6.1 the same, in effect: each side closes its write side with
        // one). close() sends it and ends the session. It was not answered.
        close();
      } else if (!a.fatal) {
        // A warning (user_canceled among them): the connection goes on. A
        // run of them is not progress.
        if (++ctx.consecutiveWarnings > MAX_WARNING_ALERTS) {
          throw parseError('DTLS: too many consecutive warning alerts', TLS_ALERT.UNEXPECTED_MESSAGE);
        }
      } else {
        // Fatal: the session ends; it used to report and carry on,
        // retransmitting.
        fail(peer_alert_error(desc));   // as TLS over TCP reports it
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
    // A handshake fragment lies wholly inside its record (RFC 6347 §4.2.3,
    // RFC 9147 §5.5: fragments are not split across records). One that does
    // not — its 12-byte header cut short, or its body running past the end
    // — is decode_error: the record itself read fine, the handshake inside
    // it is malformed (§4.5.2's silent discard is for records that do not
    // read as records). Dropping it left the session waiting for good (BoGo
    // SplitFragments-Header/Body/Boundary). Except for an unprotected record
    // once we are connected: then it can only be a stray retransmission or
    // anyone's (spoofed) datagram, and one must not end the connection — it
    // is dropped, as an unprotected ACK or alert is.
    let strict = encrypted || ctx.state !== 'connected';
    while (off < data.length) {
      if (data.length - off < 12) {
        if (!strict) return;
        throw parseError('DTLS: a handshake fragment header cut short (' + (data.length - off) + ' bytes) at the end of its record', TLS_ALERT.DECODE_ERROR);
      }
      let parsed;
      try { parsed = parse_dtls_handshake(data.subarray(off)); }   // decode_error when the body runs past
      catch (e) { if (!strict) return; throw e; }

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
        if (deliverHandshakeMessage(parsed.type, parsed.body, msgSeq, epoch)) anyNew = true;
      } else {
        // Fragment — reassemble
        if (reassembleFragment(parsed, epoch)) anyNew = true;
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
    // Whether this record carried only messages already taken — the
    // peer retransmitting — is decided for the whole datagram, in
    // feedDatagram (dtls12AnswerRetransmission): a datagram that also
    // brings something new is progress, not a retransmission.
    if (anyNew) ctx.dgAnyNew = true;
    else if (sawMessage) ctx.dgDuplicate = true;
  }

  /**
   * DTLS 1.2 (RFC 6347 §4.2.4): the peer retransmitting its last flight
   * means it never got our answer — we resend ours at once, rather than
   * waiting out our own timer. DTLS 1.3 has ACKs for this instead.
   *
   * After the handshake, too: the side that sent the LAST flight (the
   * server's CCS + Finished in a full handshake) keeps it, and resends it
   * when the peer's final flight comes again — the state machine's FINISHED
   * state. It was dropped at 'connect', so a lost server Finished left the
   * client retransmitting into a server that had nothing to say: the
   * handshake never completed (BoGo Retransmit-*-TLS12; and 1 in 7 at 30%
   * loss in dtls_loss_test). Kept until the peer's application data shows
   * it finished.
   */
  function dtls12AnswerRetransmission() {
    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_3) return;
    if (!ctx.dgDuplicate || ctx.dgAnyNew) return;
    // Damping: a peer retransmits its flight as SEVERAL datagrams; one
    // resend per 250 ms answers the whole retransmitted flight once.
    if ((Date.now() - (ctx._lastDupElicitedResend || 0)) < 250) return;
    if (ctx.state === 'handshaking' && haveFlight()) {
      ctx._lastDupElicitedResend = Date.now();
      // The regular timer keeps running unchanged, so the retransmit budget
      // still bounds the total effort.
      resendFlight();
    } else if (ctx.state === 'connected' && ctx.lastFlight12) {
      ctx._lastDupElicitedResend = Date.now();
      transmitUnacked(ctx.lastFlight12, 'lastFlight12', false);
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
  function reassembleFragment(parsed, epoch) {
    let key = parsed.msg_seq;

    // Ignore fragments for messages we've already delivered.
    if (key < ctx.nextReadMsgSeq) return false;

    // DoS guard: the 24-bit `length` is attacker-controlled on the first
    // fragment. Reject anything claiming more than our cap BEFORE allocating,
    // so a peer can't force huge buffers with a single unauthenticated packet.
    if (parsed.length > ctx.maxHandshakeMessageSize) {
      // It was reported and the session carried on, waiting for a message
      // it had refused. The same alert as TLS over TCP for an oversized
      // message (illegal_parameter, as OpenSSL).
      throw parseError('DTLS handshake message of ' + parsed.length + ' bytes, more than ' + ctx.maxHandshakeMessageSize, TLS_ALERT.ILLEGAL_PARAMETER);
    }

    let frag = ctx.fragments[key];
    // Every fragment of one message names the same type and total length
    // (RFC 6347 §4.2.3, RFC 9147 §5.5). One that disagrees with those
    // already held was copied in anyway — or, past the buffer, dropped — and
    // the message never completed: the session waited for good.
    if (frag && frag.epoch !== epoch) {
      // Half a message under one key and half under another (RFC 8446
      // §5.1: handshake messages MUST NOT span key changes).
      throw parseError('DTLS: message ' + key + ' in fragments of epochs ' + frag.epoch + ' and ' + epoch, TLS_ALERT.UNEXPECTED_MESSAGE);
    }
    if (frag && (frag.type !== parsed.type || frag.totalLength !== parsed.length)) {
      throw parseError('DTLS: fragments of message ' + key + ' disagree on its type or length', TLS_ALERT.ILLEGAL_PARAMETER);
    }
    if (!frag) {
      frag = ctx.fragments[key] = {
        epoch: epoch,
        totalLength: parsed.length,
        type: parsed.type,
        buf: new Uint8Array(parsed.length),
        ranges: [],   // sorted, merged [start, end) covered ranges
      };
    }

    let start = parsed.frag_offset;
    let end = parsed.frag_offset + parsed.frag_length;

    // A fragment past the message's end (parse_dtls_handshake already holds
    // the body to frag_length; this is offset + length > the total).
    if (end > frag.totalLength) {
      throw parseError('DTLS: fragment ' + start + '+' + parsed.frag_length + ' runs past message length ' + frag.totalLength, TLS_ALERT.ILLEGAL_PARAMETER);
    }

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


    // A fragment past a hole: one before it is missing (§7.1).
    if (merged.length > 1 || merged[0][0] !== 0) ctx.ackDisruption = true;

    // Complete when a single range covers [0, totalLength).
    if (merged.length === 1 && merged[0][0] === 0 && merged[0][1] === frag.totalLength) {
      delete ctx.fragments[key];
      return deliverHandshakeMessage(frag.type, frag.buf, key, frag.epoch);
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
  function deliverHandshakeMessage(type, body, msgSeq, epoch) {
    // Skip if we've already processed this msg_seq (duplicate / retransmit).
    if (msgSeq < ctx.nextReadMsgSeq) return false;

    // Check for HelloVerifyRequest (DTLS 1.2 server→client, type=3)
    if (type === 3 && !isServer) {
      // Only where one can come (RFC 6347 §4.2.1): unprotected, before any
      // ServerHello, as the answer to a ClientHello (message_seq 0 or 1).
      // Anywhere else it is no server's — and it was taken anywhere: one
      // datagram, after our last flight or after the handshake, made the
      // client start over (a new ClientHello, transcript and flights wiped).
      // Dropped (D2).
      if (epoch !== 0 || tls.context.remote_random != null || msgSeq > 1) return false;
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
        fail(new Error(
          'DTLS 1.3 ClientHello carries a non-empty legacy_cookie (' +
          ch.dtls_cookie.length + ' bytes) — RFC 9147 §5.3 requires zero length'), 47);
        return false;
      }

      // RFC 9147 §5.1: "DTLS 1.3-compliant implementations MUST NOT use the
      // HelloVerifyRequest to execute a return-routability check." DTLS 1.3
      // does return-routability with HelloRetryRequest + the cookie extension
      // instead. The old guard tested ctx.selectedVersion, which is null here,
      // so a DTLS 1.3 handshake could still be answered with an HVR.
      // Only for the handshake's first ClientHello (nothing read yet): a
      // later one with a valid cookie — the attacker's replay of the real
      // one — reset the read cursor mid-handshake (or after it) and stalled
      // it without a word (D3). Later, a ClientHello goes the normal way:
      // in order, to the TLS state machine, which refuses it.
      if (options.useCookies === true && !offersDtls13 && ctx.nextReadMsgSeq === 0) {

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
      // Out of order: a message is missing before it — the peer should
      // learn now what arrived (an ACK, RFC 9147 §7.1).
      ctx.ackDisruption = true;
      // Out of order — hold it (ignore a duplicate already buffered).
      if (!(msgSeq in ctx.pendingMessages)) {
        ctx.pendingMessages[msgSeq] = { type: type, body: body, epoch: epoch };
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
    if (!epochFitsHandshake(epoch, type)) return false;
    flightAnswered();
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
      // Held while a message before it was missing — and that message may
      // have changed the keys (a ServerHello): checked now, not when held.
      if (!epochFitsHandshake(next.epoch, next.type)) break;
      startRetransmitTimer();
      ctx.newFlightPending = true;
      feedHandshakeToTls(next.type, next.body, ctx.nextReadMsgSeq);
      ctx.nextReadMsgSeq++;
    }
    return true;
  }

  /**
   * DTLS 1.3: the epoch a handshake message must arrive in is the one the
   * handshake is at when it is taken — 0 up to the ServerHello, 2 (the
   * handshake keys) up to the peer's Finished, 3 and up after it (RFC 9147
   * §6.1, RFC 8446 §5.1). A message held out of order was checked when it
   * arrived, before the message ahead of it moved the keys: a plaintext
   * message buffered behind a missing ServerHello was then taken as if it
   * had come encrypted (BoGo: a key change with messages buffered).
   * Unprotected, it may be anyone's, and is dropped (RFC 9147 §4.5.2) — the
   * real one, protected, takes its place; protected, it is the peer's own
   * doing: unexpected_message.
   *
   * DTLS 1.2 is not checked here: its key change is the peer's
   * ChangeCipherSpec, which may arrive ahead of the ClientKeyExchange it
   * depends on, and a protected message cannot be read before it anyway.
   */
  function epochFitsHandshake(epoch, type) {
    if (typeof epoch !== 'number') return true;
    if (ctx.selectedVersion === DTLS_VERSION.DTLS1_2) {
      // DTLS 1.2 (RFC 6347 §4.1, RFC 5246 §7.1): Finished is the first
      // message under the new keys — epoch 1. One in epoch 0 was taken: the
      // handshake ended with no key change at all, the Finished in the clear
      // (DTLS-Fuzzer D1; the CCS-injection family). Epoch 1 is the proof of
      // the change — the record opened under the new keys — not the CCS
      // record itself, which can be lost while the Finished behind it
      // arrives (dtls_loss_test: requiring both failed a third of the
      // handshakes at 15% loss). Messages before it may still come in epoch
      // 0 after the CCS: reordered, a CertificateVerify can trail it.
      if (type === 20 && epoch !== 1) {
        throw parseError('DTLS 1.2: Finished in epoch ' + epoch + ' — it must come protected, after the key change', TLS_ALERT.UNEXPECTED_MESSAGE);
      }
      // After the handshake an unprotected handshake message is anyone's — a
      // HelloVerifyRequest or ClientHello sent to tear the connection down
      // (D2, D3): dropped. (Renegotiation would come protected, epoch 1.)
      if (epoch === 0 && ctx.state === 'connected') return false;
      return true;
    }
    if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3) return true;
    let hsKeys = !!(ctx.keys[2] && ctx.keys[2].read);
    let fits = !hsKeys ? epoch === 0 : (ctx.state === 'connected' ? epoch >= 3 : epoch === 2);
    if (fits) return true;
    if (epoch === 0) return false;
    throw parseError('DTLS 1.3: a handshake message in epoch ' + epoch + ', where epoch ' +
      (!hsKeys ? 0 : (ctx.state === 'connected' ? '3 or later' : 2)) + ' was due', TLS_ALERT.UNEXPECTED_MESSAGE);
  }

  /**
   * Feed one in-order handshake message to the TLSSession, converting from DTLS
   * to TLS wire format and driving version detection.
   */
  function feedHandshakeToTls(type, body, msgSeq) {
    // DTLS 1.3's own post-handshake messages: the TLS engine has no part in them.
    if (type === TLS_MESSAGE_TYPE.REQUEST_CONNECTION_ID || type === TLS_MESSAGE_TYPE.NEW_CONNECTION_ID) { takeConnectionIdMessage(type, body); return; }

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
   * RequestConnectionId / NewConnectionId (RFC 9147 §5.8, §9): DTLS 1.3,
   * after the handshake, and only where CIDs were agreed to — a peer that
   * did not, or asked for an empty one, "MUST NOT send" them
   * (unexpected_message otherwise).
   *
   * NewConnectionId: CIDs to put in what we send. cid_immediate — the first
   * of them, from now on (§9: the peer "wants the recipient to use" one of
   * them at once); cid_spare — there for later: we have no reason to move,
   * and are not obliged to.
   * RequestConnectionId: "does not force the receiver to send a
   * NewConnectionId": we give out one CID, the one agreed, and keep it.
   * Both are ACKed, as any handshake record.
   */
  function takeConnectionIdMessage(type, body) {
    let unexpected = function (why) { throw parseError(why, TLS_ALERT.UNEXPECTED_MESSAGE); };
    let malformed = function (why) { throw parseError(why, TLS_ALERT.DECODE_ERROR); };
    let name = type === TLS_MESSAGE_TYPE.NEW_CONNECTION_ID ? 'NewConnectionId' : 'RequestConnectionId';
    if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3 || ctx.state !== 'connected' || !ctx.cid) unexpected(name + ' without connection IDs agreed to');
    if (type === TLS_MESSAGE_TYPE.REQUEST_CONNECTION_ID) {
      if (body.length !== 1) malformed('RequestConnectionId is malformed');
      if (ctx.cid.local.length === 0) unexpected('RequestConnectionId, and we asked for no CID');
      return;
    }
    if (ctx.cid.peer.length === 0) unexpected('NewConnectionId from a peer that asked for no CID');
    if (body.length < 3) malformed('NewConnectionId is malformed');
    let listLen = (body[0] << 8) | body[1];
    if (2 + listLen + 1 !== body.length) malformed('NewConnectionId is malformed');
    let cids = [];
    for (let off = 2; off < 2 + listLen;) {
      let n = body[off];
      if (n === 0 || off + 1 + n > 2 + listLen) malformed('NewConnectionId: an empty or truncated CID');
      cids.push(body.slice(off + 1, off + 1 + n));
      off += 1 + n;
    }
    let usage = body[2 + listLen];
    if (usage > 1) throw parseError('NewConnectionId: usage ' + usage, TLS_ALERT.ILLEGAL_PARAMETER);
    if (usage === 0 && cids.length > 0) {
      ctx.cid = { local: ctx.cid.local, peer: new Uint8Array(cids[0]) };
      ev.emit('connectionId', getConnectionIds());
    }
  }

  // The Connection IDs as they are now: { local, peer }, or null.
  function getConnectionIds() {
    return ctx.cid ? { local: new Uint8Array(ctx.cid.local), peer: new Uint8Array(ctx.cid.peer) } : null;
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
    queueOut({ kind: 'raw', epoch: 0, contentType: CT.HANDSHAKE, payload: hvrMsg, label: 'hvr' });
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
    ctx.flightQueued = 0;
    ctx.fragments = {};          // discard any partial reassembly from CH1 flight
    ctx.pendingMessages = {};    // discard any out-of-order buffer from CH1 flight
    transcriptMsgSeqs = [];

    // Push CH2 to transcript (transcriptHook will store TLS format for now,
    // and fixTranscriptForDtls12() will convert when version is determined)
    ctx._incomingMsgSeq = undefined; // not incoming — use message_sent_seq
    tls.context.transcript.push(
      tls.context.transcriptHook ? tls.context.transcriptHook(ch2) : ch2
    );

    // Send — msg_seq 1 per the RFC figure above — as every flight message
    // goes: fragmented to the MTU, each fragment kept for retransmission.
    queueFlightMessage(ch2, 1, 0);

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
    if (ctx.state === 'closed' || (ctx.state === 'connected' && !ctx.finalFlightPending)) {
      cancelRetransmit();
      return;
    }
    // DTLS 1.3 (RFC 9147 §7.1): records the peer has ACKed are not resent.
    ctx.flightResent = true;   // no RTT sample from it now (Karn)
    transmitUnacked(ctx.currentFlight, 'flight-rtx', false);
  }

  /**
   * (Re)send the entries of a flight or post-handshake message that are not
   * ACKed yet — in new records, with new numbers (flushOut). `skipPlaintext`:
   * not the epoch-0 ones.
   */
  function transmitUnacked(entries, label, skipPlaintext) {
    for (let i = 0; i < entries.length; i++) {
      let f = entries[i];
      if (f.acked || (skipPlaintext && f.epoch === 0)) continue;
      queueOut({ kind: 'entry', entry: f, label: label });
    }
  }

  // A record number (RFC 9147 §4: epoch, sequence number) as one key — the
  // way sent records and ACKs are matched up. A string: epoch * 2^48 + seq
  // stops being exact past epoch 31 (2^53), which KeyUpdates reach, and two
  // records' numbers would collide.
  function recordNumber(epoch, seq) { return epoch + '/' + seq; }

  // Entries (of a flight, or of a post-handshake message) an ACK covers:
  // any of the records an entry went out in, its first sending or a
  // retransmission, is in `got`.
  // Returns how many it marked now.
  function markAcked(entries, got) {
    let newly = 0;
    for (let i = 0; i < entries.length; i++) {
      let e = entries[i];
      if (e.acked || !e.sent) continue;
      for (let k = 0; k < e.sent.length; k++) {
        if (got.has(e.sent[k])) { e.acked = true; newly++; break; }
      }
    }
    return newly;
  }

  function startRetransmitTimer() {
    cancelRetransmit();
    // ONE GATE, AT THE SOURCE. Four call sites arm this timer and only
    // one of them checks the state, so a timer armed while the handshake
    // was still running could fire after it finished and re-emit the
    // flight into the application-data epoch. Refusing to arm once
    // connected (or closed) covers every caller, including any added
    // later, without each having to remember the rule.
    if (ctx.state === 'closed' || (ctx.state === 'connected' && !ctx.finalFlightPending)) return;
    if (ctx.flightBegan === null) ctx.flightBegan = Date.now();
    ctx.retransmitTimer = setTimeout(function() {
      if (ctx.finalFlightPending && exhausted(ctx.retransmitCount, ctx.flightBegan)) {
        // The connection is up on our side; stop resending without failing it.
        finalFlightDone();
        return;
      }
      if (exhausted(ctx.retransmitCount, ctx.flightBegan)) {
        fail(new Error('DTLS handshake timeout — no answer after ' + ctx.retransmitCount +
          ' retransmissions in ' + Math.round((Date.now() - ctx.flightBegan) / 1000) + ' s'));
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

  // The client's final flight is known to have arrived: stop resending it.
  function finalFlightDone() {
    ctx.finalFlightPending = false;
    cancelRetransmit();
    startNewFlight();
  }

  function cancelRetransmit() {
    if (ctx.retransmitTimer !== null) {
      clearTimeout(ctx.retransmitTimer);
      ctx.retransmitTimer = null;
    }
  }

  // Whether we have a flight out (or on its way out: its messages become
  // entries of ctx.currentFlight only when packed, at the end of the pass).
  // Asked of currentFlight alone, the client that had just queued its
  // Finished found nothing to keep under the timer — and a lost Finished
  // was never resent.
  function haveFlight() { return ctx.currentFlight.length > 0 || ctx.flightQueued > 0; }

  function startNewFlight() {
    ctx.currentFlight = [];
    ctx.flightQueued = 0;
    ctx.retransmitCount = 0;
    ctx.retransmitTimeout = currentRto();
    ctx.flightBegan = null;
    ctx.rttStart = null;
    ctx.flightResent = false;
  }

  // Where a timer starts: the initial value until there is a round-trip
  // sample, then SRTT + 4·RTTVAR (RFC 6298 §2) — not under RTO_MIN_MS, not
  // over 60 s. An initialRetransmitTimeout given (the option, or
  // setInitialRetransmitTimeout) is a schedule the caller chose: it is kept
  // — from it, doubling — and no round trip changes it (fixedRto).
  //
  // The floor was 50 ms. A loopback, or a peer that answers within the same
  // tick, measures a round trip of 0, and a real path that once measured
  // short then lost its next flight to a 50 ms timer. RFC 9147 sets no
  // floor; 100 ms is WebRTC's own initial timer. And a fixed schedule
  // matters to a peer that times itself by one (BoGo advances its clock by
  // BoringSSL's 400 ms, 800 ms …: an adaptive 50 ms timer fired several
  // times in each step).
  function currentRto() {
    if (ctx.fixedRto || ctx.srtt === null) return ctx.initialRetransmitTimeout;
    return Math.max(RTO_MIN_MS, Math.min(60000, Math.round(ctx.srtt + 4 * ctx.rttvar)));
  }
  function sampleRtt(r) {
    if (ctx.srtt === null) { ctx.srtt = r; ctx.rttvar = r / 2; }
    else { ctx.rttvar = 0.75 * ctx.rttvar + 0.25 * Math.abs(ctx.srtt - r); ctx.srtt = 0.875 * ctx.srtt + 0.125 * r; }
  }
  // The peer's answer to our flight has begun (a new message of its next
  // flight, or — DTLS 1.3 — an ACK of a protected record of ours).
  function flightAnswered() {
    if (ctx.rttStart !== null && !ctx.flightResent) sampleRtt(Date.now() - ctx.rttStart);
    ctx.rttStart = null;
  }
  // Time to give up on what keeps going unanswered: tried enough, and long
  // enough (maxRetransmits, giveUpAfter).
  function exhausted(attempts, began) {
    return attempts >= ctx.maxRetransmits && began !== null && Date.now() - began >= ctx.giveUpAfter;
  }


  // ============================================================
  //  ACK (DTLS 1.3)
  // ============================================================

  function processAck(acks) {
    let got = new Set();
    for (let i = 0; i < acks.length; i++) got.add(recordNumber(acks[i].epoch, acks[i].seq));

    // Post-handshake messages first — a KeyUpdate's epoch switch among them.
    if (ctx.postHandshake.length > 0) ackPostHandshake(got);
    if (ctx.state === 'closed' || (ctx.state === 'connected' && !ctx.finalFlightPending)) return;

    // During the handshake an ACK may cover only PART of our flight (RFC 9147
    // §7.1): the peer lists the records it received. Those are done; the
    // rest stay under the retransmit timer and are what the next
    // retransmission resends. Treating any ACK as acknowledging the whole
    // flight cancelled the timer while a record was still missing — the
    // peer, waiting for it, ACKed again and again, and the handshake hung
    // (≈ half of all handshakes at 5% loss, when the lost record was inside
    // the server's flight).
    if ((ctx.state !== 'connected' || ctx.finalFlightPending) && ctx.currentFlight.length > 0) {
      let newly = markAcked(ctx.currentFlight, got);
      if (newly > 0) flightAnswered();
      let remaining = 0, protectedEntries = 0, protectedAcked = 0;
      for (let i = 0; i < ctx.currentFlight.length; i++) {
        let f = ctx.currentFlight[i];
        // Plaintext epoch-0 records (ClientHello, ServerHello) are never
        // ACKed — the peer acknowledges them implicitly by answering — so
        // they do not keep the flight open on their own.
        if (f.epoch === 0) continue;
        protectedEntries++;
        if (f.acked) protectedAcked++; else remaining++;
      }
      // A flight of plaintext alone (a ClientHello) is answered, never
      // ACKed: an ACK — an empty one, from a peer that could not read
      // something of ours — confirms none of it, and ended its
      // retransmission (the timer cancelled below), the ClientHello lost
      // for good.
      if (protectedEntries === 0) return;
      if (remaining > 0) {
        // RFC 9147 §7.2: "Upon receipt of an ACK that leaves it with only
        // some messages from a flight having been acknowledged, an
        // implementation SHOULD retransmit the unacknowledged messages or
        // fragments." The peer ACKs a partial flight when it sees a gap, or
        // after a quarter of its timer with the rest still missing — either
        // way the rest is lost, and waiting for our own timer (doubled by
        // every earlier loss: 8 s and more) stalled the handshake past its
        // deadline (dtls_loss_test, 30% loss).
        //
        // At once when this ACK confirmed something new. One that confirms
        // nothing new — a repeat, or an empty one (wolfSSL sends one for
        // each record it cannot read: with our ServerHello lost, all of
        // them) — at most once a quarter of the initial timer: resending on
        // each, both sides fed each other 15 000–34 000 datagrams a second.
        // Epoch-0 records go too while the peer has ACKed none of the
        // protected ones — it may lack our ServerHello, and so the keys;
        // once it has ACKed one, it has them.
        let now = Date.now();
        if (newly > 0 || now - ctx.lastAckResend >= ackDelay(currentRto())) {
          ctx.lastAckResend = now;
          ctx.flightResent = true;
          transmitUnacked(ctx.currentFlight, 'partial-ack', protectedAcked > 0);
          // The records just resent start their wait again: the timer, left
          // as it was, fired soon after and sent the same records a second
          // time — wasted on a real path, and packed with the first copy
          // where both go out in one pass (BoGo DTLS-Retransmit-Server-
          // ACKMatchingEpoch-TLS13: "excess data"). Its value is kept: this
          // was no timeout.
          startRetransmitTimer();
        }
        return;
      }
      if (newly === 0 && !ctx.finalFlightPending) return;   // nothing this ACK confirmed
    }

    // The whole flight is acknowledged — or, the ACK for the client's final
    // flight (which RFC 9147 §7.1 requires the peer to send explicitly, and
    // which arrives at the application epoch): cancel the retransmit timer.
    ctx.finalFlightPending = false;
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
    queueOut({ kind: 'raw', epoch: epoch, contentType: CT.ACK, payload: payload, label: 'ack' });
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

  // Agreed (the hello), or moved by the peer's NewConnectionId: the record
  // layer's from now on, and the application's to know.
  tls.on('connectionId', function(ids) { ctx.cid = ids; ev.emit('connectionId', getConnectionIds()); });

  tls.on('secureConnect', function() {
    _ldbg('handshake complete — secureConnect (version=0x' +
      ((ctx.selectedVersion || tls.context.selected_version || 0).toString(16)) + ')');
    ctx.state = 'connected';
    // DTLS 1.3 client (RFC 9147 §5.8.3, §7.1): our final flight (…Finished)
    // is answered by nothing but an ACK, so it must stay under the
    // retransmit timer until that ACK — or anything else from the peer at
    // the application epoch — shows it arrived. Dropping it here meant one
    // lost Finished left us "connected" and the peer waiting for good.
    if (!isServer && ctx.selectedVersion === DTLS_VERSION.DTLS1_3 && haveFlight()) {
      ctx.finalFlightPending = true;
      startRetransmitTimer();
    } else {
      // DTLS 1.2: if the last flight is ours — sent after the peer's last
      // message, so nothing of the peer's acknowledges it — it is kept for
      // the peer's retransmissions (dtls12AnswerRetransmission). No timer:
      // RFC 6347 §4.2.4's FINISHED state answers, it does not repeat.
      if (ctx.selectedVersion !== DTLS_VERSION.DTLS1_3 && !ctx.newFlightPending && haveFlight()) {
        ctx.lastFlight12 = ctx.currentFlight;
      }
      cancelRetransmit();
      startNewFlight();
    }
    ev.emit('connect');
  });

  tls.on('error', function(e) {
    // The peer's REASON, spelled out. When BoringSSL rejects part of our
    // flight it sends an alert and closes; without printing it here the
    // only symptom is a connection that dies after a handshake that
    // looked complete, which is exactly the DTLS 1.3 interop case.
    _ldbg('ERROR ' + (e && e.message ? e.message : e) +
          (e && e.alertDesc != null ? ' alertDesc=' + e.alertDesc : '') +
          (e && e.code ? ' code=' + e.code : ''));
    // TLSSession has sent its alert already.
    fail(e);
  });

  tls.on('session', function(ticket) {
    ctx.lastSession = ticket;
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
    // One send, one record — a datagram's message is not split. Larger than
    // a record may carry (2^14, or the peer's record_size_limit): refused,
    // not sent as a record the peer must refuse.
    if (data.length > tls.recordSendLimit()) {
      let big = new RangeError('DTLS: ' + data.length + ' bytes in one record, more than ' + tls.recordSendLimit() + ' (the record limit)');
      big.code = 'ERR_DTLS_RECORD_TOO_LARGE';
      ev.emit('error', big);
      return;
    }

    let epoch = ctx.selectedVersion === DTLS_VERSION.DTLS1_3
      ? appEpoch()
      : 1;
    queueOut({ kind: 'raw', epoch: epoch, contentType: CT.APPLICATION_DATA, payload: data, label: 'data' });
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
    // type instead of a clean shutdown. alertEpoch() decides, as for every
    // alert we send.
    sendAlertRecord(alertEpoch(), new Uint8Array([1, 0])); // warning, close_notify
    shutDown();
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
    // Encrypted Client Hello, as TLSSocket's echStatus / echBackend.
    getEchStatus: function() { return tls.getEchStatus(); },
    isEchBackend: function() { return tls.isEchBackend(); },
    // External PSK: the identity this connection was authenticated with.
    getPskIdentity: function() { return tls.getPskIdentity(); },
    /** Connection IDs (RFC 9146), once agreed: { local, peer } — local, in
     *  the records we receive; peer, in those we send (NewConnectionId may
     *  have changed it since the handshake). Null otherwise. */
    getConnectionIds: getConnectionIds,

    /** Peer certificate. */
    getPeerCertificate: function() { return tls.getPeerCertificate(); },

    /** TLS fingerprints (see TLSSession): JA4, JA5 of the ClientHello, JA4S
     *  of the ServerHello. The transport character resolves to 'd' on its
     *  own — the inner TLSSession reads the 0xFE high byte off the hello's
     *  legacy_version — so no `protocol` override is needed for plain DTLS. */
    getJA4: function(opts) { return tls.getJA4(opts); },
    getJA5: function(opts) { return tls.getJA5(opts); },
    getJA4S: function(opts) { return tls.getJA4S(opts); },

    /** Set the key and certificate for this connection (Node parity). */
    setKeyCert: function(ctxOrOpts) { return tls.setKeyCert(ctxOrOpts); },

    /** Finished verify_data, ours and the peer's (RFC 5929 channel binding). */
    getFinished: function() { return tls.getFinished(); },
    getPeerFinished: function() { return tls.getPeerFinished(); },

    /** Whether this connection resumed an earlier session. */
    isSessionReused: function() { return !!tls.isResumed; },

    /** The last session (a Buffer for `session` next time), as TLSSocket#getSession; undefined until one. */
    getSession: function() { return ctx.lastSession; },

    /**
     * The path MTU: the largest datagram this session writes (every record
     * is one datagram). Takes effect for the next message fragmented —
     * a flight already sent is resent as it was cut. 128..65507 bytes.
     */
    setMTU: function(mtu) { ctx.mtu = checkedMtu(mtu); },
    getMTU: function() { return ctx.mtu; },

    /**
     * Where each flight's retransmission timer starts (it doubles on every
     * timeout, to 60 s). RFC 9147 §5.8.2 recommends 1 s; a known short
     * path can go lower. 10..60000 ms. The flight in progress keeps its own.
     */
    setInitialRetransmitTimeout: function(ms) {
      ctx.initialRetransmitTimeout = checkedRetransmitTimeout(ms);
      // Said explicitly: the schedule from now on — every flight's timer
      // starts there, whatever round trip is measured (currentRto).
      ctx.fixedRto = true;
      ctx.srtt = null; ctx.rttvar = null;
      if (ctx.retransmitTimer === null) ctx.retransmitTimeout = ctx.initialRetransmitTimeout;
    },
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
export { SERVER_CID_LEN };