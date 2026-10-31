import * as crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

import {
  TLS_CIPHER_SUITES,
  default_cipher_suites,
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
  derive_client_early_traffic_secret,
  hkdf_expand_label,
  getHashFn,
  getHashLen,
  derive_exporter_master_secret_with_hash,
  tls13_exporter,
  tls12_exporter,
  LABEL_PREFIX_TLS13,
  LABEL_PREFIX_DTLS13,
  suite_matches_version,
  is_usable_cipher_suite,
} from './crypto.js';

import {
  concatUint8Arrays,
  arraysEqual,
  uint8Equal,
  timingSafeEqualU8,
  certificateObject,
} from './utils.js';

import * as wire from './wire.js';

// Extracted modules
import { pick_scheme, sign_with_scheme, verify_with_scheme, default_signature_schemes, scheme_name } from './session/signing.js';
import createSecureContext from './secure_context.js';
import { x25519_get_public_key, SUPPORTED_GROUPS as ECDH_SUPPORTED_GROUPS, generate_keypair as ecdh_generate_keypair, get_shared_secret as ecdh_get_shared_secret, is_supported_group,
  is_kem_group, kem_server_exchange, group_name as ecdh_group_name
} from './session/ecdh.js';
import { build_tls_message, parse_tls_message } from './session/message.js';
import { encrypt_session_blob, decrypt_session_blob, encode_client_session, decode_client_session } from './session/ticket.js';
import { parse_cert_compression, supported_cert_compression, compress_certificate_body, decompress_certificate_body, cert_compression_name } from './session/cert_compression.js';
import { prepare_ech_server, server_process_client_hello, accept_confirmation, EXT_ECH,
         parse_ech_config_list, prepare_ech_client, client_hpke_setup, client_outer_ext_data, client_encode_inner,
         client_seal_outer, grease_ech_state, grease_ech_ext_data, hrr_ech_offset } from './session/ech.js';

// RFC 8446 §4.1.3 downgrade-protection sentinels. A TLS 1.3-capable server that
// negotiates a lower version stamps one of these into the last 8 bytes of
// ServerHello.random; a TLS 1.3-capable client that ends up on a lower version
// MUST reject the handshake if it sees the sentinel. This defeats an active
// attacker forcing a version downgrade (the sentinel is covered by the server's
// signature / Finished, so it can't be stripped without breaking the handshake).
const DOWNGRADE_SENTINEL_TLS12 = new Uint8Array([0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,0x01]); // "DOWNGRD\x01"
const DOWNGRADE_SENTINEL_TLS11 = new Uint8Array([0x44,0x4F,0x57,0x4E,0x47,0x52,0x44,0x00]); // "DOWNGRD\x00" (TLS 1.1 and below)

// Debug logging — enabled via LEMON_DEBUG=1 env var
// A (D)TLS 1.2 suite whose key exchange is ephemeral elliptic-curve
// Diffie-Hellman — ECDHE_RSA or ECDHE_ECDSA. Read from the suite table rather
// than listed by code: a hand-kept list here had fallen behind it, missing
// both ChaCha20 suites, and a client that preferred them got a ServerHello
// and then a dead handshake.
function is_ecdhe_suite(cs) {
  let meta = TLS_CIPHER_SUITES[cs];
  return !!meta && typeof meta.kex === 'string' && meta.kex.indexOf('ECDHE_') === 0;
}

const LEMON_DEBUG = typeof process !== 'undefined' && process.env && process.env.LEMON_DEBUG === '1';
function dbg(tag, ...args) { if (LEMON_DEBUG) console.error('[LEMON ' + tag + ']', ...args); }
function hexPreview(buf, max) {
  if (!buf) return 'null';
  let b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  let n = Math.min(b.length, max || 32);
  return b.slice(0, n).toString('hex') + (b.length > n ? `... (${b.length} bytes)` : ` (${b.length} bytes)`);
}


const MAX_CHAIN_DEPTH = 10;

// 0-RTT anti-replay, the default (earlyDataReplay): the tickets that have
// carried early data, in this process, each for its time — a second use
// within it gets no 0-RTT (RFC 8446 §8.1: single-use tickets). A cluster
// shares its own store instead. Bounded: full, early data is refused.
const EARLY_REPLAY_MAX = 100000;
const earlyReplaySeen = new Map();   // id → until (ms)
// What it remembers began here: a ticket issued before (by this process's
// predecessor, under ticket keys kept across the restart) may have carried
// early data then, and that flight could be sent again now. Such a ticket
// gets no 0-RTT for as long as a flight stays fresh (2 × earlyDataMaxAge)
// — one handshake in 1-RTT, and its new ticket is fine.
const EARLY_REPLAY_START = Date.now();
function defaultEarlyReplay(id, ttl, cb) {
  let now = Date.now();
  if (earlyReplaySeen.size >= EARLY_REPLAY_MAX) {
    for (const [k, until] of earlyReplaySeen) { if (until > now) break; earlyReplaySeen.delete(k); }
    if (earlyReplaySeen.size >= EARLY_REPLAY_MAX) { cb(null, false); return; }
  }
  let until = earlyReplaySeen.get(id);
  if (until !== undefined && until > now) { cb(null, false); return; }
  earlyReplaySeen.delete(id);
  earlyReplaySeen.set(id, now + ttl);
  cb(null, true);
}
const EARLY_REPLAY_TIMEOUT_MS = 100;

// Our certificate's private key, parsed: by the bytes it was parsed from
// (local_private_key). Gone with them.
const PRIVATE_KEY_OBJECTS = new WeakMap();

function _x509(x) {
  try { return new crypto.X509Certificate(Buffer.isBuffer(x) ? x : Buffer.from(x)); }
  catch (e) { return null; }
}
// Trust anchors, parsed once. The anchors are the same certificates on every
// handshake — the platform bundle (~150 roots) or the caller's `ca` — and
// parsing all of them per handshake cost 5–8 ms of blocking CPU on the client,
// plus as many native objects for the GC to finalize afterwards. The peer's
// own chain is still parsed fresh each time: it is untrusted input.
//
// PEM strings are cached by value (the bundle is a list of strings); Buffers
// and other objects by identity. The string cache is bounded so an
// application that builds a new `ca` string per connection cannot grow it
// without limit — it just falls back to parsing.
const ANCHOR_CACHE_MAX = 1024;
const _anchorByPem = new Map();
const _anchorByObj = new WeakMap();
function _anchorX509(a) {
  if (typeof a === 'string') {
    let hit = _anchorByPem.get(a);
    if (hit !== undefined) return hit;
    hit = _x509(a);
    if (_anchorByPem.size >= ANCHOR_CACHE_MAX) _anchorByPem.clear();
    _anchorByPem.set(a, hit);
    return hit;
  }
  if (a && typeof a === 'object') {
    let hit = _anchorByObj.get(a);
    if (hit !== undefined) return hit;
    hit = _x509(a);
    _anchorByObj.set(a, hit);
    return hit;
  }
  return null;
}
function _sameCert(a, b) { return a.raw.length === b.raw.length && a.raw.equals(b.raw); }
function _validNow(x509, now) {
  return !(now < new Date(x509.validFrom) || now > new Date(x509.validTo));
}
// The node:tls (OpenSSL) code for a certificate outside its validity window.
function _validityError(x509, now) {
  return now < new Date(x509.validFrom) ? 'CERT_NOT_YET_VALID' : 'CERT_HAS_EXPIRED';
}
function _selfSigned(x509) {
  try { return !!x509.checkIssued(x509) && x509.verify(x509.publicKey); } catch (e) { return false; }
}

/**
 * Build and verify a certificate chain from `chainDer` (leaf first) up to one
 * of `anchors`.
 *
 * This replaces a check that compared ONLY the leaf against each configured CA,
 * which was wrong in both directions:
 *
 *   - A real chain (leaf <- intermediate <- root) FAILED, because nothing ever
 *     walked the intermediates the peer sent.
 *   - The whole check sat behind `if (context.ca)`, so when no CA was
 *     configured a peer presenting ANY self-signed certificate was authorized
 *     outright — with rejectUnauthorized defaulting to true, which reads as if
 *     verification were on.
 *
 * Each link has its signature verified, each non-leaf must actually assert
 * CA:TRUE, and every certificate in the path must be inside its validity
 * window. Intermediates come from the peer and are never trusted on their own;
 * only reaching an anchor ends the walk.
 *
 * Returns { ok: true, depth } or { ok: false, error }. The error codes are
 * the ones node:tls reports for the same failure (OpenSSL's X509_V_ERR_*
 * names), so an application can test err.code the same way on both:
 *
 *   DEPTH_ZERO_SELF_SIGNED_CERT        the leaf is self-signed and not trusted
 *   UNABLE_TO_VERIFY_LEAF_SIGNATURE    the leaf alone, its issuer unknown
 *   SELF_SIGNED_CERT_IN_CHAIN          the chain ends in an untrusted root
 *   UNABLE_TO_GET_ISSUER_CERT_LOCALLY  the chain stops at an unknown issuer
 *   INVALID_CA                         an issuer that is not a CA
 *   CERT_HAS_EXPIRED / CERT_NOT_YET_VALID   a certificate in the path
 */
function verify_cert_chain(chainDer, anchors, now) {
  if (!chainDer || chainDer.length === 0) return { ok: false, error: 'NO_PEER_CERTIFICATE' };
  now = now || new Date();

  const leaf = _x509(chainDer[0].cert || chainDer[0]);
  if (!leaf) return { ok: false, error: 'CERTIFICATE_PARSE_ERROR' };

  const pool = [];
  for (let i = 1; i < chainDer.length; i++) {
    const x = _x509(chainDer[i].cert || chainDer[i]);
    if (x) pool.push(x);
  }

  const trusted = [];
  for (let i = 0; i < (anchors || []).length; i++) {
    const x = _anchorX509(anchors[i]);
    if (x) trusted.push(x);
  }
  if (trusted.length === 0) return { ok: false, error: 'NO_TRUST_ANCHORS' };

  let current = leaf;
  const used = new Set();

  for (let depth = 0; depth < MAX_CHAIN_DEPTH; depth++) {
    // Explicitly trusted certificate (pinned leaf, or a self-signed cert the
    // caller deliberately placed in the trust store).
    for (const a of trusted) if (_sameCert(current, a)) return { ok: true, depth: depth };

    for (const a of trusted) {
      try {
        if (current.checkIssued(a) && current.verify(a.publicKey)) {
          if (!_validNow(a, now)) return { ok: false, error: _validityError(a, now) };
          return { ok: true, depth: depth + 1 };
        }
      } catch (e) { /* try next anchor */ }
    }

    let next = null;
    for (let i = 0; i < pool.length; i++) {
      if (used.has(i)) continue;                 // cycle guard
      const cand = pool[i];
      try {
        if (!current.checkIssued(cand)) continue;
        if (!current.verify(cand.publicKey)) continue;
        if (cand.ca !== true) return { ok: false, error: 'INVALID_CA' };
        if (!_validNow(cand, now)) return { ok: false, error: _validityError(cand, now) };
        used.add(i); next = cand; break;
      } catch (e) { /* try next candidate */ }
    }

    if (!next) {
      let selfSigned = _selfSigned(current);
      return { ok: false, error: depth === 0
        ? (selfSigned ? 'DEPTH_ZERO_SELF_SIGNED_CERT' : 'UNABLE_TO_VERIFY_LEAF_SIGNATURE')
        : (selfSigned ? 'SELF_SIGNED_CERT_IN_CHAIN' : 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY') };
    }
    current = next;
  }

  return { ok: false, error: 'CERT_CHAIN_TOO_LONG' };
}


// An IPv4 or IPv6 address literal (IPv6 with or without brackets) — what
// SNI may never carry, and what a certificate is checked against by IP SAN.
function is_ip_literal(host) {
  host = String(host);
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) ||
         (host.indexOf(':') >= 0 && /^[0-9a-fA-F:.\[\]]+$/.test(host));
}


function TLSSession(options){
  if (!(this instanceof TLSSession)) return new TLSSession(options);
  options = options || {};

  const ev = new EventEmitter();

  let context = {
    state: 'new', //new | negotiating | ...
    isServer: !!options.isServer,
    rejectUnauthorized: options.rejectUnauthorized !== false, // default true
    // Node parity: replaces the default RFC 6125 identity check. Returns
    // undefined to accept, an Error to reject. See validatePeerCertificate().
    checkServerIdentity: typeof options.checkServerIdentity === 'function'
      ? options.checkServerIdentity : null,
    // When no `ca` is configured, chain against the platform trust store
    // instead of authorizing everything. Opt out with useDefaultCA:false —
    // DTLS does exactly that, since WebRTC peers are self-signed by design
    // and authenticated out of band via the SDP fingerprint.
    useDefaultCA: options.useDefaultCA !== false,
    defaultCA: typeof options.defaultCA === 'function' ? options.defaultCA : null,
    // Node parity: synchronous ALPN selector, server side. Receives
    // { servername, protocols } and returns the chosen protocol, or undefined
    // to refuse with no_application_protocol. Mutually exclusive with
    // ALPNProtocols — compat.js rejects passing both, as Node does.
    ALPNCallback: typeof options.ALPNCallback === 'function' ? options.ALPNCallback : null,
    ca: options.ca || null, // CA certificates (PEM strings or Buffers)

    SNICallback: options.SNICallback || null,
    ticketKeys: options.ticketKeys || null, // 48 bytes: [0:16]=key_name, [16:48]=AES-256-GCM key
    // Server, TLS 1.2: whether a session ID issued now will be kept anywhere —
    // a function, asked when the ServerHello is built (listeners are added
    // after the session exists). A session ID is a promise to resume from it;
    // with nothing storing the session (no 'newSession' listener) the promise
    // is false, and every client that comes back with the ID is turned to a
    // full handshake. With no store the ServerHello carries an empty
    // session_id instead, which RFC 5246 §7.4.1.3 defines as "this session
    // will not be cached". Not given: IDs are issued, as before.
    sessionIdStore: typeof options.sessionIdStore === 'function' ? options.sessionIdStore : null,
    // Seconds. RFC 8446 §4.6.1: "Servers MUST NOT use any value greater than
    // 604800 seconds (7 days)" — capped here rather than trusted.
    ticketLifetime: Math.min(options.ticketLifetime != null ? (options.ticketLifetime >>> 0) : 7200, 604800),
    // Server: what the application wants carried inside the tickets it issues.
    // Called as ticketData(resumed) each time a ticket is issued, where
    // `resumed` is the data of the ticket this connection resumed with (null
    // on a full handshake); its return value — JSON-safe, small — rides inside
    // the ticket, encrypted with ticketKeys, and comes back in getTicketInfo()
    // on the connection that presents it. The application decides what carries
    // over from one ticket to the next; this layer only carries it.
    ticketData: typeof options.ticketData === 'function' ? options.ticketData : null,
    // Server: what the tickets this session issues are for, beyond what TLS
    // itself checks — a ticket issued under one context is not accepted
    // under another (full handshake), as OpenSSL's session id context. A
    // QUIC stack puts its version here (RFC 9369 §5: a ticket from a v1
    // connection MUST NOT resume a v2 one); setTicketContext() changes it
    // while the ClientHello is read, once the version is decided. '' = none.
    ticketContext: typeof options.ticketContext === 'string' ? options.ticketContext : '',
    // 0-RTT (RFC 8446 §4.2.10, early data). Server: issue tickets that allow
    // it (max_early_data_size: maxEarlyData — QUIC's 0xffffffff, RFC 9001
    // §4.6.1) and accept it when a ticket of ours comes back fresh (within
    // earlyDataMaxAge of the age the client states), for the first time
    // (earlyDataReplay), under the same earlyDataContext (what the layer
    // above needs unchanged: QUIC's transport parameters), with the same
    // ALPN and cipher suite, and with no HelloRetryRequest. Client: offer it
    // with a ticket that allows it. Off on both unless asked for; the secret
    // is handed out ('earlySecret'), the records are the layer above's.
    earlyData: options.earlyData === true,
    // TLS over TCP: early data ends with EndOfEarlyData (RFC 8446 §4.5),
    // which the client sends under the early key before its second flight
    // and the server must have before the client's Finished. QUIC has none
    // (RFC 9001 §8.3): off unless the record layer asks for it.
    endOfEarlyData: options.endOfEarlyData === true,
    earlyDataMaxAge: (typeof options.earlyDataMaxAge === 'number' && options.earlyDataMaxAge > 0) ? options.earlyDataMaxAge : 10000,
    earlyDataReplay: typeof options.earlyDataReplay === 'function' ? options.earlyDataReplay : null,
    earlyDataContext: typeof options.earlyDataContext === 'string' ? options.earlyDataContext : '',
    maxEarlyData: (typeof options.maxEarlyData === 'number' && options.maxEarlyData >= 0) ? (options.maxEarlyData >>> 0) : 0xffffffff,
    // A client's own data kept in the session it saves (QUIC: the server's
    // transport parameters, which 0-RTT must respect, RFC 9000 §7.4.1), and
    // given back with the early secret on a resumed connection.
    sessionAppData: options.sessionAppData != null ? options.sessionAppData : null,
    // Certificate compression (RFC 8879), TLS 1.3: the algorithms this side
    // decompresses — offered in the ClientHello (client) or the
    // CertificateRequest (server) — and compresses with, for a peer that
    // offered them. ['brotli', 'zlib', 'zstd'], true (all) or false. Server:
    // every one this Node has, unless set; client: none unless set — what a
    // ClientHello carries is its fingerprint, and changing it is the
    // application's call.
    cert_compression: parse_cert_compression(options.certificateCompression) ||
                      (options.isServer ? supported_cert_compression() : []),
    peer_cert_compression: null,     // what the peer can decompress (its ClientHello / CertificateRequest)
    cert_compression_sent: null,     // the algorithm our Certificate went in, null if it went plain or not at all
    cert_compression_received: null, // the algorithm the peer's came in
    // OCSP stapling (RFC 6066 §8; TLS 1.3: RFC 8446 §4.4.2.1).
    //  Server: ocspRequest(certificate, issuer, cb) — node:tls's 'OCSPRequest'
    //  — asked when a client requests status and a certificate will be sent;
    //  cb(err, response): a DER OCSP response to staple, or null for none.
    //  Client: requestOCSP — ask for it; what comes is emitted 'OCSPResponse'.
    ocspRequest: (options.isServer && typeof options.ocspRequest === 'function') ? options.ocspRequest : null,
    requestOCSP: !options.isServer && options.requestOCSP === true,
    ocsp_requested: false,
    ocsp_pending: false,
    ocsp_response: null,
    // Encrypted Client Hello (RFC 9849), server: the keys, and this
    // connection's outcome — status null (not offered) | 'accepted' | 'rejected'.
    ech_server: options.isServer ? prepare_ech_server(options.ech) : null,
    // Client: the config to encrypt the real ClientHello to (an
    // ECHConfigList, `ech`), or GREASE ECH without one (`echGrease`). Status
    // null (none) | 'grease' | 'accepted' | 'rejected'; the rest of `ech` is
    // the client's state for this connection (see ech_split onwards).
    ech_client: options.isServer ? null : prepare_ech_client(options.ech),
    ech_grease: !options.isServer && options.echGrease === true,
    ech: { status: null },
    sessionTickets: options.sessionTickets !== false, // default true (was noTickets inverted)

    // Advanced options
    maxHandshakeSize: options.maxHandshakeSize || 0, // 0 = no limit
    customExtensions: options.customExtensions || [], // [{type:0xNN, data:Uint8Array}]

    // Shuffle ClientHello extension order (Chrome 110+ behaviour). Off by
    // default: a fixed order keeps handshakes diffable against each other and
    // avoids waking up middleboxes that ossified on one. See
    // permute_extensions() for what this does and does not buy.
    permuteExtensions: !!options.permuteExtensions,
    // The order chosen for CH1, replayed on a post-HRR CH2.
    extension_order: null,

    // Insert GREASE (RFC 8701) reserved values into the ClientHello. Off by
    // default: a peer that mishandles an unknown value fails the handshake
    // with no clue as to why, and GREASE changes no fingerprint (JA4 and JA5
    // strip it), so the cost of being wrong outweighs the benefit of being
    // right. Safe and worth enabling against public HTTPS servers; leave off
    // for DTLS/WebRTC peers until tested. See apply_grease().
    grease: !!options.grease,
    // The cipher-list GREASE value picked for CH1, reused on a post-HRR CH2.
    grease_cipher: null,
    handshakeBytes: 0,
    handshakeStartTime: null,
    handshakeEndTime: null,
    // Raw hello messages, stored regardless of role: whichever side sent it,
    // both are visible to both peers, and every fingerprint below is computed
    // from one of them. rawClientHello also backs the 'clienthello' event.
    //
    // ClientHello keeps the FIRST one seen — after a HelloRetryRequest the
    // client sends a second, amended ClientHello, and the original offer is
    // what a passive observer fingerprints. ServerHello keeps the LAST one,
    // because HRR is itself encoded as a ServerHello and would otherwise
    // shadow the real one.
    rawClientHello: null,
    rawServerHello: null,

    // One cache slot per fingerprint, each filled the first time it is asked
    // for. getJA4() is legitimately called from the 'clienthello' handler,
    // which fires before the ServerHello exists; a slot is only filled once
    // its hello exists, so ja4s is not frozen at null by an early call.
    parsedClientHello: null,   // null = not tried, false = threw, object = parsed
    parsedServerHello: null,
    fpCache: {},

    //local stuff...
    local_sni: options.servername || null,
    local_session_id: 'sessionId' in options ? options.sessionId : null,

    local_random: null,
    local_extensions: [],
    // DTLS-SRTP protection profiles we accept, in preference order (RFC 5764).
    // Value-based, not key-based: transports forward the option unconditionally,
    // so the key is present with an undefined value when it was never set.
    srtp_profiles: Array.isArray(options.srtpProfiles) ? options.srtpProfiles.slice() : [],
    selected_srtp_profile: null,
    // Extension types we offered — see note_offered_extensions().
    offered_extension_types: [],


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
    
    // RFC 8446 §7.1: the application traffic secrets (and exporter_master_secret)
    // are derived from the transcript hash through the SERVER's Finished —
    // ClientHello..server Finished, and nothing after it.
    //
    // This is a SEMANTIC checkpoint, so it is captured at the moment that event
    // happens (server: when it pushes its own Finished; client: when it accepts
    // the server's), NOT read off the live transcript wherever the derivation
    // block happens to sit in the reactive loop. Those two differ: on the
    // client, the loop may already have emitted its own Certificate (when the
    // server requested client auth) before reaching the derivation block, which
    // silently derived app keys over a longer transcript than the server used —
    // a split-key handshake that surfaced only as a late bad_record_mac.
    tls13_app_transcript_hash: null,

    local_app_traffic_secret: null,

    local_cert_chain: null,
    remote_cert_chain: null,
    peerAuthorized: false,
    // Set only after the peer's handshake signature (TLS 1.3
    // CertificateVerify, or TLS 1.2 ServerKeyExchange) actually verified
    // against its certificate's public key. Gates handshake completion.
    peerSignatureVerified: false,
    peerSignatureScheme: null,
    authorizationError: null,

    selected_cert: null,

    cert_private_key: null,
    // Server: choose the cipher suite by our order, not the client's
    // (node:tls's honorCipherOrder; default false, the client's).
    honor_cipher_order: options.honorCipherOrder === true,
    local_cert_alternates: null,      // other key/certificate pairs (key/cert arrays): [{ certificateChain, privateKey }]
    cert_chosen: false,               // which of them this handshake presents, decided

    // Client certificate authentication
    requestCert: !!options.requestCert,       // server: send CertificateRequest?
    clientCert: options.cert || null,          // client: cert to send if requested
    clientKey: options.key || null,            // client: private key for CertificateVerify
    // Needed to decrypt an encrypted PEM key. createSecureContext() has always
    // accepted this, but nothing forwarded it here, so an encrypted client key
    // threw on parse no matter what the caller passed.
    clientKeyPassphrase: options.passphrase || null,
    certificateRequested: false,              // client: server sent CertificateRequest?
    certificateRequestSent: false,            // server: we sent CertificateRequest?
    certificateRequestContext: null,
    certificateRequestSigAlgs: [],
    clientCertSent: false,

    // HelloRetryRequest
    helloRetried: false,                      // true if HRR was sent/received
    client_hellos_received: 0,               // server: one, or two after a HelloRetryRequest
    // What a received HelloRetryRequest committed the server to; the second
    // ServerHello is validated against these (RFC 8446 §4.1.4).
    hrr_version: null,
    hrr_group: null,
    hrr_cipher: null,

    // DTLS cookie (set by DTLSSession via set_context)
    dtls_cookie: undefined,                   // Uint8Array or undefined

    // TLS 1.3 resumption
    tls13_master_secret: null,
    exporter_master_secret: null,     // RFC 8446 §7.1 "exp master" — for exportKeyingMaterial
    resumption_master_secret: null,
    ticket_nonce_counter: 0,
    session_ticket_sent: false,
    psk_offered: null,       // client: { identity, psk, cipher } offered in ClientHello
    // 0-RTT on this connection. offered: the client sent early_data;
    // candidate: the server found it acceptable but for ALPN and suite,
    // { cipher, alpn, secret }; pending: the replay check is out;
    // status: null | 'accepted' | 'rejected'; appData: the client's saved
    // sessionAppData, given back.
    early: { offered: false, candidate: null, pending: false, status: null, alpn: null, appData: null, clientOffered: false, eoed: false },
    psk_accepted: false,     // server accepted PSK → abbreviated handshake
    client_secure_renegotiation: false,   // server: the client sent renegotiation_info or its SCSV (RFC 5746)
    renegotiation_refusals: 0,            // no_renegotiation warnings sent (TLS 1.2)
    isResumed: false,        // true if PSK was accepted (1.3) or abbreviated handshake (1.2)
    hrr_hash: null,            // client: the hash of the suite a HelloRetryRequest named
    resumed_ticket_data: null, // application data of the ticket resumed with (see ticketData)
    // The protocol layer's own slot in a ticket, apart from the application's
    // ticketData: what setTicketState() last set, carried by the tickets
    // issued from then on, and what the ticket resumed with carried
    // (getTicketInfo().state). A QUIC stack keeps its path measurements there,
    // to start a returning client's connection where the last one left off.
    ticket_state: null,
    resumed_ticket_state: null,
    resumed_peer_chain: null,  // the client's certificate, from the ticket resumed with
    ticket_offered: false,     // the client presented a ticket, used or not (see getTicketInfo)
    app_ticket_data: undefined, // what this connection's ticket carries: decided once (ticket_app_data)

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

    // Waiting for SNICallback to hand back a certificate.
    //
    // Node documents SNICallback as (servername, cb) precisely so a server can
    // look a certificate up — from disk, from a cache, from another process —
    // and any virtual-host server must, because it cannot know every
    // certificate in advance. The lookup may therefore answer later, and until
    // it does there is nothing to sign or send with.
    //
    // Same shape and same reason as tls12_resume_pending directly above: a
    // gate the reactive loop honours, cleared by the callback, which then lets
    // the loop run again with the answer in context.
    sni_pending: false,
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
  /**
   * Negotiated-version predicates.
   *
   * The engine deliberately handles TLS 1.2 and 1.3 in ONE state machine: the
   * version is chosen *during* the handshake, so the machine must start
   * version-agnostic, and a large part of the flow (hello parsing, extensions,
   * transcript, certificates, ALPN/SNI, alerts) is genuinely shared. What
   * differs is expressed as guards on individual steps.
   *
   * These two helpers exist so those guards read as the protocol question they
   * actually are. Each site used to spell out
   *   (context.selected_version === wire.TLS_VERSION.TLS1_3 ||
   *    context.selected_version === wire.DTLS_VERSION.DTLS1_3)
   * — ~90 characters that buried the *rest* of the condition it was ANDed with.
   * (D)TLS 1.3 and 1.2 are treated as one version each because the record layer
   * differences live in record.js / the transports, not here.
   */
  // Delegate rather than restate: wire.js owns the "which message format does
  // this version constant mean" question, because that is where getting it
  // wrong silently produced a TLS 1.2 Certificate on a DTLS 1.3 connection.
  // Introducing is_tls13_wire there and leaving a second copy of the same test
  // here would have recreated exactly the drift it was added to remove.
  function is13() { return wire.is_tls13_wire(context.selected_version); }
  function is12() { return wire.is_tls12_wire(context.selected_version); }
  // DTLS or TLS: a DTLSSession sets DTLS versions before the first message;
  // a TLS session's, when set at all by then, are TLS ones.
  function dtls_transport() {
    return (context.local_supported_versions || []).some(function (v) { return (v & 0xff00) === 0xfe00; });
  }

  /**
   * Assemble the ClientHello extension list.
   *
   * ONE builder for both the initial ClientHello and the post-HelloRetryRequest
   * CH2. RFC 8446 §4.1.2 requires CH2 to be identical to CH1 except for
   * key_share, cookie and (optionally) a trimmed PSK — so building them from
   * two hand-maintained copies is a standing invitation to divergence, and the
   * copies HAD already diverged: one gated supported_versions/key_share on
   * "do we offer 1.3", the other always emitted them, and the 1.3-only test
   * differed between them (one accounted for DTLS 1.3, the other did not).
   *
   * @param {object} opts
   *   keyShareGroup  — NamedGroup for the key_share entry (null = omit)
   *   keySharePublic — public key bytes for that group
   *   extraKeyShares — further { group, key_exchange } entries (CH1 only:
   *                    after a HelloRetryRequest there is exactly one)
   *   cookie         — HRR cookie to echo (RFC 8446 §4.2.2), or null
   */
  function build_client_hello_extensions(opts) {
    opts = opts || {};

    let offers13 = context.local_supported_versions.some(function (v) {
      return v === wire.TLS_VERSION.TLS1_3 || v === wire.DTLS_VERSION.DTLS1_3;
    });
    // "1.3-only" means every offered version is (D)TLS 1.3 — a QUIC-style
    // profile that must not carry TLS 1.2 legacy extensions.
    let tls13Only = context.local_supported_versions.length > 0 &&
                    context.local_supported_versions.every(function (v) {
                      return v === wire.TLS_VERSION.TLS1_3 || v === wire.DTLS_VERSION.DTLS1_3;
                    });

    let extensions = [];

    if (offers13) {
      // With ECH, TLS 1.3 only (RFC 9849 §6.1: ECH is a TLS 1.3 mechanism; a
      // server steering to 1.2 would carry the hello's real name nowhere and
      // the public name in the clear).
      extensions.push({ type: 'SUPPORTED_VERSIONS', value: ech_on() ? context.local_supported_versions.filter(function (v) { return v === wire.TLS_VERSION.TLS1_3; })
                                                                      : context.local_supported_versions });
    }
    // supported_groups is a CAPABILITY claim, not a copy of configuration.
    //
    // A configured list may name groups ecdh.js does not implement — a caller
    // passing a curve list through, a post-quantum group in a profile we do not
    // yet support. Advertising one is a promise: RFC 8446 §4.2.7 lets the
    // server pick any group in this list and send a HelloRetryRequest for it.
    // We would then have to abort a handshake the server conducted correctly,
    // purely because we over-promised. Filtering here keeps the configured list
    // intact for introspection while never claiming more than we can do.
    let advertisable = [];
    for (let gi = 0; gi < context.local_supported_groups.length; gi++) {
      let g = context.local_supported_groups[gi];
      if (!is_supported_group(g)) continue;
      // A KEM group only in a hello that offers TLS 1.3: TLS 1.2's key
      // exchange cannot carry one, and a 1.2-only hello should look like one.
      if (!offers13 && is_kem_group(g)) continue;
      advertisable.push(g);
    }
    extensions.push({ type: 'SUPPORTED_GROUPS', value: advertisable });
    if (offers13 && opts.keySharePublic) {
      let shares = [{ group: opts.keyShareGroup, key_exchange: opts.keySharePublic }];
      if (opts.extraKeyShares) shares = shares.concat(opts.extraKeyShares);
      extensions.push({ type: 'KEY_SHARE', value: shares });
    }
    extensions.push({
      type: 'SIGNATURE_ALGORITHMS',
      value: context.local_supported_signature_algorithms
    });

    if (!tls13Only) {
      // TLS 1.2 compatibility — meaningless (and suspicious to strict stacks)
      // in a 1.3-only hello.
      extensions.push({ type: 'RENEGOTIATION_INFO', value: new Uint8Array(0) });
      extensions.push({ type: 'EXTENDED_MASTER_SECRET', value: null });
    }
    if (!context.isServer && context.requestOCSP) {
      // status_request (RFC 6066 §8): an OCSP response for the server's
      // certificate, stapled — node:tls's requestOCSP.
      extensions.push({ type: 'STATUS_REQUEST', value: { ocsp: true } });
    }
    if (offers13 && !context.isServer && context.cert_compression.length > 0) {
      // compress_certificate (RFC 8879): the server's chain may come
      // compressed. TLS 1.3 only.
      extensions.push({ type: 'COMPRESS_CERTIFICATE', value: context.cert_compression });
    }
    if (offers13) {
      // psk_key_exchange_modes: a server MUST NOT send NewSessionTicket to a
      // client that omitted it (RFC 8446 §4.2.9) — in any hello that offers
      // 1.3, as browsers and OpenSSL send it. It was in 1.3-only hellos alone:
      // a client offering 1.2 and 1.3 asked for no tickets, and the
      // resumption path then added it a second time to a 1.3-only one —
      // duplicate extension 45, which a server refuses (decode_error from
      // lemon-tls, illegal_parameter from OpenSSL): a saved TLS 1.3 session
      // never resumed. It is here once, for both.
      extensions.push({ type: 'PSK_KEY_EXCHANGE_MODES', value: [1] });
    }

    // SNI must come first. A host NAME only: RFC 6066 §3 — "Literal IPv4 and
    // IPv6 addresses are not permitted in HostName". local_sni holds whatever
    // the caller connected to, an address included, because the certificate
    // is still checked against it (see the identity check); it is only kept
    // off the wire. node:tls does the same.
    if (context.local_sni && !is_ip_literal(context.local_sni)) {
      extensions.unshift({ type: 'SERVER_NAME', value: context.local_sni });
    }

    if (context.local_supported_alpns && context.local_supported_alpns.length > 0) {
      extensions.push({ type: 'ALPN', value: context.local_supported_alpns });
    }

    // RFC 5077 SessionTicket. This belongs HERE, not at the CH1 call site,
    // because RFC 8446 §4.1.2 requires the second ClientHello to be identical
    // to the first except for key_share, cookie and pre_shared_key. Anything
    // appended to CH1 *after* this assembler returns is silently absent from
    // CH2, and a strict peer rejects the retry ("second ClientHello missing
    // extension 35"). Every extension common to both hellos has to be produced
    // by the one function that builds both.
    //
    // It is a TLS 1.2 mechanism (1.3 resumes via NewSessionTicket/PSK), so it
    // is never offered in a 1.3-only profile. Skipped for DTLS as well:
    // implementations often do not handle RFC 5077 there and it broke interop
    // with openssl s_server -dtls1_2.
    let isDtlsProfile = context.local_supported_versions &&
                        context.local_supported_versions.some(function (v) { return (v & 0xFF00) === 0xFE00; });
    if (!isDtlsProfile && !tls13Only && context.sessionTickets) {
      if (opts.sessionTicket) {
        extensions.push({ type: 'SESSION_TICKET', value: opts.sessionTicket });
      } else {
        extensions.push({ type: 'SESSION_TICKET', value: new Uint8Array(0) });
      }
    }

    // Cookie from HelloRetryRequest — MUST be echoed when present.
    if (opts.cookie) {
      extensions.push({ type: 'COOKIE', value: opts.cookie });
    }

    // Caller-supplied extensions (e.g. transport parameters).
    // DTLS-SRTP offer (RFC 5764 §4.1.1): the client advertises every profile it
    // accepts. Built here so CH1 and CH2 stay identical (RFC 8446 §4.1.2).
    if (!context.isServer && Array.isArray(context.srtp_profiles) &&
        context.srtp_profiles.length > 0) {
      extensions.push({ type: 'USE_SRTP',
                        value: { profiles: context.srtp_profiles.slice(),
                                 mki: new Uint8Array(0) } });
    }

    for (let i = 0; i < context.local_extensions.length; i++) {
      extensions.push(context.local_extensions[i]);
    }

    // Encrypted Client Hello (RFC 9849). With a config: this list is the
    // inner hello's, marked as such (§5: the inner extension, type 1) — the
    // outer one is made from it (ech_split). Without one, and echGrease:
    // a GREASE extension (§6.2), a CH2's with an empty enc.
    if (!context.isServer && offers13 && !isDtlsProfile) {
      if (ech_on()) {
        extensions.push({ type: EXT_ECH, data: new Uint8Array([1]) });
      } else if (context.ech_grease) {
        if (!context.ech.grease) { context.ech.grease = grease_ech_state(); context.ech.status = 'grease'; }
        extensions.push({ type: EXT_ECH, data: grease_ech_ext_data(context.ech.grease, context.helloRetried === true) });
      }
    }

    if (context.grease) apply_grease(extensions);
    if (context.permuteExtensions) extensions = permute_extensions(extensions);

    note_offered_extensions(extensions);
    return extensions;
  }

  /* --------------------------------- GREASE -------------------------------- */

  /** RFC 8701 §2: the sixteen two-byte reserved values. */
  const GREASE_U16 = [
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
  ];
  /** RFC 8701 §2: psk_key_exchange_modes is a vector of SINGLE bytes and
   *  therefore has its own, entirely separate reserved table. Reusing the u16
   *  values here would emit a mode the registry does not reserve. */
  const GREASE_U8 = [0x0B, 0x2A, 0x49, 0x68, 0x87, 0xA6, 0xC5, 0xE4];

  function is_grease_u16(v) {
    return typeof v === 'number' && (v & 0x0f0f) === 0x0a0a && ((v >>> 8) & 0xff) === (v & 0xff);
  }
  function is_grease_u8(v) { return GREASE_U8.indexOf(v) >= 0; }

  function pick_from(table) {
    return table[crypto.randomBytes(4).readUInt32BE(0) % table.length];
  }

  /**
   * Insert GREASE (RFC 8701) into the ClientHello — opt-in via `grease`.
   *
   * The point is anti-ossification: a peer that cannot tolerate an unknown
   * value in a list breaks immediately and visibly, instead of quietly
   * calcifying the protocol until a real value is deployed years later.
   *
   * Note that this does NOT hide you. JA4 and JA5 both strip GREASE before
   * hashing, so every fingerprint is identical with this on or off. What
   * changes is only that a ClientHello carrying zero GREASE reads as
   * "not a browser" to anyone looking.
   *
   * COLLISION HANDLING — the reason this is not a blind push. A caller can
   * already inject GREASE by hand through customExtensions, local_extensions,
   * or the local_supported_* lists. Adding a second value on top of that would
   * at best be redundant and at worst fatal: RFC 8446 §4.2 forbids two
   * extensions of the same type outright, and this library's own parser
   * rejects that with decode_error. So every list is inspected first, and a
   * list that already carries a GREASE value is left exactly as it is. Manual
   * configuration always wins.
   */
  function apply_grease(extensions) {
    let byType = {};
    for (let i = 0; i < extensions.length; i++) {
      let t = extensions[i] && extensions[i].type;
      if (t != null) byType[String(t)] = extensions[i];
    }
    let find = function (name, code) { return byType[name] || byType[String(code)] || null; };

    // --- a GREASE extension type of its own ---
    let hasGreaseExt = false;
    for (let i = 0; i < extensions.length; i++) {
      if (is_grease_u16(extensions[i] && extensions[i].type)) { hasGreaseExt = true; break; }
    }
    if (!hasGreaseExt) {
      // Body length is deliberately varied: a peer that tolerates an unknown
      // extension only when it is empty is still ossified.
      let n = crypto.randomBytes(1)[0] % 3;
      extensions.push({ type: pick_from(GREASE_U16), value: new Uint8Array(n) });
    }

    // --- value lists that take u16 entries ---
    let u16Lists = [
      ['SUPPORTED_GROUPS', 10], ['SIGNATURE_ALGORITHMS', 13], ['SUPPORTED_VERSIONS', 43]
    ];
    for (let i = 0; i < u16Lists.length; i++) {
      let e = find(u16Lists[i][0], u16Lists[i][1]);
      if (!e || !Array.isArray(e.value) || e.value.length === 0) continue;
      if (e.value.some(is_grease_u16)) continue;              // caller already did it
      e.value = [pick_from(GREASE_U16)].concat(e.value);
    }

    // --- psk_key_exchange_modes: single bytes, separate table ---
    let pk = find('PSK_KEY_EXCHANGE_MODES', 45);
    if (pk && Array.isArray(pk.value) && !pk.value.some(is_grease_u8)) {
      pk.value = [pick_from(GREASE_U8)].concat(pk.value);
    }

    // --- ALPN: a two-BYTE protocol name, not a u16 ---
    let alpn = find('ALPN', 16);
    if (alpn && Array.isArray(alpn.value) && alpn.value.length > 0) {
      let already = alpn.value.some(function (p) {
        if (typeof p !== 'string' || p.length !== 2) return false;
        return is_grease_u16((p.charCodeAt(0) << 8) | p.charCodeAt(1));
      });
      if (!already) {
        let g = pick_from(GREASE_U16);
        alpn.value = [String.fromCharCode((g >>> 8) & 0xff) + String.fromCharCode(g & 0xff)]
                       .concat(alpn.value);
      }
    }

    // --- key_share: a GREASE group carrying an arbitrary key ---
    // This is the one that actually exercises a server: it must skip an entry
    // whose group it does not recognise rather than try to parse the key.
    let ks = find('KEY_SHARE', 51);
    if (ks && Array.isArray(ks.value) && ks.value.length > 0) {
      let already = ks.value.some(function (k) { return is_grease_u16(k && k.group); });
      if (!already) {
        // Prefer the group we just advertised, so the offer stays self-consistent.
        let sg = find('SUPPORTED_GROUPS', 10);
        let g = null;
        if (sg && Array.isArray(sg.value)) {
          for (let i = 0; i < sg.value.length; i++) {
            if (is_grease_u16(sg.value[i])) { g = sg.value[i]; break; }
          }
        }
        if (g === null) g = pick_from(GREASE_U16);
        ks.value = [{ group: g, key_exchange: new Uint8Array(1) }].concat(ks.value);
      }
    }
  }

  /** GREASE for the cipher_suites list, applied at the build site because the
   *  list is not part of the extension array. Same rule as everywhere else: a
   *  caller-supplied GREASE value is left alone.
   *
   *  The chosen value is remembered, because CH1 and CH2 must be identical
   *  across a HelloRetryRequest (RFC 8446 §4.1.2) — re-rolling on the retry
   *  would change the offered cipher list and could be rejected. */
  function grease_cipher_suites(list) {
    if (!context.grease || !Array.isArray(list) || list.length === 0) return list;
    if (list.some(is_grease_u16)) return list;
    if (context.grease_cipher === null) context.grease_cipher = pick_from(GREASE_U16);
    return [context.grease_cipher].concat(list);
  }

  /**
   * Shuffle ClientHello extension order (opt-in via `permuteExtensions`).
   *
   * Chrome has done this since 110 as an anti-ossification measure: middleboxes
   * that hardcode a fixed extension order break loudly rather than silently
   * calcifying the protocol. It is a separate mechanism from GREASE (RFC 8701),
   * which inserts reserved dummy VALUES; this reorders real extensions.
   *
   * What it changes, for anyone reaching for it as evasion: nothing this
   * library computes. JA4 and JA5 sort extensions before hashing, so both are
   * byte-for-byte identical with this on or off. It defeats only JA3, the 2017
   * fingerprint, which hashed extensions in wire order — and a client whose
   * JA3 differs on every connection is itself a distinctive pattern.
   *
   * Two ordering rules are preserved:
   *
   *  - pre_shared_key MUST come last (RFC 8446 §4.2.11) — its binders are
   *    computed over everything before it. It is appended after assembly, so it
   *    is not in this array yet and cannot be displaced.
   *
   *  - CH1 and CH2 must stay identical across a HelloRetryRequest
   *    (RFC 8446 §4.1.2), which lists the permitted changes and does not
   *    include reordering. The permutation is therefore computed once per
   *    session and replayed by type on the retry, rather than re-rolled — a
   *    fresh shuffle on CH2 would be a spec violation that strict servers
   *    could reject.
   */
  function permute_extensions(list) {
    let key = function (e) { return String(e && e.type); };

    // Replay the order chosen for CH1 rather than re-rolling.
    if (context.extension_order !== null) {
      let byType = {};
      for (let i = 0; i < list.length; i++) {
        let k = key(list[i]);
        if (!byType[k]) byType[k] = [];
        byType[k].push(list[i]);
      }
      let out = [];
      for (let i = 0; i < context.extension_order.length; i++) {
        let bucket = byType[context.extension_order[i]];
        if (bucket && bucket.length > 0) out.push(bucket.shift());
      }
      // Anything CH2 added that CH1 never had (the HRR cookie) keeps its
      // position at the end; dropping it would corrupt the retry.
      for (let k in byType) {
        if (Object.prototype.hasOwnProperty.call(byType, k)) {
          for (let j = 0; j < byType[k].length; j++) out.push(byType[k][j]);
        }
      }
      return out;
    }

    // Fisher-Yates over a copy, with a CSPRNG rather than Math.random: the
    // order is observable on the wire, and a predictable shuffle would be a
    // weaker signal than no shuffle at all.
    let out = list.slice();
    for (let i = out.length - 1; i > 0; i--) {
      let j = crypto.randomBytes(4).readUInt32BE(0) % (i + 1);
      let tmp = out[i]; out[i] = out[j]; out[j] = tmp;
    }

    context.extension_order = out.map(key);
    return out;
  }

  /**
   * Remember which extension types we actually offered.
   *
   * RFC 8446 §4.2: "Implementations MUST NOT send extension responses if the
   * remote endpoint did not send the corresponding extension requests ...
   * Upon receiving such an extension, an endpoint MUST abort the handshake
   * with an unsupported_extension alert."
   *
   * Enforcing that needs one fact — what we asked for — recorded in one place.
   * The assembler is that place: every ClientHello, first or post-HRR, is built
   * through it, so the record cannot drift from what actually went on the wire.
   * Extensions appended after assembly (pre_shared_key, session_ticket) call
   * this again to add themselves.
   */
  /**
   * RFC 8446 §4.2 (TLS 1.3): a server MUST NOT answer with an extension the
   * client did not request, and a client receiving one MUST abort with
   * unsupported_extension.
   *
   * IMPORTANT: this function does NOT gate on version itself, because the
   * ServerHello caller cannot rely on context.selected_version yet (it is set
   * in a later pass of the reactive loop). The caller decides scope from the
   * message's own supported_versions, which is authoritative.
   *
   * TLS/DTLS 1.2 (RFC 5246 §7.4.1.4) is deliberately looser: unknown
   * extensions must be ignored. Applying the 1.3 rule to a 1.2 handshake
   * rejects entirely valid peers (the WebRTC regression against pion /
   * webrtc-rs).
   *
   * One rule for every server-originated extension block (ServerHello,
   * EncryptedExtensions) — they all fail for the same reason and must fail
   * the same way. Returns true when the caller should stop processing.
   *
   * HelloRetryRequest is handled earlier and returns before this point, so its
   * cookie — which by definition we could not have offered — never lands here.
   */
  function reject_unsolicited_extensions(message, where) {
    if (context.isServer) return false;                       // servers answer, not ask
    if (!Array.isArray(message.extensions)) return false;
    if (context.offered_extension_types.length === 0) return false;  // nothing recorded yet

    for (let i = 0; i < message.extensions.length; i++) {
      let et = message.extensions[i] && message.extensions[i].type;
      if (typeof et !== 'number') continue;

      // RFC 8701 §3.3 lets a SERVER advertise GREASE extensions of its own in
      // EncryptedExtensions, CertificateRequest, Certificate and
      // NewSessionTicket — the whole point being that we could not have asked
      // for them. Testing those against offered_extension_types therefore
      // rejects a peer that is behaving exactly as specified, which is the
      // same class of over-strictness as the 1.2 regression noted above, only
      // with us on the rejecting side this time.
      if (is_grease_u16(et)) continue;

      if (context.offered_extension_types.indexOf(et) < 0) {
        fatalAlert(wire.TLS_ALERT.UNSUPPORTED_EXTENSION,
          where + ' carried extension ' + et + ' which we did not offer');
        return true;
      }
    }
    return false;
  }

  function note_offered_extensions(list) {
    if (!Array.isArray(context.offered_extension_types)) {
      context.offered_extension_types = [];
    }
    for (let i = 0; i < list.length; i++) {
      let t = list[i] && list[i].type;
      let code = (typeof t === 'number') ? t : wire.TLS_EXT[t];
      if (typeof code === 'number' && context.offered_extension_types.indexOf(code) < 0) {
        context.offered_extension_types.push(code);
      }
    }
  }

  /**
   * The peer's leaf-certificate public key, as a crypto.KeyObject.
   *
   * Single place that turns remote_cert_chain[0] into a usable key. Both the
   * TLS 1.3 CertificateVerify path and the TLS 1.2 ServerKeyExchange path need
   * it, and having two copies means a future change to how we read the chain
   * (chain building, alternative encodings) could be applied to one and missed
   * on the other — the kind of half-fix that has bitten us before.
   *
   * Returns null if there is no chain or the leaf cannot be parsed; callers
   * turn that into the appropriate alert for their context.
   */
  function peer_leaf_public_key() {
    if (!context.remote_cert_chain || context.remote_cert_chain.length === 0) return null;
    try {
      return new crypto.X509Certificate(Buffer.from(context.remote_cert_chain[0].cert)).publicKey;
    } catch (e) {
      return null;
    }
  }

  /**
   * The peer's handshake signature — TLS 1.3 CertificateVerify (either role),
   * TLS 1.2 CertificateVerify (a client's), TLS 1.2 ServerKeyExchange (a
   * server's) — checked in one place, in one order:
   *
   *   1. the signature itself, under the leaf's key (verify_with_scheme, which
   *      also binds the scheme to the key type): decrypt_error if it fails;
   *   2. then the scheme: one we offered (RFC 8446 §4.4.3, RFC 5246 §7.4.8,
   *      RFC 4492 §5.4 — "MUST be one of those present in" our
   *      signature_algorithms, sent in the ClientHello or the
   *      CertificateRequest): illegal_parameter if not. Not before 1: a
   *      policy error must not stand in for a signature failure.
   *
   * It was three copies, one per message, and the scheme was held to what we
   * offered in none of them (1.3: removed on purpose; 1.2: never written) —
   * so `sigalgs` narrowed what we asked for, not what we took.
   *
   * Returns null when the signature stands; otherwise { alert, reason }, for
   * the caller's fatalAlert. On success, records it (peerSignatureVerified).
   */
  function check_peer_signature(version, scheme, tbs, signature, what) {
    let pub = peer_leaf_public_key();
    if (!pub) return { alert: wire.TLS_ALERT.BAD_CERTIFICATE, reason: 'Cannot read peer certificate public key' };
    if (verify_with_scheme(version, scheme, tbs, pub, signature) !== true) {
      return { alert: wire.TLS_ALERT.DECRYPT_ERROR, reason: what + ' signature verification failed' };
    }
    let offered = context.local_supported_signature_algorithms || [];
    if (offered.length > 0 && offered.indexOf(scheme) < 0) {
      return { alert: wire.TLS_ALERT.ILLEGAL_PARAMETER, reason: what + ' signed with scheme 0x' + (scheme >>> 0).toString(16) + ', which was not offered' };
    }
    context.peerSignatureVerified = true;
    context.peerSignatureScheme = scheme;
    return null;
  }

  /**
   * The cipher suite a ServerHello / HelloRetryRequest selected.
   *
   * parse_hello normalises the server's single choice into `cipher_suites[0]`,
   * but some paths surface it as `cipher_suite`. Both spellings are in use, so
   * reading only one of them silently yields undefined — which is how the
   * HelloRetryRequest cipher-consistency check came to accept every mismatch.
   */
  function hello_cipher_suite(message) {
    if (Array.isArray(message.cipher_suites) && message.cipher_suites.length > 0) {
      return message.cipher_suites[0];
    }
    if (typeof message.cipher_suite === 'number') return message.cipher_suite;
    return null;
  }

  /* ====================== Encrypted Client Hello: client ===================== */

  // A config to use, on a hello that offers TLS 1.3 (not DTLS: RFC 9849 is
  // TLS's).
  function ech_on() {
    return !context.isServer && context.ech_client !== null &&
           context.local_supported_versions.indexOf(wire.TLS_VERSION.TLS1_3) >= 0;
  }

  function ext_code(e) { return typeof e.type === 'number' ? e.type : wire.TLS_EXT[e.type]; }

  /**
   * The assembled list → the inner hello's, in place, and what the outer
   * one is made of. Inner: server_name, then every other extension, then
   * the inner ECH marker (pre_shared_key, when there is one, goes last after
   * this — the PSK path adds it). Outer: the config's public_name, then the
   * same extensions, the same objects — so the inner hello can name them
   * instead of carrying them (ech_outer_extensions, §5.1): one block, in
   * the outer's order. It is the key_share above all that this saves; with
   * a post-quantum share, a ClientHello carrying it twice would not fit a
   * QUIC Initial packet.
   */
  function ech_split(extensions) {
    let sni = null, marker = null, psk = null, block = [];
    for (let i = 0; i < extensions.length; i++) {
      let e = extensions[i], c = ext_code(e);
      if (c === 0) sni = e;
      else if (c === EXT_ECH) marker = e;
      else if (c === 41) psk = e;
      else block.push(e);
    }
    extensions.length = 0;
    if (sni) extensions.push(sni);
    for (let i = 0; i < block.length; i++) extensions.push(block[i]);
    extensions.push(marker);
    if (psk) extensions.push(psk);
    return {
      compressed: block.map(ext_code),
      outer: [{ type: 'SERVER_NAME', value: context.ech_client.config.public_name }].concat(block),
      sniLength: sni ? Buffer.byteLength(String(context.local_sni)) : null
    };
  }

  /**
   * The inner hello (a handshake message, as the transcript has it) → the
   * outer one that goes on the wire, carrying it encrypted. The first
   * hello sets up the HPKE context; the second (after a HelloRetryRequest)
   * uses it again with an empty enc (§6.1.5).
   */
  function ech_outer_hello(innerMsg, split, second) {
    let prep = context.ech_client, st = context.ech;
    if (!second) { let hs = client_hpke_setup(prep); st.hpke = hs.context; st.enc = hs.enc; }
    let encoded = client_encode_inner(innerMsg, split.compressed, prep.config.maximum_name_length, split.sniLength);
    let extData = client_outer_ext_data(prep.kdf_id, prep.aead_id, prep.config.config_id,
                                        second ? new Uint8Array(0) : st.enc, encoded.length + prep.suite.Nt);
    let outerMsg = build_tls_message({
      type: 'client_hello',
      version: 0x0303,
      random: st.outer_random,
      session_id: context.local_session_id,
      cookie: context.dtls_cookie,
      cipher_suites: grease_cipher_suites(context.local_supported_cipher_suites),
      cipher_suite: context.local_supported_cipher_suites,
      extensions: split.outer.concat([{ type: EXT_ECH, data: extData }], split.outerPsk ? [split.outerPsk] : []),
    });
    return client_seal_outer(outerMsg, st.hpke, encoded);
  }

  /**
   * The server did not take the inner hello (§6.1.6): the handshake goes on
   * as the outer one — its transcript, its random — and the server must
   * prove itself for the public_name, which it then holds keys for. It ends,
   * whatever happens, with ech_required (ech_abort_rejected).
   */
  function ech_rejected() {
    let st = context.ech;
    st.status = 'rejected';
    st.decided = true;
    st.verify_name = context.ech_client.config.public_name;
    context.local_random = st.outer_random;
    context.transcript = [st.outer_ch1];
    context.transcriptHash = null;           // rebuilt from the outer transcript when next asked
    context.transcriptHashName = null;
  }

  /**
   * §7.2, §7.2.1: did the server take the inner hello? Asked of a
   * HelloRetryRequest (its encrypted_client_hello extension) and of the
   * ServerHello (the last 8 bytes of its random), before either joins the
   * transcript. False when the handshake has been aborted.
   */
  function ech_decide(message, data) {
    let st = context.ech;
    let suite = TLS_CIPHER_SUITES[hello_cipher_suite(message)];
    let hashName = suite ? suite.hash : null;
    if (!hashName) return true;                              // the hello's own checks will refuse it
    let ver = Array.isArray(message.supported_versions) ? message.supported_versions[0] : message.supported_versions;
    let prefix = label_prefix_for(ver);
    if (message.random && uint8Equal(message.random, wire.TLS13_HRR_RANDOM)) {
      let off;
      try { off = hrr_ech_offset(data); }
      catch (e) { fatalAlert(e.alertDesc || wire.TLS_ALERT.DECODE_ERROR, e.message); return false; }
      if (off >= 0) {
        let z = new Uint8Array(data); z.fill(0, off, off + 8);
        let mh = wire.build_message(wire.TLS_MESSAGE_TYPE.MESSAGE_HASH, getHashFn(hashName)(concatUint8Arrays(context.transcript)));
        let th = getHashFn(hashName)(concatUint8Arrays([mh, z]));
        if (timingSafeEqualU8(accept_confirmation(hashName, st.inner_random, th, true, prefix), data.subarray(off, off + 8))) {
          st.hrr_accepted = true;
          return true;
        }
      }
      ech_rejected();
      return true;
    }
    let z = new Uint8Array(data); z.fill(0, 4 + 2 + 24, 4 + 2 + 32);
    let th = getHashFn(hashName)(concatUint8Arrays(context.transcript.concat([z])));
    if (timingSafeEqualU8(accept_confirmation(hashName, st.inner_random, th, false, prefix), data.subarray(4 + 2 + 24, 4 + 2 + 32))) {
      st.status = 'accepted';
      st.decided = true;
      return true;
    }
    if (st.hrr_accepted) {
      fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'ECH: accepted in the HelloRetryRequest, not in the ServerHello');
      return false;
    }
    ech_rejected();
    return true;
  }

  /**
   * §6.1.6: ECH was rejected, and the server has proven itself for the
   * public_name (its Certificate, CertificateVerify and Finished checked).
   * The connection is not used: ech_required, and an error carrying the
   * server's new keys — `retryConfigs`, an ECHConfigList to connect again
   * with — or null: the server has turned ECH off (a connection without it
   * is then the caller's decision, not this library's). Keys from a server
   * that was not authenticated (rejectUnauthorized false) are not trusted.
   */
  function ech_abort_rejected() {
    if (context.state === 'error' || context.state === 'closed') return;
    let retry = context.ech.retry_configs && context.peerAuthorized === true ? context.ech.retry_configs : null;
    sendAlert(2, wire.TLS_ALERT.ECH_REQUIRED);
    let err = new Error('ECH rejected by the server (it answered as ' + JSON.stringify(context.ech.verify_name) + ')' +
      (retry ? ': it sent new keys — reconnect with err.retryConfigs' : ': it sent no keys to retry with'));
    err.code = 'ERR_ECH_REJECTED';
    err.retryConfigs = retry ? Buffer.from(retry) : null;
    err.publicName = context.ech.verify_name;
    ev.emit('error', err);
  }

  /**
   * Build and send the second ClientHello after a HelloRetryRequest.
   *
   * ONE emitter for both retry shapes — the server asked for a different group,
   * or it asked only for a cookie. They differ in exactly two values
   * (which group's key share to carry, and whether a cookie is echoed) and in
   * nothing else, so writing them out twice means every future change to CH2
   * has to be made in two places. That is precisely how the "second ClientHello
   * missing extension 35" bug arose: an extension was added to one path and not
   * the other.
   *
   * RFC 8446 §4.1.2 requires CH2 to be identical to CH1 apart from key_share,
   * cookie and pre_shared_key — an invariant that is only cheap to hold when a
   * single function produces it.
   */
  function send_second_client_hello(keyShareGroup, keySharePublic, cookie) {
    let extensions = build_client_hello_extensions({
      keyShareGroup: keyShareGroup,
      keySharePublic: keySharePublic,
      cookie: cookie
    });
    let echSplit = ech_on() && context.ech.outer_ch1 ? ech_split(extensions) : null;

    // The PSK offered in the first hello goes in this one too, its age and
    // binder made again (RFC 8446 §4.1.2) — the binder over message_hash,
    // the HelloRetryRequest and this hello (§4.2.11.2). It was left out:
    // a resumption that met a HelloRetryRequest became a full handshake —
    // the certificate sent and checked — or, against a server that kept the
    // first hello's PSK, a ServerHello selecting an identity this hello
    // never offered. Dropped when the server's suite has another hash
    // (§4.1.4: the PSK cannot serve it), or when ECH was refused (the outer
    // hello carries no ticket). No early data: none after a retry (§4.2.10).
    let pskExt = null, pskHash = null;
    let po = context.psk_offered;
    if (po && po.identity && !(echSplit && context.ech.status === 'rejected')) {
      pskHash = TLS_CIPHER_SUITES[po.cipher] ? TLS_CIPHER_SUITES[po.cipher].hash : 'sha256';
      if (context.hrr_hash && pskHash !== context.hrr_hash) {
        context.psk_offered = null;
      } else {
        let hashLen = getHashFn(pskHash).outputLen;
        let ticketAge = po.lifetime ? Math.min((Date.now() - (po.created || Date.now())) / 1000, po.lifetime) * 1000 : 0;
        pskExt = {
          type: 'PRE_SHARED_KEY',
          value: {
            identities: [{ identity: po.identity, age: ((ticketAge + (po.age_add || 0)) & 0xFFFFFFFF) >>> 0 }],
            binders: [new Uint8Array(hashLen)]
          }
        };
        extensions.push(pskExt);   // last
        if (echSplit) {
          echSplit.outerPsk = {
            type: 'PRE_SHARED_KEY',
            value: {
              identities: [{ identity: new Uint8Array(crypto.randomBytes(po.identity.length)), age: crypto.randomBytes(4).readUInt32BE(0) }],
              binders: [new Uint8Array(crypto.randomBytes(hashLen))]
            }
          };
        }
      }
    } else if (po) {
      context.psk_offered = null;
    }

    let ch2Params = {
      type: 'client_hello',
      version: 0x0303,
      // Each hello repeats its own first random (RFC 8446 §4.1.2) — the
      // inner one's, with ECH.
      random: echSplit ? context.ech.inner_random : context.local_random,
      session_id: context.local_session_id,
      cookie: context.dtls_cookie,
      cipher_suites: grease_cipher_suites(context.local_supported_cipher_suites),
      cipher_suite: context.local_supported_cipher_suites,
      extensions: extensions,
    };
    let ch2 = build_tls_message(ch2Params);
    if (pskExt) {
      let hashLen = getHashFn(pskHash).outputLen;
      let truncated = concatUint8Arrays(context.transcript.concat([ch2.slice(0, ch2.length - (2 + 1 + hashLen))]));
      let binder_key = derive_binder_key(pskHash, context.psk_offered.psk, false, label_prefix());
      pskExt.value.binders = [compute_psk_binder(pskHash, binder_key, truncated, label_prefix())];
      ch2 = build_tls_message(ch2Params);
    }

    // ECH: the outer hello goes; the transcript takes the inner one — or the
    // outer, when the HelloRetryRequest said the server did not decrypt.
    let onWire = ch2;
    if (echSplit) {
      onWire = ech_outer_hello(ch2, echSplit, true);
      if (context.ech.status === 'rejected') ch2 = onWire;
    }
    pushTranscript(ch2);
    ev.emit('message', 0, context.message_sent_seq, 'hello', onWire);
    context.message_sent_seq++;
  }

  /**
   * The signature algorithms the peer asked us to sign a client certificate
   * with, from its CertificateRequest.
   *
   * There is deliberately NO fallback to our own offer list. Both call sites
   * used to do `certificateRequestSigAlgs.length > 0 ? … : local_supported…`,
   * which reads as caution but is not: signing with an algorithm the verifier
   * never requested produces a signature it rejects, and it hid the real bug
   * (the 1.3 list was never extracted from the CertificateRequest extensions,
   * so the fallback fired on every handshake and looked like it worked).
   *
   * An empty list is a genuine protocol error — RFC 8446 §4.3.2 makes
   * signature_algorithms mandatory in a TLS 1.3 CertificateRequest, and the
   * decoder now rejects one without it — so returning empty here lets
   * pick_scheme return null and the caller raise handshake_failure, which is
   * the honest outcome.
   */
  function peer_requested_sig_algs() {
    return context.certificateRequestSigAlgs || [];
  }

  /**
   * Hash of the negotiated cipher suite — the hash the whole TLS 1.3 key
   * schedule, every transcript hash and every Finished MAC are computed with.
   *
   * It was spelled out as negotiated_hash()
   * at nineteen sites. That is a named protocol concept, not an incidental
   * lookup, and writing it out each time means nineteen places to touch if the
   * suite table ever changes shape — and nineteen chances to read the wrong
   * field.
   */
  function negotiated_hash() {
    let meta = TLS_CIPHER_SUITES[context.selected_cipher_suite];
    return meta ? meta.hash : null;
  }

  /**
   * Our certificate's private key as a crypto.KeyObject.
   *
   * The DER/pkcs8 encoding of `cert_private_key` is an internal storage
   * detail; four sites repeated the same three-line construction to undo it.
   * Keeping the shape in one place means a future change to how keys are held
   * (PEM, an external signer, a KeyObject cached up front) is a change here
   * and nowhere else.
   */
  function local_private_key() {
    return private_key_object(context.cert_private_key);
  }
  function private_key_object(der) {
    if (!der) return null;
    // Parsed once per key, not once per handshake: the bytes come from the
    // secure context (or the SNICallback's), the same array for every
    // session that uses it, and a KeyObject is immutable. Parsing the PKCS#8
    // was a few percent of a server's CPU per connection.
    let keyObj = PRIVATE_KEY_OBJECTS.get(der);
    if (!keyObj) {
      keyObj = crypto.createPrivateKey({ key: Buffer.from(der), format: 'der', type: 'pkcs8' });
      PRIVATE_KEY_OBJECTS.set(der, keyObj);
    }
    return keyObj;
  }

  /**
   * HKDF-Expand-Label prefix for THIS session's key schedule.
   *
   * RFC 8446 §7.1 uses "tls13 "; RFC 9147 §5.9 requires "dtls13" (no trailing
   * space) for DTLS 1.3, precisely so that the two protocols cannot derive the
   * same keys from the same secrets. Using the TLS prefix over DTLS produces a
   * handshake where every message parses and every transcript matches, and only
   * the keys differ — which surfaces as "bad record MAC" with no other clue.
   */
  // ── Tickets: what goes in, what is accepted back ────────────────────────
  //
  // The session both issues its tickets and opens them, with one ticketKeys:
  // format and key live in one place. (Opening TLS 1.3 tickets used to live
  // in TLSSocket, so a TLSSession used on its own — QUIC — issued tickets it
  // could not accept, and every returning QUIC client paid a full handshake.)

  // A ticket past its lifetime is not accepted. The time of issue was always
  // written into the ticket and never read, so a ticket stayed valid for as
  // long as its key did — which, with keys kept across restarts, is forever,
  // and a stolen ticket with it. A ticket from before `lifetime` was recorded
  // falls back to the configured one.
  // A ticket is accepted only under the context it was issued for (ticketContext).
  function ticket_context_ok(state) {
    return (state.cx || '') === (context.ticketContext || '');
  }

  function ticket_expired(state) {
    if (typeof state.created !== 'number') return true;
    let lifetime = (typeof state.lifetime === 'number' ? state.lifetime : context.ticketLifetime) * 1000;
    let age = Date.now() - state.created;
    return age < -60000 || age > lifetime;     // a minute of clock skew either way
  }

  // ── 0-RTT, the server's decision ────────────────────────────────────────
  //
  // The ClientHello offered early data with a ticket we accepted. Whether
  // the early data is taken is settled here as far as the hello allows —
  // the ticket allowed it, and it is fresh:
  // the age the client states (obfuscated_ticket_age − ticket_age_add) within
  // earlyDataMaxAge of what our clock says (RFC 8446 §8.3) — then by the
  // replay check, asynchronous: the ServerHello waits for it, as for an
  // asynchronous SNICallback. No answer within 100 ms, or an error: no 0-RTT
  // — the handshake goes on in full, nothing is lost. The rest (the ALPN,
  // the cipher suite and the early-data context are the ticket's) is checked
  // when EncryptedExtensions is built (early_decide).
  function early_consider(pskResult, pskIdentity, hashName) {
    context.early.offered = true;
    let e = pskResult.early;
    if (!context.earlyData || !e || context.helloRetried) return;
    // The context is compared at EncryptedExtensions (early_decide): the
    // application may still set it from the SNICallback, which comes after.
    let clientAge = (((pskIdentity.age >>> 0) - (e.age_add >>> 0)) >>> 0);
    let serverAge = Date.now() - e.created;
    if (!(Math.abs(serverAge - clientAge) <= context.earlyDataMaxAge)) { dbg('SRV-0RTT', 'ticket age off by', serverAge - clientAge, 'ms — no 0-RTT'); return; }
    if (!context.earlyDataReplay && e.created < EARLY_REPLAY_START && Date.now() - EARLY_REPLAY_START < 2 * context.earlyDataMaxAge) {
      dbg('SRV-0RTT', 'ticket from before this process, within the replay window — no 0-RTT');
      return;
    }
    let secret = derive_client_early_traffic_secret(hashName, context.psk_offered.psk, get_transcript_hash(hashName), label_prefix());
    let candidate = { cipher: pskResult.cipher, alpn: e.alpn, secret: secret, context: e.context || '' };
    let id = crypto.createHash('sha256').update(pskIdentity.identity).digest('hex');
    let ttl = 2 * context.earlyDataMaxAge;
    let store = context.earlyDataReplay || defaultEarlyReplay;
    let sync = true, done = false;
    context.early.pending = true;
    let timer = setTimeout(function () { finish(new Error('no answer within ' + EARLY_REPLAY_TIMEOUT_MS + ' ms'), false); }, EARLY_REPLAY_TIMEOUT_MS);
    if (timer.unref) timer.unref();
    function finish(err, fresh) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      context.early.pending = false;
      if (!err && fresh === true) context.early.candidate = candidate;
      else dbg('SRV-0RTT', err ? 'replay check failed: ' + (err.message || err) : 'ticket already used for 0-RTT', '— no 0-RTT');
      if (!sync && context.state !== 'error' && context.state !== 'closed') set_context({ run_loop: true });
    }
    try { store(id, ttl, finish); } catch (err) { finish(err, false); }
    sync = false;
  }

  // At EncryptedExtensions: taken (the secret handed out — 'earlySecret',
  // then 'earlyData' true) or not ('earlyData' false). Once.
  function early_decide() {
    if (!context.isServer || !context.early.offered) return false;
    if (context.early.status !== null) return context.early.status === 'accepted';
    let c = context.early.candidate;
    // The context again: it may have changed since the hello was read (QUIC
    // decides a connection's transport parameters in the SNICallback, after
    // the PSK was looked at — setEarlyDataContext).
    if (c && !context.helloRetried && c.cipher === context.selected_cipher_suite &&
        (c.alpn || null) === (context.selected_alpn || null) &&
        c.context === (context.earlyDataContext || '')) {
      context.early.status = 'accepted';
      _emitKeylogSingle('CLIENT_EARLY_TRAFFIC_SECRET', c.secret);
      ev.emit('earlySecret', c.secret);
      ev.emit('earlyData', true);
      return true;
    }
    context.early.status = 'rejected';
    ev.emit('earlyData', false);
    return false;
  }

  function _emitKeylogSingle(label, secret) {
    if (ev.listenerCount('keylog') === 0 || !secret) return;
    let clientRandom = context.isServer ? context.remote_random : context.local_random;
    if (!clientRandom) return;
    ev.emit('keylog', Buffer.from(label + ' ' + Buffer.from(clientRandom).toString('hex') + ' ' + Buffer.from(secret).toString('hex') + '\n'));
  }

  // The client's: rejected (a HelloRetryRequest, or no early_data in
  // EncryptedExtensions) or accepted — told once ('earlyData').
  function early_client_result(accepted) {
    if (context.isServer || !context.early.offered || context.early.status !== null) return;
    context.early.status = accepted ? 'accepted' : 'rejected';
    ev.emit('earlyData', accepted);
  }

  // The default answer to a TLS 1.3 PSK identity: one of our own tickets.
  function open_ticket_13(identity) {
    if (!context.sessionTickets || !context.ticketKeys) return null;
    let state = decrypt_session_blob(identity, context.ticketKeys);
    if (!state || state.v !== 13 || !state.psk || !state.cipher) return null;
    if (ticket_expired(state)) {
      dbg('SRV-PSK', 'ticket expired — full handshake');
      return null;
    }
    if (!ticket_context_ok(state)) {
      dbg('SRV-PSK', 'ticket issued under another context — full handshake');
      return null;
    }
    if (!ticket_peer_acceptable(state)) {
      dbg('SRV-PSK', 'ticket without an authorized client certificate, one is required — full handshake');
      return null;
    }
    return { psk: state.psk, cipher: state.cipher, data: state.app != null ? state.app : null, sni: state.sni != null ? state.sni : null,
             state: state.st != null ? state.st : null, peer: state,
             early: state.ed === 1 ? { context: state.edc || '', alpn: state.alpn || null, created: state.created, age_add: state.age_add >>> 0 } : null };
  }

  // A session is resumed only under the name it was established for. RFC 6066
  // §3: a server "MUST NOT accept the request to resume the session if the
  // server_name extension contains a different name. Instead, it proceeds
  // with a full handshake". The ticket kept the name and nothing read it: a
  // ticket from one site resumed on another, skipping that site's
  // certificate — and its client-certificate check, which a resumed
  // handshake does not repeat (nginx's CVE-2025-23419 is this). Compared as
  // DNS names are: case-insensitively, a trailing dot ignored; no name on
  // both sides (a connection to an address) is the same name. A ticket that
  // does not say (an application's own 'psk' answer without one) is not held
  // to it.
  function same_server_name(ticketSni, helloSni) {
    if (ticketSni === undefined) return true;
    let norm = function (n) { return n == null || n === '' ? '' : String(n).toLowerCase().replace(/\.$/, ''); };
    return norm(ticketSni) === norm(helloSni);
  }

  // ── The client's certificate, kept with the session ──────────────────────
  //
  // A resumed handshake has no Certificate and no CertificateRequest
  // (RFC 8446 §4.6.1 / §4.3.2: not with a PSK), so whatever the client proved
  // on its full handshake has to come back from the ticket — as OpenSSL keeps
  // the peer certificate and its verify result in the SSL_SESSION. Nothing
  // was kept: every resumed connection reported `authorized: false` and no
  // peer certificate, so an mTLS server turned away its own returning
  // clients; and the client-certificate requirement is checked on full
  // handshakes only, so a ticket issued when none was required (before the
  // server turned requestCert on, or one with rejectUnauthorized: false)
  // resumed into a server that now requires one, with no certificate at all.
  //
  // So the ticket carries the leaf certificate, whether it was authorized and
  // why not; a server that requires an authorized client (requestCert +
  // rejectUnauthorized) accepts only a ticket that says so — anything else is
  // a full handshake, where the certificate is asked for again.
  function ticket_peer_fields() {
    if (!context.isServer) return {};
    // This handshake's certificate, or — resumed — the one the ticket
    // carried in: a ticket issued on a resumed connection carries it on.
    let chain = (context.remote_cert_chain && context.remote_cert_chain.length > 0) ? context.remote_cert_chain : context.resumed_peer_chain;
    let leaf = chain && chain.length > 0 && chain[0] ? chain[0].cert : null;
    return {
      pc: leaf || null,
      pa: !!(leaf && context.peerAuthorized),
      pe: leaf ? (context.authorizationError || null) : 'NO_PEER_CERTIFICATE',
    };
  }
  function ticket_peer_acceptable(state) {
    if (!(context.requestCert && context.rejectUnauthorized)) return true;
    return !!(state && state.pa === true && state.pc);
  }
  // Kept apart from remote_cert_chain, which means "a Certificate arrived in
  // THIS handshake" — and so has to be proved by a CertificateVerify in it.
  // getPeerCertificate() answers with either.
  function restore_ticket_peer(state) {
    if (!state || !state.pc) return;
    context.resumed_peer_chain = [{ cert: state.pc }];
    context.peerAuthorized = state.pa === true;
    context.authorizationError = state.pa === true ? null : (state.pe || 'UNABLE_TO_VERIFY_LEAF_SIGNATURE');
  }

  // Our Certificate message — compressed (RFC 8879) when the peer offered an
  // algorithm we have, by our preference, in TLS 1.3. The compressed form
  // is cached per chain and algorithm (cert_compression.js).
  // ---- OCSP stapling (server) ----

  /** The client asked for an OCSP response (status_request, type ocsp). */
  function client_requested_ocsp() {
    let ex = context.remote_extensions || [];
    for (let i = 0; i < ex.length; i++) {
      if (ex[i] && ex[i].type === wire.TLS_EXT.STATUS_REQUEST && ex[i].data && ex[i].data.length > 0 && ex[i].data[0] === 1) return true;
    }
    return false;
  }

  /**
   * Ask the application for the OCSP response — once, when a client asked
   * for it, our certificate is settled (after the SNI lookup) and it will be
   * sent (not a resumption). As node:tls's 'OCSPRequest': (certificate,
   * issuer, callback), DER both, issuer null when the chain has none. The
   * ServerHello waits for the answer, as it waits for SNICallback: in TLS
   * 1.2 it must say whether a CertificateStatus follows.
   */
  function maybe_request_ocsp(version) {
    if (!context.isServer || context.ocsp_requested || !context.ocspRequest) return;
    if (context.sni_pending || context.local_cert_chain === null || context.local_cert_chain.length === 0) return;
    if (context.psk_accepted || context.tls12_abbreviated || context.tls12_resume_pending) return;
    // A TLS 1.2 resumption (ticket or session ID) sends no Certificate. Its
    // decision is taken in this same pass and committed only at its end, so
    // tls12_abbreviated is not yet set here: the loaded state says it. It is
    // dropped (null) when the resumption is refused, and the next pass asks.
    // `version` is the one being chosen now — a 1.3 handshake whose client
    // also carried a 1.2 ticket is a full one.
    let is12Now = version === wire.TLS_VERSION.TLS1_2 || version === wire.DTLS_VERSION.DTLS1_2;
    if (is12Now && context.tls12_resume_state) return;
    if (!client_requested_ocsp()) return;
    context.ocsp_requested = true;
    context.ocsp_pending = true;
    let done = false, sync = true;
    let chain = context.local_cert_chain;
    let issuer = chain.length > 1 && chain[1] && chain[1].cert ? chain[1].cert : null;
    try {
      context.ocspRequest(chain[0].cert, issuer, function (err, response) {
        if (done) return;
        done = true;
        context.ocsp_pending = false;
        if (err) {
          fatalAlert(wire.TLS_ALERT.INTERNAL_ERROR, 'OCSPRequest: ' + (err.message || err));
          return;
        }
        if (response && response.length > 0) context.ocsp_response = new Uint8Array(response);
        // Answered later: the pass that would have sent the ServerHello has
        // already stopped at the gate, so run the loop again.
        if (!sync) set_context({ run_loop: true });
      });
    } catch (e) {
      done = true;
      context.ocsp_pending = false;
      fatalAlert(wire.TLS_ALERT.INTERNAL_ERROR, 'OCSPRequest: ' + (e.message || e));
    }
    sync = false;
  }

  function certificate_message(entries, requestContext) {
    let plain = build_tls_message({
      type: 'certificate',
      version: context.selected_version || wire.TLS_VERSION.TLS1_3,
      entries: entries,
      certificate_request_context: requestContext,
    });
    let peer = context.peer_cert_compression;
    if (!is13() || !Array.isArray(peer) || entries.length === 0) return plain;
    let alg = null;
    for (let i = 0; i < context.cert_compression.length && alg === null; i++) {
      if (peer.indexOf(context.cert_compression[i]) >= 0) alg = context.cert_compression[i];
    }
    if (alg === null) return plain;
    let body = plain.subarray(4);     // the handshake header off
    let compressed = compress_certificate_body(body, alg);
    if (!compressed || compressed.length >= body.length) return plain;
    context.cert_compression_sent = alg;
    return build_tls_message({ type: 'compressed_certificate', algorithm: alg, uncompressed_length: body.length, compressed: compressed });
  }

  // The client's side of the same. A resumed handshake has no Certificate:
  // the server is who it was when the session was saved, and nothing else
  // says who that was. The session ('session' event) left the certificate
  // out, so a resumed connection answered getPeerCertificate() with nothing
  // and `authorized` false — node:tls answers both from the session — and a
  // session saved with rejectUnauthorized: false (an unverified server, a
  // self-signed one) resumed into a connection that requires verification,
  // with nothing verified: the PSK proves the server is the one that issued
  // the ticket, not that it is the one the caller trusts.
  //
  // So the session carries the server's chain and the verdict on it; a
  // connection that requires an authorized server offers only a session that
  // says so.
  function client_session_peer_fields() {
    let chain = (context.remote_cert_chain && context.remote_cert_chain.length > 0) ? context.remote_cert_chain : context.resumed_peer_chain;
    let certs = chain ? chain.map(function (e) { return e.cert; }).filter(function (c) { return !!c; }) : [];
    return {
      peer_chain: certs.length > 0 ? certs : null,
      peer_authorized: certs.length > 0 && context.peerAuthorized === true,
      peer_error: certs.length > 0 ? (context.authorizationError || null) : 'NO_PEER_CERTIFICATE',
    };
  }
  function restore_client_session_peer(sessionData) {
    if (!sessionData) return;     // an external PSK: no saved server
    let certs = sessionData && Array.isArray(sessionData.peer_chain) ? sessionData.peer_chain : null;
    context.resumed_peer_chain = certs ? certs.map(function (c) { return { cert: c }; }) : null;
    context.peerAuthorized = !!certs && sessionData.peer_authorized === true;
    context.authorizationError = context.peerAuthorized ? null : (sessionData.peer_error || 'UNABLE_TO_VERIFY_LEAF_SIGNATURE');
  }
  // Whether a saved session may be offered on this connection. Not one for
  // another server name (RFC 8446 §4.6.1: resume only with the SNI it was
  // made with), not one past its lifetime (§4.6.1: not cached longer than
  // ticket_lifetime — the server refuses it anyway, after a wasted binder),
  // and not one whose server was not verified when verification is required.
  function client_session_usable(sessionData) {
    if (!sessionData) return false;
    let sni = sessionData.sni != null ? String(sessionData.sni).toLowerCase() : null;
    let want = context.local_sni != null ? String(context.local_sni).toLowerCase() : null;
    if (sni !== want) { dbg('CLI-PSK', 'saved session is for another server name — not offered'); return false; }
    if (typeof sessionData.lifetime === 'number' && typeof sessionData.created === 'number' &&
        Date.now() > sessionData.created + sessionData.lifetime * 1000) {
      dbg('CLI-PSK', 'saved session expired — not offered'); return false;
    }
    if (context.rejectUnauthorized && sessionData.peer_authorized !== true) {
      dbg('CLI-PSK', 'saved session has no verified server — not offered'); return false;
    }
    return true;
  }

  // A TLS 1.3 NewSessionTicket, sent now: the one every full handshake ends
  // with, and any issued later (sendTicket) — each with its own nonce, so its
  // own PSK (RFC 8446 §4.6.1), carrying the application's ticketData and the
  // protocol layer's ticket state as they are at the time.
  function issue_ticket_13() {
    let hashName = negotiated_hash();
    let ticket_nonce = new Uint8Array([context.ticket_nonce_counter++]);
    let psk = derive_psk(hashName, context.resumption_master_secret, ticket_nonce, label_prefix());
    let ticket_age_add = crypto.randomBytes(4).readUInt32BE(0);
    let ticket_lifetime = context.ticketLifetime;

    dbg('SRV-NST', 'issuing TLS 1.3 NST — cipher:', '0x' + context.selected_cipher_suite.toString(16),
        'hash:', hashName,
        'transcript len:', concatUint8Arrays(context.transcript).length);
    if (LEMON_DEBUG) dbg('SRV-NST', 'ticket_nonce:', hexPreview(ticket_nonce, 4),
        'age_add:', ticket_age_add,
        'lifetime:', ticket_lifetime);
    if (LEMON_DEBUG) dbg('SRV-NST', 'resumption_master_secret:', hexPreview(context.resumption_master_secret, 8),
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
      lifetime: ticket_lifetime,
      app: ticket_app_data(),
      st: context.ticket_state != null ? context.ticket_state : undefined,
      cx: context.ticketContext || undefined,
      // 0-RTT allowed with it, and under what (open_ticket_13, early_eligible).
      ed: context.earlyData ? 1 : undefined,
      edc: context.earlyData ? context.earlyDataContext : undefined,
      ...ticket_peer_fields(),
    }, context.ticketKeys);

    // early_data in the ticket (RFC 8446 §4.2.10): max_early_data_size.
    let nstExts = [];
    if (context.earlyData) {
      let m = context.maxEarlyData >>> 0;
      nstExts.push({ type: wire.TLS_EXT.EARLY_DATA, data: new Uint8Array([m >>> 24 & 255, m >>> 16 & 255, m >>> 8 & 255, m & 255]) });
    }

    let nst_data = wire.build_message(wire.TLS_MESSAGE_TYPE.NEW_SESSION_TICKET,
      wire.build_new_session_ticket({
        ticket_lifetime: ticket_lifetime,
        ticket_age_add: ticket_age_add,
        ticket_nonce: ticket_nonce,
        ticket: ticket,
        extensions: nstExts
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

  // What the application wants in the ticket being issued (ticketData).
  // Never allowed to break a handshake: a throw, something that does not
  // serialize, or anything too big means a ticket without application data.
  // Too big because a ticket travels in every ClientHello that presents it —
  // over QUIC that ClientHello should fit the first packet.
  const TICKET_DATA_MAX = 256;   // bytes, serialized
  const TICKET_STATE_MAX = 128;  // setTicketState's, apart from it
  //
  // Asked once per connection, and the answer kept: the ticket issued and
  // getTicketInfo() — asked by the application for this very connection —
  // must carry the same value. Asked twice, ticketData minting a new id on a
  // full handshake would give the connection one id and its ticket another,
  // and the first connection would never be tied to the ones resuming it.
  function ticket_app_data() {
    if (context.app_ticket_data !== undefined) return context.app_ticket_data;
    context.app_ticket_data = ticket_app_data_ask();
    return context.app_ticket_data;
  }
  function ticket_app_data_ask() {
    if (!context.ticketData) return null;
    let data;
    try { data = context.ticketData(context.isResumed ? context.resumed_ticket_data : null); }
    catch (e) { dbg('SRV-NST', 'ticketData threw:', e && e.message); return null; }
    if (data == null) return null;
    let size;
    try { size = Buffer.byteLength(JSON.stringify(data)); } catch (e) { return null; }
    if (!(size <= TICKET_DATA_MAX)) {
      dbg('SRV-NST', 'ticketData is ' + size + ' bytes, over ' + TICKET_DATA_MAX + ' — left out');
      return null;
    }
    return data;
  }

  function label_prefix() {
    return label_prefix_for(context.selected_version);
  }

  // For a version chosen in this pass but not yet committed to context
  // (the HelloRetryRequest is built before the pass commits).
  function label_prefix_for(version) {
    return version === wire.DTLS_VERSION.DTLS1_3 ? LABEL_PREFIX_DTLS13 : LABEL_PREFIX_TLS13;
  }

  /**
   * DTLS-SRTP profile negotiation (RFC 5764 §4.1).
   *
   * The library previously decoded the client's use_srtp extension and handed
   * it to the caller, but selected nothing and answered nothing — so every
   * consumer had to re-implement the negotiation, and a peer that expects the
   * stack to answer (as BoringSSL's SSL_CTX_set_tlsext_use_srtp does) got no
   * use_srtp back at all.
   *
   * Selection is by SERVER preference over the mutually supported set, matching
   * how the cipher suite and group are chosen. The answer carries exactly one
   * profile and an empty MKI: RFC 5764 §4.1.1 says the server "MUST include
   * exactly one" protection profile, and §4.1.2 that an MKI it does not
   * understand is ignored rather than fatal.
   *
   * Returns the chosen profile, or null when there is no overlap — in which
   * case NO use_srtp extension is sent, which is how RFC 5764 §4.1.2 says a
   * server declines ("if no acceptable profile is found, the server SHOULD NOT
   * include the extension").
   */
  function negotiate_srtp_profile() {
    if (!context.isServer) return null;
    if (!Array.isArray(context.srtp_profiles) || context.srtp_profiles.length === 0) return null;

    let offered = null;
    for (let i = 0; i < context.remote_extensions.length; i++) {
      let e = context.remote_extensions[i];
      if (e && e.type === wire.TLS_EXT.USE_SRTP) { offered = e.value; break; }
    }
    if (!offered || !Array.isArray(offered.profiles) || offered.profiles.length === 0) return null;

    for (let i = 0; i < context.srtp_profiles.length; i++) {
      let p = context.srtp_profiles[i] | 0;
      if (offered.profiles.indexOf(p) >= 0) return p;
    }
    return null;
  }

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

  /**
   * Abort the handshake with a fatal alert.
   * Single funnel for every protocol-violation path: sends the alert (which
   * also flips context.state to 'error', making the session inert — the
   * reactive loop and process_income_message both early-return on terminal
   * states, so a poisoned context can never keep producing messages), then
   * surfaces the reason to the owner via 'error'.
   */
  function fatalAlert(description, msg) {
    if (context.state === 'error' || context.state === 'closed') return;
    sendAlert(2, description); // sets context.state = 'error'
    ev.emit('error', new Error(msg));
  }

  function process_income_message(data){

    // Terminal states: a fatal alert (ours or a parse failure) already ended
    // this session. Feeding more data must not resurrect the state machine.
    if (context.state === 'error' || context.state === 'closed') return;

    // Track handshake start time
    if (context.handshakeStartTime === null) context.handshakeStartTime = Date.now();

    // Track handshake size and enforce limit
    context.handshakeBytes += data.length;
    if (context.maxHandshakeSize > 0 && context.handshakeBytes > context.maxHandshakeSize) {
      // Must go through the same funnel as every other abort: previously this
      // emitted 'error' but sent no alert and left the session in a live state,
      // so the reactive loop could keep processing the very flood the limit
      // exists to stop, and the peer was never told why we went quiet.
      fatalAlert(wire.TLS_ALERT.INTERNAL_ERROR,
        'Handshake size exceeded maxHandshakeSize (' + context.maxHandshakeSize + ')');
      return;
    }

    // The ONE place peer bytes become structured messages. wire.js throws
    // parse errors carrying .alertDesc (decode_error / illegal_parameter);
    // convert them to a fatal alert instead of letting them crash the
    // transport's data handler (remote DoS) or be silently swallowed.
    let message;
    try {
      message = parse_tls_message(data, context.selected_version, { dtls: dtls_transport() });
    } catch (e) {
      fatalAlert(e.alertDesc || wire.TLS_ALERT.DECODE_ERROR, 'Malformed handshake message: ' + e.message);
      return;
    }

    // Direction enforcement (RFC 8446 §5.1 / unexpected_message): each
    // handshake type is legal from exactly one peer role. Without this, a
    // client-sent EncryptedExtensions (etc.) walks straight into server
    // state it was never meant to touch.
    {
      let t = message.type;
      let serverOnly = t === 'server_hello' || t === 'encrypted_extensions' ||
                       t === 'server_hello_done' || t === 'certificate_request' ||
                       t === 'server_key_exchange' || t === 'new_session_ticket' ||
                       t === 'certificate_status';
      let clientOnly = t === 'client_hello' || t === 'client_key_exchange' || t === 'end_of_early_data';
      if ((context.isServer && serverOnly) || (!context.isServer && clientOnly)) {
        fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'Unexpected ' + t + ' from ' + (context.isServer ? 'client' : 'server'));
        return;
      }
    }

    // A server takes one ClientHello, and a second only in answer to its
    // HelloRetryRequest (RFC 8446 §4.1.2, §4.1.4). There is no
    // renegotiation here, so any other — after the ServerHello, a second
    // with no retry asked, a third — is unexpected_message. Before, it was
    // run through the handshake again: the SNI callback fired anew, and
    // with ECH the decrypted state of this connection was overwritten.
    // Renegotiation (TLS 1.2) is not done here: a ClientHello once the
    // handshake is over (server), a HelloRequest (client) are answered with
    // a no_renegotiation warning and otherwise left alone (RFC 5246 §7.2.2,
    // RFC 5746 §4.2, §4.4) — the peer decides whether to go on. A peer that
    // keeps asking is cut off.
    if (context.state === 'connected' && is12() &&
        ((context.isServer && message.type === 'client_hello') ||
         (!context.isServer && message.type === 'unknown_handshake' && message.handshake_type === 0))) {
      if (++context.renegotiation_refusals > 3) {
        fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'Renegotiation asked for again after no_renegotiation');
        return;
      }
      sendAlert(wire.TLS_ALERT_LEVEL.WARNING, wire.TLS_ALERT.NO_RENEGOTIATION);
      return;
    }

    // renegotiation_info in a first ClientHello (RFC 5746 §3.6): empty, or
    // "MUST abort the handshake" — handshake_failure. Whether the client
    // speaks it (the extension or TLS_EMPTY_RENEGOTIATION_INFO_SCSV, 0x00ff)
    // decides whether ours goes in the ServerHello.
    if (context.isServer && message.type === 'client_hello' && context.client_hellos_received === 0) {
      let ri = message.renegotiation_info;
      if (ri && ri.length > 0) {
        fatalAlert(wire.TLS_ALERT.HANDSHAKE_FAILURE, 'renegotiation_info not empty in an initial ClientHello');
        return;
      }
      context.client_secure_renegotiation = (ri !== undefined && ri !== null) ||
        (Array.isArray(message.cipher_suites) && message.cipher_suites.indexOf(0x00ff) >= 0);
    }

    if (context.isServer && message.type === 'client_hello') {
      let n = context.client_hellos_received;
      if (!(n === 0 || (n === 1 && context.helloRetried === true && context.hello_sent === false))) {
        fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'Unexpected ClientHello (' + (n + 1) + ')');
        return;
      }
      context.client_hellos_received = n + 1;
    }

    // Encrypted Client Hello (RFC 9849 §7.1): the hello that arrived may
    // carry the real one encrypted. Decrypted, it takes the place of the
    // outer hello from here on — transcript, SNI, ALPN, key share, every
    // check below — exactly as if it had come in the clear; the outer one
    // is kept only as the wire's fingerprint. Not decryptable, the outer
    // hello goes on as it came, and EncryptedExtensions will carry
    // retry_configs.
    if (context.isServer && message.type === 'client_hello' && context.ech_server) {
      if (context.rawClientHello === null) context.rawClientHello = data;
      let echResult;
      try {
        echResult = server_process_client_hello(context.ech_server, context.ech, data, context.helloRetried === true);
      } catch (e) {
        fatalAlert(e.alertDesc || wire.TLS_ALERT.ILLEGAL_PARAMETER, e.message);
        return;
      }
      if (echResult) {
        try {
          message = parse_tls_message(echResult.data, context.selected_version, { dtls: dtls_transport() });
        } catch (e) {
          fatalAlert(e.alertDesc || wire.TLS_ALERT.DECODE_ERROR, 'Malformed ClientHelloInner: ' + e.message);
          return;
        }
        data = echResult.data;
      }
    }

    // Emit 'handshakeMessage' hook for every message
    ev.emit('handshakeMessage', message.type, data, message);

    // What the peer can decompress (RFC 8879): from its ClientHello, or —
    // for our client certificate — its CertificateRequest.
    if (context.isServer && message.type === 'client_hello') {
      if ('early_data' in message) context.early.clientOffered = true;
      context.peer_cert_compression = Array.isArray(message.compress_certificate) ? message.compress_certificate : null;
    } else if (!context.isServer && message.type === 'certificate_request' && Array.isArray(message.extensions)) {
      for (let ei = 0; ei < message.extensions.length; ei++) {
        let ce = message.extensions[ei];
        if (ce && (ce.type === wire.TLS_EXT.COMPRESS_CERTIFICATE || ce.name === 'COMPRESS_CERTIFICATE') && Array.isArray(ce.value)) context.peer_cert_compression = ce.value;
      }
    }

    // A CompressedCertificate (RFC 8879 §4) is read as the Certificate it
    // holds; the transcript keeps the message as it came (`data`). Only in
    // TLS 1.3, only with an algorithm this side offered (illegal_parameter),
    // and only if it decompresses to exactly the length it declares
    // (bad_certificate) — never past the handshake size limit.
    if (message.type === 'compressed_certificate') {
      if (!is13() || context.cert_compression.indexOf(message.algorithm) < 0) {
        fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'CompressedCertificate with an algorithm not offered (' + message.algorithm + ')');
        return;
      }
      // Never past HANDSHAKE_MESSAGE_MAX (wire.js): the declared length was
      // the 24-bit field's 16 MB, and a few hundred compressed bytes could
      // be inflated to it — in memory and time, before anything was verified.
      let limit = context.maxHandshakeSize > 0 ? Math.min(context.maxHandshakeSize, wire.HANDSHAKE_MESSAGE_MAX) : wire.HANDSHAKE_MESSAGE_MAX;
      let body = decompress_certificate_body(message.algorithm, message.compressed, message.uncompressed_length, limit);
      if (!body) {
        fatalAlert(wire.TLS_ALERT.BAD_CERTIFICATE, 'CompressedCertificate does not decompress to its declared length');
        return;
      }
      let algorithm = message.algorithm;
      try { message = wire.parse_certificate(body); }
      catch (e) { fatalAlert(wire.TLS_ALERT.BAD_CERTIFICATE, 'CompressedCertificate: ' + e.message); return; }
      message.type = 'certificate';
      message.compressed = true;
      context.cert_compression_received = algorithm;
    }

    if((context.isServer==false && message.type=='server_hello') || (context.isServer==true && message.type=='client_hello')){

      // Server-side ClientHello policy checks — BEFORE the transcript push,
      // the 'clienthello' emit and set_context's reactive loop, because the
      // loop may synchronously build and send a ServerHello for a hello we
      // are about to reject.
      if (context.isServer && message.type === 'client_hello') {
        let comp = message.legacy_compression || [];

        // RFC 5246 §7.4.1.2: null compression MUST be present in every CH.
        if (comp.indexOf(0) < 0) {
          fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'ClientHello without null compression');
          return;
        }

        // RFC 8446 §4.1.2: a CH offering TLS 1.3 must carry exactly one
        // compression method: null. Enforced when 1.3 is on the table for
        // this negotiation (client offers it and we support it — an empty
        // local list means "not configured yet", which defaults to 1.3+1.2).
        let sv = message.supported_versions || [];
        let offers13 = sv.indexOf(wire.TLS_VERSION.TLS1_3) >= 0 || sv.indexOf(wire.DTLS_VERSION.DTLS1_3) >= 0;
        let lv = context.local_supported_versions || [];
        let we13 = lv.length === 0 || lv.indexOf(wire.TLS_VERSION.TLS1_3) >= 0 || lv.indexOf(wire.DTLS_VERSION.DTLS1_3) >= 0;
        if (offers13 && we13 && comp.length !== 1) {
          fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'TLS 1.3 ClientHello must offer exactly the null compression method');
          return;
        }

        // RFC 8446 §4.2.11: one binder per identity, and never zero of either.
        if (message.pre_shared_key && Array.isArray(message.pre_shared_key.identities)) {
          let nIds = message.pre_shared_key.identities.length;
          let nBinders = Array.isArray(message.pre_shared_key.binders) ? message.pre_shared_key.binders.length : 0;
          if (nIds === 0 || nBinders !== nIds) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'pre_shared_key identities/binders count mismatch (' + nIds + '/' + nBinders + ')');
            return;
          }
          // ...and the last extension, its binders list the hello's last bytes
          // (§4.2.11: "MUST be the last extension", or illegal_parameter): the
          // binders are computed over the hello up to them.
          let chExts = Array.isArray(message.extensions) ? message.extensions : [];
          let lastExt = chExts[chExts.length - 1];
          let bindersLen = 0;
          for (let bi = 0; bi < nBinders; bi++) bindersLen += 1 + message.pre_shared_key.binders[bi].length;
          let ld = lastExt && lastExt.data;
          if (!lastExt || lastExt.type !== 41 || !ld || ld.length < 2 + bindersLen ||
              ((ld[ld.length - 2 - bindersLen] << 8) | ld[ld.length - 1 - bindersLen]) !== bindersLen) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'pre_shared_key not the last extension, or its binders not the last bytes');
            return;
          }
        }
      }

      // ECH (RFC 9849 §6.1.4): which hello the server answered — before this
      // message joins the transcript, which it decides.
      if (!context.isServer && message.type === 'server_hello' && context.ech.outer_ch1 && !context.ech.decided) {
        if (!ech_decide(message, data)) return;
      }

      pushTranscript(data);

      // Record the peer's hello for fingerprinting, whichever side we are.
      // A client sees the ServerHello here; a server sees the ClientHello.
      if (message.type === 'client_hello') {
        if (context.rawClientHello === null) context.rawClientHello = data;
      } else if (message.type === 'server_hello') {
        context.rawServerHello = data;
        context.parsedServerHello = null;   // HRR then real SH: re-parse
        context.fpCache.ja4s = undefined;
      }

      // Save raw ClientHello + emit event (server side)
      if (context.isServer && message.type === 'client_hello') {
        // Make the peer's extensions readable INSIDE the 'clienthello'
        // handler (getRemoteExtension/getRemoteExtensions) — the main
        // set_context that stores them runs after this emit, and the
        // whole point of the event is to let callers inspect the offer
        // and set answering local_extensions before the ServerHello is
        // built (e.g. DTLS-SRTP use_srtp, RFC 5764 §4.1.2). The later
        // set_context stores the identical array; its equality check
        // makes that a no-op.
        context.remote_extensions = message.extensions || [];
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
      //
      // RFC 8446 §4.2.9: a client offering pre_shared_key without
      // psk_key_exchange_modes is to be refused outright; and a PSK may only be
      // used in a mode the client listed. This server resumes in one mode only,
      // psk_dhe_ke (the key schedule always mixes in a fresh ECDHE secret, so
      // resumption keeps forward secrecy) — a client that did not offer it is
      // given a full handshake instead.
      if (context.isServer && message.pre_shared_key && !Array.isArray(message.psk_modes)) {
        fatalAlert(wire.TLS_ALERT.MISSING_EXTENSION, 'pre_shared_key without psk_key_exchange_modes');
        return;
      }
      let pskDheOffered = Array.isArray(message.psk_modes) && message.psk_modes.indexOf(1) >= 0;
      if (context.isServer && pskDheOffered && message.pre_shared_key && message.pre_shared_key.identities && message.pre_shared_key.identities.length > 0) {
        let pskIdentity = message.pre_shared_key.identities[0];
        context.ticket_offered = true;
        let pskBinder = message.pre_shared_key.binders ? message.pre_shared_key.binders[0] : null;

        if (LEMON_DEBUG) dbg('SRV-PSK', 'received identity:', hexPreview(pskIdentity.identity, 24),
            'age:', (pskIdentity.age || 0) >>> 0,
            'received binder:', hexPreview(pskBinder, 16));

        // A 'psk' listener decides, when there is one and it answers. When
        // nobody answers, this session opens the ticket itself — it issued it,
        // with its own ticketKeys (see open_ticket_13). That default used to
        // live in TLSSocket, so a TLSSession used on its own (QUIC) issued
        // tickets it could never accept.
        let pskResult;
        ev.emit('psk', {
          identity: pskIdentity.identity,
          obfuscatedAge: (pskIdentity.age || 0) >>> 0
        }, function(result) {
          pskResult = result;
        });
        if (pskResult === undefined) pskResult = open_ticket_13(pskIdentity.identity);

        if (LEMON_DEBUG) dbg('SRV-PSK', 'pskResult:', pskResult ? `psk=${hexPreview(pskResult.psk, 8)} cipher=0x${pskResult.cipher?.toString(16)}` : 'null (decrypt failed)');

        if (pskResult && pskResult.psk && !same_server_name(pskResult.sni, message.sni)) {
          dbg('SRV-PSK', 'ticket for another server name — full handshake');
          pskResult = null;
        }
        if (pskResult && pskResult.psk) {
          let pskCipher = pskResult.cipher || 0x1301;
          let hashName = TLS_CIPHER_SUITES[pskCipher] ? TLS_CIPHER_SUITES[pskCipher].hash : 'sha256';
          let binder_key = derive_binder_key(hashName, pskResult.psk, false, label_prefix());

          let hashLen = getHashFn(hashName).outputLen;
          // The binders list, as it is on the wire, ends the hello (§4.2.11:
          // pre_shared_key is last): its 2-byte length, then each binder with
          // its 1-byte length. Taken as one binder of hashLen, as it was, a
          // client offering two tickets (h3spec does; a client that keeps
          // every ticket it is given does) never matched: always a full
          // handshake, never 0-RTT.
          let bindersSize = 2;
          for (let bi = 0; bi < message.pre_shared_key.binders.length; bi++) bindersSize += 1 + message.pre_shared_key.binders[bi].length;
          // After a HelloRetryRequest the binder covers message_hash and the
          // retry too (§4.2.11.2): what the transcript holds before this hello.
          let truncatedCH = data.slice(0, data.length - bindersSize);
          if (context.helloRetried && context.transcript.length > 1) {
            truncatedCH = concatUint8Arrays(context.transcript.slice(0, -1).concat([truncatedCH]));
          }
          let expectedBinder = compute_psk_binder(hashName, binder_key, truncatedCH, label_prefix());

          dbg('SRV-PSK', 'hash:', hashName, 'hashLen:', hashLen,
              'truncatedCH len:', truncatedCH.length,
              'full CH len:', data.length);
          if (LEMON_DEBUG) dbg('SRV-PSK', 'expected binder:', hexPreview(expectedBinder, 16));
          if (LEMON_DEBUG) dbg('SRV-PSK', 'received binder:', hexPreview(pskBinder, 16));

          // Constant-time binder comparison. A byte-by-byte early-exit compare
          // would let an attacker recover a valid binder via timing, one byte at
          // a time. timingSafeEqualU8 always compares the full length.
          let binderOk = timingSafeEqualU8(expectedBinder, pskBinder);

          dbg('SRV-PSK', binderOk ? '✓ BINDER MATCH — psk_accepted' : '✗ BINDER MISMATCH — decrypt_error');

          // A ticket of ours, opened, whose binder does not verify: the
          // handshake ends (RFC 8446 §4.2.11: "MUST abort", decrypt_error) —
          // the hello was changed on the way, or the client does not hold the
          // PSK. It went on as a full handshake, which hid exactly the bug that
          // made every two-ticket hello miss. A ticket that cannot be opened
          // (expired, another key, another server) is still just not used.
          if (!binderOk) {
            fatalAlert(wire.TLS_ALERT.DECRYPT_ERROR, 'PSK binder does not verify');
            return;
          }

          if (binderOk) {
            context.psk_accepted = true;
            context.isResumed = true;
            context.resumed_ticket_data = pskResult.data != null ? pskResult.data : null;
            context.resumed_ticket_state = pskResult.state != null ? pskResult.state : null;
            if (pskResult.peer) restore_ticket_peer(pskResult.peer);
            context.psk_offered = {
              psk: pskResult.psk instanceof Uint8Array ? pskResult.psk : new Uint8Array(pskResult.psk),
              cipher: pskCipher,
              // The HASH is what actually constrains cipher selection
              // (RFC 8446 §4.2.11), not the exact suite the ticket was issued
              // under. Stored here so selection does not have to re-derive it.
              hash: hashName,
            };
            if ('early_data' in message) early_consider(pskResult, pskIdentity, hashName);
          }
        }
      }

      // Client: detect if server accepted PSK from ServerHello (BEFORE set_context)
      if (!context.isServer && message.pre_shared_key && typeof message.pre_shared_key.selected === 'number') {
        // RFC 8446 §4.2.11: the server picks one of the identities offered
        // (one, here), with a suite of the PSK's hash — anything else is
        // illegal_parameter. A pre_shared_key nobody offered is an
        // extension we did not send: unsupported_extension (§4.2).
        if (!context.psk_offered) {
          fatalAlert(wire.TLS_ALERT.UNSUPPORTED_EXTENSION, 'pre_shared_key in ServerHello without one offered');
          return;
        }
        let shSuite = hello_cipher_suite(message);
        let pskHash = TLS_CIPHER_SUITES[context.psk_offered.cipher] ? TLS_CIPHER_SUITES[context.psk_offered.cipher].hash : null;
        let shHash = TLS_CIPHER_SUITES[shSuite] ? TLS_CIPHER_SUITES[shSuite].hash : null;
        if (message.pre_shared_key.selected !== 0 || (shSuite !== null && pskHash !== shHash)) {
          fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'ServerHello selected a PSK identity or suite that was not offered');
          return;
        }
        dbg('CLI-PSK', '✓ server accepted PSK, selected_identity:', message.pre_shared_key.selected);
        context.psk_accepted = true;
        context.isResumed = true;
        restore_client_session_peer(context.psk_offered.session);
      } else if (!context.isServer && context.psk_offered && message.type === 'server_hello') {
        dbg('CLI-PSK', '✗ server did NOT include pre_shared_key in SH — full handshake');
      }

      // Client: detect HelloRetryRequest (ServerHello with magic random)
      if (!context.isServer && message.random && uint8Equal(message.random, wire.TLS13_HRR_RANDOM)) {
        context.helloRetried = true;
        early_client_result(false);   // §4.2.10: no early data after a HelloRetryRequest

        // Get cipher from HRR to determine hash
        let hrrCipher = null;
        if (message.cipher_suites && message.cipher_suites.length > 0) hrrCipher = message.cipher_suites[0];
        else if (message.cipher_suite) hrrCipher = message.cipher_suite;
        if (!hrrCipher) hrrCipher = 0x1301;
        let hashName = TLS_CIPHER_SUITES[hrrCipher] ? TLS_CIPHER_SUITES[hrrCipher].hash : 'sha256';
        context.hrr_hash = hashName;   // the second hello's PSK must use it

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

        // RFC 8446 §4.1.4: "Clients MUST abort the handshake with an
        // illegal_parameter alert if the HelloRetryRequest would not result in
        // any change in the ClientHello."
        //
        // A retry that names neither a new group nor a cookie asks us to resend
        // a byte-identical ClientHello, which the server would answer with the
        // same retry — an unbounded loop. Detecting it is not an optimisation:
        // without it we neither retried nor failed, we simply stopped, and the
        // peer sat waiting until it timed out. A stall is a denial of service.
        if (!requestedGroup && !hrrCookie) {
          fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
            'HelloRetryRequest requests no change (no key_share and no cookie)');
          return;
        }

        // Record EVERYTHING the retry committed to, in one place, before the
        // branch below splits on whether a group was requested.
        //
        // RFC 8446 §4.1.4: the second ServerHello must agree with the retry on
        // version, cipher suite and group. Those three checks need three
        // recorded values, and recording them in two different places — the
        // cipher here, the version and group inside the requestedGroup branch —
        // meant a cookie-only retry recorded the cipher and nothing else, so
        // two of the three consistency checks silently never fired for it. One
        // concept, one place.
        let hrrCipherSel = hello_cipher_suite(message);
        if (hrrCipherSel !== null) context.hrr_cipher = hrrCipherSel;

        let hrrVersionSel = null;
        if (Array.isArray(message.supported_versions) && message.supported_versions.length > 0) {
          hrrVersionSel = message.supported_versions[0];
        } else if (typeof message.supported_versions === 'number') {
          hrrVersionSel = message.supported_versions;
        }
        if (hrrVersionSel !== null) context.hrr_version = hrrVersionSel;

        // Null for a cookie-only retry — which is correct: it committed to no
        // group, so there is nothing for SH2 to contradict.
        context.hrr_group = requestedGroup;

        // A cookie-only retry is legal: the server is asking us to prove
        // reachability without changing our key share. The group path below is
        // skipped, so drive CH2 from here — previously this case produced no
        // second ClientHello at all and stalled exactly like the empty retry.
        if (!requestedGroup && hrrCookie) {
          set_context({
            selected_version: (Array.isArray(message.supported_versions) && message.supported_versions.length > 0)
              ? message.supported_versions[0]
              : (typeof message.supported_versions === 'number' ? message.supported_versions : null),
            // NOTE: dtls_cookie is the DTLS ClientHello's own cookie FIELD
            // (RFC 6347 §4.2.1), which lives in the message body and makes
            // wire.js encode the hello in DTLS framing. The HelloRetryRequest
            // cookie is a completely different thing — a TLS EXTENSION
            // (RFC 8446 §4.2.2) that build_client_hello_extensions already
            // carries. They share a name and nothing else. Assigning the HRR
            // cookie here injected a 1-byte length plus the cookie into a TLS
            // ClientHello body, which strict peers reject outright ("error
            // decoding ClientHello message"). Leave the DTLS field alone.
          });

          let firstGroup = context.local_supported_groups[0];
          let firstShare = context.local_key_groups[firstGroup]
            ? context.local_key_groups[firstGroup].public_key : null;
          send_second_client_hello(firstGroup, firstShare, hrrCookie);
          return;
        }

        if (requestedGroup) {
          // RFC 8446 §4.1.4: the retry must ask for a group the client offered
          // in supported_groups but did NOT already send a key_share for.
          // Asking for one we already shared is pointless — the server had
          // everything it needed — and the RFC requires the client to abort
          // rather than send a second share for the same group.
          if (requestedGroup in context.local_key_groups) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
              'HelloRetryRequest asked for group 0x' + (requestedGroup >>> 0).toString(16) +
              ' for which we already sent a key share');
            return;
          }

          // The retry must also stay within what we advertised: a group absent
          // from our supported_groups was never on offer.
          if (context.local_supported_groups.length > 0 &&
              context.local_supported_groups.indexOf(requestedGroup) < 0) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
              'HelloRetryRequest asked for group 0x' + (requestedGroup >>> 0).toString(16) +
              ' which we did not offer');
            return;
          }

          // Generate key for the requested group (ecdh.js owns curve dispatch).
          // A group we don't implement means the server asked for something we
          // never offered -- RFC 8446 4.1.4 makes that illegal_parameter.
          let newKeyGroup = null;
          let hrrKp = ecdh_generate_keypair(requestedGroup);
          if (hrrKp) {
            newKeyGroup = { group: requestedGroup, public_key: hrrKp.public_key, private_key: hrrKp.private_key };
            context.local_key_groups[requestedGroup] = { public_key: hrrKp.public_key, private_key: hrrKp.private_key };
          } else {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
              'HelloRetryRequest asked for unsupported group 0x' + (requestedGroup >>> 0).toString(16));
            return;
          }

          if (newKeyGroup) {
            // Record what the HelloRetryRequest told us THROUGH set_context,
            // rather than only acting on it locally. The HRR carries the
            // server's chosen version and group; skipping the reactive setter
            // left selected_version unset for the whole CH2 exchange, which is
            // why the record layer could not tell a 1.3 compat-CCS from a 1.2
            // cipher change and had to be given a weaker test. State the peer
            // told us belongs in the context like any other negotiated value.
            let hrrVersion = null;
            if (Array.isArray(message.supported_versions) && message.supported_versions.length > 0) {
              hrrVersion = message.supported_versions[0];
            } else if (typeof message.supported_versions === 'number') {
              hrrVersion = message.supported_versions;
            }

            set_context({
              selected_version: hrrVersion,
              selected_group: requestedGroup,
              // See the note above: the HRR cookie is an extension, not the
              // DTLS ClientHello cookie field. Preserve whatever DTLS cookie
              // the transport established, and nothing more.
              dtls_cookie: context.dtls_cookie,
              add_local_key_groups: [{
                group: requestedGroup,
                private_key: newKeyGroup.private_key,
                public_key: newKeyGroup.public_key
              }],
            });

            // CH2 MUST match CH1 except key_share/cookie (RFC 8446 §4.1.2) —
            // guaranteed here by building both from the same assembler.
            send_second_client_hello(requestedGroup, newKeyGroup.public_key, hrrCookie);
          }
        }

        // Don't process HRR as a regular ServerHello
        return;
      }

      // Whether THIS ServerHello is 1.3: the server declares its choice via
      // the supported_versions extension (RFC 8446 §4.2.1). Reading
      // context.selected_version here would be too early — that field is set
      // in the set_context below, in a later pass of the reactive loop. Base
      // the decision on the message itself, which is authoritative.
      let sh_is_13 = false;
      if (Array.isArray(message.supported_versions)) {
        sh_is_13 = message.supported_versions.indexOf(wire.TLS_VERSION.TLS1_3) >= 0 ||
                   message.supported_versions.indexOf(wire.DTLS_VERSION.DTLS1_3) >= 0;
      } else if (typeof message.supported_versions === 'number') {
        sh_is_13 = message.supported_versions === wire.TLS_VERSION.TLS1_3 ||
                   message.supported_versions === wire.DTLS_VERSION.DTLS1_3;
      }

      // ── Second ServerHello must honour the HelloRetryRequest ──
      // RFC 8446 §4.1.4: after a retry, the ServerHello that follows must name
      // the SAME version and the SAME group the retry asked for. A server that
      // changes its mind between the two is either broken or steering us, and
      // §4.1.4 makes the mismatch an illegal_parameter. Checked here, once,
      // against the values the HRR committed to (hrr_version / hrr_group) —
      // the HRR branch itself has already returned by this point, so this only
      // ever sees the real ServerHello.
      if (!context.isServer && message.type === 'server_hello' && context.helloRetried) {

        if (context.hrr_version !== null) {
          let shVersion = null;
          if (Array.isArray(message.supported_versions) && message.supported_versions.length > 0) {
            shVersion = message.supported_versions[0];
          } else if (typeof message.supported_versions === 'number') {
            shVersion = message.supported_versions;
          }
          if (shVersion !== null && shVersion !== context.hrr_version) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
              'Second ServerHello version 0x' + (shVersion >>> 0).toString(16) +
              ' does not match the HelloRetryRequest (0x' + (context.hrr_version >>> 0).toString(16) + ')');
            return;
          }
        }

        // RFC 8446 §4.1.4: "the server MUST send the same cipher suite in the
        // ServerHello as it did in the HelloRetryRequest." The retry already
        // fixed the hash that the whole key schedule depends on, so a change
        // here is not a preference the client may follow — it is a mismatch
        // that would silently derive different keys on each side.
        let shCipherSel = hello_cipher_suite(message);
        if (context.hrr_cipher !== null && shCipherSel !== null &&
            shCipherSel !== context.hrr_cipher) {
          fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
            'ServerHello cipher suite 0x' + (shCipherSel >>> 0).toString(16) +
            ' differs from the HelloRetryRequest (0x' + (context.hrr_cipher >>> 0).toString(16) + ')');
          return;
        }

        if (context.hrr_group !== null &&
            Array.isArray(message.key_groups) && message.key_groups.length > 0) {
          let shGroup = message.key_groups[0] && message.key_groups[0].group;
          if (typeof shGroup === 'number' && shGroup !== context.hrr_group) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
              'Second ServerHello selected group 0x' + (shGroup >>> 0).toString(16) +
              ' but the HelloRetryRequest asked for 0x' + (context.hrr_group >>> 0).toString(16));
            return;
          }
        }
      }

      // Record the server's DTLS-SRTP choice (it answers in EncryptedExtensions
      // for 1.3, in the ServerHello for 1.2 — both land in remote_extensions).
      if (!context.isServer && Array.isArray(message.extensions)) {
        for (let sx = 0; sx < message.extensions.length; sx++) {
          let e = message.extensions[sx];
          if (e && e.type === wire.TLS_EXT.USE_SRTP && e.value &&
              Array.isArray(e.value.profiles) && e.value.profiles.length > 0) {
            context.selected_srtp_profile = e.value.profiles[0];
          }
        }
      }

      if (sh_is_13 && reject_unsolicited_extensions(message, 'ServerHello')) return;

      // ── legacy_session_id_echo (RFC 8446 §4.1.3) ──
      // "A client which receives a legacy_session_id_echo field that does not
      // match what it sent in the ClientHello MUST abort the handshake with an
      // illegal_parameter alert."
      //
      // This is unconditional for the client, and RFC 9147's errata is explicit
      // that it still applies over DTLS 1.3 — DTLS disables the *server* side of
      // TLS 1.3's compatibility mode (Appendix D.4) but NOT this check. We were
      // not verifying it at all: a server could echo anything, or nothing, and
      // we accepted it. The field is also the one signal that distinguishes a
      // genuine ServerHello from one replayed or crafted for a different
      // ClientHello, so skipping it is not cosmetic.
      // TLS 1.3 ONLY. In TLS 1.2 the server is free to return a NEW session_id
      // to establish a new session (RFC 5246 §7.4.1.3) — echoing the client's is
      // how it signals RESUMPTION, not a requirement. Applying the 1.3 rule there
      // rejects every ordinary 1.2 handshake.
      if (sh_is_13 && !context.isServer && message.type === 'server_hello') {
        let sentSid = context.local_session_id || new Uint8Array(0);
        let echoSid = message.session_id || new Uint8Array(0);
        let sameSid = sentSid.length === echoSid.length;
        if (sameSid) {
          for (let si = 0; si < sentSid.length; si++) {
            if (sentSid[si] !== echoSid[si]) { sameSid = false; break; }
          }
        }
        if (!sameSid) {
          fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
            'ServerHello legacy_session_id_echo does not match the ClientHello (' +
            'sent ' + sentSid.length + ' bytes, echoed ' + echoSid.length + ')');
          return;
        }
      }


      // ── Client side of the negotiation-outcome rule ──
      // RFC 8446 §4.2.8 (TLS 1.3 ONLY): "servers offer exactly one
      // KeyShareEntry in the ServerHello ... This value MUST be in the same
      // group as the KeyShareEntry value offered by the client." §4.1.4 says a
      // server that wants a different group must send HelloRetryRequest
      // instead.
      //
      // Scoped to 1.3 explicitly. DTLS 1.2 (and TLS 1.2) do not use key_share
      // at all — they carry the server's ECDHE public key in
      // ServerKeyExchange, and the ServerHello may legitimately carry
      // extensions the parser exposes on the same field. Running this check
      // there rejects entirely valid 1.2 handshakes and was the WebRTC
      // regression against pion / webrtc-rs.
      //
      // Testing membership in local_key_groups — the shares we actually SENT —
      // is the RFC's own test, and is stricter than "was it in our
      // supported_groups": offering a group is not the same as having sent a
      // key share for it. HelloRetryRequest has returned earlier, and its
      // requested group is added to local_key_groups before CH2, so a genuine
      // retry passes here.
      if (!context.isServer && message.type === 'server_hello' &&
          sh_is_13 &&
          Array.isArray(message.key_groups) && message.key_groups.length > 0) {
        for (let ki = 0; ki < message.key_groups.length; ki++) {
          let g = message.key_groups[ki] && message.key_groups[ki].group;
          if (typeof g !== 'number') continue;
          if (!(g in context.local_key_groups)) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
              'ServerHello selected key_share group 0x' + (g >>> 0).toString(16) +
              ' for which we sent no key share');
            return;
          }
        }
      }

      // ── Server side: the client's key shares (RFC 8446 §4.2.8) ──
      // "Clients MUST NOT offer multiple KeyShareEntry values for the same
      // group. Clients MUST NOT offer any KeyShareEntry values for groups not
      // listed in the client's 'supported_groups' extension. Servers MAY check
      // for violations of these rules and abort the handshake with an
      // 'illegal_parameter' alert." Checked, as OpenSSL and BoringSSL do.
      // Unchecked, a share for a group the client never listed was used —
      // a handshake in a group it had not agreed to — and of two shares for
      // one group the first was taken, the second silently ignored: two
      // implementations reading one ClientHello two ways.
      // §9.2: "If containing a 'supported_groups' extension, it MUST also
      // contain a 'key_share' extension, and vice versa. An empty
      // KeyShare.client_shares vector is permitted" — missing_extension
      // otherwise. Present is what counts, empty included: an empty key_share
      // with no supported_groups was answered with a HelloRetryRequest. The
      // other way round only for a hello that offers TLS 1.3 to a server that
      // speaks it: a TLS 1.2 client sends supported_groups alone.
      if (context.isServer === true && message.type === 'client_hello') {
        let hasShares = Array.isArray(message.key_groups);
        let hasGroups = Array.isArray(message.supported_groups);
        let sv13 = message.supported_versions || [];
        let lv13 = context.local_supported_versions || [];
        let both13 = (sv13.indexOf(wire.TLS_VERSION.TLS1_3) >= 0 || sv13.indexOf(wire.DTLS_VERSION.DTLS1_3) >= 0) &&
                     (lv13.length === 0 || lv13.indexOf(wire.TLS_VERSION.TLS1_3) >= 0 || lv13.indexOf(wire.DTLS_VERSION.DTLS1_3) >= 0);
        if (hasShares && !hasGroups) {
          fatalAlert(wire.TLS_ALERT.MISSING_EXTENSION, 'ClientHello has key_share without supported_groups');
          return;
        }
        if (hasGroups && !hasShares && both13) {
          fatalAlert(wire.TLS_ALERT.MISSING_EXTENSION, 'ClientHello offering TLS 1.3 has supported_groups without key_share');
          return;
        }
      }
      if (context.isServer === true && message.type === 'client_hello' &&
          Array.isArray(message.key_groups) && message.key_groups.length > 0) {
        let offered = message.supported_groups;
        let seenShare = {};
        for (let ki = 0; ki < message.key_groups.length; ki++) {
          let g = message.key_groups[ki] && message.key_groups[ki].group;
          if (typeof g !== 'number') continue;
          if (seenShare[g]) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'ClientHello has two key shares for group 0x' + (g >>> 0).toString(16));
            return;
          }
          seenShare[g] = true;
          if (offered.indexOf(g) < 0) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'ClientHello has a key share for group 0x' + (g >>> 0).toString(16) + ', not in its supported_groups');
            return;
          }
        }
      }

      // Resolve our certificate BEFORE the set_context below.
      //
      // The reactive loop derives the cipher suite from the inputs present when
      // it runs, and (D)TLS 1.2 suites name an authentication algorithm that
      // MUST match our certificate's key type (RFC 4492 §2). Resolving the
      // certificate afterwards — as the SNI callback used to — meant selection
      // ran with no key in hand, so a server holding an ECDSA certificate could
      // pick an ECDHE_RSA suite and then present a certificate the peer rejects
      // as "wrong certificate type". Inputs first, then the loop.
      // No server_name in the hello: Node does not call SNICallback at all
      // and presents the default certificate. Same here when there is one.
      // With no default certificate, the callback is still asked (with null)
      // — the only chance left to pick a certificate rather than fail a
      // handshake Node would also fail.
      if (context.isServer === true && message.type === 'client_hello' &&
          typeof context.SNICallback === 'function' &&
          (message.sni || context.local_cert_chain === null)) {

        // Raised BEFORE calling out, so the set_context below — which runs
        // whether or not the callback has answered — finds the gate closed and
        // stops short of the ServerHello. A synchronous callback lowers it
        // again before that line is reached and nothing is deferred at all.
        context.sni_pending = true;

        let sniResolved = false;
        // True only while the call below is still on the stack.
        let sniSync = true;

        context.SNICallback(message.sni || null, function (err, creds) {
          // A lookup that times out and then answers late would otherwise
          // re-enter the handshake a second time.
          if (sniResolved) return;
          sniResolved = true;
          context.sni_pending = false;

          if (!err && creds) {
            // Direct assignment, not set_context: these are inputs seeded
            // ahead of the loop, not a reason to run it.
            context.local_cert_chain  = creds.certificateChain;
            context.cert_private_key  = creds.privateKey;
            context.local_cert_alternates = creds.alternates || null;

            // Whether to run the loop depends on WHEN this fired:
            //
            //   Synchronously — the set_context that processes this hello has
            //   not run yet. It will, in a moment, carrying the certificate
            //   with it. Running the loop here as well would process the same
            //   hello twice.
            //
            //   Asynchronously — that set_context has already run and stopped
            //   at the closed gate. Nothing else will run the loop, so it has
            //   to be nudged.
            if (!sniSync) set_context({ run_loop: true });
            return;
          }

          // No certificate for this name. Refusing is the only honest answer:
          // leaving the gate raised means a handshake that never completes and
          // never fails either — a timeout for the client and silence in the
          // log. unrecognized_name (112) is what RFC 6066 §3 defines for it.
          fatalAlert(112, 'No certificate for server name ' +
                          JSON.stringify(message.sni || '') +
                          (err ? ': ' + (err.message || err) : ''));
        });

        sniSync = false;
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

      // RFC 8446 §4.1.3: downgrade-protection check (client side).
      // If we offered TLS 1.3 but the server steered us to a lower version, the
      // server's random must NOT carry the downgrade sentinel — if it does, an
      // active attacker forced the downgrade. HRR was already handled and
      // returned above, so `message` here is a genuine ServerHello.
      if (!context.isServer && message.type === 'server_hello' &&
          context.local_supported_versions.indexOf(wire.TLS_VERSION.TLS1_3) >= 0 &&
          context.selected_version !== null &&
          context.selected_version !== wire.TLS_VERSION.TLS1_3 &&
          context.selected_version !== wire.DTLS_VERSION.DTLS1_3 &&
          message.random && message.random.length === 32) {

        let tail = message.random.subarray(24, 32);
        if (timingSafeEqualU8(tail, DOWNGRADE_SENTINEL_TLS12) ||
            timingSafeEqualU8(tail, DOWNGRADE_SENTINEL_TLS11)) {
          dbg('DOWNGRADE', 'sentinel detected in ServerHello.random — aborting');
          // Same abort funnel as everything else (fatalAlert = alert + terminal
          // state + 'error'); the hand-rolled pair here predated it and was the
          // one abort path that could drift out of sync with the rest.
          fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
            'TLS downgrade attack detected (RFC 8446 §4.1.3 sentinel present)');
          return;
        }
      }

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
          context.ticket_offered = true;
          let state = decrypt_session_blob(message.session_ticket, context.ticketKeys);
          if (state && state.v === 12 && state.master_secret && !ticket_expired(state) && ticket_context_ok(state) && same_server_name(state.sni, message.sni) && ticket_peer_acceptable(state)) {
            // Honor ticket-based resumption: we'll proceed as abbreviated handshake once TLS 1.2 is selected.
            context.tls12_resume_state = state;
            restore_ticket_peer(state);
            context.resumed_ticket_data = state.app != null ? state.app : null;
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
              if (state && state.v === 12 && state.master_secret && !ticket_expired(state) && ticket_context_ok(state) && same_server_name(state.sni, message.sni) && ticket_peer_acceptable(state)) {
                // Directly, not through set_context: it acts only on the fields
                // it knows, and drops anything else without a word.
                context.resumed_ticket_data = state.app != null ? state.app : null;
                restore_ticket_peer(state);
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

        if (LEMON_DEBUG) dbg('CLI-12RESUME', 'saved sid:', hexPreview(savedSid, 16),
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
          restore_client_session_peer(context.tls12_client_session);
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




    }else if(message.type=='client_key_exchange' || message.type=='server_key_exchange'){

      if (message.type === 'server_key_exchange') context.ske_received = true;   // CertificateStatus comes before it
      pushTranscript(data);

      // TLS 1.2 ECDHE: the ServerKeyExchange is signed over
      //   client_random | server_random | ServerECDHParams
      // (RFC 4492 §5.4). Verifying it is what binds the ephemeral key to the
      // certificate — without it an active attacker can substitute their own
      // ECDHE public key and the handshake still completes. This was never
      // checked before.
      if (message.type === 'server_key_exchange' && !context.isServer &&
          message.signature && message.public_key) {

        if (!context.remote_cert_chain || context.remote_cert_chain.length === 0) {
          fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'ServerKeyExchange before Certificate');
          return;
        }

        // Rebuild the exact signed payload: randoms in wire order (client
        // first) followed by the ServerECDHParams as they appeared.
        let ecdhParams = wire.build_server_ecdh_params(message.group, message.public_key);
        let skeTbs = concatUint8Arrays([
          context.local_random,    // client_random (we are the client)
          context.remote_random,   // server_random
          ecdhParams
        ]);

        let skeBad = check_peer_signature(wire.TLS_VERSION.TLS1_2, message.sig_alg, skeTbs, message.signature, 'ServerKeyExchange');
        if (skeBad) { fatalAlert(skeBad.alert, skeBad.reason); return; }
      }

      if (is_ecdhe_suite(context.selected_cipher_suite)) {//ECDHE

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

      context.shd_received = true;   // CertificateStatus comes before it
      pushTranscript(data);


      set_context({
        remote_hello_done: true,
      });

    }else if(message.type=='encrypted_extensions'){

      if (reject_unsolicited_extensions(message, 'EncryptedExtensions')) return;

      // RFC 8446 §4.2 (table): extensions with a defined home elsewhere MUST
      // NOT appear in EncryptedExtensions — a peer that puts key_share (etc.)
      // here is violating the extension placement rules → illegal_parameter.
      // Everything unknown/custom is allowed through: EE is exactly where
      // application extensions (QUIC transport params, use_srtp, ALPN) live.
      {
        let forbiddenInEE = {
          5: 1,      // status_request (CH/CR/Certificate only)
          13: 1,     // signature_algorithms
          21: 1,     // padding (CH only)
          23: 1,     // extended_master_secret (not a TLS 1.3 extension)
          35: 1,     // session_ticket (not a TLS 1.3 extension)
          41: 1,     // pre_shared_key
          43: 1,     // supported_versions
          44: 1,     // cookie
          45: 1,     // psk_key_exchange_modes
          47: 1,     // certificate_authorities (CH/CR only)
          50: 1,     // signature_algorithms_cert
          51: 1,     // key_share
          0xff01: 1, // renegotiation_info (not a TLS 1.3 extension)
        };
        let eeExts = Array.isArray(message.extensions) ? message.extensions : [];
        for (let fi = 0; fi < eeExts.length; fi++) {
          if (eeExts[fi] && forbiddenInEE[eeExts[fi].type] === 1) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'Forbidden extension ' + eeExts[fi].type + ' in EncryptedExtensions');
            return;
          }
        }
      }

      // ECH retry_configs (RFC 9849 §6.1.6): kept when ECH was rejected — a
      // well-formed ECHConfigList, or decode_error. After an acceptance the
      // server has no reason to send them (§6.1.4: unsupported_extension).
      // To a GREASE client they mean nothing (§6.2).
      if (!context.isServer && context.ech.outer_ch1) {
        let eeAll = Array.isArray(message.extensions) ? message.extensions : [];
        for (let ri = 0; ri < eeAll.length; ri++) {
          if (!eeAll[ri] || eeAll[ri].type !== EXT_ECH) continue;
          if (context.ech.status === 'accepted') {
            fatalAlert(wire.TLS_ALERT.UNSUPPORTED_EXTENSION, 'ECH retry_configs after ECH was accepted');
            return;
          }
          try { parse_ech_config_list(eeAll[ri].data); }
          catch (e) { fatalAlert(wire.TLS_ALERT.DECODE_ERROR, 'ECH retry_configs malformed: ' + e.message); return; }
          context.ech.retry_configs = new Uint8Array(eeAll[ri].data);
        }
      }

      pushTranscript(data);

      // 0-RTT: early_data in EncryptedExtensions is the server taking it —
      // with the ALPN the ticket was made with, or the handshake is broken
      // (RFC 8446 §4.2.10: the client MUST abort with illegal_parameter).
      if (!context.isServer && context.early.offered) {
        let edIn = false, eeList = Array.isArray(message.extensions) ? message.extensions : [];
        for (let ei2 = 0; ei2 < eeList.length; ei2++) if (eeList[ei2] && eeList[ei2].type === wire.TLS_EXT.EARLY_DATA) edIn = true;
        if (edIn) {
          let eeAlpn = message.alpn != null ? (Array.isArray(message.alpn) ? message.alpn[0] : message.alpn) : null;
          if ((eeAlpn || null) !== (context.early.alpn || null)) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'early data accepted with another ALPN than the ticket\'s');
            return;
          }
        }
        early_client_result(edIn);
      }

      // TLS 1.3: most server extensions arrive HERE, not in the
      // ServerHello (RFC 8446 §4.3.1) — including application-protocol
      // ones like use_srtp (RFC 8842 requires it in EncryptedExtensions).
      // Merge them into remote_extensions so getRemoteExtension() sees a
      // version-agnostic union: ServerHello entries first (kept on type
      // collision, which the RFC forbids anyway), then EE entries.
      if (Array.isArray(message.extensions) && message.extensions.length > 0) {
        var _mergedExts = (context.remote_extensions || []).slice();
        for (var _eei = 0; _eei < message.extensions.length; _eei++) {
          var _ee = message.extensions[_eei];
          if (!_ee) continue;
          var _dup = false;
          for (var _mj = 0; _mj < _mergedExts.length; _mj++) {
            if (_mergedExts[_mj] && _mergedExts[_mj].type === _ee.type) { _dup = true; break; }
          }
          if (!_dup) _mergedExts.push(_ee);
        }
        context.remote_extensions = _mergedExts;
      }

      // The server's ALPN choice lives HERE in TLS 1.3, not in the ServerHello:
      // RFC 8446 §4.3.1 moved every non-key-establishment extension into
      // EncryptedExtensions, and RFC 7301 negotiation is one of them.
      //
      // Reading only supported_groups left selected_alpn null on the client:
      // the server picked 'h2', said so, and the client reported
      // alpnProtocol === false. Nothing failed, so nothing pointed here — the
      // connection simply behaved as though ALPN had never been negotiated,
      // which for HTTP/2 means it cannot be used at all (RFC 9113 §3.2).
      let eeUpdate = { remote_supported_groups: message.supported_groups || [] };
      if (message.alpn !== undefined && message.alpn !== null) {
        // The extension carries a list, but a server names exactly one
        // protocol in its answer (RFC 7301 §3.2).
        let chosenAlpn = Array.isArray(message.alpn) ? message.alpn[0] : message.alpn;
        if (typeof chosenAlpn === 'string' && chosenAlpn.length > 0) {
          // A server may only select something we offered; anything else is
          // unnegotiable and must not be accepted.
          if (context.local_supported_alpns &&
              context.local_supported_alpns.indexOf(chosenAlpn) < 0) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER,
                       'Server selected an ALPN protocol that was not offered: ' + chosenAlpn);
            return;
          }
          eeUpdate.selected_alpn = chosenAlpn;
        }
      }
      set_context(eeUpdate);

    }else if(message.type=='certificate_status'){

      // TLS 1.2 (RFC 6066 §8): only after a status_request we sent, and the
      // server's ServerHello said one follows.
      let shSaid = false;
      for (let ri = 0; ri < (context.remote_extensions || []).length; ri++) {
        if (context.remote_extensions[ri] && context.remote_extensions[ri].type === wire.TLS_EXT.STATUS_REQUEST) shSaid = true;
      }
      // Once, right after the server's Certificate (before ServerKeyExchange
      // and ServerHelloDone), and never in a resumption, which has none.
      let inPlace = !context.tls12_abbreviated && context.remote_cert_chain !== null &&
                    !context.cert_status_received && !context.ske_received && !context.shd_received;
      if (!is12() || !context.requestOCSP || !shSaid || !inPlace) {
        fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'Unexpected CertificateStatus');
        return;
      }
      context.cert_status_received = true;
      pushTranscript(data);
      if (message.status_type === 1) ev.emit('OCSPResponse', message.response);
      set_context({ run_loop: true });

    }else if(message.type=='certificate'){

      // A client sends a Certificate only when asked for one (RFC 8446
      // §4.4.2, RFC 5246 §7.4.6): unasked, unexpected_message. It was taken,
      // checked and kept — a peer certificate the server never wanted.
      if (context.isServer && !context.certificateRequestSent) {
        fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'Certificate from a client that was not asked for one');
        return;
      }

      pushTranscript(data);

      let entries = message.entries || [];

      // TLS 1.3: a stapled OCSP response is in the leaf's entry (RFC 8446
      // §4.4.2.1) — read on the client that asked for it.
      if (!context.isServer && is13() && entries.length > 0 && Array.isArray(entries[0].extensions)) {
        for (let oi = 0; oi < entries[0].extensions.length; oi++) {
          let oe = entries[0].extensions[oi];
          if (oe && oe.type === wire.TLS_EXT.STATUS_REQUEST) {
            // Not asked for: RFC 8446 §4.2 — unsupported_extension.
            if (!context.requestOCSP) {
              fatalAlert(wire.TLS_ALERT.UNSUPPORTED_EXTENSION, 'status_request in a Certificate the client did not ask for');
              return;
            }
            let st;
            try { st = wire.parse_certificate_status(oe.data); }
            catch (e) { fatalAlert(wire.TLS_ALERT.DECODE_ERROR, 'Bad CertificateStatus in Certificate: ' + e.message); return; }
            if (st.status_type === 1) ev.emit('OCSPResponse', st.response);
          }
        }
      }

      // RFC 8446 §4.4.2.4 / RFC 5246 §7.4.6.
      //  - From a SERVER an empty certificate_list is always illegal: the
      //    server has nothing else to authenticate with, so this is fatal here
      //    and now.
      //  - From a CLIENT it is legal — it means "I have no certificate". Whether
      //    that is acceptable is a POLICY question answered at the completion
      //    gate, which also catches the client that omits the message entirely.
      //    So we only record the outcome and let the reactive loop proceed;
      //    returning early here would skip the set_context that drives it.
      if (entries.length === 0) {
        if (!context.isServer) {
          fatalAlert(wire.TLS_ALERT.DECODE_ERROR, 'Server sent an empty certificate_list');
          return;
        }
        context.authorizationError = 'NO_PEER_CERTIFICATE';
        context.peerAuthorized = false;   // no set_context setter for this field
        set_context({ remote_cert_chain: [] });
      } else {
        set_context({
          remote_cert_chain: entries,
        });

        // Validate peer certificate
        validatePeerCertificate();
        if (context.rejectUnauthorized && !context.peerAuthorized) {
          fatalAlert(wire.TLS_ALERT.BAD_CERTIFICATE,
            'Peer certificate validation failed: ' + (context.authorizationError || 'unknown'));
          return;
        }
      }

    }else if(message.type=='certificate_verify'){

      // Likewise its CertificateVerify, and only after a certificate.
      if (context.isServer && (!context.certificateRequestSent || !context.remote_cert_chain || context.remote_cert_chain.length === 0)) {
        fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'CertificateVerify from a client with no certificate asked for or sent');
        return;
      }

      // RFC 8446 §4.4.3 — verify the peer's handshake signature.
      //
      // This is the step that actually authenticates the peer: without it,
      // ANY party able to send us a certificate (which is public data) is
      // accepted, because nothing proves they hold the matching private key.
      // Previously this branch only pushed to the transcript.
      //
      // Ordering is critical: the signed transcript covers everything up to
      // but NOT including this message, so the hash MUST be taken before
      // pushTranscript(data) below.
      // A TLS 1.3 CertificateVerify that we cannot verify must NEVER be
      // silently skipped. The block below is the only thing standing between
      // us and accepting an unauthenticated peer, so every path that isn't a
      // successful verification has to be an abort — including "we somehow got
      // here without a negotiated cipher suite", which would otherwise fall
      // through with peerSignatureVerified still false and no explanation.
      if (context.selected_version === wire.TLS_VERSION.TLS1_3 ||
          context.selected_version === wire.DTLS_VERSION.DTLS1_3) {

        if (context.selected_cipher_suite === null) {
          fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE,
            'CertificateVerify received before a cipher suite was negotiated');
          return;
        }

        if (!context.remote_cert_chain || context.remote_cert_chain.length === 0) {
          fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'CertificateVerify without a preceding Certificate');
          return;
        }

        let cvHashName = negotiated_hash();
        // The label follows the SIGNER's role, the opposite of ours.
        let tbs = build_cert_verify_tbs_with_hash(cvHashName, !context.isServer, get_transcript_hash(cvHashName));
        // DTLS 1.3 shares TLS 1.3's scheme semantics.
        let cvBad = check_peer_signature(wire.TLS_VERSION.TLS1_3, message.scheme, tbs, message.signature, 'CertificateVerify');
        if (cvBad) { fatalAlert(cvBad.alert, cvBad.reason); return; }
      } else {

        // TLS 1.2 / DTLS 1.2 (RFC 5246 §7.4.8): the client's signature over
        // every handshake message up to this one — the bytes themselves, which
        // the scheme hashes; DTLS's transcript holds its own form (the
        // transcript hook), as for Finished. It was never checked: only the
        // 1.3 branch above verified, and the completion gate was 1.3-only too,
        // so a client presenting anyone's certificate — public data — with
        // random bytes for a signature, or none, was authorized as its owner.
        // Fail closed, as above.
        if (!context.isServer) {
          fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'CertificateVerify from a TLS 1.2 server');
          return;
        }
        if (!context.remote_cert_chain || context.remote_cert_chain.length === 0) {
          fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'CertificateVerify without a preceding Certificate');
          return;
        }
        let cvBad12 = check_peer_signature(wire.TLS_VERSION.TLS1_2, message.scheme, concatUint8Arrays(context.transcript), message.signature, 'CertificateVerify');
        if (cvBad12) { fatalAlert(cvBad12.alert, cvBad12.reason); return; }
      }

      pushTranscript(data);

    }else if(message.type=='finished'){

      // Early data taken over TCP: its EndOfEarlyData comes first (§4.5).
      if (context.isServer && context.endOfEarlyData && context.early.status === 'accepted' && !context.early.eoed) {
        fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'Finished before EndOfEarlyData');
        return;
      }

      // ── Order enforcement: Finished may not follow a bare Certificate ──
      //
      // RFC 8446 §4.4.3: a peer that sends a non-empty Certificate MUST follow
      // it with CertificateVerify. Skipping it and going straight to Finished
      // means the peer never proved possession of the certificate's private
      // key — it merely presented somebody's certificate.
      //
      // A completion-time check alone is not enough here. A peer that omits
      // CertificateVerify still shares the ECDHE secret, so it can compute a
      // perfectly valid Finished; we would verify that Finished, derive
      // application keys and only then notice. Rejecting on ARRIVAL keeps the
      // omission from ever influencing the key schedule, and reports the
      // protocol error (unexpected_message) rather than a downstream symptom.
      //
      // Applies in both roles: a client checks the server's certificate, and a
      // server checks a client certificate it was offered.
      // Every version: in 1.2 a client's certificate is proved by its
      // CertificateVerify, the server's by its ServerKeyExchange signature.
      if (context.remote_cert_chain && context.remote_cert_chain.length > 0 &&
          context.peerSignatureVerified !== true) {
        fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE,
          'Finished received after a certificate that was never proved by a CertificateVerify');
        return;
      }


      set_context({
        remote_finished: message.body
      });

    }else if(message.type=='new_session_ticket'){

      // Client receives NewSessionTicket from server (post-handshake in TLS 1.3, pre-CCS in TLS 1.2)
      if(!context.isServer){
        if ((is13()) && context.resumption_master_secret) {
          // TLS 1.3: derive PSK from resumption_master_secret + ticket_nonce
          let hashName = negotiated_hash();
          let psk = derive_psk(hashName, context.resumption_master_secret, message.ticket_nonce, label_prefix());

          dbg('CLI-NST', 'received TLS 1.3 NST — cipher:', '0x' + context.selected_cipher_suite.toString(16),
              'hash:', hashName,
              'transcript len:', concatUint8Arrays(context.transcript).length);
          if (LEMON_DEBUG) dbg('CLI-NST', 'ticket_nonce:', hexPreview(message.ticket_nonce, 4),
              'age_add:', message.ticket_age_add,
              'lifetime:', message.ticket_lifetime);
          if (LEMON_DEBUG) dbg('CLI-NST', 'resumption_master_secret:', hexPreview(context.resumption_master_secret, 8),
              'derived psk:', hexPreview(psk, 8));

          // Encode opaque client-side session Buffer (JSON — user is responsible for secure storage)
          // early_data in the ticket: 0-RTT allowed, up to this many bytes.
          let maxEarly = 0, nstExts = Array.isArray(message.extensions) ? message.extensions : [];
          for (let ni = 0; ni < nstExts.length; ni++) {
            let ne = nstExts[ni];
            if (ne && ne.type === wire.TLS_EXT.EARLY_DATA && ne.data && ne.data.length === 4) {
              maxEarly = ((ne.data[0] << 24) | (ne.data[1] << 16) | (ne.data[2] << 8) | ne.data[3]) >>> 0;
            }
          }
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
            max_early_data: maxEarly || undefined,
            qa: context.sessionAppData != null ? context.sessionAppData : undefined,
            ...client_session_peer_fields(),
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
            ...client_session_peer_fields(),
          });

          ev.emit('session', session_blob);
          context.tls12_client_session_emitted = true;
        }
      }

    }else if(message.type=='end_of_early_data'){

      // RFC 8446 §4.5: after the early data the server took, before the
      // client's second flight — and only then.
      if (!context.isServer || !context.endOfEarlyData || context.early.status !== 'accepted' ||
          context.early.eoed || context.remote_finished !== null || context.state === 'connected') {
        fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'Unexpected EndOfEarlyData');
        return;
      }
      pushTranscript(data);
      context.early.eoed = true;
      ev.emit('endOfEarlyData');

    }else if(message.type=='key_update'){

      // Only once the handshake is done (RFC 8446 §4.6.3: "an
      // unexpected_message alert" for one before Finished). It used to be
      // passed over without a word.
      if(context.state!=='connected' || !is13()){
        fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE, 'KeyUpdate before the handshake is complete');
        return;
      }

      // Peer is updating their traffic secret (we update our read key)
      {
        let hashName = negotiated_hash();
        let hashLen = getHashLen(hashName);
        let newRemoteSecret = hkdf_expand_label(hashName, context.remote_app_traffic_secret, 'traffic upd', new Uint8Array(0), hashLen, label_prefix());
        context.remote_app_traffic_secret = newRemoteSecret;
        ev.emit('keyUpdate', { direction: 'receive', secret: newRemoteSecret });

        // If peer requested us to update too
        if(message.request_update === 1){
          let newLocalSecret = hkdf_expand_label(hashName, context.local_app_traffic_secret, 'traffic upd', new Uint8Array(0), hashLen, label_prefix());
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

    }else{

      // Terminal branch: a handshake message we do not implement, or one that
      // is illegal at the negotiated version (RFC 8446 §4: HelloRequest and the
      // other TLS 1.2-only types have no place in a 1.3 handshake). Anything
      // reaching here was NOT processed, so it must not be ignored — silently
      // dropping unknown messages let a peer stream them forever and hid real
      // protocol errors behind a handshake that simply never progressed.
      fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE,
        'Unexpected handshake message type ' +
        (message.handshake_type !== undefined ? message.handshake_type : message.type));
      return;

    }

  }


  function set_context(options){
    // Terminal states are terminal: after a fatal alert ('error') or a close,
    // the reactive loop must not keep selecting parameters, deriving keys or
    // emitting messages. This is also what stops it from writing into a
    // transport whose peer already went away (see TLSSocket's destroyed
    // marking — the two guards meet in the middle).
    if (context.state === 'error' || context.state === 'closed') return;

    let has_changed=false;

    if (options && typeof options === 'object'){


      // A bare nudge: carries no state, exists only to set has_changed so the
      // loop runs again. Used where an input was assigned directly and there
      // is nothing else to carry it in: an SNI callback or an OCSPRequest
      // answering asynchronously, a CertificateStatus read.
      if('run_loop' in options){
        has_changed=true;
      }

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
        for(let i = 0; i < options['add_local_key_groups'].length; i++){

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
        for(let i = 0; i < options['add_remote_key_groups'].length; i++){

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

      if('exporter_master_secret' in options){
        if(context.exporter_master_secret==null && options.exporter_master_secret!==null){
          context.exporter_master_secret=options.exporter_master_secret;
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

      /**
       * Values decided during THIS pass of the reactive loop.
       *
       * They are written here and only copied into `context` when the pass
       * commits. That gives one rule, and getting it wrong has already caused
       * three separate bugs (a spurious ServerHello rejection, the wrong cipher
       * on PSK resumption, and a HelloRetryRequest that was never sent — the
       * last two presenting as hangs rather than as wrong answers):
       *
       *   A gate whose decision MUST be made on the same pass that the input
       *   arrived reads params_to_set first, falling back to context. Use the
       *   `pending()` helper defined just below rather than writing the
       *   ternary out:
       *
       *       if (pending('selected_version') === wire.TLS_VERSION.TLS1_3) { … }
       *
       *   A step that can simply wait may read `context` directly. Writing to
       *   params_to_set sets has_changed, so the loop runs again and the value
       *   will be in `context` next time round.
       *
       * A SECOND rule, same root, different shape — worth stating because it has
       * now caused four bugs (a spurious ServerHello rejection, the wrong cipher
       * on PSK resumption, a HelloRetryRequest that was never sent, and a
       * HelloVerifyRequest sent in violation of RFC 9147 §5.1):
       *
       *   A decision derived from an INCOMING MESSAGE must be read from that
       *   message, never from state the message itself is about to establish.
       *
       * `is13()` answers "what did we negotiate", which is the right question
       * once negotiation is done and the wrong one while processing the very
       * message that decides it. When handling a ClientHello or ServerHello,
       * take the version from the message's own supported_versions — see
       * `sh_is_13` in the ServerHello path and `offersDtls13` in dtls_session.
       *
       * The test is whether deferring changes the OUTCOME. Key generation and
       * shared-secret derivation can wait — they just happen a pass later.
       * HelloRetryRequest cannot: by the next pass the ServerHello may already
       * have been sent, and the opportunity is gone. Anything gated on
       * `hello_sent`, `finished_sent` or another one-shot latch is in that
       * category.
       */
      let params_to_set = {};

      /**
       * The value of a negotiated field AS OF THIS PASS.
       *
       * Reads params_to_set first, then context — the rule documented above,
       * expressed once so no gate can forget the fallback half of it. Seven
       * gates spelled this ternary out under seven different local names
       * (pickedVersion, pskPassVersion, hrrVersionNow …), which meant a reader
       * had to re-derive the intent each time and a new gate could easily copy
       * only the `context` half. `pending('selected_version')` says what it is.
       */
      function pending(field) {
        return (field in params_to_set) ? params_to_set[field] : context[field];
      }


      

      
      
          
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

        // TLS_FALLBACK_SCSV (RFC 7507). A client that retried with a lower
        // version after a failed attempt says so with the 0x5600 value in its
        // cipher suites. If we support something higher than the highest it
        // now offers, the retry was caused by an attacker breaking the first
        // attempt, not by us: refuse with inappropriate_fallback rather than
        // accept the downgrade. (TLS 1.3's own protection is the DOWNGRD
        // sentinel in our random; this covers clients that fall back.)
        //
        // Checked whether or not a version in common was found. A client that
        // fell back below anything we speak (TLS 1.1, 1.0) got protocol_version
        // (70) from the check further down — which RFC 7507 allows, but it
        // hides the one thing the client asked about: this was a fallback, and
        // we support better. Scanners test exactly that case and read 70 as
        // "SCSV not supported". inappropriate_fallback (86) comes first.
        if (context.isServer &&
            (context.remote_supported_cipher_suites || []).indexOf(0x5600) >= 0) {
          let ourMax = 0, theirMax = 0;
          for (let i = 0; i < context.local_supported_versions.length; i++) {
            let v = context.local_supported_versions[i] | 0;
            if (v >= 0x0300 && v < 0x0400 && v > ourMax) ourMax = v;       // TLS, not DTLS
          }
          for (let i = 0; i < context.remote_supported_versions.length; i++) {
            let v = context.remote_supported_versions[i] | 0;
            if (v >= 0x0300 && v < 0x0400 && v > theirMax) theirMax = v;
          }
          if (ourMax && theirMax && ourMax > theirMax) {
            fatalAlert(wire.TLS_ALERT.INAPPROPRIATE_FALLBACK,
              'TLS_FALLBACK_SCSV: the client fell back to 0x' + theirMax.toString(16) +
              ', and 0x' + ourMax.toString(16) + ' is supported here');
            return;
          }
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

      //select certificate... (several key/certificate pairs)
      //
      // The one the client asks for: the first scheme in ITS
      // signature_algorithms (its order is its preference, RFC 8446 §4.2.3)
      // that one of our keys can sign with at this version — an ML-DSA
      // certificate for a client that puts ML-DSA first, the ECDSA or RSA one
      // for a browser, which offers no ML-DSA. None: the default pair, as
      // with one. Decided once the version and the server name's certificate
      // are known, before the cipher suite (which, in TLS 1.2, depends on
      // the key's type).
      if (context.isServer && !context.cert_chosen && context.local_cert_alternates && context.local_cert_alternates.length > 0 &&
          !context.sni_pending && pending('selected_version') != null && context.cert_private_key) {
        context.cert_chosen = true;
        let cv = pending('selected_version');
        let sv = (cv === wire.TLS_VERSION.TLS1_3 || cv === wire.DTLS_VERSION.DTLS1_3) ? wire.TLS_VERSION.TLS1_3 : wire.TLS_VERSION.TLS1_2;
        let cands = [{ certificateChain: context.local_cert_chain, privateKey: context.cert_private_key }].concat(context.local_cert_alternates);
        let peerAlgs = context.remote_supported_signature_algorithms || [];
        let chosen = null;
        for (let i = 0; i < peerAlgs.length && chosen === null; i++) {
          for (let j = 0; j < cands.length; j++) {
            if (pick_scheme(sv, private_key_object(cands[j].privateKey), [peerAlgs[i]], context.local_supported_signature_algorithms) !== null) { chosen = cands[j]; break; }
          }
        }
        if (chosen !== null && chosen !== cands[0]) {
          context.local_cert_chain = chosen.certificateChain;
          context.cert_private_key = chosen.privateKey;
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

        // TLS 1.3 PSK resumption — RFC 8446 §4.2.11:
        //   "The server MUST ensure that it selects a compatible PSK (if any)
        //    and cipher suite ... a cipher suite with the same hash algorithm."
        //
        // The constraint is on the HASH, not on the exact suite the ticket was
        // issued under. Two bugs lived in the previous version, which forced
        // the stored suite and otherwise fell through:
        //
        //   - it ignored our own preference order among the suites that DO
        //     match the hash, so a client offering several compatible suites
        //     got whichever one the ticket happened to carry;
        //   - when the stored suite was no longer on offer it silently
        //     continued with the PSK anyway and let ordinary selection pick a
        //     suite with a DIFFERENT hash — resuming under a key schedule the
        //     peer never agreed to.
        //
        // Correct rule: choose, by our normal preference, among the mutually
        // supported suites whose hash matches the PSK. If none exists the PSK
        // is unusable and must be dropped so the handshake falls back to a full
        // one — accepting a PSK we cannot honour is not an "edge case", it is a
        // resumption the peer will reject.
        // Version check reads params_to_set first: selection runs in the same
        // pass that decides the version, so context.selected_version is still
        // null here and is13() would report false for every 1.3 handshake.
        let pskPassVersion = pending('selected_version');
        let pskPassIs13 = pskPassVersion === wire.TLS_VERSION.TLS1_3 ||
                          pskPassVersion === wire.DTLS_VERSION.DTLS1_3;


        if (context.isServer && context.psk_accepted && context.psk_offered &&
            context.psk_offered.hash && pskPassIs13) {

          let pskHash = context.psk_offered.hash;
          let chosen = null;

          // Early data offered, and we take early data: the ticket's own
          // suite, if the client offers it — 0-RTT is accepted only under
          // "the same cipher suite" the ticket was issued with (RFC 8446
          // §4.2.10), and early_decide holds to that. Chosen by our order
          // alone, a ChaCha20 ticket resumed under AES-128-GCM (same hash,
          // allowed) and its early data was always refused.
          let ticketCs = context.psk_offered.cipher | 0;
          if (context.earlyData && context.early.offered && ticketCs &&
              context.local_supported_cipher_suites.indexOf(ticketCs) >= 0 &&
              context.remote_supported_cipher_suites.indexOf(ticketCs) >= 0 &&
              TLS_CIPHER_SUITES[ticketCs] && TLS_CIPHER_SUITES[ticketCs].hash === pskHash &&
              is_usable_cipher_suite(ticketCs)) {
            chosen = ticketCs;
          }

          for (let i = 0; chosen === null && i < context.local_supported_cipher_suites.length; i++) {
            let cs = context.local_supported_cipher_suites[i] | 0;
            if (context.remote_supported_cipher_suites.indexOf(cs) < 0) continue;
            let meta = TLS_CIPHER_SUITES[cs];
            if (!meta || meta.hash !== pskHash) continue;
            // Describable is not usable — record.js implements AEAD only.
            if (!is_usable_cipher_suite(cs)) continue;
            chosen = cs;
            break;
          }


          if (chosen !== null) {
            params_to_set['selected_cipher_suite'] = chosen;
          } else {
            // No compatible suite → the PSK cannot be used. Undo acceptance and
            // let the normal path run a full handshake.
            dbg('SRV-PSK', 'no mutually-supported cipher with hash', pskHash,
                '— rejecting PSK, falling back to full handshake');
            context.psk_accepted = false;
            context.isResumed = false;
            context.psk_offered = null;
          }
        }

        if (!('selected_cipher_suite' in params_to_set)) {
          // RFC 4492 §2 / RFC 5246 §7.4.2: a (D)TLS 1.2 cipher suite names the
          // authentication algorithm, and it MUST match the key type of the
          // certificate we are going to present — an ECDHE_RSA suite cannot be
          // used with an ECDSA certificate. Selecting purely by mutual support
          // let a server with an EC certificate pick ECDHE_RSA and then send a
          // certificate the peer rejects as "wrong certificate type".
          //
          // The suite→auth mapping already exists in crypto.js's cipher table
          // (the `sig` field), so this reads that authority rather than
          // re-deriving it. TLS 1.3 suites are authentication-agnostic
          // (sig: 'TLS13'), so they are never filtered here.
          let localAuth = null;
          if (context.isServer) {
            try {
              if (context.cert_private_key) {
                let lk = local_private_key();
                localAuth = lk ? lk.asymmetricKeyType : null;
              }
            } catch (e) { localAuth = null; }
          }

          let suiteAuthOk = function (suite) {
            if (!context.isServer || localAuth === null) return true;   // client, or key type unknown
            let meta = TLS_CIPHER_SUITES[suite];
            if (!meta || !meta.sig || meta.sig === 'TLS13') return true; // not auth-bound
            if (meta.sig === 'RSA')   return localAuth === 'rsa' || localAuth === 'rsa-pss';
            if (meta.sig === 'ECDSA') return localAuth === 'ec';
            return true;
          };

          // Whose order: the client's, as node:tls (OpenSSL) chooses by
          // default — honorCipherOrder: true for ours. It was always ours: a
          // client that put AES-256 first (CNSA 2.0 requires it) was given
          // AES-128 because our list had it first. Browsers list AES-128
          // first, and get it either way.
          let suiteOrder = context.local_supported_cipher_suites;
          if (context.isServer && !context.honor_cipher_order) {
            suiteOrder = context.remote_supported_cipher_suites.filter(function (c) {
              return context.local_supported_cipher_suites.indexOf(c | 0) >= 0;
            });
          }
          for (let i2 = 0; i2 < suiteOrder.length; i2++) {
            let cs = suiteOrder[i2] | 0;
            if (!suiteAuthOk(cs)) continue;
            // A suite belongs to exactly one protocol generation (RFC 8446
            // §B.4). Selecting a 1.3 suite while negotiating 1.2 — which a
            // configured list can easily contain — yields a ServerHello the
            // peer cannot act on. This is the server-side mirror of not
            // OFFERING 1.3 suites from a 1.2-only client profile.
            if (!suite_matches_version(cs, pending('selected_version'))) continue;
            // The suite table names more suites than the record layer can
            // protect (CBC entries exist for parsing peer offers). Selecting a
            // described-but-unimplemented suite yields a handshake that agrees
            // on parameters and then cannot encrypt a record — the cipher-suite
            // analogue of picking a key-exchange group we cannot compute.
            if (!is_usable_cipher_suite(cs)) continue;
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

        if (storedEMS && !clientEMS) {
          // RFC 7627 §5.3: a session made with the extended master secret, a
          // hello now without it — "the server MUST abort the abbreviated
          // handshake": its master secret is not one this hello can be held
          // to. handshake_failure, as OpenSSL. It went on to a full handshake.
          fatalAlert(wire.TLS_ALERT.HANDSHAKE_FAILURE, 'Resumption without extended_master_secret of a session made with it');
          return;
        } else if (!storedEMS && clientEMS) {
          // The other way: not resumed, a full handshake (§5.3).
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
      //
      // Two ways to choose, matching Node:
      //
      //   ALPNCallback  — synchronous, gets { servername, protocols } and
      //                   returns the chosen protocol, or undefined to refuse.
      //                   Lets the choice depend on SNI or anything else known
      //                   at this point, which a fixed list cannot do.
      //   ALPNProtocols — the static list; server preference order wins.
      //
      // RFC 7301 §3.2: if the client offered ALPN and no protocol is agreed,
      // the server MUST abort with no_application_protocol(120). Falling
      // through silently — which is what this did before — leaves the client
      // believing ALPN was simply not supported, and it then speaks whatever
      // it would have defaulted to. For a server that only serves h2 that is a
      // protocol confusion, not a graceful degradation.
      if (context.isServer && context.selected_alpn == null &&
          Array.isArray(context.remote_supported_alpns) &&
          context.remote_supported_alpns.length > 0) {

        let chosen = null;
        let refused = false;

        if (typeof context.ALPNCallback === 'function') {
          let picked;
          try {
            picked = context.ALPNCallback({
              servername: context.remote_sni || null,
              protocols: context.remote_supported_alpns.slice()
            });
          } catch (e) {
            // A throwing selector refuses. Treating it as "no preference"
            // would hand the peer a protocol the application rejected.
            picked = undefined;
          }
          if (typeof picked === 'string' && picked.length > 0) {
            // Only a protocol the client actually offered may be selected
            // (RFC 7301 §3.2) — echoing anything else is unnegotiable.
            if (context.remote_supported_alpns.indexOf(picked) >= 0) chosen = picked;
            else refused = true;
          } else {
            refused = true;
          }

        } else if (context.local_supported_alpns && context.local_supported_alpns.length > 0) {
          for (let a = 0; a < context.local_supported_alpns.length && chosen === null; a++) {
            let cand = context.local_supported_alpns[a];
            for (let b = 0; b < context.remote_supported_alpns.length; b++) {
              if (context.remote_supported_alpns[b] === cand) { chosen = cand; break; }
            }
          }
          if (chosen === null) refused = true;
        }
        // No callback and no configured list at all means this server does not
        // do ALPN. That is not a failed negotiation, so no alert: stay silent
        // and let the client fall back, as a pre-ALPN server would.

        if (chosen !== null) {
          params_to_set['selected_alpn'] = chosen;
        } else if (refused) {
          fatalAlert(wire.TLS_ALERT.NO_APPLICATION_PROTOCOL,
            'no overlap between offered ALPN protocols and this server');
          return;
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
          // Two passes over our preference order. First: a group the client
          // already sent a key share for — the handshake goes on in one round
          // trip. Only if there is none: the first group both sides support,
          // for which a HelloRetryRequest will ask. Choosing by preference
          // alone asked a client that listed the post-quantum group, but sent
          // its share for X25519, to start over — one wasted round trip on
          // every such connection (BoringSSL chooses the same way).
          //
          // A KEM group only in TLS 1.3: TLS 1.2's key exchange is ECDHE in a
          // ServerKeyExchange, and a KEM does not fit it.
          let selIs13 = pending('selected_version') === wire.TLS_VERSION.TLS1_3 ||
                        pending('selected_version') === wire.DTLS_VERSION.DTLS1_3;

          // Post-quantum before everything: a client that supports a KEM group
          // gets it even without a key share for it — the HelloRetryRequest
          // asks for one. Choosing by key share alone gave X25519 to a client
          // that listed the hybrid group but sent its share for X25519, so the
          // connection was not quantum-safe although both sides could have
          // made it so (and a scanner testing exactly that reported no PQ
          // support). It costs a round trip only for such clients: browsers
          // send the hybrid share up front.
          //
          // Among the post-quantum groups, the CLIENT's order — the first it
          // lists that we have, whether or not it sent a key share for it (a
          // HelloRetryRequest asks for one then). Each is post-quantum, so none
          // is weaker for us to accept, and the client has the reason for its
          // order we cannot see: CNSA 2.0's TLS profile has a client list
          // ML-KEM-1024 first and expects to get it; a browser lists
          // X25519MLKEM768 first, with its share, and gets it in one round
          // trip. Taking the first one it sent a share for gave a CNSA client
          // that sent its share for X25519MLKEM768 (or none) the hybrid
          // instead — a scanner reported exactly that.
          for (let i = 0; selIs13 && i < context.remote_supported_groups.length; i++) {
            let g = context.remote_supported_groups[i];
            if (!is_kem_group(g) || !is_supported_group(g) || context.local_supported_groups.indexOf(g) < 0) continue;
            params_to_set['selected_group'] = g;
            break;
          }

          for (let i = 0; !('selected_group' in params_to_set) && i < context.local_supported_groups.length; i++) {
            let g = context.local_supported_groups[i];
            if (context.remote_supported_groups.indexOf(g) < 0) continue;
            if (!is_supported_group(g)) continue;
            if (is_kem_group(g) && !selIs13) continue;
            let rk = context.remote_key_groups[g];
            if (!rk || !rk.public_key) continue;
            params_to_set['selected_group'] = g;
            break;
          }
          for (let i = 0; !('selected_group' in params_to_set) && i < context.local_supported_groups.length; i++) {
            let g = context.local_supported_groups[i];
            if (is_kem_group(g) && !selIs13) continue;
            if (context.remote_supported_groups.indexOf(g) < 0) continue;

            // Mutual support is not enough: we must be able to actually PRODUCE
            // a key share for the group. ecdh.js is the single source of truth
            // for which groups are implemented, and generate_keypair returns
            // null (rather than throwing) for one it does not know — so a group
            // that reaches here from configuration alone, such as a
            // post-quantum group named in a --curves list we merely echo back,
            // gets selected and then silently never produces a key. The
            // reactive loop then waits forever for a key share that cannot
            // exist: no ServerHello, no alert, connection held open. That is a
            // denial of service, and it is caused by trusting a configured list
            // over the implementation.
            if (!is_supported_group(g)) continue;

            params_to_set['selected_group'] = g;
            break;
          }
        }
      }
      


      // ── Negotiation outcome: decidable, or impossible? ──
      //
      // Every selection step above is written as "if not chosen yet, try to
      // choose" — which quietly conflates two very different states: the
      // inputs have not arrived yet, and the inputs HAVE arrived and share
      // nothing with ours. The first must wait; the second can never succeed.
      // Treating both as "wait" is what made a ClientHello offering only
      // groups/ciphers/versions we do not implement hang forever instead of
      // being refused — a stall is a DoS, and it is also how an unimplemented
      // post-quantum group (Kyber, X25519MLKEM768) took the connection down
      // without a single line of code mentioning it.
      //
      // This is deliberately ONE check covering all three negotiated
      // parameters rather than a special case per parameter: they fail for the
      // same reason and must fail the same way. RFC 8446 §4.1.1 / RFC 5246
      // §7.4.1.3.
      //
      // Only the server decides these; the client validates the server's
      // choice elsewhere. A non-empty remote cipher list is the signal that a
      // ClientHello was actually processed, so we never fire before the peer
      // has spoken.
      if (context.isServer && context.remote_supported_cipher_suites.length > 0) {

        let pickedVersion = pending('selected_version');

        if (pickedVersion === null && context.local_supported_versions.length > 0 &&
            context.remote_supported_versions.length > 0) {
          fatalAlert(wire.TLS_ALERT.PROTOCOL_VERSION,
            'No protocol version in common with the peer');
          return;
        }

        // Cipher and group are checked INDEPENDENTLY of the version outcome.
        //
        // These used to be nested inside `if (pickedVersion !== null)`, which
        // silently made "we could not agree on a group" undetectable whenever
        // version selection had not completed — and version selection does not
        // complete when local_supported_versions has not been configured yet,
        // which is exactly the state a bare server session is in. The result
        // was the original stall surviving for the one shape that matters:
        // a ClientHello offering ONLY an unimplemented group (Kyber,
        // X25519MLKEM768). Each parameter's failure is terminal on its own; one
        // undecided parameter must not mask another's impossibility.
        let pickedCipher = pending('selected_cipher_suite');
        if (pickedCipher === null &&
            context.local_supported_cipher_suites.length > 0 &&
            context.remote_supported_cipher_suites.length > 0) {
          fatalAlert(wire.TLS_ALERT.HANDSHAKE_FAILURE,
            'No cipher suite in common with the peer');
          return;
        }

        // Groups: only meaningful once the peer actually offered some. An
        // offer we share nothing with is terminal; note that a shared group
        // for which the peer merely sent no key_share is NOT this case —
        // selected_group is set there and HelloRetryRequest handles it.
        let pickedGroup = pending('selected_group');
        if (pickedGroup === null &&
            context.remote_supported_groups.length > 0 &&
            context.local_supported_groups.length > 0) {
          fatalAlert(wire.TLS_ALERT.HANDSHAKE_FAILURE,
            'No key-exchange group in common with the peer');
          return;
        }
      }

      //create the key by the group if dont have...
      // Curve-specific keygen lives in ecdh.js (single source of truth for
      // which groups exist and how their keys are formed); the loop only
      // decides WHEN a key is needed.
      if(context.selected_group !== null && context.selected_group in context.local_key_groups==false &&
         context.isServer && is_kem_group(context.selected_group)){

        // A KEM group, server side: there is no key pair of our own to make.
        // Our share is the ciphertext encapsulated to the client's key, and it
        // comes out of the same step as the secret — so both are set here,
        // and the ECDHE step below (which needs a private key of ours) is not
        // reached. Without the client's share yet, nothing: the
        // HelloRetryRequest below asks for it.
        let rk = context.remote_key_groups[context.selected_group];
        if (rk && rk.public_key) {
          try {
            let ex = kem_server_exchange(context.selected_group, rk.public_key);
            params_to_set['add_local_key_groups'] = [{
              group: context.selected_group,
              private_key: new Uint8Array(0),
              public_key: ex.public_key
            }];
            params_to_set['ecdhe_shared_secret'] = ex.shared_secret;
          } catch (e) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'Invalid peer key share for group 0x' + context.selected_group.toString(16) + ': ' + e.message);
            return;
          }
        }

      } else if(context.selected_group !== null && context.selected_group in context.local_key_groups==false){

        let kp = ecdh_generate_keypair(context.selected_group);
        if (kp) {
          params_to_set['add_local_key_groups']=[
            {
              group: context.selected_group,
              private_key: kp.private_key,
              public_key: kp.public_key
            }
          ];
        }

      }

      //get shared_secret...
      // Can we compute the ECDHE secret yet? Needs a chosen group, both halves
      // of the exchange present, and no secret computed already.
      let ecdheReady = context.selected_group !== null &&
                       context.ecdhe_shared_secret == null &&
                       (context.selected_group in context.local_key_groups) &&
                       (context.selected_group in context.remote_key_groups);

      if (ecdheReady) {

        //check we have remote public key and local private key...
        if(context.remote_key_groups[context.selected_group].public_key!==null && context.local_key_groups[context.selected_group].private_key!==null){

          let remote_public_key=context.remote_key_groups[context.selected_group].public_key;
          let local_private_key=context.local_key_groups[context.selected_group].private_key;

          // The peer's key share is fully attacker-controlled. ecdh.js owns the
          // point-format rules and throws on anything malformed (wrong length,
          // bad prefix, off-curve, low-order producing an all-zero secret per
          // RFC 7748 6.1); node:crypto throws too. Our job here is only to turn
          // any such failure into a fatal illegal_parameter (RFC 8446 4.2.8)
          // rather than let it escape through set_context into the transport's
          // data handler -- that would be a remote DoS on every transport.
          // fatalAlert moves us to a terminal state, so the reactive loop
          // cannot re-enter and retry the poisoned computation.
          try {
            params_to_set['ecdhe_shared_secret'] =
              ecdh_get_shared_secret(context.selected_group, local_private_key, remote_public_key);
          } catch (e) {
            fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'Invalid peer key share for group 0x' + context.selected_group.toString(16) + ': ' + e.message);
            return;
          }

        }
        
      }




      if(context.isServer==true){

        // HelloRetryRequest: if we selected a group but client didn't send a key_share for it
        // Read the negotiated values from params_to_set first. Version, cipher
        // and group are all decided EARLIER IN THIS SAME PASS and are only
        // copied into `context` when the pass commits, so reading `context`
        // here sees nulls on exactly the pass that processes the ClientHello.
        //
        // The consequence was a hang, not a wrong choice: a client that offers
        // a group we support but sends its key_share for a different one (very
        // much including an unimplemented post-quantum group offered alongside
        // X25519) needs a HelloRetryRequest, and we silently sent nothing at
        // all. The connection then sat open until the peer timed out — the same
        // "impossible mistaken for not-yet-decidable" confusion, one layer up.
        let hrrVersionNow = pending('selected_version');
        let hrrIs13 = hrrVersionNow === wire.TLS_VERSION.TLS1_3 ||
                      hrrVersionNow === wire.DTLS_VERSION.DTLS1_3;
        let hrrGroupNow = pending('selected_group');
        let hrrCipherNow = pending('selected_cipher_suite');

        if(context.hello_sent==false && !context.helloRetried && hrrIs13 &&
           hrrGroupNow !== null && hrrCipherNow !== null &&
           !(hrrGroupNow in context.remote_key_groups)){

          context.helloRetried = true;

          // Replace transcript with message_hash (RFC 8446 §4.4.1)
          let hashName = TLS_CIPHER_SUITES[hrrCipherNow].hash;
          let ch1_hash = getHashFn(hashName)(concatUint8Arrays(context.transcript));
          let message_hash = wire.build_message(wire.TLS_MESSAGE_TYPE.MESSAGE_HASH, ch1_hash);
          context.transcript = [message_hash];

          // Rebuild the running hash to match the reshaped transcript.
          reset_transcript_hash(hashName);

          // Build and send HRR (it's a ServerHello with magic random)
          let hrr_body = wire.build_hello_retry_request({
            cipher_suite: hrrCipherNow,
            // The version chosen in THIS pass (hrrVersionNow, above): it is
            // not in `context` until the pass commits. context.selected_version
            // was still null here, and the builder's fallback is TLS 1.3 —
            // right for TLS by accident, wrong for DTLS: the retry carried
            // 0x0304 where DTLS 1.3 is 0xfefc (RFC 9147), and a client that
            // checks (this one does, RFC 8446 §4.1.4) refused the ServerHello
            // that followed.
            selected_version: hrrVersionNow,
            selected_group: hrrGroupNow,
            session_id: context.remote_session_id,
            // ECH (RFC 9849 §7.2.1): accepted → 8 bytes confirming it,
            // computed below over this very message; rejected → 8 random
            // bytes, so a retry looks the same either way (§7.1, §10.10.4).
            // Last in the message, so they are its last 8 bytes.
            other_exts: context.ech.status ? [{ type: EXT_ECH, data: context.ech.status === 'accepted'
              ? new Uint8Array(8) : new Uint8Array(crypto.randomBytes(8)) }] : undefined,
          });
          let hrr_data = wire.build_message(wire.TLS_MESSAGE_TYPE.SERVER_HELLO, hrr_body);
          if (context.ech.status === 'accepted') {
            let th = getHashFn(hashName)(concatUint8Arrays(context.transcript.concat([hrr_data])));
            hrr_data.set(accept_confirmation(hashName, context.ech.inner_random, th, true, label_prefix_for(hrrVersionNow)), hrr_data.length - 8);
          }
          pushTranscript(hrr_data);

          ev.emit('message', 0, context.message_sent_seq, 'hello_retry_request', hrr_data);
          context.message_sent_seq++;

          // Reset for second ClientHello. The PSK too: it is decided again
          // from the second hello, its binder over this retry (RFC 8446
          // §4.2.11.2). It was kept from the first: a second hello with no
          // PSK, or another, still resumed with the first's — accepted on a
          // binder that never covered the hello it answered.
          context.psk_accepted = false;
          context.isResumed = false;
          context.psk_offered = null;
          context.resumed_ticket_data = null;
          context.resumed_ticket_state = null;
          context.early.candidate = null;
          if (context.resumed_peer_chain) { context.resumed_peer_chain = null; context.peerAuthorized = false; context.authorizationError = null; }
          context.remote_random = null;
          context.remote_extensions = [];
          context.remote_supported_versions = [];
          context.remote_supported_cipher_suites = [];
          context.remote_supported_signature_algorithms = [];

          // Don't proceed to ServerHello — wait for new ClientHello
        }

        let can_send_hello=false;

        // Nothing goes out while the certificate is still being looked up.
        //
        // The ServerHello COMMITS this connection to a cipher suite, and which
        // suites are even possible depends on the key type of the certificate
        // about to be presented — an ECDSA certificate cannot serve an
        // ECDHE_RSA suite. Sending it first is not merely early, it is a
        // decision made without its input.
        //
        // What that looked like in practice, with an asynchronous SNICallback:
        // ServerHello and EncryptedExtensions went out, the certificate
        // arrived a moment later, and by then nothing was left to run the
        // reactive loop again — so Certificate was never sent at all. The
        // handshake simply stopped, with no alert on either side, and the peer
        // waited until it timed out.
        if(context.hello_sent==false && !context.sni_pending && !context.early.pending){
          
          if(context.selected_version!==null && context.selected_cipher_suite!==null && context.selected_session_id!==null){
            if((is13())){
              if(context.selected_group in context.local_key_groups==true && context.local_key_groups[context.selected_group].public_key!==null){
                // After HRR, don't send ServerHello until CH2 provides the requested key_share
                if (!context.helloRetried || (context.selected_group in context.remote_key_groups)) {
                  can_send_hello=true;
                }
              }
            }else if((is12())){
              // Block ServerHello while waiting for async resumeSession decision
              if (!context.tls12_resume_pending) {
                can_send_hello=true;
              }
            }
          }
        }
        
        // The OCSP response (node:tls 'OCSPRequest') is asked for at the
        // moment the ServerHello could go — version, certificate and the
        // resumption decision all settled — and the ServerHello waits for it.
        // Asked any earlier (when the ClientHello's extensions arrive), a
        // TLS 1.2 resumption not yet decided was taken for a full handshake:
        // the application was asked, and the ServerHello promised a
        // CertificateStatus that never came.
        if (can_send_hello) {
          maybe_request_ocsp(context.selected_version);
          if (context.ocsp_pending) can_send_hello = false;
        }

        if(can_send_hello==true){

          if(context.local_random==null){
            context.local_random=new Uint8Array(crypto.randomBytes(32));

            // RFC 8446 §4.1.3: if we support TLS 1.3 but negotiated something
            // lower, stamp the downgrade sentinel into the last 8 bytes of the
            // ServerHello random so a 1.3-capable client can detect the downgrade.
            // Only meaningful for a real ServerHello (not HRR, which reuses the
            // magic HRR random), and only for the TLS transport (not DTLS here).
            if (context.local_supported_versions.indexOf(wire.TLS_VERSION.TLS1_3) >= 0) {
              if (context.selected_version === wire.TLS_VERSION.TLS1_2) {
                context.local_random.set(DOWNGRADE_SENTINEL_TLS12, 24);
              } else if (context.selected_version === wire.TLS_VERSION.TLS1_1 ||
                         context.selected_version === wire.TLS_VERSION.TLS1_0) {
                context.local_random.set(DOWNGRADE_SENTINEL_TLS11, 24);
              }
            }
          }

          let build_message_params=null;

          if((is13())){

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
              // legacy_session_id_echo.
              //
              // TLS 1.3 (RFC 8446 §4.1.3) requires the server to echo the
              // client's legacy_session_id verbatim — that is the whole point
              // of the Appendix D.4 compatibility mode.
              //
              // DTLS 1.3 requires the OPPOSITE. RFC 9147 §5: "DTLS
              // implementations do not use the TLS 1.3 'compatibility mode'
              // described in Appendix D.4 of [TLS13]. DTLS servers MUST NOT
              // echo the 'legacy_session_id' value from the client and
              // endpoints MUST NOT send ChangeCipherSpec messages."
              //
              // Same field, same struct, opposite MUST — and the shared engine
              // was doing the TLS thing for both transports. A DTLS peer that
              // enforces §5 sees an echo it never expected. This is exactly the
              // shape of the other DTLS 1.3 bugs: a legacy field whose meaning
              // inverted between the two protocols.
              session_id: (function () {
                // RFC 9147 §5 — see the note above.
                let isDtls = context.selected_version === wire.DTLS_VERSION.DTLS1_3;
                return isDtls ? new Uint8Array(0) : context.remote_session_id;
              })(),
              cipher_suite: context.selected_cipher_suite,
              extensions: shExtensions
            };
            

          }else if((is12())){

            
            // TLS 1.2 ServerHello: no SUPPORTED_VERSIONS or KEY_SHARE.
            // Include renegotiation_info (empty for initial handshake) and extended_master_secret.
            // ALPN (type=16) — optional, echoes selected protocol.

            // renegotiation_info only for a client that signalled it — the
            // extension or the SCSV (RFC 5746 §3.6: "the server MUST include
            // an empty renegotiation_info" then; unasked, an extension the
            // client never offered, RFC 5246 §7.4.1.4).
            let ext_list = context.client_secure_renegotiation ? [
              { type: 'RENEGOTIATION_INFO', value: new Uint8Array(0) }
            ] : [];

            // status_request, empty: a CertificateStatus follows the
            // Certificate (RFC 6066 §8). Only when there is one to send.
            if (context.ocsp_response) {
              ext_list.push({ type: wire.TLS_EXT.STATUS_REQUEST, data: new Uint8Array(0) });
            }

            // Only echo extended_master_secret if client sent it
            if (context.use_extended_master_secret) {
              ext_list.push({ type: 'EXTENDED_MASTER_SECRET', value: null });
            }

            // ec_point_formats (RFC 8422 §5.2): "included in a ServerHello
            // message in response to a ClientHello message containing the
            // Supported Point Formats Extension when negotiating an ECC cipher
            // suite", listing the formats we parse — uncompressed only, the
            // one every peer must support. Leaving it out cost nothing with
            // browsers, but it is a MUST, and scanners flag the server as
            // non-compliant (NIST SP 800-52) for it.
            if (is_ecdhe_suite(context.selected_cipher_suite)) {
              let clientFormats = null;
              for (let pfi = 0; pfi < context.remote_extensions.length; pfi++) {
                if (context.remote_extensions[pfi].type === wire.TLS_EXT.EC_POINT_FORMATS) {
                  clientFormats = context.remote_extensions[pfi].value;
                  break;
                }
              }
              if (clientFormats) {
                // §5.1.2: a client that lists formats without uncompressed,
                // having offered curves defined there, "MUST" be refused with
                // illegal_parameter: nothing else can carry its key share.
                if (clientFormats.indexOf(0) < 0) {
                  fatalAlert(wire.TLS_ALERT.ILLEGAL_PARAMETER, 'ec_point_formats without uncompressed');
                  return;
                }
                ext_list.push({ type: 'EC_POINT_FORMATS', value: [0] });
              }
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

            // Custom local extensions (generic pass-through — same mechanism
            // as the ClientHello and TLS 1.3 EncryptedExtensions paths).
            // This is where server-side answers to client-offered extensions
            // (e.g. use_srtp for DTLS-SRTP, RFC 5764 §4.1) go on the wire in
            // (D)TLS 1.2. Previously local_extensions were silently dropped
            // for the 1.2 ServerHello, so a server could never answer them.
            // Responsibility for only answering extensions the client
            // actually offered stays with the caller (it can inspect the
            // ClientHello via the 'clienthello' event / getRemoteExtension).
            // DTLS-SRTP answer for (D)TLS 1.2, where it rides the ServerHello
            // rather than EncryptedExtensions (which does not exist in 1.2).
            let srtpSel12 = negotiate_srtp_profile();
            if (srtpSel12 !== null) {
              context.selected_srtp_profile = srtpSel12;
              ext_list.push({ type: 'USE_SRTP',
                              value: { profiles: [srtpSel12], mki: new Uint8Array(0) } });
            }

            for (let lei = 0; lei < context.local_extensions.length; lei++) {
              ext_list.push(context.local_extensions[lei]);
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
            } else if (context.sessionIdStore && !context.sessionIdStore()) {
              sid_to_send = new Uint8Array(0);   // nothing would keep it: see sessionIdStore
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


            // ECH accepted (RFC 9849 §7.2): the last 8 bytes of the random
            // confirm it — zero while the transcript up to this ServerHello
            // is hashed, then that hash's confirmation.
            let echConfirm = build_message_params.type === 'server_hello' && is13() && context.ech.status === 'accepted';
            if (echConfirm) build_message_params.random.fill(0, 24);

            let message_data = build_tls_message(build_message_params);

            if (echConfirm) {
              let echHash = negotiated_hash();
              let th = getHashFn(echHash)(concatUint8Arrays(context.transcript.concat([message_data])));
              let conf = accept_confirmation(echHash, context.ech.inner_random, th, false, label_prefix());
              message_data.set(conf, 4 + 2 + 24);            // header, legacy_version, random[24..32]
              context.local_random.set(conf, 24);
            }

            // Our own hello counts too: on a server this is the ServerHello a
            // client would fingerprint us by, so getJA4S() answers in both
            // roles.
            if (build_message_params.type === 'server_hello') {
              context.rawServerHello = message_data;
              context.parsedServerHello = null;
              context.fpCache.ja4s = undefined;
            } else if (build_message_params.type === 'client_hello' && context.rawClientHello === null) {
              context.rawClientHello = message_data;
            }

            pushTranscript(message_data);

            context.hello_sent=true;

            ev.emit('message',0,context.message_sent_seq,'hello',message_data);

            context.message_sent_seq++;
          }
        }
          
      }else{

      }
      


      

      //get base_secret
      //
      // Guarded by hello_sent on the server, and this is not a formality.
      //
      // RFC 8446 §7.1 derives the handshake traffic secrets over
      // ClientHello || ServerHello — both of them. Running before our
      // ServerHello has been pushed to the transcript hashes ONE message
      // instead of two, so the server derives one set of keys and the client,
      // which has seen both, derives another. Nothing detects the mismatch:
      // the handshake completes and the first encrypted record fails with
      // bad_record_mac, which names the symptom and hides the cause entirely.
      //
      // Before an asynchronous SNICallback existed this could not happen —
      // hello_sent and the key derivation were reached on the same pass, in
      // that order. Holding the ServerHello back for a certificate lookup
      // separates them, and only then does the ordering become load-bearing.
      var _keysReadyToDerive = context.isServer ? (context.hello_sent === true) : true;

      if (context.base_secret==null && context.selected_cipher_suite !== null && _keysReadyToDerive){
        if((is13()) && (context.ecdhe_shared_secret !== null)){

          let hashName = negotiated_hash();
          let result;
          // Use incremental transcript hash — avoids concat+hash of full transcript
          let tx_hash = get_transcript_hash(hashName);
          if (context.psk_accepted && context.psk_offered && context.psk_offered.psk) {
            // PSK + ECDHE key schedule
            result = derive_handshake_traffic_secrets_psk_with_hash(hashName, context.psk_offered.psk, context.ecdhe_shared_secret, tx_hash, label_prefix());
          } else {
            // Standard key schedule (no PSK)
            result = derive_handshake_traffic_secrets_with_hash(hashName, context.ecdhe_shared_secret, tx_hash, label_prefix());
          }

          params_to_set['base_secret']=result.handshake_secret;

          if(context.isServer==true){
            params_to_set['remote_handshake_traffic_secret']=result.client_handshake_traffic_secret;
            params_to_set['local_handshake_traffic_secret']=result.server_handshake_traffic_secret;
          }else{
            params_to_set['local_handshake_traffic_secret']=result.client_handshake_traffic_secret;
            params_to_set['remote_handshake_traffic_secret']=result.server_handshake_traffic_secret;
          }

        }else if((is12()) && context.local_random!==null && context.remote_random!==null){
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
                let hashFn  = getHashFn(negotiated_hash());

                // Use snapshot up to CKE if available (excludes CertificateVerify)
                let emsTranscript = context._emsTranscriptLen
                  ? context.transcript.slice(0, context._emsTranscriptLen)
                  : context.transcript;
                let transcript_hash = hashFn(concatUint8Arrays(emsTranscript));

                let master_secret = tls12_prf(context.ecdhe_shared_secret, "extended master secret", transcript_hash, 48, negotiated_hash());

                params_to_set['base_secret']=master_secret;
              }
            }else{
              let master_secret = tls12_prf(context.ecdhe_shared_secret, "master secret", concatUint8Arrays([client_random, server_random]), 48, negotiated_hash());

              params_to_set['base_secret']=master_secret;
            }

            
            
            


          }
        }
      }



      //send encrypted_extensions...
      if (context.isServer==true && (is13())){
        if(context.encrypted_exts_sent==false && context.hello_sent==true && context.local_handshake_traffic_secret!==null){

          let extensions=[];
          if(context.selected_alpn!==null){
            extensions.push({ type: 'ALPN', value: [context.selected_alpn] });
          }
          // 0-RTT accepted (early_decide): early_data, empty (§4.2.10).
          if (early_decide()) extensions.push({ type: wire.TLS_EXT.EARLY_DATA, data: new Uint8Array(0) });

          // server_name acknowledgement (RFC 6066 §3, RFC 8446 §4.4.2).
          // When a client sent SNI and we accepted it, the server confirms by
          // echoing an EMPTY server_name extension here — no ServerNameList,
          // zero-length body. The extension is asymmetric: the list only ever
          // travels client→server.
          //
          // NOT on a resumed handshake. RFC 6066 §3: the acknowledgement means
          // "I used this name to select my certificate", which only happens in
          // a full handshake — on resumption the identity comes from the
          // established session instead, and sending the extension anyway is a
          // protocol error ("server acknowledged server_name when resuming").
          // The psk_accepted flag is the same signal the Certificate and
          // CertificateVerify steps already use to know they must be skipped.
          if (context.remote_sni && !context.psk_accepted) {
            extensions.push({ type: 'SERVER_NAME', value: null });
          }


          // The groups this server takes, in its preference (RFC 8446
          // §4.2.7): "servers ... MAY send supported_groups" in
          // EncryptedExtensions, for the client to start its NEXT connection
          // with a key share for one the server prefers — a HelloRetryRequest
          // round trip saved, or a stronger group chosen. The client may not
          // act on it in this handshake. Only what this build can carry out.
          {
            let eeGroups = [];
            for (let gi = 0; gi < context.local_supported_groups.length; gi++) {
              let g = context.local_supported_groups[gi];
              if (is_supported_group(g)) eeGroups.push(g);
            }
            if (eeGroups.length > 0) extensions.push({ type: 'SUPPORTED_GROUPS', value: eeGroups });
          }

          // DTLS-SRTP answer (RFC 5764 §4.1). One profile, empty MKI.
          let srtpSel = negotiate_srtp_profile();
          if (srtpSel !== null) {
            context.selected_srtp_profile = srtpSel;
            extensions.push({ type: 'USE_SRTP',
                              value: { profiles: [srtpSel], mki: new Uint8Array(0) } });
          }

          // ECH offered and not decrypted (RFC 9849 §7.1): the keys to use
          // instead. The client checks our certificate for the public name
          // and reconnects with them.
          if (context.ech.status === 'rejected' && context.ech_server && context.ech_server.retry_config_list) {
            extensions.push({ type: EXT_ECH, data: context.ech_server.retry_config_list });
          }

          for(let i = 0; i < context.local_extensions.length; i++){
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
      if(context.isServer==true && context.requestCert==true && !context.certificateRequestSent && context.encrypted_exts_sent==true && context.local_handshake_traffic_secret!==null && (is13()) && !context.psk_accepted){
        let cr_data = build_tls_message({
          type: 'certificate_request',
          certificate_request_context: new Uint8Array(0),
          signature_algorithms: context.local_supported_signature_algorithms,
          // The client's certificate may come compressed (RFC 8879).
          extensions: context.cert_compression.length > 0 ? [{ type: 'COMPRESS_CERTIFICATE', value: context.cert_compression }] : undefined,
        });
        pushTranscript(cr_data);
        context.certificateRequestSent = true;
        ev.emit('message', 1, context.message_sent_seq, 'certificate_request', cr_data);
        context.message_sent_seq++;
      }

      if(context.isServer==true && context.cert_sent==false && context.local_cert_chain!==null && !context.psk_accepted && !context.tls12_abbreviated){
        // When may we put our Certificate on the wire?
        //  1.3: it is encrypted, so it follows EncryptedExtensions and needs
        //       the handshake traffic secret to exist.
        //  1.2: it is cleartext and follows the ServerHello directly.
        let certDue13 = is13() && context.encrypted_exts_sent === true &&
                        context.local_handshake_traffic_secret !== null;
        let certDue12 = is12() && context.hello_sent === true;

        if(certDue13 || certDue12){

          // TLS 1.3: the OCSP response rides the leaf's CertificateEntry
          // (RFC 8446 §4.4.2.1) — inside the encrypted Certificate.
          let certEntries = context.local_cert_chain;
          if (is13() && context.ocsp_response) {
            certEntries = certEntries.slice();
            certEntries[0] = Object.assign({}, certEntries[0], {
              extensions: [{ type: wire.TLS_EXT.STATUS_REQUEST, data: wire.build_certificate_status(context.ocsp_response) }]
            });
          }
          let message_data = certificate_message(certEntries, new Uint8Array(0));
          pushTranscript(message_data);

          if ((is13())){
            ev.emit('message',1,context.message_sent_seq,'certificate',message_data);
          }else{
            ev.emit('message',0,context.message_sent_seq,'certificate',message_data);
          }

          context.message_sent_seq++;

          // TLS 1.2: its own message, right after the Certificate and before
          // ServerKeyExchange (RFC 6066 §8) — sent here, before cert_sent
          // lets the key exchange go.
          if (is12() && context.ocsp_response) {
            let cs_data = build_tls_message({ type: 'certificate_status', response: context.ocsp_response });
            pushTranscript(cs_data);
            ev.emit('message', 0, context.message_sent_seq, 'certificate_status', cs_data);
            context.message_sent_seq++;
          }

          context.cert_sent=true;
          

        }
      }



        


      //send certificate verify...
      if (context.isServer==true && (is13())){
        if(context.cert_sent==true && context.cert_verify_sent==false && context.local_cert_chain!==null && context.local_handshake_traffic_secret!==null && context.selected_cipher_suite!==null){

          let tbsHashName = negotiated_hash();
          let tbs_data = build_cert_verify_tbs_with_hash(tbsHashName, true, get_transcript_hash(tbsHashName));

          let cert_private_key_obj = local_private_key();

          // Scheme choice and signing belong to session/signing.js, which owns
          // the SignatureScheme registry for BOTH signing and verification.
          // This block used to re-declare the scheme constants, re-implement
          // pick_scheme's candidate/preference logic and re-implement
          // sign_with_scheme's padding+salt switch — ~90 lines duplicating that
          // module. It was already drifting: the fix that made RSA-PSS and
          // EdDSA usable in TLS 1.2 (RFC 8447/8422) landed in signing.js and
          // never reached this copy. One implementation, used by both roles.
          let selected_scheme = pick_scheme(
            wire.TLS_VERSION.TLS1_3,
            cert_private_key_obj,
            context.remote_supported_signature_algorithms || [],
            context.local_supported_signature_algorithms
          );

          let sig_data = null;
          if (selected_scheme !== null) {
            sig_data = sign_with_scheme(
              wire.TLS_VERSION.TLS1_3,
              selected_scheme,
              tbs_data,
              cert_private_key_obj
            );
          }

          if (selected_scheme === null || !sig_data) {
            fatalAlert(wire.TLS_ALERT.HANDSHAKE_FAILURE,
              'No signature scheme shared with peer for our certificate');
            return;
          }

          if(sig_data){
            context.selected_signature_algorithm = selected_scheme;   // reported (getNegotiationResult)

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
      if (context.key_exchange_sent == false && (is12())) {
        if(context.selected_group!==null && context.selected_group in context.local_key_groups==true && context.local_key_groups[context.selected_group].public_key!==null){

          if (context.isServer==false && context.remote_hello_done==true) {

            // TLS 1.2: send Certificate before CKE if server requested client auth
            if (context.certificateRequested && !context.clientCertSent) {
              context.clientCertSent = true;

              // The client's cert / key options (tls.connect's): what the 1.3
              // path sends. This one read only local_cert_chain, which a
              // client's options never fill — so a TLS 1.2 client sent an
              // empty Certificate whatever it was given.
              if ((!context.local_cert_chain || context.local_cert_chain.length === 0) && context.clientCert && context.clientKey) {
                let cc = { key: context.clientKey, cert: context.clientCert };
                if (context.clientKeyPassphrase) cc.passphrase = context.clientKeyPassphrase;
                let ccCtx;
                // A key that is not the certificate's (or unreadable): the
                // handshake ends here, an alert sent — it threw out of the
                // record layer, uncaught.
                try { ccCtx = createSecureContext(cc); }
                catch (e) { fatalAlert(wire.TLS_ALERT.INTERNAL_ERROR, 'client certificate: ' + e.message); return; }
                context.local_cert_chain = ccCtx.certificateChain;
                context.cert_private_key = ccCtx.privateKey;
              }

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
              let cert_key_obj = local_private_key();
              let reqAlgs = peer_requested_sig_algs();
              let scheme = pick_scheme(wire.TLS_VERSION.TLS1_2, cert_key_obj, reqAlgs, context.local_supported_signature_algorithms);
              let signature = scheme === null ? null : sign_with_scheme(wire.TLS_VERSION.TLS1_2, scheme, transcript_data, cert_key_obj);
              // As for TLS 1.3: no shared scheme is handshake_failure, not a
              // crash on a null signature.
              if (scheme === null || !signature) {
                fatalAlert(wire.TLS_ALERT.HANDSHAKE_FAILURE, 'No signature scheme shared with server for client certificate');
                return;
              }

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


            let cert_private_key_obj = local_private_key();

            let scheme12 = pick_scheme(wire.TLS_VERSION.TLS1_2, cert_private_key_obj, context.remote_supported_signature_algorithms, context.local_supported_signature_algorithms);
            let sig_data = scheme12 === null ? null : sign_with_scheme(wire.TLS_VERSION.TLS1_2, scheme12, tbs_data, cert_private_key_obj);
            // No scheme our key can sign with that the client accepts (or the
            // signing failed): handshake_failure. It went out with sig_alg 0
            // and an empty signature, for the client to refuse.
            if (scheme12 === null || !sig_data || sig_data.length === 0) {
              fatalAlert(wire.TLS_ALERT.HANDSHAKE_FAILURE, 'No signature scheme shared with the client for ServerKeyExchange');
              return;
            }

            
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

      // TLS 1.2 / DTLS 1.2 server: send CertificateRequest if mutual auth was
      // requested via { requestCert: true }. Per RFC 5246 §7.4.4 this message
      // goes between ServerKeyExchange and ServerHelloDone. The TLS 1.3 path
      // (line ~1805) sends CertificateRequest between EncryptedExtensions and
      // Certificate and is handled separately — version branching matters
      // because the wire formats differ (RFC 5246 §7.4.4 vs RFC 8446 §4.3.2).
      //
      // Without this block, a 1.2 server that sets requestCert never actually
      // requests the client's certificate, the client never sends one (TLS
      // clients only send a cert in response to CertificateRequest), and any
      // application-layer fingerprint check on the server fails with "peer
      // presented no certificate" — most notably breaking WebRTC, which
      // mandates mutual authentication (RFC 8827 §6.5) and pins to DTLS 1.2.
      if (context.isServer == true && context.requestCert == true &&
          !context.certificateRequestSent &&
          context.key_exchange_sent == true && !context.hello_done_sent &&
          (context.selected_version === wire.TLS_VERSION.TLS1_2 ||
           context.selected_version === wire.DTLS_VERSION.DTLS1_2)) {

        let cr_body = wire.build_certificate_request({
          version: wire.TLS_VERSION.TLS1_2,
          // rsa_sign(1), ecdsa_sign(64) — accept both. WebRTC uses ECDSA,
          // most other 1.2 deployments use RSA. The client picks whichever
          // matches its certificate.
          certificate_types: [1, 64],
          signature_algorithms: context.local_supported_signature_algorithms || [],
          certificate_authorities: [],  // empty: accept any CA
        });
        let cr_data = wire.build_message(wire.TLS_MESSAGE_TYPE.CERTIFICATE_REQUEST, cr_body);
        pushTranscript(cr_data);
        context.certificateRequestSent = true;
        ev.emit('message', 0, context.message_sent_seq, 'certificate_request', cr_data);
        context.message_sent_seq++;
      }

      //server hello done - 1.2 only...
      if(context.isServer==true && (is12())){
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
            lifetime: context.ticketLifetime,
            app: ticket_app_data(),
            cx: context.ticketContext || undefined,
            ...ticket_peer_fields(),
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

      // ECH rejected (RFC 9849 §6.1.6): the server's flight has been checked
      // — for the public_name — and nothing of ours follows it.
      if (context.isServer === false && context.ech.status === 'rejected' && context.ech.outer_ch1 &&
          context.remote_finished_ok === true && context.finished_sent === false) {
        ech_abort_rejected();
        return;
      }

      // Client, TLS over TCP, early data taken: EndOfEarlyData under the
      // early key, first in the second flight (RFC 8446 §4.5) — epoch 3 for
      // the record layer.
      if (!context.isServer && is13() && context.endOfEarlyData && context.early.status === 'accepted' &&
          !context.early.eoed && context.remote_finished_ok === true) {
        context.early.eoed = true;
        let eoed = build_tls_message({ type: 'end_of_early_data' });
        pushTranscript(eoed);
        ev.emit('message', 3, context.message_sent_seq, 'end_of_early_data', eoed);
        context.message_sent_seq++;
      }

      //send finished...
      // Client: send Certificate + CertificateVerify before Finished (if server requested)
      if(context.isServer==false && context.certificateRequested && !context.clientCertSent &&
         context.remote_finished_ok==true && context.local_handshake_traffic_secret!==null){
        context.clientCertSent = true;

        if(context.clientCert && context.clientKey){
          // Send client certificate
          // Only include passphrase when there is one — node:crypto treats an
          // explicit null as an error rather than as "no passphrase".
          let certOpts = { key: context.clientKey, cert: context.clientCert };
          if (context.clientKeyPassphrase) certOpts.passphrase = context.clientKeyPassphrase;
          let certCtx;
          try { certCtx = createSecureContext(certOpts); }
          catch (e) { fatalAlert(wire.TLS_ALERT.INTERNAL_ERROR, 'client certificate: ' + e.message); return; }
          let cert_data = certificate_message(certCtx.certificateChain, context.certificateRequestContext || new Uint8Array(0));
          pushTranscript(cert_data);
          ev.emit('message', 1, context.message_sent_seq, 'certificate', cert_data);
          context.message_sent_seq++;

          // Send CertificateVerify
          let hashName = negotiated_hash();
          let transcript_hash = get_transcript_hash(hashName);
          // Both calls had the wrong arity/order: pick_scheme takes
          // (version, keyObject, peerSupportedList) and sign_with_scheme takes
          // (version, scheme, tbs, keyObject). They were being passed a raw
          // DER key and shuffled arguments, so client-certificate auth could
          // never produce a valid signature.
          let clientKeyObj = crypto.createPrivateKey({
            key: Buffer.from(certCtx.privateKey),
            format: 'der',
            type: 'pkcs8',
          });
          let peerSigAlgs = peer_requested_sig_algs();

          let scheme = pick_scheme(wire.TLS_VERSION.TLS1_3, clientKeyObj, peerSigAlgs, context.local_supported_signature_algorithms);
          if (scheme === null) {
            fatalAlert(wire.TLS_ALERT.HANDSHAKE_FAILURE, 'No signature scheme shared with server for client certificate');
            return;
          }

          // TBS uses the CLIENT CertificateVerify label, over the transcript
          // hash taken before this message is pushed.
          let cvHash = negotiated_hash();
          let clientTbs = build_cert_verify_tbs_with_hash(cvHash, false, get_transcript_hash(cvHash));
          let signature = sign_with_scheme(wire.TLS_VERSION.TLS1_3, scheme, clientTbs, clientKeyObj);
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

        if((is13()) && context.local_handshake_traffic_secret!==null){

          // When is our Finished due (TLS 1.3, RFC 8446 §4.4.4)? Three distinct
          // situations, one per role/handshake kind — named rather than ORed
          // inline so each stays readable and independently checkable.
          //
          //  client: only after the server's Finished verified AND both
          //          application secrets exist (ours is the last message of
          //          the handshake).
          //  server, certificate handshake: after our CertificateVerify.
          //  server, PSK handshake: no Certificate/CertificateVerify at all,
          //          so EncryptedExtensions is the predecessor.
          let clientFinishedDue = context.isServer === false &&
                                  context.remote_finished_ok === true &&
                                  context.local_app_traffic_secret !== null &&
                                  context.remote_app_traffic_secret !== null;

          let serverCertFinishedDue = context.isServer === true &&
                                      context.cert_verify_sent === true &&
                                      context.local_cert_chain !== null;

          let serverPskFinishedDue = context.isServer === true &&
                                     context.psk_accepted === true &&
                                     context.encrypted_exts_sent === true;

          if(clientFinishedDue || serverCertFinishedDue || serverPskFinishedDue){

            let finHashName = negotiated_hash();
            // THE LABEL PREFIX BELONGS IN THE *FOURTH* ARGUMENT. It was being
            // passed to get_transcript_hash(), which takes only a hash name and
            // silently ignored it — so get_handshake_finished_with_hash received
            // labelPrefix=undefined and derived finished_key with the TLS 1.3
            // prefix "tls13 " instead of DTLS 1.3's "dtls13" (RFC 9147 §5.9).
            // Both peers running this library make the same substitution and
            // their Finished MACs agree, so it is invisible in a self-test and
            // shows up only against a conforming peer as
            // "Finished verify_data mismatch" — after every message parsed and
            // every signature verified.
            let finished_data=get_handshake_finished_with_hash(finHashName,context.local_handshake_traffic_secret,get_transcript_hash(finHashName), label_prefix());
            context.local_finished_data = finished_data;

            let message_data = build_tls_message({
              type: 'finished',
              data: finished_data
            });

            pushTranscript(message_data);

            // Checkpoint for app-secret derivation (see tls13_app_transcript_hash).
            // On the SERVER our own Finished IS the server Finished, so the
            // transcript is now exactly ClientHello..server Finished.
            if (context.isServer && context.tls13_app_transcript_hash === null) {
              context.tls13_app_transcript_hash = get_transcript_hash(finHashName);
            }

            context.finished_sent=true;

            ev.emit('message',1,context.message_sent_seq,'finished',message_data);

            context.message_sent_seq++;

          }

        }else if((is12())){

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

            let finishedHashName = negotiated_hash();
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
      if ((is13())){
        if(context.base_secret!==null && context.local_app_traffic_secret==null && context.remote_app_traffic_secret==null){

          if((context.isServer==true && context.finished_sent==true && context.remote_finished_ok==false) || (context.isServer==false && context.finished_sent==false && context.remote_finished_ok==true)){

            let appHashName = negotiated_hash();
            // Use the checkpoint captured when the server's Finished entered the
            // transcript. Reading the live transcript here would silently pick up
            // anything the loop emitted in between (client Certificate /
            // CertificateVerify), producing app keys the peer never derives.
            let appTranscriptHash = context.tls13_app_transcript_hash;
            if (appTranscriptHash === null) {
              // No checkpoint means we reached derivation without either side's
              // Finished passing through the transcript — a state-machine bug,
              // not a peer error. Refuse rather than derive from a guess.
              fatalAlert(wire.TLS_ALERT.INTERNAL_ERROR,
                'Internal error: app traffic secrets requested before the server Finished transcript checkpoint');
              return;
            }
            let result2 = derive_app_traffic_secrets_with_hash(appHashName, context.base_secret, appTranscriptHash, label_prefix());

            // Save master_secret for resumption before clearing
            params_to_set['tls13_master_secret'] = result2.master_secret;

            // RFC 8446 §7.1: exporter_master_secret uses the SAME transcript
            // hash (ClientHello..server Finished) as the app traffic secrets.
            // Kept for the lifetime of the connection so exportKeyingMaterial
            // (RFC 8446 §7.5) works after handshake completion.
            params_to_set['exporter_master_secret'] =
              derive_exporter_master_secret_with_hash(appHashName, result2.master_secret, appTranscriptHash, label_prefix());
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

        if((is13()) && context.remote_handshake_traffic_secret!==null){

          // Compute the expected peer Finished only once the peer's Finished
          // has actually arrived — for BOTH roles.
          //
          // verify_data is a MAC over the transcript as it stands immediately
          // before the peer's Finished, so the value is only well-defined at
          // that moment. The server used to compute it as soon as it had sent
          // its OWN Finished, which is a different point in the transcript:
          // with client authentication the client's Certificate and
          // CertificateVerify arrive in between, so the server's expectation
          // was fixed too early and every client-auth handshake failed with a
          // verify_data mismatch. (Without client auth the two points coincide,
          // which is why it went unnoticed.) The client already did this
          // lazily; both roles now share the same rule.
          if(context.remote_finished !== null){

            let remoteFinHashName = negotiated_hash();
            // Same fix as the local Finished above: the prefix is the FOURTH
            // argument, not an argument to get_transcript_hash().
            params_to_set['expected_remote_finished']=get_handshake_finished_with_hash(remoteFinHashName,context.remote_handshake_traffic_secret,get_transcript_hash(remoteFinHashName), label_prefix());

            // ── DIAGNOSTIC (LEMON_DEBUG=1 or WEBRTC_DEBUG=1) ──────────────
            // verify_data is a MAC over three inputs, and a mismatch means
            // ONE of them differs from what the peer computed. Two peers
            // running this same library make the SAME choice and agree with
            // each other, so a self-test can never expose it — only a real
            // peer (BoringSSL) can. Print all three so the difference is
            // visible instead of inferred:
            //   • which handshake messages went into the transcript, in
            //     order, with their lengths — a missing or duplicated
            //     message is the usual cause;
            //   • the transcript hash and the label prefix used;
            //   • both verify_data values.
            try {
              if (typeof process !== 'undefined' && process.env &&
                  (process.env.LEMON_DEBUG === '1' || process.env.WEBRTC_DEBUG === '1')) {
                var _hsNames = { 1:'ClientHello', 2:'ServerHello', 4:'NewSessionTicket',
                                 5:'EndOfEarlyData', 8:'EncryptedExtensions', 11:'Certificate',
                                 13:'CertificateRequest', 15:'CertificateVerify',
                                 20:'Finished', 24:'KeyUpdate', 254:'MessageHash' };
                var _t = context.transcript || [];
                var _list = [];
                for (var _ti = 0; _ti < _t.length; _ti++) {
                  var _e = _t[_ti];
                  if (!_e || !_e.length) { _list.push('?'); continue; }
                  _list.push((_hsNames[_e[0]] || ('type' + _e[0])) + '(' + _e.length + ')');
                }
                var _hex = function (u8) {
                  if (!u8) return 'null';
                  var s = '';
                  for (var _i = 0; _i < u8.length && _i < 16; _i++) {
                    s += ('0' + u8[_i].toString(16)).slice(-2);
                  }
                  return s + (u8.length > 16 ? '..' : '');
                };
                console.log('[lemon-fin] role=' + (context.is_server ? 'server' : 'client') +
                  ' version=0x' + (context.selected_version || 0).toString(16) +
                  ' labelPrefix="' + label_prefix() + '"' +
                  ' hash=' + remoteFinHashName);
                console.log('[lemon-fin] transcript(' + _t.length + '): ' + _list.join(' → '));
                console.log('[lemon-fin] transcriptHash=' +
                  _hex(get_transcript_hash(remoteFinHashName, label_prefix())));
                console.log('[lemon-fin] remoteSecret=' + _hex(context.remote_handshake_traffic_secret));
                console.log('[lemon-fin] peerSent=' + _hex(context.remote_finished));
                console.log('[lemon-fin] weExpect=' + _hex(params_to_set['expected_remote_finished']));
              }
            } catch (_eDiag) {}
            // ─────────────────────────────────────────────────────────────

          }

        }else if((is12()) && context.base_secret!==null){

          if(context.remote_finished!==null){


            let tls12FinHashName = negotiated_hash();
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

        // RFC 8446 §4.4.4: verify_data has exactly Hash.length bytes. A body
        // of any other length (BoGo: TrailingDataWithFinished) is a framing
        // violation — decode_error, checked BEFORE the value comparison so the
        // constant-time compare below always runs on equal-length inputs.
        if (context.remote_finished.length !== context.expected_remote_finished.length) {
          fatalAlert(wire.TLS_ALERT.DECODE_ERROR, 'Finished verify_data has wrong length (' +
            context.remote_finished.length + ', expected ' + context.expected_remote_finished.length + ')');
          return;
        }

        // Constant-time Finished comparison — verify_data is a MAC; a timing
        // oracle here would let a peer forge a valid Finished byte by byte.
        if(timingSafeEqualU8(context.remote_finished, context.expected_remote_finished)==true){

          let message_data = build_tls_message({
            type: 'finished',
            data: context.remote_finished
          });

          pushTranscript(message_data);

          // Checkpoint for app-secret derivation (see tls13_app_transcript_hash).
          // On the CLIENT the peer's Finished IS the server's Finished, so the
          // transcript is now exactly ClientHello..server Finished. Capture it
          // here, before the loop can append our own Certificate/CertificateVerify.
          if (!context.isServer && context.selected_cipher_suite !== null &&
              (context.selected_version === wire.TLS_VERSION.TLS1_3 ||
               context.selected_version === wire.DTLS_VERSION.DTLS1_3) &&
              context.tls13_app_transcript_hash === null) {
            let ckHash = negotiated_hash();
            context.tls13_app_transcript_hash = get_transcript_hash(ckHash);
          }

          params_to_set['remote_finished_ok']=true;

          context.remote_finished_data = context.remote_finished;
          context.remote_finished=null;
          context.expected_remote_finished=null;



        }else{
          // RFC 8446 §4.4.4: "Recipients of Finished messages MUST verify
          // that the contents are correct and if incorrect MUST terminate the
          // connection with a decrypt_error alert." The old behavior (null it
          // out and keep waiting) left the peer hanging with a half-open
          // handshake — and hid real key-schedule bugs.
          context.remote_finished=null;
          fatalAlert(wire.TLS_ALERT.DECRYPT_ERROR, 'Finished verify_data mismatch');
          return;
        }

      }
      



      if(context.state!=='connected' && context.remote_finished_ok==true && (((is13()) && context.local_app_traffic_secret!==null && context.remote_app_traffic_secret!==null) || (is12()))){

        // ── Authentication gate ──
        // Peer authentication is enforced HERE, at the single point where the
        // handshake is declared complete, and deliberately not (only) in the
        // per-message branches. A message-level check can be bypassed simply by
        // OMITTING the message: BoGo's SkipClientCertificate does exactly that,
        // and an "empty certificate_list" check in the Certificate branch never
        // runs because no Certificate ever arrives. In a reactive state machine
        // the durable place for a MUST-have-happened invariant is the state
        // transition it guards, not the event that usually satisfies it.

        // Client: the server must have proved possession of its certificate
        // key — TLS 1.3 CertificateVerify, or the TLS 1.2 ServerKeyExchange
        // signature. PSK/abbreviated handshakes authenticate via the binder /
        // resumed master secret instead.
        if (!context.isServer && !context.psk_accepted && !context.tls12_abbreviated &&
            context.peerSignatureVerified !== true) {
          fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE,
            'Handshake completed without a verified server signature');
          return;
        }

        // Server-side client authentication. Two DIFFERENT questions, which
        // were previously collapsed into one condition:
        //
        //   (a) Must a client certificate arrive at all?  -> policy, and only
        //       when we both asked for one and refuse to proceed without it.
        //   (b) If a certificate DID arrive, must it be proved?  -> ALWAYS.
        //
        // Collapsing them meant a server with requestCert but without
        // rejectUnauthorized skipped the whole block, so a client could send a
        // certificate — any certificate, including one it does not own — and
        // never prove possession, because the CertificateVerify check lived
        // behind the (a) policy flag. Presenting someone else's certificate is
        // an impersonation, not a policy preference, so (b) cannot be optional.
        if (context.isServer && !context.psk_accepted && !context.tls12_abbreviated) {

          let clientCertPresent = !!(context.remote_cert_chain && context.remote_cert_chain.length > 0);

          // (a) required-but-absent
          if (context.requestCert && context.rejectUnauthorized && !clientCertPresent) {
            fatalAlert(wire.TLS_ALERT.CERTIFICATE_REQUIRED,
              'Client certificate was required but none was provided');
            return;
          }

          // (b) present-but-unproved. Unconditional: it applies even when the
          // certificate was optional, because the question is not "did we want
          // one" but "does this peer own the one it sent". In TLS 1.2 the
          // client's CertificateVerify sets peerSignatureVerified the same way
          // — every version, now: this was 1.3-only, whatever this said.
          if (clientCertPresent && context.peerSignatureVerified !== true) {
            fatalAlert(wire.TLS_ALERT.UNEXPECTED_MESSAGE,
              'Client sent a certificate without a valid CertificateVerify');
            return;
          }
        }

        context.state='connected';
        context.handshakeEndTime = Date.now();

        // The TLS 1.3 ticket goes out BEFORE secureConnect, as OpenSSL (and so
        // Node) sends it. Emitted after, a server that answered and closed from
        // its secure handler — a health check, a redirect — closed before the
        // ticket was written, and its clients never received one; and one that
        // wrote from the handler put its data ahead of the ticket. Both records
        // use the application keys, which exist from the server's Finished on.
        // TLS 1.3: compute resumption_master_secret (both client and server need it)
        if ((is13()) && context.tls13_master_secret && !context.resumption_master_secret) {
          let hashName = negotiated_hash();
          context.resumption_master_secret = derive_resumption_master_secret_with_hash(
            hashName, context.tls13_master_secret, get_transcript_hash(hashName, label_prefix())
          );
        }

        // TLS 1.3 server: send NewSessionTicket
        // Two after a full handshake, one after a resumption — as OpenSSL and
        // BoringSSL issue them: a client uses each ticket once (RFC 8446 §C.4:
        // a ticket reused links the connections, and its 0-RTT is refused as
        // a replay), so a client opening two connections at once — or the
        // next before this one ends — has one for each.
        if ((is13()) && context.isServer && !context.session_ticket_sent && context.sessionTickets && context.resumption_master_secret) {
          context.session_ticket_sent = true;
          issue_ticket_13();
          if (!context.psk_accepted) issue_ticket_13();
        }

        ev.emit('secureConnect');

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
            lifetime: context.ticketLifetime,
            app: ticket_app_data(),
            cx: context.ticketContext || undefined,
            ...ticket_peer_fields(),
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
            ...client_session_peer_fields(),
          });
          ev.emit('session', session_blob);
        }
      }


      
      set_context(params_to_set);
    }
  }

  /**
   * The peer's leaf certificate shaped the way Node's checkServerIdentity
   * expects: `subject` / `subjectaltname` as OpenSSL-formatted strings, plus
   * the fingerprints an app needs to pin against.
   *
   * Deliberately the same shape TLSSocket#getPeerCertificate() returns, so a
   * check written against one works against the other.
   */
  function peer_cert_for_identity() {
    let chain = context.remote_cert_chain;
    if (!chain || chain.length === 0) return null;
    return certificateObject(chain[0].cert || chain[0]);
  }

  /**
   * RFC 6125 identity check, or the caller's replacement for it.
   *
   * Node semantics: `checkServerIdentity` REPLACES the built-in check rather
   * than adding to it — returning undefined accepts, returning an Error
   * rejects. That is what lets an app pin a fingerprint, or deliberately
   * accept a name the default rules would refuse.
   *
   * The option was documented and exported but never read, so a caller who
   * passed one got no error and no call: their check silently never ran while
   * the connection reported itself verified.
   *
   * Returns true to continue, false when the caller should stop — the failure
   * state is already recorded on context by then.
   */
  function checkIdentity(x509) {
    // ECH rejected: the server answered as the config's public_name, and
    // must prove that name (RFC 9849 §6.1.6), not the one in the inner hello.
    let expectName = context.ech.verify_name || context.local_sni;
    if (context.isServer || !expectName) return true;

    if (typeof context.checkServerIdentity === 'function') {
      let err;
      try {
        err = context.checkServerIdentity(expectName, peer_cert_for_identity());
      } catch (e) {
        // A throwing check is a failed check. Swallowing it would authorize
        // the peer on a bug in the caller's code.
        err = e instanceof Error ? e : new Error(String(e));
      }
      if (err) {
        context.authorizationError = err.message || 'ERR_TLS_CERT_ALTNAME_INVALID';
        context.peerAuthorized = false;
        return false;
      }
      return true;
    }

    // checkHost matches DNS names and ignores IP SANs entirely, so a
    // connection to a literal address whose certificate carries the matching
    // IP SAN was rejected. RFC 6066 says SNI carries host names only, but this
    // field is populated from whatever the caller connected to, so an address
    // does land here. X509Certificate exposes checkIP for exactly this.
    let host = String(expectName);
    let ok = is_ip_literal(host)
      ? !!x509.checkIP(host.replace(/^\[|\]$/g, ''))
      : !!x509.checkHost(host);

    if (!ok) {
      context.authorizationError = 'ERR_TLS_CERT_ALTNAME_INVALID';
      context.peerAuthorized = false;
      return false;
    }
    return true;
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


      // Verify the full chain against the configured trust anchors.
      //
      // NOTE the `context.ca == null` branch. Previously the entire check was
      // wrapped in `if (context.ca)`, so "no CA configured" meant "authorize
      // everything" — while rejectUnauthorized defaulted to true, which reads
      // as though verification were on. That is a MITM hole for any plain-TLS
      // consumer of this library. It is preserved here ONLY because callers
      // (notably the WebRTC/DTLS path, which authenticates by SDP fingerprint
      // and sets rejectUnauthorized:false) may rely on it — but it is now
      // explicit, recorded in authorizationError, and trivial to flip.
      // See LEMON_TLS_INSECURE_NO_CA below.
      // Resolve trust anchors: explicit `ca` first, then the platform store.
      //
      // This is the fix for the branch below. Previously an absent `ca` meant
      // "authorize everything" while rejectUnauthorized defaulted to true, so
      // a plain-TLS caller who configured nothing got a connection that
      // reported itself verified and was not. Node has always fallen back to
      // its bundled roots; now so do we.
      let anchors = context.ca;
      if ((anchors == null || (Array.isArray(anchors) && anchors.length === 0)) &&
          context.useDefaultCA && context.defaultCA) {
        let roots = context.defaultCA();
        if (roots && roots.length > 0) anchors = roots;
      }

      if (anchors == null ||
          (Array.isArray(anchors) && anchors.length === 0)) {
        // The identity check still runs here. It is the only check left, and
        // skipping it would make "no CA configured" mean "no verification at
        // all" — including any fingerprint pin the caller installed precisely
        // because there is no CA to chain to.
        if (!checkIdentity(x509)) return;
        context.peerAuthorized = true;
        context.authorizationError = null;
        context.certChainUnverified = true;   // no trust anchors were available
        return;
      }

      let cas = Array.isArray(anchors) ? anchors : [anchors];
      let chainResult = verify_cert_chain(context.remote_cert_chain, cas, now);
      if (!chainResult.ok) {
        context.authorizationError = chainResult.error;
        context.peerAuthorized = false;
        return;
      }

      // Identity comes LAST, after the chain verifies.
      //
      // Node documents checkServerIdentity as "only called if the certificate
      // passed all other checks, such as being issued by a trusted CA". The
      // order is not cosmetic: a hook that only compares a fingerprint and
      // returns undefined would, if run first, authorize a peer whose chain
      // never verified — the hook author reasonably assumes the CA check
      // already happened. Running identity before the chain quietly turns
      // every such pin into the ONLY check.
      if (!checkIdentity(x509)) return;

      // All checks passed
      context.peerAuthorized = true;
      context.authorizationError = null;

    } catch(e) {
      context.authorizationError = e.message || 'CERTIFICATE_PARSE_ERROR';
      context.peerAuthorized = false;
    }
  }


  function sendAlert(level, description) {
    // Nothing may follow a fatal alert (RFC 8446 §6.2). The guard lives here,
    // at the single point every alert leaves through, rather than at each
    // caller — a caller that forgets is exactly how the stray close_notify
    // arose. `fatalAlert` has its own early return for the same reason; this
    // covers the warning-level paths too.
    if (context.state === 'error' || context.state === 'closed') return;

    let alertData = new Uint8Array([level, description]);

    // Alerts must go out at the protection level the PEER is currently reading
    // at, otherwise they are unreadable and the real reason for the abort is
    // lost behind a decrypt failure.
    //
    //   epoch 0 — cleartext: before any keys exist, and for all of TLS 1.2's
    //             handshake (alerts stay cleartext until CCS).
    //   epoch 1 — handshake keys: TLS 1.3 after ServerHello but before our
    //             Finished has been sent. This case was missing entirely.
    //   epoch 2 — application keys.
    //
    // The subtlety is that the right answer depends on what the PEER reads,
    // not on whether WE consider the handshake finished. In TLS 1.3 a server
    // that has already sent its Finished has handed the client everything it
    // needs to switch to application keys, and the client does so immediately —
    // so an abort discovered afterwards (a missing client Certificate is
    // discovered exactly there) must be encrypted under application keys even
    // though our own state is not yet 'connected'. Encrypting it under
    // handshake keys produced an undecryptable record and the peer reported a
    // decrypt error instead of certificate_required.
    let epoch;
    if (context.state === 'connected') {
      epoch = 2;
    } else if (is13() && context.local_app_traffic_secret !== null && context.finished_sent) {
      epoch = 2;
    } else if (is13() && context.local_handshake_traffic_secret !== null) {
      epoch = 1;
    } else {
      epoch = 0;
    }


    ev.emit('message', epoch, 0, 'alert', alertData);
    ev.emit('alert', { level: level, description: description });
    if (level === 2) {
      // Fatal alert — session is dead
      context.state = 'error';
    }
  }

  function close(){
    // 'error' counts as closed. RFC 8446 §6.2: after a fatal alert the
    // connection is torn down immediately and NO further record may be sent.
    // close_notify signals an ORDERLY shutdown, so emitting one after a failure
    // both contradicts the alert we just sent and appends a record the peer is
    // not expecting — it reads the fatal alert, then hits an extra record and
    // reports a decrypt failure instead of the reason we actually gave it.
    // Testing only for 'closed' missed exactly this case.
    if (context.state === 'closed' || context.state === 'error') {
      context.state = 'closed';
      return;
    }
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

      // TLS 1.3-only mode (QUIC and any client that offers no other version):
      // the ClientHello must not carry TLS 1.2 baggage. QUIC mandates TLS 1.3
      // (RFC 9001), and strict 1.3-only stacks reject hellos with legacy
      // artifacts. Detected from the configured versions, so plain TLS over
      // TCP (which offers 1.3+1.2) keeps the full compatibility behavior.
      // Which versions does this profile actually offer? The suite list must
      // follow BOTH answers, not just one of them.
      //
      // The old form asked only "is this 1.3-only?" and hardcoded the 1.3 half
      // to true, so a 1.2-ONLY profile still advertised 0x1301..0x1303. Those
      // suites cannot be negotiated at 1.2 — a TLS 1.3 suite is meaningless in
      // a 1.2 handshake — so the hello claimed capabilities the profile had
      // ruled out. The asymmetry was invisible because only the 1.3-only case
      // had ever been considered.
      let offers13 = context.local_supported_versions.length === 0 ||
                     context.local_supported_versions.indexOf(wire.TLS_VERSION.TLS1_3) >= 0 ||
                     context.local_supported_versions.indexOf(wire.DTLS_VERSION.DTLS1_3) >= 0;
      let offers12 = context.local_supported_versions.length === 0 ||
                     context.local_supported_versions.some(v => v !== wire.TLS_VERSION.TLS1_3 &&
                                                                v !== wire.DTLS_VERSION.DTLS1_3);

      if(context.local_supported_cipher_suites.length<=0){
        // crypto.js owns the default suite list; we only say which halves apply.
        context.local_supported_cipher_suites = default_cipher_suites(offers13, offers12);
      }

      if(context.local_supported_groups.length<=0){
        context.local_supported_groups = ECDH_SUPPORTED_GROUPS.slice(); // whatever ecdh.js implements
      }

      if(context.local_supported_versions.length<=0){
        context.local_supported_versions=[0x0304, 0x0303]; // TLS 1.3, TLS 1.2
      }

      // Initial key_share: generate for our most-preferred group that we can
      // actually PRODUCE a share for. If the server wants a different one it
      // sends HelloRetryRequest, handled above.
      //
      // The list may name groups ecdh.js does not implement — a configured
      // curve list is not a capability list, and a post-quantum group can sit
      // in it because a caller passed it straight through. generate_keypair
      // returns null for those (it does not throw), and this code used to read
      // `.public_key` off that null and crash the whole session with a
      // TypeError before a single byte was sent. Skip what we cannot make; if
      // that leaves nothing, say so plainly rather than dying.
      let initialGroup = null;
      let initialKp = null;
      for (let gi = 0; gi < context.local_supported_groups.length; gi++) {
        let g = context.local_supported_groups[gi];
        if (!is_supported_group(g)) continue;
        if (!offers13 && is_kem_group(g)) continue;   // not in a 1.2-only hello (see above)
        let kp = ecdh_generate_keypair(g);
        if (!kp) continue;
        initialGroup = g;
        initialKp = kp;
        break;
      }

      if (initialKp === null) {
        fatalAlert(wire.TLS_ALERT.INTERNAL_ERROR,
          'No configured key-exchange group is implemented — cannot build a key_share');
        return;
      }

      let public_key = initialKp.public_key;

      context.local_key_groups[initialGroup]={
        public_key: initialKp.public_key,
        private_key: initialKp.private_key
      };

      // A post-quantum group first gets a classical share beside it — the
      // next implemented non-KEM group in the list — as browsers do. A server
      // without the hybrid group then uses the classical share at once; with
      // only the hybrid share it would have to ask again (HelloRetryRequest),
      // a round trip on every connection to a classical server. Each share's
      // key stays in local_key_groups, so whichever the server picks is there.
      let extraKeyShares = null;
      if (is_kem_group(initialGroup)) {
        for (let gi = 0; gi < context.local_supported_groups.length; gi++) {
          let g2 = context.local_supported_groups[gi];
          if (g2 === initialGroup || is_kem_group(g2) || !is_supported_group(g2)) continue;
          let kp2 = ecdh_generate_keypair(g2);
          if (!kp2) continue;
          context.local_key_groups[g2] = { public_key: kp2.public_key, private_key: kp2.private_key };
          extraKeyShares = [{ group: g2, key_exchange: kp2.public_key }];
          break;
        }
      }

      // Honor the configured signature algorithms; the hardcoded list is only
      // the default when none were set (previously the configured list was
      // ignored here — while the HRR CH2 hardcoded its own, so CH1 and CH2
      // could differ, violating RFC 8446 §4.1.2's exact-match requirement).
      let ch_sigalgs = (context.local_supported_signature_algorithms &&
                        context.local_supported_signature_algorithms.length > 0)
        ? context.local_supported_signature_algorithms
        : default_signature_schemes();   // signing.js owns the list
      context.local_supported_signature_algorithms = ch_sigalgs; // for CH2 reuse

      // supported_versions (43) and key_share (51) are the TLS 1.3
      // negotiation machinery (RFC 8446 §4.1.2, §4.2.8). Offer them only
      // when 1.3 is actually in the offered version set — a pure 1.2
      // hello must look like a 1.2 hello, exactly as OpenSSL/BoringSSL
      // behave with max_version=1.2. Previously both were emitted
      // unconditionally, so even a maxVersion:'DTLSv1.2' profile (the
      // WebRTC default) advertised a single-entry supported_versions and
      // a dangling key_share: spec-legal (receivers MUST ignore unknown
      // extensions, RFC 5246 §7.4.1.4) but non-canonical — and fatal to
      // at least one deployed stack (webrtc-dtls ≤0.7 hard-errors on any
      // extension outside its known set, then poisons its replay window
      // so no retransmission can ever recover the handshake).
      // Same assembler as the post-HelloRetryRequest CH2 (RFC 8446 §4.1.2
       // requires the two hellos to be identical apart from key_share/cookie).
      let extensions = build_client_hello_extensions({
        keyShareGroup: initialGroup,
        keySharePublic: public_key,
        extraKeyShares: extraKeyShares,
        cookie: null
      });

      // ECH: this list is the inner hello's; the outer one is made from it
      // once the inner hello — its PSK binder included — is complete.
      let echSplit = null;
      if (ech_on()) {
        context.ech.inner_random = context.local_random;
        context.ech.outer_random = new Uint8Array(crypto.randomBytes(32));
        echSplit = ech_split(extensions);
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
        // A saved session: only where it may be (client_session_usable). An
        // external PSK (options.psk) authenticates the server by itself.
        if (sessionData && !client_session_usable(sessionData)) sessionData = null;
      } else if (options.psk) {
        sessionData = options.psk; // legacy path
      }

      let message_data;

      // TLS 1.3 PSK resumption (sessionData contains psk)
      if (sessionData && sessionData.psk && sessionData.ticket && sessionData.cipher) {
        // psk_key_exchange_modes (psk_dhe_ke) is already in the hello: the
        // assembler adds it to every hello that offers 1.3.

        // Save PSK for later verification
        context.psk_offered = {
          identity: sessionData.ticket,
          psk: sessionData.psk instanceof Uint8Array ? sessionData.psk : new Uint8Array(sessionData.psk),
          cipher: sessionData.cipher,
          age_add: sessionData.age_add || 0,
          created: sessionData.created, lifetime: sessionData.lifetime,   // the age again, in a second hello
          session: options.session ? sessionData : null,   // the server it was made with (restore_client_session_peer)
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
        // 0-RTT (RFC 8446 §4.2.10): offered with a ticket that allows it,
        // when the ALPN it was made with is one offered now (the server must
        // pick it again). With ECH too (RFC 9849 §6.1): the early data is
        // the inner hello's — its keys from the inner transcript, which a
        // server that decrypts it uses — and early_data goes in the outer
        // hello as well, so a server that does not decrypt it knows to skip
        // what follows (RFC 8446 §4.2.10). Early data was never offered with
        // ECH: a client using ECH paid a round trip on every resumption.
        if (context.earlyData && (sessionData.max_early_data >>> 0) > 0 &&
            (!sessionData.alpn || (context.local_supported_alpns || []).indexOf(sessionData.alpn) >= 0)) {
          let edExt = { type: wire.TLS_EXT.EARLY_DATA, data: new Uint8Array(0) };
          extensions.push(edExt);
          note_offered_extensions([edExt]);
          if (echSplit) echSplit.outer.push(edExt);
          context.early.offered = true;
          context.early.alpn = sessionData.alpn || null;
          context.early.maxEarly = sessionData.max_early_data >>> 0;
          context.early.appData = sessionData.qa != null ? sessionData.qa : null;
        }
        extensions.push(pskExt); // MUST be last
        note_offered_extensions([pskExt]);
        // ECH: the ticket is the inner hello's alone; the outer one carries
        // a pre_shared_key of the same shape with random contents (RFC 9849
        // §10.12.3), so it does not show resumption was attempted — and a
        // server that does not decrypt finds no ticket there, and does a
        // full handshake. Last in the outer hello too.
        if (echSplit) {
          echSplit.outerPsk = {
            type: 'PRE_SHARED_KEY',
            value: {
              identities: [{ identity: new Uint8Array(crypto.randomBytes(sessionData.ticket.length)), age: crypto.randomBytes(4).readUInt32BE(0) }],
              binders: [new Uint8Array(crypto.randomBytes(hashLen))]
            }
          };
        }

        // Build the full message with placeholder
        let build_message_params = {
          type: 'client_hello',
          version: 0x0303,
          random: context.local_random,
          session_id: context.local_session_id,
          cookie: context.dtls_cookie,
          // BUGFIX: `cipher_suites` (plural) is what wire.js's client_hello
          // builder actually reads; the singular key was silently ignored and
          // wire.js substituted its own hardcoded fallback list — the
          // configured cipher suites never reached the wire. Both names passed.
          cipher_suites: grease_cipher_suites(context.local_supported_cipher_suites),
          cipher_suite: context.local_supported_cipher_suites,
          extensions: extensions
        };
        let tempMessage = build_tls_message(build_message_params);

        // Truncation point: message length - binders vec (2 + 1 + hashLen)
        let bindersSize = 2 + 1 + hashLen;
        let truncatedMessage = tempMessage.slice(0, tempMessage.length - bindersSize);

        // Compute real binder
        let binder_key = derive_binder_key(hashName, context.psk_offered.psk, false, label_prefix());
        let binder = compute_psk_binder(hashName, binder_key, truncatedMessage, label_prefix());

        if (LEMON_DEBUG) dbg('CLI-PSK', 'ticket:', hexPreview(sessionData.ticket, 24),
            'cipher:', '0x' + sessionData.cipher.toString(16),
            'hash:', hashName);
        if (LEMON_DEBUG) dbg('CLI-PSK', 'psk:', hexPreview(sessionData.psk, 8),
            'age_add:', sessionData.age_add,
            'lifetime:', sessionData.lifetime,
            'ticketAge (ms):', ticketAge,
            'obfuscatedAge:', obfuscatedAge);
        dbg('CLI-PSK', 'truncatedMessage len:', truncatedMessage.length,
            'full CH len (after real binder):', 'see next');
        if (LEMON_DEBUG) dbg('CLI-PSK', 'sent binder:', hexPreview(binder, 16));

        // Rebuild with real binder
        pskExt.value.binders = [binder];
        message_data = build_tls_message(build_message_params);

      } else if (!echSplit && sessionData && sessionData.v === 12 && sessionData.master_secret) {
        // TLS 1.2 resumption: session ID and/or SessionTicket
        // Save for later verification when ServerHello arrives
        context.tls12_client_session = sessionData;

        // Only advertise SESSION_TICKET ext if we actually have a ticket to present.
        // If we only have a session_id (no ticket), don't include empty SESSION_TICKET ext:
        // servers with SSL_OP_NO_TICKET can behave inconsistently when the extension appears
        // alongside a session_id resumption attempt — they may skip the session_id lookup.
        // Fill in the ticket on the SESSION_TICKET entry the assembler already
        // produced, rather than pushing a second one — two extensions of the
        // same type is itself a protocol violation (RFC 8446 §4.2), and it
        // would also change CH2's extension list relative to CH1. If the
        // assembler did not emit one (1.3-only or DTLS profile), there is
        // nothing to resume with here anyway.
        if (sessionData.ticket && sessionData.ticket.length > 0) {
          let stEntry = null;
          for (let ei = 0; ei < extensions.length; ei++) {
            if (extensions[ei] && extensions[ei].type === 'SESSION_TICKET') { stEntry = extensions[ei]; break; }
          }
          if (stEntry) stEntry.value = sessionData.ticket;
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
          // BUGFIX: `cipher_suites` (plural) is what wire.js's client_hello
          // builder actually reads; the singular key was silently ignored and
          // wire.js substituted its own hardcoded fallback list — the
          // configured cipher suites never reached the wire. Both names passed.
          cipher_suites: grease_cipher_suites(context.local_supported_cipher_suites),
          cipher_suite: context.local_supported_cipher_suites,
          extensions: extensions
        };
        message_data = build_tls_message(build_message_params);

      } else {
        // No resumption — advertise empty SessionTicket extension to offer support.
        // Skip for DTLS (DTLS clients/servers often don't implement RFC 5077 fully,
        // and adding it caused interop issues with openssl s_server -dtls1_2).
        // Standard ClientHello
        let build_message_params = {
          type: 'client_hello',
          version: 0x0303,
          random: context.local_random,
          session_id: context.local_session_id,
          cookie: context.dtls_cookie,
          // BUGFIX: `cipher_suites` (plural) is what wire.js's client_hello
          // builder actually reads; the singular key was silently ignored and
          // wire.js substituted its own hardcoded fallback list — the
          // configured cipher suites never reached the wire. Both names passed.
          cipher_suites: grease_cipher_suites(context.local_supported_cipher_suites),
          cipher_suite: context.local_supported_cipher_suites,
          extensions: extensions
        };
        message_data = build_tls_message(build_message_params);
      }

      // ECH: what goes on the wire is the outer hello; the transcript has the
      // inner one until the ServerHello says which (ech_decide).
      let onWire = message_data;
      if (echSplit) {
        onWire = ech_outer_hello(message_data, echSplit, false);
        context.ech.outer_ch1 = onWire;
      }

      // Client side: our own ClientHello is what a server fingerprints us by.
      // First one wins — a post-HRR retry must not replace the original offer.
      if (context.rawClientHello === null) context.rawClientHello = onWire;

      pushTranscript(message_data);

      context.hello_sent=true;

      // 0-RTT offered: its secret, from the PSK and this ClientHello — before
      // the hello goes, so the layer above has the key for what follows it.
      if (context.early.offered && context.psk_offered) {
        let edHash = TLS_CIPHER_SUITES[context.psk_offered.cipher] ? TLS_CIPHER_SUITES[context.psk_offered.cipher].hash : 'sha256';
        let edSecret = derive_client_early_traffic_secret(edHash, context.psk_offered.psk, get_transcript_hash(edHash), label_prefix());
        _emitKeylogSingle('CLIENT_EARLY_TRAFFIC_SECRET', edSecret);
        ev.emit('earlySecret', edSecret, { cipher: context.psk_offered.cipher, alpn: context.early.alpn, appData: context.early.appData, maxEarlyData: context.early.maxEarly });
      }

      ev.emit('message',0,context.message_sent_seq,'hello',onWire);

      context.message_sent_seq++;

    },0);
  }

  

  /* ======================= ClientHello fingerprinting ======================= */

  /**
   * GREASE (RFC 8701) reserved values: both bytes equal, low nibble of each
   * is 0xA — 0x0A0A, 0x1A1A ... 0xFAFA. Clients sprinkle these into ciphers,
   * extensions, groups and signature schemes specifically so that peers who
   * hardcode value lists break loudly. Every fingerprint below drops them:
   * they are random per connection, so leaving one in makes the fingerprint
   * change on every handshake from the same client.
   *
   * The narrower `(v & 0x0f0f) === 0x0a0a` test used before also matched
   * non-GREASE values such as 0x1a2a, so it is not a safe stand-in.
   */
  function fp_is_grease(v) {
    return (v & 0x0f0f) === 0x0a0a && ((v >>> 8) & 0xff) === (v & 0xff);
  }

  function fp_no_grease(list) {
    let out = [];
    if (!list) return out;
    for (let i = 0; i < list.length; i++) {
      if (!fp_is_grease(list[i])) out.push(list[i]);
    }
    return out;
  }

  function fp_hex4(v) {
    let s = (v >>> 0).toString(16);
    while (s.length < 4) s = '0' + s;
    return s;
  }

  /**
   * Parse a stored hello at most once. Failure is cached as `false` so a
   * malformed message does not re-throw through the parser on every call.
   * `which` is 'client' or 'server'.
   */
  function fp_parse(which) {
    let rawKey = which === 'server' ? 'rawServerHello' : 'rawClientHello';
    let cacheKey = which === 'server' ? 'parsedServerHello' : 'parsedClientHello';
    if (context[cacheKey] === false) return null;
    if (context[cacheKey] !== null) return context[cacheKey];
    if (!context[rawKey]) return null;
    try {
      context[cacheKey] = parse_tls_message(context[rawKey]);
    } catch (e) {
      context[cacheKey] = false;
      return null;
    }
    return context[cacheKey];
  }

  function fp_hello() { return fp_parse('client'); }
  function fp_shello() { return fp_parse('server'); }

  /** Signature schemes in WIRE ORDER (JA4 deliberately does not sort these). */
  function fp_sig_algs(hello) {
    return fp_no_grease(hello.signature_algorithms || []);
  }

  /**
   * JA4 version character pair. Read from supported_versions when the peer
   * offered it, else from the ClientHello's legacy_version.
   *
   * DTLS versions are 1's complement (DTLS 1.0 = 0xFEFF, 1.2 = 0xFEFD,
   * 1.3 = 0xFEFC), so "newest" is the numerically SMALLEST value — taking a
   * max over a DTLS supported_versions list picks the oldest version offered.
   */
  function fp_version_string(hello, isDTLS) {
    let ver = hello.legacy_version || 0x0303;
    let offered = fp_no_grease(hello.supported_versions || []);
    if (offered.length > 0) {
      ver = offered[0];
      for (let i = 1; i < offered.length; i++) {
        if (isDTLS ? offered[i] < ver : offered[i] > ver) ver = offered[i];
      }
    }
    let map = {
      0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10',
      0x0300: 's3', 0x0200: 's2', 0x0100: 's1',
      0xFEFF: 'd1', 0xFEFD: 'd2', 0xFEFC: 'd3'
    };
    return map[ver] || '00';
  }

  /**
   * Raw bytes of the FIRST offered ALPN protocol, or null.
   *
   * Read off the wire rather than from hello.alpn, which the extension decoder
   * produced with a UTF-8 TextDecoder: any protocol name carrying a byte >=0x80
   * comes back with U+FFFD replacement characters, and the byte values JA4
   * needs are gone by then.
   *
   *   ProtocolNameList: uint16 list_len, then { uint8 name_len, name bytes }*
   */
  function fp_first_alpn_bytes(hello) {
    let exts = hello.extensions || [];
    for (let i = 0; i < exts.length; i++) {
      if (exts[i].type !== 0x0010) continue;
      let d = exts[i].data;
      if (!d || d.length < 3) return null;
      let listLen = (d[0] << 8) | d[1];
      if (listLen < 1 || 2 + listLen > d.length) return null;
      let n = d[2];
      if (n < 1 || 3 + n > d.length) return null;
      return d.subarray(3, 3 + n);
    }
    return null;
  }

  /**
   * JA4 ALPN pair: first and last byte of the first offered protocol.
   *
   * The FoxIO prose says an end byte outside ASCII alphanumeric falls back to
   * the first and last characters of the value's HEX form. Both reference
   * implementations — and the published test vectors — instead emit "99", and
   * accept the whole printable ASCII range (0x20-0x7E) rather than just
   * alphanumerics. Interop is the entire point of this fingerprint, so the
   * behaviour below follows the implementations, not the prose.
   *
   * A one-byte protocol repeats that byte when it is alphanumeric, else "99".
   * Absent or empty ALPN is "00".
   */
  function fp_alpn_pair(hello) {
    let bytes = fp_first_alpn_bytes(hello);

    if (!bytes || bytes.length === 0) {
      // No ALPN extension on the wire — but a caller may have handed us a
      // pre-parsed hello with only the decoded strings. Fall back to those.
      let list = hello.alpn || [];
      if (list.length === 0 || typeof list[0] !== 'string' || list[0].length === 0) return '00';
      bytes = Buffer.from(list[0], 'latin1');
    }

    let isAlnum = function (b) {
      return (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a);
    };
    let isPrintable = function (b) { return b >= 0x20 && b <= 0x7e; };

    let f = bytes[0];
    let l = bytes[bytes.length - 1];

    if (bytes.length === 1) {
      return isAlnum(f) ? (String.fromCharCode(f) + String.fromCharCode(f)) : '99';
    }
    if (isPrintable(f) && isPrintable(l)) {
      return String.fromCharCode(f) + String.fromCharCode(l);
    }
    return '99';
  }

  /** Truncated SHA-256 over a comma-joined list. An empty list hashes to zeros
   *  by convention rather than to the digest of the empty string. */
  function fp_trunc_sha256(input) {
    if (input === '') return '000000000000';
    return crypto.createHash('sha256').update(input).digest('hex').substring(0, 12);
  }

  /* ----------------------------- the computations ------------------------- */

  /**
   * JA4 — the client fingerprint:
   *
   *   t13d1516h2_8daaf6152771_e5627ece308c
   *   │ │ │ │ │ │  │            └ sha256(sorted extensions [_ sigalgs])[:12]
   *   │ │ │ │ │ │  └────────────── sha256(sorted ciphers)[:12]
   *   │ │ │ │ │ └───────────────── first+last char of first ALPN ("00" if none)
   *   │ │ │ │ └─────────────────── extension count (GREASE excluded, cap 99)
   *   │ │ │ └───────────────────── cipher count (GREASE excluded, cap 99)
   *   │ │ └─────────────────────── "d" if SNI present, "i" if not
   *   │ └───────────────────────── TLS version (13/12/11/10/s3, d1/d2/d3)
   *   └─────────────────────────── transport: t=TCP, d=DTLS, q=QUIC
   *
   * Ciphers and extensions are sorted before hashing, so a client that
   * shuffles extension order per connection still produces a stable
   * fingerprint — the main reason to prefer this over JA3. Signature
   * algorithms are appended in WIRE ORDER, unsorted, which is what preserves
   * uniqueness after that sort.
   *
   * SNI and ALPN are counted in the extension count but excluded from the
   * hash, so the same client hitting different hostnames fingerprints alike.
   */
  function fp_compute_ja4(opts) {
    let hello = fp_hello();
    if (!hello) return null;
    try {
        let isDTLS = ((hello.legacy_version & 0xFF00) === 0xFE00) ||
                     ((context.selected_version & 0xFF00) === 0xFE00);

        let proto = (opts && opts.protocol) ? String(opts.protocol).charAt(0)
                                            : (isDTLS ? 'd' : 't');

        let verStr = fp_version_string(hello, isDTLS);

        let allExts = (hello.extensions || []).map(function(e){ return e.type; });
        let hasSNI  = allExts.indexOf(0x0000) >= 0;

        let ciphers = fp_no_grease(hello.cipher_suites || []);
        let exts    = fp_no_grease(allExts);

        let pad2 = function(n){ n = Math.min(n, 99); return (n < 10 ? '0' : '') + n; };

        let ja4_a = proto + verStr + (hasSNI ? 'd' : 'i') +
                    pad2(ciphers.length) + pad2(exts.length) + fp_alpn_pair(hello);

        // --- b: ciphers, sorted ---
        let cipherList = ciphers.map(fp_hex4).sort().join(',');

        // --- c: extensions minus SNI(0) and ALPN(16), sorted, then sigalgs ---
        let extList = exts
          .filter(function(t){ return t !== 0x0000 && t !== 0x0010; })
          .map(fp_hex4).sort().join(',');

        let sigList = fp_sig_algs(hello).map(fp_hex4).join(',');
        let cInput  = sigList ? (extList + '_' + sigList) : extList;

        // The raw form carries JA4_c as it was hashed: with no signature
        // algorithms, the extensions alone — no "_" after them (FoxIO's ja4_r;
        // the hash already followed this, the raw form ended in "_").
        return {
          hash: ja4_a + '_' + fp_trunc_sha256(cipherList) + '_' + fp_trunc_sha256(cInput),
          raw:  ja4_a + '_' + cipherList + '_' + cInput
        };
      } catch (e) { return null; }
  }

  /**
   * JA4S — the server-side counterpart of JA4:
   *
   *   t130200_1301_a56c5b993250
   *   │ │ │ │  │    └ sha256(extensions in WIRE ORDER)[:12]
   *   │ │ │ │  └────── the chosen cipher, printed raw — one value, nothing to hash
   *   │ │ │ └───────── ALPN pair of the selected protocol
   *   │ │ └─────────── extension count
   *   │ └───────────── TLS version
   *   └─────────────── transport
   *
   * Two deliberate differences from JA4. There is no SNI character, because a
   * server never sends one. And extensions are NOT sorted: sorting exists in
   * JA4 to defeat clients that shuffle extension order per connection, which
   * servers do not do — so here the order is signal worth keeping rather than
   * noise worth removing.
   */
  function fp_compute_ja4s(opts) {
    let hello = fp_shello();
    if (!hello) return null;
    try {
      let isDTLS = ((hello.legacy_version & 0xFF00) === 0xFE00) ||
                   ((context.selected_version & 0xFF00) === 0xFE00);
      let proto = (opts && opts.protocol) ? String(opts.protocol).charAt(0)
                                          : (isDTLS ? 'd' : 't');

      // Extensions here are NOT GREASE-filtered, unlike every list in JA4.
      // The reference implementations filter GREASE only out of the server's
      // supported_versions, and pass the extension list through untouched;
      // filtering it produced a different hash from every other tool on the
      // one vector where a server echoed a GREASE extension. Servers do not
      // normally emit GREASE at all, so this is a rare path — but a wrong
      // fingerprint on a rare path is exactly what breaks a threat hunt.
      let exts = (hello.extensions || []).map(function(e){ return e.type; });
      let pad2 = function(n){ n = Math.min(n, 99); return (n < 10 ? '0' : '') + n; };

      let cs = hello.cipher_suites || [];
      let cipher = cs.length > 0 ? fp_hex4(cs[0]) : '0000';

      let a = proto + fp_version_string(hello, isDTLS) + pad2(exts.length) + fp_alpn_pair(hello);
      let extList = exts.map(fp_hex4).join(',');

      return {
        hash: a + '_' + cipher + '_' + fp_trunc_sha256(extList),
        raw:  a + '_' + cipher + '_' + extList
      };
    } catch (e) { return null; }
  }

  /**
   * JA5 — ntop's successor to JA4 (draft, CC BY 4.0; the specification is
   * README.ja5.md in the nDPI repository).
   *
   *   t13d1514h2_acb858a92679_7dc829385eb9_0a47a2b05960
   *   │          │            │            └ sha256(sorted supported_groups)[:12]
   *   │          │            └───────────── as JA4_c, without the ephemeral
   *   │          │                           extensions
   *   │          └────────────────────────── as JA4_b: sorted ciphers
   *   └───────────────────────────────────── as JA4_a, the extension count
   *                                          without the ephemeral extensions
   *
   * The one thing it fixes: JA4 counts and hashes every extension, and some
   * of them say nothing about the client — only about THIS connection. A
   * browser coming back with a session ticket adds pre_shared_key, and its JA4
   * changes (t13d1516 → t13d1517 for Chrome 149) though nothing about the
   * browser did. JA5 leaves those out, so the same client build has one JA5
   * whether it resumed or not. The list is the specification's registry, v1:
   *
   *   0x0015 padding                  0x002a early_data
   *   0x0023 session_ticket           0x002c cookie
   *   0x0029 pre_shared_key           0x002d psk_key_exchange_modes
   *
   * The one thing it adds: the supported_groups a client offers, which JA4
   * does not look at — a client that copies a browser's cipher list and not
   * its groups is caught, and whether it offers a post-quantum group
   * (X25519MLKEM768) is part of what it is. No supported_groups at all leaves
   * the field EMPTY, not zeros, so "absent" stays distinct from anything
   * present.
   *
   * GREASE is filtered with the same test as JA4 (fp_is_grease). The draft
   * writes it as (v & 0x0F0F) == 0x0A0A, which also takes in non-GREASE
   * values such as 0x1a2a; no client sends one, and one test for both
   * fingerprints keeps them from ever disagreeing on what GREASE is.
   *
   * `raw` is this library's, not the draft's (it defines none): JA4's raw
   * form with the groups appended — a_ciphers_c_groups, c as JA4 hashes it
   * (the extensions, and "_" and the signature algorithms if there are any).
   */
  var JA5_EPHEMERAL = { 0x0015: 1, 0x0023: 1, 0x0029: 1, 0x002a: 1, 0x002c: 1, 0x002d: 1 };

  function fp_compute_ja5(opts) {
    let hello = fp_hello();
    if (!hello) return null;
    try {
      let isDTLS = ((hello.legacy_version & 0xFF00) === 0xFE00) ||
                   ((context.selected_version & 0xFF00) === 0xFE00);
      let proto = (opts && opts.protocol) ? String(opts.protocol).charAt(0)
                                          : (isDTLS ? 'd' : 't');
      let verStr = fp_version_string(hello, isDTLS);

      let allExts = (hello.extensions || []).map(function(e){ return e.type; });
      let hasSNI  = allExts.indexOf(0x0000) >= 0;
      let exts    = fp_no_grease(allExts).filter(function(t){ return !JA5_EPHEMERAL[t]; });
      let ciphers = fp_no_grease(hello.cipher_suites || []);

      let pad2 = function(n){ n = Math.min(n, 99); return (n < 10 ? '0' : '') + n; };
      let a = proto + verStr + (hasSNI ? 'd' : 'i') +
              pad2(ciphers.length) + pad2(exts.length) + fp_alpn_pair(hello);

      let cipherList = ciphers.map(fp_hex4).sort().join(',');
      let extList = exts
        .filter(function(t){ return t !== 0x0000 && t !== 0x0010; })
        .map(fp_hex4).sort().join(',');
      let sigList = fp_sig_algs(hello).map(fp_hex4).join(',');
      let cInput  = sigList ? (extList + '_' + sigList) : extList;

      let groups = fp_no_grease(hello.supported_groups || []).map(fp_hex4).sort().join(',');
      let d = groups ? crypto.createHash('sha256').update(groups).digest('hex').substring(0, 12) : '';

      return {
        hash: a + '_' + fp_trunc_sha256(cipherList) + '_' + fp_trunc_sha256(cInput) + '_' + d,
        raw:  a + '_' + cipherList + '_' + cInput + '_' + groups
      };
    } catch (e) { return null; }
  }

  /**
   * Cached fingerprint accessor. Each value is computed the first time it is
   * asked for AND its underlying hello exists; until then the slot stays
   * `undefined` and is retried on the next call. That is what lets getJA4S()
   * be called from the 'clienthello' handler — before any ServerHello exists
   * — without freezing it at null forever.
   */
  function fp_get(name, opts) {
    if (context.fpCache[name] !== undefined) return context.fpCache[name];
    let v = null;
    if (name === 'ja4')       v = fp_compute_ja4(opts);
    else if (name === 'ja5')  v = fp_compute_ja5(opts);
    else if (name === 'ja4s') v = fp_compute_ja4s(opts);
    if (v !== null) context.fpCache[name] = v;
    return v;
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

    /**
     * Current session state: 'new' | 'handshaking' | 'connected' | 'error' | 'closed'.
     *
     * Exposed so a transport can tell whether the session is still alive
     * WITHOUT reaching into context. A transport that keeps feeding records to
     * an aborted session decrypts them under keys the peer no longer uses and
     * reports a misleading bad_record_mac, hiding the real failure.
     */
    getState: function(){
      return context.state;
    },

    /** Returns the negotiated cipher suite code (e.g. 0x1301, 0xC02F), or null. */
    getCipher: function(){
      return context.selected_cipher_suite;
    },


    /**
     * Server: this connection's ticket, from the first connection on.
     *
     *   data     what this connection's ticket carries — on a resumed
     *            connection what it came back with, on a full handshake what
     *            ticketData made for the ticket issued to it. The same value
     *            the ticket holds, so the connection that got the ticket and
     *            the ones that resume with it later share it. null without a
     *            ticketData option; on a full handshake, null until the
     *            server's Finished is sent — whether the connection resumes
     *            is settled by then, and ticketData is asked then, once. QUIC
     *            reports a server connection ready at that very point, before
     *            the client's Finished arrives.
     *   resumed  resumed with a ticket (isSessionReused()).
     *   offered  the client presented a ticket — resumed, or turned away:
     *            expired, issued before a restart (other ticketKeys), no
     *            compatible cipher. offered && !resumed: a client that has
     *            been here before and cannot show who it was.
     *
     * On a full handshake `data` is what the server has just made up, not
     * something the client proved it holds; whether to trust it is the
     * application's call, by `resumed`.
     */
    /**
     * The protocol layer's state for the tickets this server issues from now
     * on — JSON-safe and small (at most 128 bytes serialized; larger, or not
     * serializable: refused, and the tickets carry none). Separate from the
     * application's ticketData, which it neither sees nor limits. Comes back
     * in getTicketInfo().state on the connection that resumes with one of
     * those tickets. TLS 1.3. Returns whether it was taken.
     */
    /** Server: the context the tickets issued from now on are for, and the
     *  only one a presented ticket is accepted under (see ticketContext). */
    setTicketContext: function(ctx){
      context.ticketContext = typeof ctx === 'string' ? ctx : '';
    },

    setTicketState: function(state){
      if (state == null) { context.ticket_state = null; return true; }
      let size;
      try { size = Buffer.byteLength(JSON.stringify(state)); } catch (e) { return false; }
      if (!(size <= TICKET_STATE_MAX)) return false;
      context.ticket_state = state;
      return true;
    },

    /**
     * Issue another NewSessionTicket now (server, TLS 1.3, after the
     * handshake), as OpenSSL's SSL_new_session_ticket(): the first went out
     * with the handshake, before anything was known that a later one can
     * carry (setTicketState). Clients keep the newest. Returns whether one
     * was sent.
     */
    sendTicket: function(){
      if (!context.isServer || context.state !== 'connected' || !is13() ||
          !context.sessionTickets || !context.resumption_master_secret) return false;
      if (context.ticket_nonce_counter > 255) return false;   // a one-byte nonce
      issue_ticket_13();
      return true;
    },

    getTicketInfo: function(){
      let data = null;
      if (context.isServer) {
        // Settled once our Finished is out (TLS 1.3: the application
        // secrets exist), or the handshake is done (TLS 1.2).
        if (context.state === 'connected' || context.local_app_traffic_secret) data = ticket_app_data();
        else if (context.isResumed) data = context.resumed_ticket_data;
      }
      return { data: data, resumed: !!context.isResumed, offered: !!context.ticket_offered,
               state: context.isResumed ? context.resumed_ticket_state : null };
    },

    /**
     * Encrypted Client Hello on this connection. Server: null when the
     * client did not offer it, 'accepted' when its real ClientHello was
     * decrypted and used, 'rejected' when it could not be (the handshake
     * then ran as the public name, and retry_configs went out). Client:
     * null (none, or not yet decided), 'grease', 'accepted', 'rejected'.
     */
    getEchStatus: function(){
      return context.ech.status;
    },

    /** 0-RTT on this connection: null (not offered), 'accepted', 'rejected'
     *  — the server's verdict, once given (EncryptedExtensions). */
    // Server: whether the ClientHello offered early data at all — taken or
    // not; not taken, the record layer skips it (RFC 8446 §4.2.10).
    earlyDataOfferedByPeer: function(){ return context.early.clientOffered === true; },

    getEarlyDataStatus: function(){
      if (!context.early.offered) return null;
      return context.early.status;
    },

    /** Client: the data to keep with the sessions this connection saves
     *  (sessionAppData) — set once it is known, before a ticket arrives. */
    setSessionAppData: function(v){
      context.sessionAppData = v != null ? v : null;
    },

    /** Server: what 0-RTT is accepted under (earlyDataContext) — set before
     *  the ClientHello is read, as setTicketContext. */
    setEarlyDataContext: function(ctx){
      context.earlyDataContext = typeof ctx === 'string' ? ctx : '';
    },

    /** Returns the negotiated ALPN protocol string (e.g. 'h2'), or null. */
    getALPN: function(){
      return context.selected_alpn || null;
    },

    /** Returns the remote certificate chain, or null. */
    getPeerCertificate: function(){
      return context.remote_cert_chain || context.resumed_peer_chain || null;
    },

    /** Returns our own certificate chain — the one this connection presents
     *  (on a server, the one the SNI lookup chose) — or null. */
    getCertificate: function(){
      return context.local_cert_chain || null;
    },

    /**
     * Replace the certificate and private key this connection will present.
     *
     * Node parity with tlsSocket.setKeyCert(context), whose stated purpose is
     * selecting a server certificate from inside ALPNCallback: the chosen
     * protocol is known there, but SNICallback has already run, so this is the
     * only place left to swap credentials for that one connection.
     *
     * Accepts either a context from createSecureContext() or a plain
     * { key, cert, passphrase } that will be compiled here.
     *
     * Assigns directly rather than through set_context, matching the
     * SNICallback path above: both seed inputs ahead of the single set_context
     * that actually runs the reactive loop, and routing through it here would
     * run that loop a second time on a half-populated hello.
     *
     * Only meaningful before our Certificate message goes out; afterwards the
     * peer already has the old chain and swapping is a no-op on the wire.
     */
    setKeyCert: function(ctxOrOpts){
      if (!ctxOrOpts) return;
      let sc = ctxOrOpts;
      if (!sc.certificateChain || !sc.privateKey) {
        if (!ctxOrOpts.key || !ctxOrOpts.cert) return;
        sc = createSecureContext(ctxOrOpts);
      }
      if (sc.certificateChain) context.local_cert_chain = sc.certificateChain;
      if (sc.privateKey)       context.cert_private_key = sc.privateKey;
      context.local_cert_alternates = sc.alternates || null;
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
        // Handshake-epoch secrets. The record layer needs these to encrypt an
        // alert raised BEFORE anything has been written at epoch 1 — an abort
        // during the peer's flight is exactly that case, and without them the
        // alert could only go out in cleartext.
        localHandshakeSecret:  context.local_handshake_traffic_secret,
        remoteHandshakeSecret: context.remote_handshake_traffic_secret,
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

    /**
     * Export keying material (RFC 5705 for TLS 1.2, RFC 8446 §7.5 for
     * TLS 1.3). Mirrors Node's tls.TLSSocket#exportKeyingMaterial.
     *
     * DTLS-SRTP (RFC 5764) usage:
     *   session.exportKeyingMaterial(len, 'EXTRACTOR-dtls_srtp')
     * with NO context argument. Note the TLS 1.2 subtlety: "no context"
     * and "empty context" produce different output — omit the argument
     * (or pass null) for the RFC 5764 form.
     *
     * Returns a Buffer of `length` bytes, or null before the secrets
     * are available (handshake not far enough along).
     *
     * NOTE: the previous implementation was TLS 1.3-only AND derived from
     * the app traffic secret in a single HKDF stage — which is not the
     * RFC 8446 §7.5 construction and would not interoperate with
     * OpenSSL/BoringSSL exporters. Both issues are fixed here; if anything
     * consumed the old output, its derived values will change.
     *
     * @param {number} length
     * @param {string} label
     * @param {Uint8Array|Buffer|null} [context_value]
     * @returns {Buffer|null}
     */
    /**
     * The negotiated DTLS-SRTP protection profile (RFC 5764), or null if none
     * was agreed. Pair with exportKeyingMaterial(len, 'EXTRACTOR-dtls_srtp').
     */
    getSelectedSrtpProfile: function(){
      return context.selected_srtp_profile;
    },

    exportKeyingMaterial: function(length, label, context_value){
      if (!context.selected_cipher_suite || !length || !label) return null;
      var suite = TLS_CIPHER_SUITES[context.selected_cipher_suite];
      if (!suite) return null;
      var is13 = (context.selected_version === wire.TLS_VERSION.TLS1_3 ||
                  context.selected_version === wire.DTLS_VERSION.DTLS1_3);

      if (is13) {
        // RFC 8446 §7.5 — two-stage derivation from exporter_master_secret.
        if (!context.exporter_master_secret) return null;
        return Buffer.from(tls13_exporter(
          suite.hash, context.exporter_master_secret, label,
          (context_value != null) ? context_value : null, length
        , label_prefix()));
      }

      // TLS 1.2 — RFC 5705 over the master secret + hello randoms.
      // client_random comes first in the seed regardless of our role.
      if (!context.base_secret || !context.local_random || !context.remote_random) return null;
      var clientRandom = context.isServer ? context.remote_random : context.local_random;
      var serverRandom = context.isServer ? context.local_random  : context.remote_random;
      return Buffer.from(tls12_exporter(
        suite.hash, context.base_secret, label,
        clientRandom, serverRandom,
        (context_value != null) ? context_value : null, length
      ));
    },

    /**
     * All extensions the peer sent in its hello (ClientHello when we're
     * the server, ServerHello when we're the client), as parsed by
     * wire.parse_extensions: [{ type, name, data, value }].
     * `data` is the raw extension payload (Uint8Array); `value` is the
     * decoded form for known extensions, null for unknown ones.
     */
    getRemoteExtensions: function(){
      return context.remote_extensions ? context.remote_extensions.slice() : [];
    },

    /**
     * Look up a single peer extension by its numeric type
     * (e.g. 14 = use_srtp, 0x39 = QUIC transport parameters).
     * Returns the { type, name, data, value } entry, or null.
     */
    getRemoteExtension: function(type){
      var list = context.remote_extensions || [];
      for (var i = 0; i < list.length; i++) {
        if (list[i] && list[i].type === type) return list[i];
      }
      return null;
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
        groupName: context.selected_group != null ? ecdh_group_name(context.selected_group) : null,
        // The scheme of the server's CertificateVerify — what authenticated
        // the handshake (ML-DSA for a post-quantum certificate): the one we
        // signed with, or, on a client, the one we verified. null on a
        // resumed handshake, which has none.
        signatureAlgorithm: context.isServer ? context.selected_signature_algorithm : (context.peerSignatureScheme != null ? context.peerSignatureScheme : null),
        signatureAlgorithmName: scheme_name(context.isServer ? context.selected_signature_algorithm : context.peerSignatureScheme),
        alpn: context.selected_alpn,
        sni: context.selected_sni || context.local_sni,
        resumed: context.isResumed,
        helloRetried: context.helloRetried,
        handshakeDuration: context.handshakeEndTime && context.handshakeStartTime ? context.handshakeEndTime - context.handshakeStartTime : null,
        // RFC 8879: the algorithm each side's Certificate travelled in
        // ('brotli', 'zlib', 'zstd'), null where it went plain or was not
        // sent (a resumed handshake, no client certificate). What happened on
        // the wire, not what was configured.
        certificateCompression: {
          sent: context.cert_compression_sent != null ? cert_compression_name(context.cert_compression_sent) : null,
          received: context.cert_compression_received != null ? cert_compression_name(context.cert_compression_received) : null,
        },
      };
    },

    /**
     * TLS fingerprints, one method each, each computed the first time it is
     * asked for and kept. Each is { hash, raw } once its hello has been seen,
     * null before that. Both hellos of a connection are visible to both
     * peers, so all three answer in either role; which one describes you
     * depends on `isServer`.
     *
     *   getJA4()   the client, from its ClientHello — the published format,
     *              what fingerprint databases and other tools match against
     *   getJA5()   the client too, stable across session resumption (see
     *              fp_compute_ja5) — for recognising a client here
     *   getJA4S()  the server, from its ServerHello
     *
     * `opts.protocol` overrides the transport character for a caller driving
     * this session from a transport it cannot observe (QUIC -> 'q').
     */
    getJA4: function(opts){ return fp_get('ja4', opts); },
    getJA5: function(opts){ return fp_get('ja5', opts); },
    getJA4S: function(opts){ return fp_get('ja4s', opts); },

    /** Request a TLS 1.3 Key Update. requestPeer=true means ask the other side to update too. */
    requestKeyUpdate: function(requestPeer){
      if (context.state !== 'connected' || (context.selected_version !== wire.TLS_VERSION.TLS1_3 && context.selected_version !== wire.DTLS_VERSION.DTLS1_3)) return;
      let hashName = negotiated_hash();
      let hashLen = getHashLen(hashName);

      // Derive new local traffic secret
      let newLocalSecret = hkdf_expand_label(hashName, context.local_app_traffic_secret, 'traffic upd', new Uint8Array(0), hashLen, label_prefix());
      context.local_app_traffic_secret = newLocalSecret;

      // Send KeyUpdate message
      let ku_data = build_tls_message({ type: 'key_update', request_update: requestPeer ? 1 : 0 });
      ev.emit('message', 2, context.message_sent_seq, 'key_update', ku_data);
      context.message_sent_seq++;

      ev.emit('keyUpdate', { direction: 'send', secret: newLocalSecret });
    },
  };

  // Copied as property DESCRIPTORS, not values: `this[k] = api[k]` runs each
  // getter once, here, and stores what it returned — so `authorized` and
  // `authorizationError` were frozen at false / null for the life of the
  // session, and TLSSocket reported every verified peer as unauthorized and
  // every failure without its reason. handshakeDuration froze the same way.
  for (let k in api) if (Object.prototype.hasOwnProperty.call(api,k)) {
    Object.defineProperty(this, k, Object.getOwnPropertyDescriptor(api, k));
  }
  // Re-define dynamic getters (the for-in loop flattens them to values)
  Object.defineProperty(this, 'isResumed', { get: function() { return context.isResumed; }, configurable: true, enumerable: true });
  return this;
}

export default TLSSession;