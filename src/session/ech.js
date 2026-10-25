/**
 * TLS Encrypted Client Hello (RFC 9849) — the client-facing server, shared
 * mode: this server decrypts the ClientHello and is also the backend that
 * answers it.
 *
 * Without ECH the first message of every TLS connection — the ClientHello,
 * with the name of the site (SNI) and the ALPN list — crosses the network in
 * the clear; HTTPS hides everything after it. With ECH the client sends two
 * hellos in one: an outer ClientHello in the clear naming a shared
 * "public_name", and inside it the real one (ClientHelloInner), encrypted
 * with HPKE to a public key the server publishes in DNS (the `ech` key of
 * an HTTPS record, RFC 9460). The server decrypts the inner hello and the
 * handshake continues with it; it tells the client so with 8 bytes of the
 * ServerHello random that only a holder of the inner hello can compute.
 *
 * When the server cannot decrypt (a key it no longer holds, or a client
 * sending GREASE ECH) it completes the handshake with the outer hello, as
 * the public_name — its certificate must cover that name — and sends
 * `retry_configs`, its current keys, which the client takes and reconnects
 * with (§6.1.6).
 *
 * The key is not authenticated by any CA: its trust comes from DNS. A
 * substituted key lets an attacker read which name the client asked for,
 * never impersonate the server — the certificate is still checked against
 * that name.
 *
 * TLS only: the DTLS variant (other hello layout, other header) is not here.
 */

import crypto from 'node:crypto';
import { hkdf_extract, hkdf_expand_label } from '../crypto.js';
import { hpke_suite, is_supported_hpke_suite, setup_recipient, setup_sender,
         hpke_generate_key_pair, hpke_public_key } from './hpke.js';

var ECH_VERSION = 0xfe0d;            // the extension, and the ECHConfig version
var EXT_ECH = 0xfe0d;
var EXT_ECH_OUTER_EXTENSIONS = 0xfd00;
var EXT_SERVER_NAME = 0;
var EXT_SUPPORTED_VERSIONS = 43;

var ALERT_ILLEGAL_PARAMETER = 47;
var ALERT_DECODE_ERROR = 50;
var ALERT_DECRYPT_ERROR = 51;
var ALERT_MISSING_EXTENSION = 109;

function eccError(msg, alert) {
  var e = new Error('ECH: ' + msg);
  e.alertDesc = alert || ALERT_ILLEGAL_PARAMETER;
  return e;
}

var te = new TextEncoder(), td = new TextDecoder();

function u16(b, o) { return (b[o] << 8) | b[o + 1]; }
function put16(b, o, v) { b[o] = (v >>> 8) & 0xff; b[o + 1] = v & 0xff; }
function concat(list) {
  var len = 0, i;
  for (i = 0; i < list.length; i++) len += list[i].length;
  var out = new Uint8Array(len), off = 0;
  for (i = 0; i < list.length; i++) { out.set(list[i], off); off += list[i].length; }
  return out;
}
function toU8(v, what) {
  if (v instanceof Uint8Array) return v;
  if (typeof v === 'string') return new Uint8Array(Buffer.from(v, 'base64'));
  if (v && typeof v.length === 'number') return new Uint8Array(v);
  throw new TypeError(what + ' must be bytes (Uint8Array / Buffer) or base64');
}

// A bounds-checked reader: every overrun is a decode_error, never a throw
// from deep inside a typed array.
function Reader(buf, off, end) { this.b = buf; this.o = off || 0; this.end = end == null ? buf.length : end; }
Reader.prototype.need = function (n) { if (this.o + n > this.end) throw eccError('truncated structure', ALERT_DECODE_ERROR); };
Reader.prototype.u8 = function () { this.need(1); return this.b[this.o++]; };
Reader.prototype.u16 = function () { this.need(2); var v = u16(this.b, this.o); this.o += 2; return v; };
Reader.prototype.bytes = function (n) { this.need(n); var v = this.b.subarray(this.o, this.o + n); this.o += n; return v; };
Reader.prototype.vec8 = function () { return this.bytes(this.u8()); };
Reader.prototype.vec16 = function () { return this.bytes(this.u16()); };


// ============================================================
//  ECHConfig / ECHConfigList (§4)
// ============================================================

/**
 * An ECHConfigList → the configs of the version this implements, each with
 * its exact bytes (`raw`: what HPKE's info binds to). Others are skipped,
 * as §4 requires of a client. Throws on a malformed list.
 */
function parse_ech_config_list(bytes) {
  bytes = toU8(bytes, 'ECHConfigList');
  var r = new Reader(bytes);
  var list = r.vec16();
  if (r.o !== bytes.length) throw eccError('trailing bytes after ECHConfigList', ALERT_DECODE_ERROR);
  if (list.length < 4) throw eccError('empty ECHConfigList', ALERT_DECODE_ERROR);
  var out = [], lr = new Reader(list);
  while (lr.o < list.length) {
    var start = lr.o;
    var version = lr.u16();
    var contents = lr.vec16();
    var raw = list.subarray(start, lr.o);
    if (version !== ECH_VERSION) continue;
    out.push(parse_ech_config_contents(contents, raw));
  }
  return out;
}

/** One ECHConfig (version, length, contents) → its fields. */
function parse_ech_config(bytes) {
  bytes = toU8(bytes, 'ECHConfig');
  var r = new Reader(bytes);
  var version = r.u16();
  var contents = r.vec16();
  if (r.o !== bytes.length) throw eccError('trailing bytes after ECHConfig', ALERT_DECODE_ERROR);
  if (version !== ECH_VERSION) throw eccError('ECHConfig version 0x' + version.toString(16) + ' (this implements 0xfe0d)');
  return parse_ech_config_contents(contents, bytes);
}

function parse_ech_config_contents(contents, raw) {
  var r = new Reader(contents);
  var config_id = r.u8();
  var kem_id = r.u16();
  var public_key = r.vec16();
  var suitesBytes = r.vec16();
  if (suitesBytes.length < 4 || suitesBytes.length % 4) throw eccError('ECHConfig cipher_suites malformed', ALERT_DECODE_ERROR);
  var cipher_suites = [];
  for (var i = 0; i < suitesBytes.length; i += 4) cipher_suites.push({ kdf_id: u16(suitesBytes, i), aead_id: u16(suitesBytes, i + 2) });
  var maximum_name_length = r.u8();
  var name = r.vec8();
  if (name.length < 1) throw eccError('ECHConfig public_name empty', ALERT_DECODE_ERROR);
  var extBytes = r.vec16();
  if (r.o !== contents.length) throw eccError('trailing bytes in ECHConfigContents', ALERT_DECODE_ERROR);
  var extensions = [], er = new Reader(extBytes);
  while (er.o < extBytes.length) extensions.push({ type: er.u16(), data: er.vec16() });
  return {
    version: ECH_VERSION, raw: raw,
    config_id: config_id, kem_id: kem_id, public_key: public_key, cipher_suites: cipher_suites,
    maximum_name_length: maximum_name_length, public_name: td.decode(name), extensions: extensions
  };
}

function encode_ech_config(c) {
  var name = te.encode(c.public_name);
  if (name.length < 1 || name.length > 255) throw new TypeError('publicName must be 1-255 bytes');
  var suites = new Uint8Array(c.cipher_suites.length * 4);
  c.cipher_suites.forEach(function (s, i) { put16(suites, i * 4, s.kdf_id); put16(suites, i * 4 + 2, s.aead_id); });
  var exts = concat((c.extensions || []).map(function (e) {
    var h = new Uint8Array(4); put16(h, 0, e.type); put16(h, 2, e.data.length); return concat([h, e.data]);
  }));
  var pk = c.public_key;
  var contents = concat([
    new Uint8Array([c.config_id & 0xff, (c.kem_id >>> 8) & 0xff, c.kem_id & 0xff, (pk.length >>> 8) & 0xff, pk.length & 0xff]), pk,
    new Uint8Array([(suites.length >>> 8) & 0xff, suites.length & 0xff]), suites,
    new Uint8Array([c.maximum_name_length & 0xff, name.length]), name,
    new Uint8Array([(exts.length >>> 8) & 0xff, exts.length & 0xff]), exts
  ]);
  var head = new Uint8Array(4); put16(head, 0, ECH_VERSION); put16(head, 2, contents.length);
  return concat([head, contents]);
}

/** ECHConfig values → the ECHConfigList that goes in DNS and retry_configs. */
function build_ech_config_list(configs) {
  var body = concat(configs);
  var out = new Uint8Array(2 + body.length);
  put16(out, 0, body.length); out.set(body, 2);
  return out;
}

var KEM_BY_NAME = { 'x25519': 0x0020, 'p-256': 0x0010, 'p256': 0x0010, 'p-384': 0x0011, 'p384': 0x0011,
                    'p-521': 0x0012, 'p521': 0x0012, 'x448': 0x0021 };

/**
 * A new ECH key: `{ config, privateKey, configList, configListBase64 }`.
 * `configListBase64` is the value of `ech=` in the HTTPS record.
 *
 * opts: `publicName` (required — the name the outer hello carries, which
 * the server must hold a certificate for), `configId` (0-255; random by
 * default), `maxNameLength` (the longest name behind it, for client padding;
 * 0 = unknown), `kem` ('x25519' default, 'p-256', …).
 *
 * Cipher suites offered: HKDF-SHA256 with AES-128-GCM and ChaCha20-Poly1305
 * — what Chrome, Firefox, Cloudflare and Go use.
 */
function generate_ech_key(opts) {
  opts = opts || {};
  if (typeof opts.publicName !== 'string' || !opts.publicName) throw new TypeError('generateEchKey: publicName is required');
  var publicName = opts.publicName.toLowerCase().replace(/\.$/, '');
  // RFC 9849 §6.1.7: clients ignore a config whose public_name is not a
  // host name — LDH labels, not an IPv4 address (a numeric last label).
  var labels = publicName.split('.');
  var ldh = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  if (publicName.length > 253 || labels.some(function (l) { return !ldh.test(l); }) || /^[0-9]+$/.test(labels[labels.length - 1]) || /^0x[0-9a-f]+$/.test(labels[labels.length - 1])) {
    throw new TypeError('generateEchKey: publicName must be a DNS host name (letters, digits, hyphens; not an IP address): ' + JSON.stringify(opts.publicName));
  }
  var kem_id = 0x0020;
  if (opts.kem != null) {
    kem_id = typeof opts.kem === 'number' ? opts.kem : KEM_BY_NAME[String(opts.kem).toLowerCase()];
    if (!kem_id || !is_supported_hpke_suite(kem_id, 1, 1)) throw new TypeError('generateEchKey: unsupported kem ' + JSON.stringify(opts.kem));
  }
  var configId = opts.configId == null ? crypto.randomBytes(1)[0] : opts.configId;
  if (!(configId >= 0 && configId <= 255 && (configId | 0) === configId)) throw new TypeError('generateEchKey: configId must be 0-255');
  var maxNameLength = opts.maxNameLength == null ? 0 : opts.maxNameLength;
  if (!(maxNameLength >= 0 && maxNameLength <= 255)) throw new TypeError('generateEchKey: maxNameLength must be 0-255');

  var kp = hpke_generate_key_pair(kem_id);
  var config = encode_ech_config({
    config_id: configId, kem_id: kem_id, public_key: kp.public_key,
    cipher_suites: [{ kdf_id: 0x0001, aead_id: 0x0001 }, { kdf_id: 0x0001, aead_id: 0x0003 }],
    maximum_name_length: maxNameLength, public_name: publicName, extensions: []
  });
  var configList = build_ech_config_list([config]);
  return {
    config: config,
    privateKey: kp.private_key,
    configList: configList,
    configListBase64: Buffer.from(configList).toString('base64')
  };
}

/**
 * The server option — `{ keys: [{ config, privateKey, retry }] }` — checked
 * and prepared: each key's config parsed, its private key matched to its
 * public key (a mismatch would only show as every client failing), and the
 * retry_configs list built once. null when absent or with no keys.
 */
// Prepared once per option object — a server hands the same one to every
// connection, and checking a key costs a scalar multiplication. The entry
// remembers what it was made from: an application that changes the object
// in place (getEchKeys(), add a key, setEchKeys()) gets it prepared again,
// not the old result.
var prepared = new WeakMap();

function ech_option_snapshot(option) {
  var keys = option && option.keys, snap = [keys];
  if (Array.isArray(keys)) {
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i] || {};
      snap.push(k, k.config, k.privateKey, k.retry);
    }
  }
  return snap;
}

function same_snapshot(a, b) {
  if (a.length !== b.length) return false;
  for (var i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function prepare_ech_server(option) {
  if (option == null || option === false) return null;
  var snap = ech_option_snapshot(option);
  if (typeof option === 'object') {
    var hit = prepared.get(option);
    if (hit && same_snapshot(hit.snap, snap)) return hit.out;
  }
  var out = prepare_ech_server_uncached(option);
  if (typeof option === 'object') prepared.set(option, { snap: snap, out: out });
  return out;
}

function prepare_ech_server_uncached(option) {
  if (typeof option !== 'object' || !Array.isArray(option.keys)) throw new TypeError('ech must be { keys: [{ config, privateKey, retry }] }');
  if (option.keys.length === 0) return null;
  var keys = [], retry = [];
  for (var i = 0; i < option.keys.length; i++) {
    var k = option.keys[i] || {};
    var cfg = parse_ech_config(k.config);
    var sk = toU8(k.privateKey, 'ech.keys[' + i + '].privateKey');
    if (!is_supported_hpke_suite(cfg.kem_id, 1, 1)) throw new TypeError('ech.keys[' + i + ']: unsupported KEM 0x' + cfg.kem_id.toString(16));
    var pk;
    try { pk = hpke_public_key(cfg.kem_id, sk); } catch (e) { throw new TypeError('ech.keys[' + i + '].privateKey: ' + e.message); }
    if (!Buffer.from(pk).equals(Buffer.from(cfg.public_key))) throw new TypeError('ech.keys[' + i + ']: privateKey does not match the public key in its config');
    keys.push({ config: cfg, private_key: sk });
    if (k.retry !== false) retry.push(cfg.raw);
  }
  return { keys: keys, retry_config_list: retry.length ? build_ech_config_list(retry) : null };
}


// ============================================================
//  ClientHello bytes (RFC 8446 §4.1.2), without the handshake header
// ============================================================

/**
 * The fields of a ClientHello body with their positions — what rebuilding
 * the inner hello and zeroing the outer payload need, and what a parsed
 * message object no longer has.
 */
function scan_client_hello(body) {
  var r = new Reader(body);
  r.u16();                                            // legacy_version
  var random = r.bytes(32);
  var sidStart = r.o; var session_id = r.vec8();
  var afterSid = r.o;
  r.vec16();                                          // cipher_suites
  r.vec8();                                           // legacy_compression_methods
  var extsStart = r.o;
  var exts = [];
  if (r.o < body.length) {
    var extBlock = r.vec16();
    if (r.o !== body.length) throw eccError('trailing bytes after ClientHello', ALERT_DECODE_ERROR);
    var base = extsStart + 2, er = new Reader(extBlock);
    while (er.o < extBlock.length) {
      var at = er.o, type = er.u16(), data = er.vec16();
      exts.push({ type: type, start: base + at, end: base + er.o, data: data, dataStart: base + at + 4 });
    }
  }
  return { random: random, session_id: session_id, sidStart: sidStart, afterSid: afterSid, extsStart: extsStart, exts: exts };
}

function find_ext(scan, type) {
  for (var i = 0; i < scan.exts.length; i++) if (scan.exts[i].type === type) return scan.exts[i];
  return null;
}

/** The encrypted_client_hello extension's contents (§5). */
function parse_ech_ext(data) {
  var r = new Reader(data);
  var type = r.u8();
  if (type === 1) {
    if (r.o !== data.length) throw eccError('inner ECH extension is not empty', ALERT_DECODE_ERROR);
    return { type: 1 };
  }
  if (type !== 0) throw eccError('unknown ECHClientHello type ' + type);
  var kdf_id = r.u16(), aead_id = r.u16(), config_id = r.u8();
  var enc = r.vec16();
  var payloadOff = r.o + 2;
  var payload = r.vec16();
  if (payload.length < 1) throw eccError('empty ECH payload', ALERT_DECODE_ERROR);
  if (r.o !== data.length) throw eccError('trailing bytes in ECH extension', ALERT_DECODE_ERROR);
  return { type: 0, kdf_id: kdf_id, aead_id: aead_id, config_id: config_id, enc: enc, payload: payload, payloadOff: payloadOff };
}

/** §5.2: the outer hello with the ECH payload replaced by zeros. */
function outer_aad(body, ext, ech) {
  // A copy: on a Buffer, .slice() is a view, and zeroing it would zero the
  // hello the transcript is about to hash.
  var aad = new Uint8Array(body);
  aad.fill(0, ext.dataStart + ech.payloadOff, ext.dataStart + ech.payloadOff + ech.payload.length);
  return aad;
}

/**
 * §5.1: EncodedClientHelloInner → ClientHelloInner body. The session id
 * comes back from the outer hello; ech_outer_extensions is replaced by the
 * outer extensions it names. In linear time, as §5.1 asks: one forward walk
 * over the outer extensions for the whole reference list.
 */
function decode_inner(encoded, outerBody, outerScan) {
  var r = new Reader(encoded);
  r.u16(); r.bytes(32);
  var sidLen = r.u8();
  if (sidLen !== 0) throw eccError('EncodedClientHelloInner session id not empty');
  var afterSid = r.o;
  r.vec16(); r.vec8();
  var extsStart = r.o;
  var extBlock = r.vec16();
  // Everything after the ClientHello is padding, and must be zeros.
  for (var p = r.o; p < encoded.length; p++) {
    if (encoded[p] !== 0) throw eccError('non-zero padding in EncodedClientHelloInner');
  }

  var parts = [], er = new Reader(extBlock), sawOuter = false;
  while (er.o < extBlock.length) {
    var at = er.o, type = er.u16(), data = er.vec16();
    if (type !== EXT_ECH_OUTER_EXTENSIONS) { parts.push(extBlock.subarray(at, er.o)); continue; }
    if (sawOuter) throw eccError('ech_outer_extensions twice');
    sawOuter = true;
    var lr = new Reader(data);
    var list = lr.vec8();
    if (lr.o !== data.length || list.length < 2 || list.length % 2) throw eccError('ech_outer_extensions malformed', ALERT_DECODE_ERROR);
    var cursor = 0;                                     // into outerScan.exts: order and uniqueness in one pass
    for (var i = 0; i < list.length; i += 2) {
      var want = u16(list, i);
      if (want === EXT_ECH) throw eccError('ech_outer_extensions references encrypted_client_hello');
      while (cursor < outerScan.exts.length && outerScan.exts[cursor].type !== want) cursor++;
      if (cursor >= outerScan.exts.length) throw eccError('ech_outer_extensions references 0x' + want.toString(16) + ', missing or out of order in ClientHelloOuter');
      var oe = outerScan.exts[cursor++];
      parts.push(outerBody.subarray(oe.start, oe.end));
    }
  }

  var newExts = concat(parts);
  var sid = outerScan.session_id;
  var head = encoded.subarray(0, afterSid - 1);         // legacy_version + random
  var mid = encoded.subarray(afterSid, extsStart);      // cipher_suites + compression
  var extLen = new Uint8Array(2); put16(extLen, 0, newExts.length);
  return concat([head, new Uint8Array([sid.length]), sid, mid, extLen, newExts]);
}

/** A handshake message (type ClientHello) around a body. */
function wrap_client_hello(body) {
  var h = new Uint8Array(4 + body.length);
  h[0] = 1; h[1] = (body.length >>> 16) & 0xff; h[2] = (body.length >>> 8) & 0xff; h[3] = body.length & 0xff;
  h.set(body, 4);
  return h;
}

/**
 * §7.1: the inner hello must carry the inner ECH extension and offer
 * nothing below TLS 1.3.
 */
function check_inner(innerBody) {
  var scan = scan_client_hello(innerBody);
  var e = find_ext(scan, EXT_ECH);
  if (!e || parse_ech_ext(e.data).type !== 1) throw eccError('ClientHelloInner without the inner encrypted_client_hello extension');
  var sv = find_ext(scan, EXT_SUPPORTED_VERSIONS);
  if (!sv) throw eccError('ClientHelloInner offers TLS 1.2');
  var r = new Reader(sv.data), list = r.vec8();
  if (list.length === 0 || list.length % 2) throw eccError('ClientHelloInner supported_versions malformed', ALERT_DECODE_ERROR);
  for (var i = 0; i < list.length; i += 2) {
    var v = u16(list, i);
    // 0x?a?a is GREASE (RFC 8701). TLS 1.3 and up: 0x0304 to 0xfdff — the
    // 0xfexx codes are DTLS, never a TLS version.
    if ((v & 0x0f0f) === 0x0a0a) continue;
    if (v < 0x0304 || v >= 0xfe00) throw eccError('ClientHelloInner offers a version other than TLS 1.3 and up (0x' + v.toString(16) + ')');
  }
  return scan;
}


// ============================================================
//  The server's side (§7.1, §7.1.1)
// ============================================================

/**
 * A ClientHello as it arrived (handshake header included) → what the
 * handshake should continue with. `state` is per connection, `{}` at
 * first; it carries the HPKE context from the first ClientHello to the
 * second one after a HelloRetryRequest.
 *
 * Returns `{ data }` with the ClientHelloInner when it decrypted, null to
 * continue with the hello as it came (no ECH, or ECH not decryptable — then
 * `state.status` is 'rejected' and retry_configs are due). Throws, with
 * `.alertDesc`, where §5.1 / §7.1 / §7.1.1 require the connection to end.
 */
function server_process_client_hello(server, state, data, isSecond) {
  var body = data.subarray(4);
  var scan = scan_client_hello(body);
  var ext = find_ext(scan, EXT_ECH);

  if (isSecond) {
    if (state.status !== 'accepted') return null;     // §7.1.1: not decrypted
    if (!ext) throw eccError('second ClientHello without encrypted_client_hello', ALERT_MISSING_EXTENSION);
    var ech2 = parse_ech_ext(ext.data);
    if (ech2.type !== 0) throw eccError('second ClientHello carries the inner ECH extension');
    if (ech2.kdf_id !== state.kdf_id || ech2.aead_id !== state.aead_id || ech2.config_id !== state.config_id || ech2.enc.length !== 0) {
      throw eccError('second ClientHelloOuter changed the ECH cipher suite, config_id or enc');
    }
    var pt2 = state.context.open(outer_aad(body, ext, ech2), ech2.payload);
    if (!pt2) throw eccError('second ClientHelloInner does not decrypt', ALERT_DECRYPT_ERROR);
    var inner2 = decode_inner(pt2, body, scan);
    var scan2 = check_inner(inner2);
    // RFC 8446 §4.1.2: the second hello repeats the first one's random; the
    // ServerHello's confirmation (§7.2) is computed over it.
    if (!Buffer.from(scan2.random).equals(Buffer.from(state.inner_random))) {
      throw eccError('second ClientHelloInner changed its random');
    }
    return { data: wrap_client_hello(inner2) };
  }

  if (!ext) { state.status = null; return null; }
  var ech = parse_ech_ext(ext.data);
  if (ech.type !== 0) throw eccError('ClientHello from the network carries the inner ECH extension');

  // §7.1: candidates by config_id; each must offer the suite the client used.
  var aad = null;
  for (var i = 0; i < server.keys.length; i++) {
    var key = server.keys[i], cfg = key.config;
    if (cfg.config_id !== ech.config_id) continue;
    var offered = false;
    for (var j = 0; j < cfg.cipher_suites.length; j++) {
      if (cfg.cipher_suites[j].kdf_id === ech.kdf_id && cfg.cipher_suites[j].aead_id === ech.aead_id) offered = true;
    }
    // 0xFFFF is HPKE's export-only AEAD: it cannot carry a ClientHello.
    if (!offered || ech.aead_id === 0xffff || !is_supported_hpke_suite(cfg.kem_id, ech.kdf_id, ech.aead_id)) continue;

    var ctx;
    try {
      ctx = setup_recipient(hpke_suite(cfg.kem_id, ech.kdf_id, ech.aead_id), ech.enc, key.private_key,
                            concat([te.encode('tls ech'), new Uint8Array([0]), cfg.raw]),
                            { recipient_public_key: cfg.public_key });
    } catch (e) { continue; }                          // enc not a valid key: not this config
    if (!aad) aad = outer_aad(body, ext, ech);
    var pt = ctx.open(aad, ech.payload);
    if (!pt) continue;

    // Decrypted: from here a malformed inner hello is fatal (§5.1).
    var inner = decode_inner(pt, body, scan);
    var innerScan = check_inner(inner);
    state.status = 'accepted';
    state.context = ctx;
    state.kdf_id = ech.kdf_id; state.aead_id = ech.aead_id; state.config_id = ech.config_id;
    state.inner_random = new Uint8Array(innerScan.random);
    state.public_name = cfg.public_name;
    return { data: wrap_client_hello(inner) };
  }

  state.status = 'rejected';
  return null;
}

// ============================================================
//  The client's side (§6.1, §6.2)
//
//  The client sends two hellos in one. The real one — ClientHelloInner,
//  with the name it wants — goes encrypted, with HPKE, to the key of an
//  ECHConfig the server published (DNS). Around it, in the clear,
//  ClientHelloOuter names the config's public_name. Extensions the two share
//  are not sent twice: the inner hello names them (ech_outer_extensions,
//  §5.1) and the server copies them back from the outer one — the key_share
//  above all, the largest.
//
//  The server answers either as the inner hello's server — and says so with
//  8 bytes of its random that only a holder of the inner hello can compute
//  (§7.2) — or, unable to decrypt, as the public_name, with its current keys
//  in retry_configs. Which one is known only at the ServerHello, so until
//  then the client keeps both transcripts (tls_session).
// ============================================================

// RFC 9849 §6.1.7: a public_name the client uses — a DNS host name, not an
// IPv4 address in any notation (a last label that is all digits, or 0x…).
function valid_public_name(name) {
  if (!name || name.length > 253) return false;
  var labels = name.toLowerCase().replace(/\.$/, '').split('.');
  var ldh = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
  for (var i = 0; i < labels.length; i++) if (!ldh.test(labels[i])) return false;
  var last = labels[labels.length - 1];
  return !/^[0-9]+$/.test(last) && !/^0x[0-9a-f]*$/.test(last);
}

// The cipher suites a client offers, in preference: what every deployment
// publishes first.
var CLIENT_SUITE_PREF = [[0x0001, 0x0001], [0x0001, 0x0003], [0x0001, 0x0002], [0x0002, 0x0002], [0x0003, 0x0002], [0x0002, 0x0001], [0x0003, 0x0001], [0x0002, 0x0003], [0x0003, 0x0003]];

/**
 * The client option — an ECHConfigList (bytes, or base64: the `ech=` value
 * of an HTTPS record) — → the config to use: the first in the list this
 * client can (§6.1: a KEM and a suite it has, a valid public_name, no
 * mandatory extension it does not know). null when absent. Throws on a list
 * that is malformed, or that has no usable config.
 */
function prepare_ech_client(option) {
  if (option == null || option === false) return null;
  var list;
  try { list = parse_ech_config_list(option); }
  catch (e) { throw new TypeError('ech: not an ECHConfigList — ' + e.message); }
  for (var i = 0; i < list.length; i++) {
    var c = list[i];
    if (!is_supported_hpke_suite(c.kem_id, 1, 1)) continue;
    if (!valid_public_name(c.public_name)) continue;
    var mandatory = false;
    for (var x = 0; x < c.extensions.length; x++) if (c.extensions[x].type & 0x8000) mandatory = true;
    if (mandatory) continue;
    var pick = null;
    for (var p = 0; p < CLIENT_SUITE_PREF.length && !pick; p++) {
      for (var j = 0; j < c.cipher_suites.length; j++) {
        var cs = c.cipher_suites[j];
        if (cs.kdf_id === CLIENT_SUITE_PREF[p][0] && cs.aead_id === CLIENT_SUITE_PREF[p][1] && is_supported_hpke_suite(c.kem_id, cs.kdf_id, cs.aead_id)) { pick = cs; break; }
      }
    }
    if (!pick) continue;
    return { config: c, kdf_id: pick.kdf_id, aead_id: pick.aead_id, suite: hpke_suite(c.kem_id, pick.kdf_id, pick.aead_id) };
  }
  throw new TypeError('ech: no ECHConfig in the list this client can use (version 0xfe0d, a supported KEM and cipher suite, a host-name public_name)');
}

/** §6.1: the HPKE sender context for this connection: `{ enc, context }`. */
function client_hpke_setup(prep) {
  var info = concat([te.encode('tls ech'), new Uint8Array([0]), prep.config.raw]);
  return setup_sender(prep.suite, prep.config.public_key, info);
}

/** The outer encrypted_client_hello extension (§5), its payload zero. */
function client_outer_ext_data(kdf_id, aead_id, config_id, enc, payloadLen) {
  var out = new Uint8Array(1 + 2 + 2 + 1 + 2 + enc.length + 2 + payloadLen);
  var o = 0;
  out[o++] = 0;
  put16(out, o, kdf_id); o += 2;
  put16(out, o, aead_id); o += 2;
  out[o++] = config_id & 0xff;
  put16(out, o, enc.length); o += 2;
  out.set(enc, o); o += enc.length;
  put16(out, o, payloadLen);
  return out;
}

/**
 * §5.1, §6.1.3: ClientHelloInner (a handshake message, as the transcript
 * has it) → EncodedClientHelloInner: no session id (it comes back from the
 * outer hello); the extensions of type in `compressed` — consecutive in the
 * inner hello, in the order the outer one has them — replaced by one
 * ech_outer_extensions naming them; then zeros, so the length gives away
 * little of the name: the server_name padded to maximum_name_length, and
 * the whole to a multiple of 32.
 */
function client_encode_inner(innerMsg, compressed, maxNameLength, sniLength) {
  var body = innerMsg.subarray(4);
  var scan = scan_client_hello(body);
  var parts = [], placed = false;
  for (var i = 0; i < scan.exts.length; i++) {
    var e = scan.exts[i];
    if (compressed.indexOf(e.type) >= 0) {
      if (placed) continue;
      placed = true;
      var list = new Uint8Array(1 + compressed.length * 2);
      list[0] = compressed.length * 2;
      for (var k = 0; k < compressed.length; k++) put16(list, 1 + k * 2, compressed[k]);
      var h = new Uint8Array(4); put16(h, 0, EXT_ECH_OUTER_EXTENSIONS); put16(h, 2, list.length);
      parts.push(h, list);
      continue;
    }
    parts.push(body.subarray(e.start, e.end));
  }
  var exts = concat(parts);
  var head = body.subarray(0, scan.sidStart);                  // legacy_version + random
  var mid = body.subarray(scan.afterSid, scan.extsStart);      // cipher_suites + compression
  var extLen = new Uint8Array(2); put16(extLen, 0, exts.length);
  var encoded = concat([head, new Uint8Array([0]), mid, extLen, exts]);
  var pad = sniLength != null ? Math.max(0, maxNameLength - sniLength) : 9 + maxNameLength;
  pad += 31 - ((encoded.length + pad - 1) % 32);
  return concat([encoded, new Uint8Array(pad)]);
}

/**
 * ClientHelloOuter (a handshake message, its ECH payload zero) → the same
 * with the payload: `encoded` sealed with AAD = the outer hello itself, as
 * it is now (§5.2).
 */
function client_seal_outer(outerMsg, hpkeContext, encoded) {
  var body = outerMsg.subarray(4);
  var scan = scan_client_hello(body);
  var ext = find_ext(scan, EXT_ECH);
  var ech = parse_ech_ext(ext.data);
  var ct = hpkeContext.seal(new Uint8Array(body), encoded);
  if (ct.length !== ech.payload.length) throw new Error('ECH: sealed payload length differs from the space left for it');
  var out = new Uint8Array(outerMsg);
  out.set(ct, 4 + ext.dataStart + ech.payloadOff);
  return out;
}

/**
 * §6.2: GREASE ECH — an encrypted_client_hello extension that decrypts
 * under no key, from a client with no config, so that one with a config
 * does not stand out. `g` is fixed per connection (config_id, payload
 * length); after a HelloRetryRequest, `enc` is empty and the payload new
 * random bytes of the same length.
 */
function grease_ech_state() {
  var lens = [144, 176, 208, 240];
  return { config_id: crypto.randomBytes(1)[0], payload_len: lens[crypto.randomBytes(1)[0] & 3] + 16 };
}
function grease_ech_ext_data(g, second) {
  var enc = second ? new Uint8Array(0) : new Uint8Array(crypto.randomBytes(32));
  var d = client_outer_ext_data(0x0001, 0x0001, g.config_id, enc, g.payload_len);
  d.set(crypto.randomBytes(g.payload_len), d.length - g.payload_len);
  return d;
}

/**
 * A HelloRetryRequest (a handshake message): where its encrypted_client_hello
 * extension's 8 bytes start, or -1 when it has none (§7.2.1: the server did
 * not decrypt). decode_error on a malformed one.
 */
function hrr_ech_offset(hrrMsg) {
  var r = new Reader(hrrMsg, 4);
  r.u16(); r.bytes(32); r.vec8(); r.u16(); r.u8();
  if (r.o >= hrrMsg.length) return -1;
  var extEnd = r.u16(); extEnd += r.o;
  if (extEnd !== hrrMsg.length) throw eccError('HelloRetryRequest extensions malformed', ALERT_DECODE_ERROR);
  while (r.o < extEnd) {
    var type = r.u16(), len = r.u16(), at = r.o;
    r.bytes(len);
    if (type === EXT_ECH) {
      if (len !== 8) throw eccError('HelloRetryRequest encrypted_client_hello is not 8 bytes', ALERT_DECODE_ERROR);
      return at;
    }
  }
  return -1;
}


/**
 * §7.2 / §7.2.1: the 8 confirmation bytes, over the transcript hash that
 * ends with the ServerHello (its last 8 random bytes zero) or with the
 * HelloRetryRequest (its ECH extension's 8 bytes zero).
 */
function accept_confirmation(hashName, innerRandom, transcriptHash, isHrr, labelPrefix) {
  var prk = hkdf_extract(hashName, new Uint8Array(0), innerRandom);   // salt: Hash.length zeros
  return hkdf_expand_label(hashName, prk, isHrr ? 'hrr ech accept confirmation' : 'ech accept confirmation',
                           transcriptHash, 8, labelPrefix);
}

export {
  ECH_VERSION, EXT_ECH,
  parse_ech_config_list,
  prepare_ech_client,
  client_hpke_setup,
  client_outer_ext_data,
  client_encode_inner,
  client_seal_outer,
  grease_ech_state,
  grease_ech_ext_data,
  hrr_ech_offset,
  parse_ech_config,
  encode_ech_config,
  build_ech_config_list,
  generate_ech_key,
  prepare_ech_server,
  server_process_client_hello,
  accept_confirmation,
  scan_client_hello,
  parse_ech_ext,
};
