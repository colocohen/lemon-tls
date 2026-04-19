
import {
  concatUint8Arrays
} from './utils.js';


const TLS_VERSION = {
  TLS1_0: 0x0301,
  TLS1_1: 0x0302,
  TLS1_2: 0x0303,
  TLS1_3: 0x0304
};

const DTLS_VERSION = {
  DTLS1_0: 0xFEFF,
  DTLS1_2: 0xFEFD,
  DTLS1_3: 0xFEFC
};

const TLS_CONTENT_TYPE = {
  CHANGE_CIPHER_SPEC: 20,
  ALERT: 21,
  HANDSHAKE: 22,
  APPLICATION_DATA: 23
};

const TLS_ALERT_LEVEL = {
  WARNING: 1,
  FATAL: 2
};

const TLS_ALERT = {
  CLOSE_NOTIFY: 0,
  UNEXPECTED_MESSAGE: 10,
  BAD_RECORD_MAC: 20,
  RECORD_OVERFLOW: 22,
  HANDSHAKE_FAILURE: 40,
  BAD_CERTIFICATE: 42,
  CERTIFICATE_EXPIRED: 45,
  CERTIFICATE_UNKNOWN: 46,
  ILLEGAL_PARAMETER: 47,
  UNKNOWN_CA: 48,
  DECODE_ERROR: 50,
  DECRYPT_ERROR: 51,
  PROTOCOL_VERSION: 70,
  INSUFFICIENT_SECURITY: 71,
  INTERNAL_ERROR: 80,
  USER_CANCELED: 90,
  MISSING_EXTENSION: 109,
  UNSUPPORTED_EXTENSION: 110,
  UNRECOGNIZED_NAME: 112,
  NO_APPLICATION_PROTOCOL: 120
};

const TLS_MESSAGE_TYPE = {
  CLIENT_HELLO: 1,
  SERVER_HELLO: 2,
  NEW_SESSION_TICKET: 4,
  END_OF_EARLY_DATA: 5,
  ENCRYPTED_EXTENSIONS: 8,
  CERTIFICATE: 11,
  SERVER_KEY_EXCHANGE: 12,
  CERTIFICATE_REQUEST: 13,
  SERVER_HELLO_DONE: 14,
  CERTIFICATE_VERIFY: 15,
  CLIENT_KEY_EXCHANGE: 16,
  FINISHED: 20,
  KEY_UPDATE: 24,
  MESSAGE_HASH: 254 // HRR flow marker
};

// RFC 8446 §4.1.3: special sentinel random that identifies a ServerHello as HelloRetryRequest
const TLS13_HRR_RANDOM = new Uint8Array([
  0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
  0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
  0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
  0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
]);

const TLS_EXT = {
  SERVER_NAME: 0,
  MAX_FRAGMENT_LENGTH: 1,
  STATUS_REQUEST: 5,
  SUPPORTED_GROUPS: 10,
  SIGNATURE_ALGORITHMS: 13,
  USE_SRTP: 14,
  HEARTBEAT: 15,
  ALPN: 16,
  SCT: 18,
  CLIENT_CERT_TYPE: 19,
  SERVER_CERT_TYPE: 20,
  PADDING: 21,
  EXTENDED_MASTER_SECRET: 23,
  SESSION_TICKET: 35,
  PRE_SHARED_KEY: 41,
  EARLY_DATA: 42,
  SUPPORTED_VERSIONS: 43,
  COOKIE: 44,
  PSK_KEY_EXCHANGE_MODES: 45,
  CERTIFICATE_AUTHORITIES: 47,
  OID_FILTERS: 48,
  POST_HANDSHAKE_AUTH: 49,
  SIGNATURE_ALGORITHMS_CERT: 50,
  KEY_SHARE: 51,
  RENEGOTIATION_INFO: 0xFF01
};

/* =============================== Small utils ============================== */

function toU8(x) {
  if (x == null) return new Uint8Array(0);
  if (x instanceof Uint8Array) return x;
  if (typeof x === 'string') return (new TextEncoder()).encode(x);
  return new Uint8Array(0);
}

/* ============================ Binary write helpers ============================ */
function w_u8(buf, off, v) {
  buf[off++] = v & 0xFF;
  return off;
}

function w_u16(buf, off, v) {
  buf[off++] = (v >>> 8) & 0xFF;
  buf[off++] = v & 0xFF;
  return off;
}

function w_u24(buf, off, v) {
  buf[off++] = (v >>> 16) & 0xFF;
  buf[off++] = (v >>> 8) & 0xFF;
  buf[off++] = v & 0xFF;
  return off;
}

function w_u48(buf, off, v) {
  let hi = Math.floor(v / 0x100000000);
  let lo = v >>> 0;
  buf[off++] = (hi >>> 8) & 0xFF;
  buf[off++] = hi & 0xFF;
  buf[off++] = (lo >>> 24) & 0xFF;
  buf[off++] = (lo >>> 16) & 0xFF;
  buf[off++] = (lo >>> 8) & 0xFF;
  buf[off++] = lo & 0xFF;
  return off;
}

function w_bytes(buf, off, b) {
  buf.set(b, off);
  return off + b.length;
}

/* ============================ Binary read helpers ============================ */
function r_u8(buf, off) {
  return [buf[off++] >>> 0, off];
}

function r_u16(buf, off) {
  let v = ((buf[off] << 8) | buf[off + 1]) >>> 0;
  return [v, off + 2];
}

function r_u24(buf, off) {
  let v = ((buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2]) >>> 0;
  return [v, off + 3];
}

function r_bytes(buf, off, n) {
  let slice;
  if (buf instanceof Uint8Array) {
    // real slice from Uint8Array
    slice = buf.slice(off, off + n);
  } else if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(buf)) {
    // Node Buffer slice returns view, copy to Uint8Array
    let tmp = buf.slice(off, off + n);
    slice = new Uint8Array(tmp);
  } else if (Array.isArray(buf)) {
    // plain array
    let tmp = buf.slice(off, off + n);
    slice = new Uint8Array(tmp);
  } else {
    throw new Error("r_bytes: unsupported buffer type " + (typeof buf));
  }
  return [slice, off + n];
}


/* ================================= Vectors ================================= */
function veclen(lenBytes, inner) {
  let out, off = 0;

  if (lenBytes === 1) {
    out = new Uint8Array(1 + inner.length);
    off = w_u8(out, off, inner.length);
    off = w_bytes(out, off, inner);
    return out;
  }

  if (lenBytes === 2) {
    out = new Uint8Array(2 + inner.length);
    off = w_u16(out, off, inner.length);
    off = w_bytes(out, off, inner);
    return out;
  }

  if (lenBytes === 3) {
    out = new Uint8Array(3 + inner.length);
    off = w_u24(out, off, inner.length);
    off = w_bytes(out, off, inner);
    return out;
  }

  throw new Error('veclen only supports 1/2/3');
}

function readVec(buf, off, lenBytes) {
  let n, off2 = off;

  if (lenBytes === 1) {
    [n, off2] = r_u8(buf, off2);
  } else if (lenBytes === 2) {
    [n, off2] = r_u16(buf, off2);
  } else {
    [n, off2] = r_u24(buf, off2);
  }

  let b;
  [b, off2] = r_bytes(buf, off2, n);
  return [b, off2];
}

/* =========================== Extensions registry =========================== */
let exts = {};

// Predeclare wanted entries
exts.SERVER_NAME = { encode: null, decode: null };
exts.SUPPORTED_VERSIONS = { encode: null, decode: null };
exts.SUPPORTED_GROUPS = { encode: null, decode: null };
exts.SIGNATURE_ALGORITHMS = { encode: null, decode: null };
exts.PSK_KEY_EXCHANGE_MODES = { encode: null, decode: null };
exts.KEY_SHARE = { encode: null, decode: null };
exts.ALPN = { encode: null, decode: null };
exts.COOKIE = { encode: null, decode: null };
exts.RENEGOTIATION_INFO = { encode: null, decode: null };
exts.SESSION_TICKET = { encode: null, decode: null };
exts.EXTENDED_MASTER_SECRET = { encode: null, decode: null };

/* ------------------------------ SERVER_NAME (0) ------------------------------ */
exts.SERVER_NAME.encode = function (value) {
  let host = toU8(value || "");

  // one name: type(1)=0, len(2), bytes
  const inner = new Uint8Array(1 + 2 + host.length);
  let off = 0;

  off = w_u8(inner, off, 0);
  off = w_u16(inner, off, host.length);
  off = w_bytes(inner, off, host);

  // ServerNameList is vector<2>
  return veclen(2, inner);
};

exts.SERVER_NAME.decode = function (data) {
  let off = 0;
  let list;
  [list, off] = readVec(data, off, 2);

  let off2 = 0;
  let host = "";

  while (off2 < list.length) {
    let typ;
    [typ, off2] = r_u8(list, off2);

    let l;
    [l, off2] = r_u16(list, off2);

    let v;
    [v, off2] = r_bytes(list, off2, l);

    if (typ === 0) {
      host = (new TextDecoder()).decode(v);
    }
  }

  // Return just the value (string), not {host: ...}
  return host;
};

/* --------------------------- SUPPORTED_VERSIONS (43) --------------------------- */
exts.SUPPORTED_VERSIONS.encode = function (value) {
  // ServerHello form: selected (number)
  if (typeof value === 'number') {
    const out = new Uint8Array(2);
    let off = 0;
    off = w_u16(out, off, value);
    return out;
  }

  // ClientHello form: array of versions
  let arr = Array.isArray(value) ? value : [TLS_VERSION.TLS1_3, TLS_VERSION.TLS1_2];

  const body = new Uint8Array(1 + arr.length * 2);
  let off2 = 0;

  off2 = w_u8(body, off2, arr.length * 2);
  for (let i = 0; i < arr.length; i++) {
    off2 = w_u16(body, off2, arr[i]);
  }
  return body;
};

exts.SUPPORTED_VERSIONS.decode = function (data) {
  // ServerHello form: 2 bytes
  if (data.length === 2) {
    let v, off = 0;
    [v, off] = r_u16(data, off);
    return [v]; // return the selected version (number)
  }

  // ClientHello form: vector<1> of versions (u16 each)
  let off2 = 0;
  let n;
  [n, off2] = r_u8(data, off2);

  let out = [];
  for (let i = 0; i < n; i += 2) {
    let vv;
    [vv, off2] = r_u16(data, off2);
    out.push(vv);
  }
  return out; // return the array directly
};

/* ---------------------------- SUPPORTED_GROUPS (10) ---------------------------- */
exts.SUPPORTED_GROUPS.encode = function (value) {
  let groups = Array.isArray(value) && value.length>0 ? value : [23, 29]; // secp256r1, x25519

  const body = new Uint8Array(2 + groups.length * 2);
  let off = 0;

  off = w_u16(body, off, groups.length * 2);
  for (let i = 0; i < groups.length; i++) {
    off = w_u16(body, off, groups[i]);
  }
  return body;
};

exts.SUPPORTED_GROUPS.decode = function (data) {
  let off = 0;
  let n;
  [n, off] = r_u16(data, off);

  let out = [];
  for (let i = 0; i < n; i += 2) {
    let g;
    [g, off] = r_u16(data, off);
    out.push(g);
  }
  return out; // array of named groups
};

/* -------------------------- SIGNATURE_ALGORITHMS (13) -------------------------- */
exts.SIGNATURE_ALGORITHMS.encode = function (value) {
  let algs = Array.isArray(value) && value.length>0 ? value : [0x0403, 0x0804, 0x0401];

  const body = new Uint8Array(2 + algs.length * 2);
  let off = 0;

  off = w_u16(body, off, algs.length * 2);
  for (let i = 0; i < algs.length; i++) {
    off = w_u16(body, off, algs[i]);
  }
  return body;
};

exts.SIGNATURE_ALGORITHMS.decode = function (data) {
  let off = 0;
  let n;
  [n, off] = r_u16(data, off);

  let out = [];
  for (let i = 0; i < n; i += 2) {
    let a;
    [a, off] = r_u16(data, off);
    out.push(a);
  }
  return out; // array of sigalgs (u16)
};

/* ------------------------ PSK_KEY_EXCHANGE_MODES (45) ------------------------ */
exts.PSK_KEY_EXCHANGE_MODES.encode = function (value) {
  let modes = Array.isArray(value) ? value : [1]; // 0=psk_ke, 1=psk_dhe_ke

  const body = new Uint8Array(1 + modes.length);
  let off = 0;

  off = w_u8(body, off, modes.length);
  for (let i = 0; i < modes.length; i++) {
    off = w_u8(body, off, modes[i]);
  }
  return body;
};

exts.PSK_KEY_EXCHANGE_MODES.decode = function (data) {
  let off = 0;
  let n;
  [n, off] = r_u8(data, off);

  let out = [];
  for (let i = 0; i < n; i++) {
    let m;
    [m, off] = r_u8(data, off);
    out.push(m);
  }
  return out; // array of modes (u8)
};

/* ------------------------------- PRE_SHARED_KEY (41) ------------------------------- */
exts.PRE_SHARED_KEY = { encode: null, decode: null };

/**
 * Encode pre_shared_key for ClientHello.
 * value = { identities: [{identity, age}], binders: [Uint8Array] }
 * For ServerHello: value = { selected: number }
 */
exts.PRE_SHARED_KEY.encode = function (value) {
  if (typeof value.selected === 'number') {
    // ServerHello: just selected_identity (u16)
    let out = new Uint8Array(2);
    w_u16(out, 0, value.selected);
    return out;
  }

  // ClientHello: identities + binders
  let identities = value.identities || [];
  let binders = value.binders || [];

  // Build identities list
  let idParts = [];
  for (let i = 0; i < identities.length; i++) {
    let id = identities[i].identity;
    if (!(id instanceof Uint8Array)) id = new Uint8Array(id);
    let age = identities[i].age || 0;
    let entry = new Uint8Array(2 + id.length + 4);
    let off = 0;
    off = w_u16(entry, off, id.length);
    off = w_bytes(entry, off, id);
    entry[off++] = (age >>> 24) & 0xff;
    entry[off++] = (age >>> 16) & 0xff;
    entry[off++] = (age >>> 8) & 0xff;
    entry[off++] = age & 0xff;
    idParts.push(entry);
  }
  let idList = concatUint8Arrays(idParts);
  let idVec = veclen(2, idList);

  // Build binders list
  let binderParts = [];
  for (let i = 0; i < binders.length; i++) {
    let b = binders[i];
    if (!(b instanceof Uint8Array)) b = new Uint8Array(b);
    let entry = new Uint8Array(1 + b.length);
    entry[0] = b.length;
    entry.set(b, 1);
    binderParts.push(entry);
  }
  let binderList = concatUint8Arrays(binderParts);
  let binderVec = veclen(2, binderList);

  return concatUint8Arrays([idVec, binderVec]);
};

exts.PRE_SHARED_KEY.decode = function (data) {
  let off = 0;

  // Try ServerHello (2 bytes = selected_identity)
  if (data.length === 2) {
    let sel;
    [sel, off] = r_u16(data, off);
    return { selected: sel };
  }

  // ClientHello: identities + binders
  let idLen;
  [idLen, off] = r_u16(data, off);
  let idEnd = off + idLen;
  let identities = [];
  while (off < idEnd) {
    let idL;
    [idL, off] = r_u16(data, off);
    let identity;
    [identity, off] = r_bytes(data, off, idL);
    let age = (data[off] << 24) | (data[off+1] << 16) | (data[off+2] << 8) | data[off+3];
    off += 4;
    identities.push({ identity: identity, age: age >>> 0 });
  }

  let binderLen;
  [binderLen, off] = r_u16(data, off);
  let binderEnd = off + binderLen;
  let binders = [];
  while (off < binderEnd) {
    let bL;
    [bL, off] = r_u8(data, off);
    let binder;
    [binder, off] = r_bytes(data, off, bL);
    binders.push(binder);
  }

  return { identities: identities, binders: binders };
};

/* --------------------------------- KEY_SHARE (51) -------------------------------- */
exts.KEY_SHARE.encode = function (value) {
  // ServerHello form: { group:number, key_exchange:Uint8Array }
  if (value && typeof value.group === 'number' && value.key_exchange) {
    let ke = toU8(value.key_exchange);

    const out = new Uint8Array(2 + 2 + ke.length);
    let off = 0;

    off = w_u16(out, off, value.group);
    off = w_u16(out, off, ke.length);
    off = w_bytes(out, off, ke);

    return out;
  }

  // ClientHello form: [{ group:number, key_exchange:Uint8Array }, ...]
  let list = Array.isArray(value) ? value : [];

  let parts = [];
  for (let i = 0; i < list.length; i++) {
    let e = list[i];
    let ke2 = toU8(e.key_exchange || new Uint8Array(0));

    const ent = new Uint8Array(2 + 2 + ke2.length);
    let o2 = 0;

    o2 = w_u16(ent, o2, e.group >>> 0);
    o2 = w_u16(ent, o2, ke2.length);
    o2 = w_bytes(ent, o2, ke2);

    parts.push(ent);
  }

  return veclen(2, concatUint8Arrays(parts));
};

exts.KEY_SHARE.decode = function (data) {
  // HelloRetryRequest form: just NamedGroup (2 bytes, no key_exchange)
  if (data.length === 2) {
    let g, off = 0;
    [g, off] = r_u16(data, off);
    return [{ group: g, key_exchange: new Uint8Array(0) }];
  }

  // Try ServerHello form: group(2) + len(2) + key
  if (data.length >= 4) {
    let g, off = 0;
    [g, off] = r_u16(data, off);

    let l;
    [l, off] = r_u16(data, off);

    if (4 + l === data.length) {
      let ke;
      [ke, off] = r_bytes(data, off, l);
      // Two fields required → return object
      return [{ group: g, key_exchange: ke }];
    }
  }

  // ClientHello form: vector<2> of KeyShareEntry
  let off2 = 0;
  let listBytes;
  [listBytes, off2] = r_u16(data, off2);

  let end = off2 + listBytes;
  let out = [];

  while (off2 < end) {
    let g2;
    [g2, off2] = r_u16(data, off2);

    let l2;
    [l2, off2] = r_u16(data, off2);

    let ke2;
    [ke2, off2] = r_bytes(data, off2, l2);

    out.push({ group: g2, key_exchange: ke2 });
  }

  return out; // array of entries
};

/* ------------------------------------ ALPN (16) ----------------------------------- */
exts.ALPN.encode = function (value) {
  let list = Array.isArray(value) ? value : [];

  let total = 2; // vec16 length
  let items = [];

  for (let i = 0; i < list.length; i++) {
    let p = toU8(list[i]);
    items.push(p);
    total += 1 + p.length;
  }

  const out = new Uint8Array(total);
  let off = 0;

  off = w_u16(out, off, total - 2);
  for (let j = 0; j < items.length; j++) {
    off = w_u8(out, off, items[j].length);
    off = w_bytes(out, off, items[j]);
  }

  return out;
};

exts.ALPN.decode = function (data) {
  let off = 0;
  let n;
  [n, off] = r_u16(data, off);

  let end = off + n;
  let out = [];

  while (off < end) {
    let l;
    [l, off] = r_u8(data, off);

    let v;
    [v, off] = r_bytes(data, off, l);

    out.push((new TextDecoder()).decode(v));
  }

  return out; // array of protocol strings
};

/* ----------------------------- RENEGOTIATION_INFO (FF01) ----------------------------- */
exts.RENEGOTIATION_INFO.encode = function (value) {
  // value is Uint8Array of renegotiated_connection data
  let rb = toU8(value || new Uint8Array(0));
  return veclen(1, rb);
};

exts.RENEGOTIATION_INFO.decode = function (data) {
  let off = 0;
  let v;
  [v, off] = readVec(data, off, 1);
  return v; // return raw bytes (Uint8Array)
};

/* -------------------------------- COOKIE (44) -------------------------------- */
exts.COOKIE.encode = function (value) {
  let v = toU8(value || new Uint8Array(0));
  return veclen(2, v);
};

exts.COOKIE.decode = function (data) {
  let off = 0;
  let v;
  [v, off] = readVec(data, off, 2);
  return v; // Uint8Array — opaque cookie
};

/* ---------------------------- SESSION_TICKET (35) ---------------------------- */
// RFC 5077. Both directions carry opaque bytes (not a length-prefixed vector).
//   ClientHello: empty = "I support tickets" / non-empty = "resume using this ticket"
//   ServerHello: empty = "I will send a NewSessionTicket" (never non-empty in ServerHello)
exts.SESSION_TICKET.encode = function (value) {
  return toU8(value || new Uint8Array(0));
};

exts.SESSION_TICKET.decode = function (data) {
  return data; // opaque bytes — caller interprets
};

/* -------------------------- EXTENDED_MASTER_SECRET (23) -------------------------- */
// RFC 7627. Both directions: empty body. Signals support for Extended Master Secret.
exts.EXTENDED_MASTER_SECRET.encode = function (value) {
  return new Uint8Array(0);
};

exts.EXTENDED_MASTER_SECRET.decode = function (data) {
  return true; // presence is the signal
};
/* ============================= Extensions helpers ============================= */
function ext_name_by_code(code) {
  // best-effort pretty name
  for (let k in TLS_EXT) {
    if ((TLS_EXT[k] >>> 0) === (code >>> 0)) return k;
  }
  return 'EXT_' + code;
}

function build_extensions(list) {
  // list items may be {type:number|string, value:any, data?:Uint8Array}
  if (!list || !list.length) {
    const e = new Uint8Array(2);
    w_u16(e, 0, 0);
    return e;
  }

  let parts = [];
  let total = 2; // vec16

  for (let i = 0; i < list.length; i++) {
    let t = list[i].type;

    // allow symbolic name e.g. 'SERVER_NAME'
    if (typeof t === 'string') {
      t = TLS_EXT[t];
    }

    let payload;
    if (list[i].data) {
      payload = list[i].data;
    } else {
      // try registry
      let regKey = ext_name_by_code(t);
      let enc = exts[regKey] && exts[regKey].encode;
      payload = enc ? enc(list[i].value) : new Uint8Array(0);
    }

    const rec = new Uint8Array(4 + payload.length);
    let off = 0;

    off = w_u16(rec, off, t >>> 0);
    off = w_u16(rec, off, payload.length);
    off = w_bytes(rec, off, payload);

    parts.push(rec);
    total += rec.length;
  }

  const out = new Uint8Array(total);
  let off2 = 0;

  off2 = w_u16(out, off2, total - 2);

  for (let j = 0; j < parts.length; j++) {
    off2 = w_bytes(out, off2, parts[j]);
  }

  return out;
}

function parse_extensions(buf) {
  let off = 0;
  let n;
  [n, off] = r_u16(buf, off);

  let end = off + n;
  let out = [];

  while (off < end) {
    let t;
    [t, off] = r_u16(buf, off);

    let l;
    [l, off] = r_u16(buf, off);

    let d;
    [d, off] = r_bytes(buf, off, l);

    let name = ext_name_by_code(t);
    let dec = exts[name] && exts[name].decode;
    let val = dec ? dec(d) : null;

    out.push({ type: t, name: name, data: d, value: val });
  }

  return out;
}


/* ================================ Hello I/O ================================ */
function build_hello(params) {
  params = params || {};
  let kind = params.kind;

  let isDtls = (params.cookie !== undefined) ||
               (params.version !== undefined && (params.version & 0xFF00) === 0xFE00);
  let legacy_version = isDtls ? DTLS_VERSION.DTLS1_2 : TLS_VERSION.TLS1_2;

  let sid = toU8(params.session_id || "");
  if (sid.length > 32) sid = sid.subarray(0, 32);

  let extsBuf = build_extensions(params.extensions || []);

  if (kind === 'client') {
    let cs = params.cipher_suites || [0x1301, 0x1302, 0x1303, 0xC02F, 0xC02B];

    const csBlock = new Uint8Array(2 + cs.length * 2);
    let o = 0;
    o = w_u16(csBlock, o, cs.length * 2);
    for (let i = 0; i < cs.length; i++) {
      o = w_u16(csBlock, o, cs[i]);
    }

    let comp = params.legacy_compression || [0]; // for TLS1.3 must be [0]
    const compBlock = new Uint8Array(1 + comp.length);
    let oc = 0;
    oc = w_u8(compBlock, oc, comp.length);
    for (let j = 0; j < comp.length; j++) {
      oc = w_u8(compBlock, oc, comp[j]);
    }

    // DTLS cookie field (between session_id and cipher_suites)
    let cookieBuf = null;
    if (params.cookie !== undefined) {
      let cookie = toU8(params.cookie);
      cookieBuf = new Uint8Array(1 + cookie.length);
      cookieBuf[0] = cookie.length;
      if (cookie.length > 0) cookieBuf.set(cookie, 1);
    }

    const out = new Uint8Array(
      2 + 32 + 1 + sid.length +
      (cookieBuf ? cookieBuf.length : 0) +
      csBlock.length + compBlock.length + extsBuf.length
    );

    let off = 0;
    off = w_u16(out, off, legacy_version);
    off = w_bytes(out, off, params.random);
    off = w_u8(out, off, sid.length);
    off = w_bytes(out, off, sid);
    if (cookieBuf) off = w_bytes(out, off, cookieBuf);
    off = w_bytes(out, off, csBlock);
    off = w_bytes(out, off, compBlock);
    off = w_bytes(out, off, extsBuf);

    return out;
  }

  if (kind === 'server') {
    let cipher_suite = (typeof params.cipher_suite === 'number') ? params.cipher_suite : 0x1301;

    const out2 = new Uint8Array(2 + 32 + 1 + sid.length + 2 + 1 + extsBuf.length);
    let off2 = 0;

    off2 = w_u16(out2, off2, legacy_version);
    off2 = w_bytes(out2, off2, params.random);
    off2 = w_u8(out2, off2, sid.length);
    off2 = w_bytes(out2, off2, sid);
    off2 = w_u16(out2, off2, cipher_suite);
    off2 = w_u8(out2, off2, 0); // compression method = 0
    off2 = w_bytes(out2, off2, extsBuf);

    return out2;
  }

  throw new Error('build_hello: kind must be "client" or "server"');
}

function parse_hello(params) {
  let hsType = params.kind;
  let body = params.body;
  let isClient = (hsType === 'client' || hsType === TLS_MESSAGE_TYPE.CLIENT_HELLO || hsType === 'client_hello');
  let off = 0;

  // --- shared fields ---
  let legacy_version; [legacy_version, off] = r_u16(body, off);
  let random;         [random,         off] = r_bytes(body, off, 32);
  let sidLen;         [sidLen,         off] = r_u8(body, off);
  let session_id;     [session_id,     off] = r_bytes(body, off, sidLen);

  let cipher_suites = [];
  let legacy_compression = [];
  let type = isClient ? 'client_hello' : 'server_hello';

  // DTLS cookie — auto-detect by version (DTLS versions have 0xFE in high byte)
  let dtls_cookie = null;
  let isDTLS = (legacy_version & 0xFF00) === 0xFE00;

  if (isClient) {
    // --- ClientHello ---
    // DTLS ClientHello has a cookie field between session_id and cipher_suites
    if (isDTLS) {
      let cookieLen; [cookieLen, off] = r_u8(body, off);
      if (cookieLen > 0) {
        [dtls_cookie, off] = r_bytes(body, off, cookieLen);
      }
    }

    let csLen; [csLen, off] = r_u16(body, off);
    let csEnd = off + csLen;
    while (off < csEnd) {
      let cs; [cs, off] = r_u16(body, off);
      cipher_suites.push(cs);
    }

    let compLen; [compLen, off] = r_u8(body, off);
    for (let i = 0; i < compLen; i++) {
      let c; [c, off] = r_u8(body, off);
      legacy_compression.push(c);
    }

  } else {
    // --- ServerHello ---
    let cipher_suite; [cipher_suite, off] = r_u16(body, off);
    cipher_suites = [cipher_suite];

    let comp; [comp, off] = r_u8(body, off);
    legacy_compression = [comp];
  }

  // --- extensions (זהה לשני הצדדים, נעשה פעם אחת בלבד) ---
  let extensions = [];
  if (body.length > off) {
    let extRaw = body.subarray(off);
    extensions = parse_extensions(extRaw);
  }

  // --- version תמיד ערך יחיד ---
  let version = legacy_version;

  // --- החזרה ---
  return {
    type: type,                           // 'client_hello' / 'server_hello'
    legacy_version: legacy_version,       // single (u16)
    version: version,                     // single (u16)
    random: random,                       // single (Uint8Array(32))
    session_id: session_id,               // single (Uint8Array)
    dtls_cookie: dtls_cookie,             // Uint8Array or null (DTLS only)
    cipher_suites: cipher_suites,         // array
    legacy_compression: legacy_compression, // array
    extensions: extensions                // array
  };
}




function isVec2(u8){
  if (!(u8 instanceof Uint8Array) || u8.length < 2) return false;
  let len = (u8[0] << 8) | u8[1];
  return u8.length === 2 + len;
}

/* ===================== Certificate / CertificateVerify / Finished ===================== */

function build_certificate(params) {
  // Unified API:
  //   { version: TLS_VERSION.TLS1_2 | TLS_VERSION.TLS1_3,
  //     entries?: [ { cert: Uint8Array|string, extensions?: Uint8Array|ext-list } ],
  //     request_context?: Uint8Array|string,
  //     // backward-compat:
  //     certs?: [Uint8Array|string] }
  //
  // TLS 1.3 → מחזיר:  request_context (vec<1>) || certificate_list (vec<3> של [ cert(vec<3>) || extensions(vec<2>) ]*)
  // TLS 1.2 → מחזיר:  certificate_list (vec<3> של cert(vec<3>)*), מתעלם מ-extensions/request_context

  let v = params.version || TLS_VERSION.TLS1_2;

  // Normalize to entries[] always
  let entries = Array.isArray(params.entries) ? params.entries.slice() : null;
  if (!entries && Array.isArray(params.certs)) {
    // backward-compat: { certs:[...] } → entries:[{cert},...]
    entries = params.certs.map(function (c) { return { cert: c }; });
  }
  if (!entries) entries = [];

  if (v === TLS_VERSION.TLS1_3) {
    let ctx = toU8(params.request_context || new Uint8Array(0));

    let entryParts = [];
    for (let i = 0; i < entries.length; i++) {
      let certBytes = toU8(entries[i].cert || new Uint8Array(0));
      let certVec   = veclen(3, certBytes); // cert_data vec<3>

      let extRaw = entries[i].extensions;
      if (Array.isArray(extRaw)) {
        // list of ext objects → encode to vec<2>
        extRaw = build_extensions(extRaw);
      } else if (extRaw instanceof Uint8Array) {
        // already raw bytes; ensure it's vec<2>
        extRaw = isVec2 && isVec2(extRaw) ? extRaw : veclen(2, extRaw);
      } else {
        // no extensions
        extRaw = veclen(2, new Uint8Array(0));
      }

      entryParts.push(certVec, extRaw);
    }

    let ctxVec  = veclen(1, ctx);
    let listVec = veclen(3, concatUint8Arrays(entryParts));
    return concatUint8Arrays([ctxVec, listVec]);

  } else {
    // TLS 1.2: only certificate_list (vec<3> of cert(vec<3>)*), ignore per-entry extensions & request_context
    let certListParts = [];
    for (let j = 0; j < entries.length; j++) {
      let c = toU8(entries[j].cert || new Uint8Array(0));
      certListParts.push(veclen(3, c));
    }
    return veclen(3, concatUint8Arrays(certListParts));
  }
}

function parse_certificate(body) {
  // always returns:
  // {
  //   version: TLS_VERSION.TLS1_2 | TLS_VERSION.TLS1_3,
  //   request_context?: Uint8Array,         // רק ב-1.3
  //   entries: [ { cert: Uint8Array, extensions?: any[] } ]  // ב-1.2 אין extensions
  // }

  // Try to detect TLS 1.3: rc(vec<1>) ואז list(vec<3> של [cert(vec<3>) || exts(vec<2>)]*)
  if (body && body.length >= 4) {
    let off = 0;
    let rcLen; [rcLen, off] = r_u8(body, off);              // 1 byte
    const afterCtx = off + rcLen;                           // off מצביע אחרי rcLen (כלומר 1)
    if (afterCtx + 3 <= body.length) {
      let listLen, off2 = afterCtx;                         // התחלת certificate_list
      [listLen, off2] = r_u24(body, off2);                  // 3 bytes
      if (afterCtx + 3 + listLen === body.length) {
        // looks like valid TLS 1.3
        const request_context = body.subarray(off, off + rcLen);
        off = off2;
        const end = off2 + listLen;

        const entries = [];
        while (off < end) {
          let certLen; [certLen, off] = r_u24(body, off);   // cert_data vec<3>
          let cert;    [cert,    off] = r_bytes(body, off, certLen);

          let extLen;  [extLen,  off] = r_u16(body, off);   // extensions vec<2>
          let extRaw;  [extRaw,  off] = r_bytes(body, off, extLen);

          const extensions = extLen ? parse_extensions(extRaw) : [];
          entries.push({ cert, extensions });
        }

        return {
          version: TLS_VERSION.TLS1_3,
          request_context,
          entries
        };
      }
    }
  }

  // otherwise: TLS 1.2 — certificate_list(vec<3>) של cert(vec<3>)* ללא הרחבות
  let off3 = 0;
  let listLen2; [listLen2, off3] = r_u24(body, off3);

  const end2 = off3 + listLen2;
  if (end2 !== body.length) {
    // graceful recovery: אם האורך לא תואם, ננסה לפחות לא לקרוס (אפשר גם לזרוק שגיאה)
    // throw new Error('Bad TLS1.2 Certificate length');
  }

  const entries12 = [];
  while (off3 < Math.min(end2, body.length)) {
    let len3; [len3, off3] = r_u24(body, off3);
    let cert; [cert, off3] = r_bytes(body, off3, len3);
    entries12.push({ cert }); // no per-entry extensions in 1.2
  }

  return {
    version: TLS_VERSION.TLS1_2,
    entries: entries12
  };
}


// CertificateVerify (TLS 1.2/1.3 share the same wire framing at this level)
// struct {
//   SignatureScheme algorithm; // u16
//   opaque signature<0..2^16-1>;
// } CertificateVerify;
function build_certificate_verify(scheme, signature) {
  let sig = toU8(signature || new Uint8Array(0));
  let alg = scheme >>> 0;

  const out = new Uint8Array(2 + 2 + sig.length);
  let off = 0;

  off = w_u16(out, off, alg);
  off = w_u16(out, off, sig.length);
  off = w_bytes(out, off, sig);

  return out;
}

function parse_certificate_verify(body) {
  let off = 0;

  let alg;
  [alg, off] = r_u16(body, off);

  let slen;
  [slen, off] = r_u16(body, off);

  let sig;
  [sig, off] = r_bytes(body, off, slen);

  return { scheme: alg, signature: sig };
}

/* ============================ TLS 1.3 Post-Handshake ============================ */
// NewSessionTicket (TLS1.3)
// struct {
//   uint32 ticket_lifetime;
//   uint32 ticket_age_add;
//   opaque ticket_nonce<0..2^8-1>;
//   opaque ticket<1..2^16-1>;
//   Extension extensions<0..2^16-1>;
// } NewSessionTicket;
function build_new_session_ticket(p) {
  let lifetime = (p && p.ticket_lifetime) >>> 0;
  let age_add  = (p && p.ticket_age_add) >>> 0;
  let nonce    = toU8(p && p.ticket_nonce || new Uint8Array(0));
  let ticket   = toU8(p && p.ticket || new Uint8Array(0));
  let extsBuf  = Array.isArray(p && p.extensions) ? build_extensions(p.extensions) : (p && p.extensions) || veclen(2, new Uint8Array(0));

  const out = new Uint8Array(4 + 4 + 1 + nonce.length + 2 + ticket.length + extsBuf.length);
  let off = 0;

  // u32 big-endian
  off = w_u8(out, off, (lifetime>>>24)&0xFF);
  off = w_u8(out, off, (lifetime>>>16)&0xFF);
  off = w_u8(out, off, (lifetime>>>8)&0xFF);
  off = w_u8(out, off, (lifetime)&0xFF);

  off = w_u8(out, off, (age_add>>>24)&0xFF);
  off = w_u8(out, off, (age_add>>>16)&0xFF);
  off = w_u8(out, off, (age_add>>>8)&0xFF);
  off = w_u8(out, off, (age_add)&0xFF);

  off = w_u8(out, off, nonce.length);
  off = w_bytes(out, off, nonce);

  off = w_u16(out, off, ticket.length);
  off = w_bytes(out, off, ticket);

  off = w_bytes(out, off, extsBuf);

  return out;
}

function parse_new_session_ticket(body) {
  let off = 0;

  let lifetime = (body[off]<<24 | body[off+1]<<16 | body[off+2]<<8 | body[off+3]) >>> 0; off+=4;
  let age_add  = (body[off]<<24 | body[off+1]<<16 | body[off+2]<<8 | body[off+3]) >>> 0; off+=4;

  let nlen;
  [nlen, off] = r_u8(body, off);
  let nonce;
  [nonce, off] = r_bytes(body, off, nlen);

  let tlen;
  [tlen, off] = r_u16(body, off);
  let ticket;
  [ticket, off] = r_bytes(body, off, tlen);

  let extBuf = body.subarray(off);
  let extensions = extBuf.length ? parse_extensions(extBuf) : [];

  return {
    ticket_lifetime: lifetime,
    ticket_age_add: age_add,
    ticket_nonce: nonce,
    ticket: ticket,
    extensions: extensions
  };
}


/* ================================ CertificateRequest ================================ */
// TLS 1.3:
// struct {
//   opaque certificate_request_context<0..2^8-1>;
//   Extension extensions<0..2^16-1>;
// } CertificateRequest;
//
// TLS 1.2:
// struct {
//   ClientCertificateType certificate_types<1..2^8-1>;
//   SignatureAndHashAlgorithm signature_algorithms<2..2^16-2>; // optional in <1.2
//   DistinguishedName certificate_authorities<0..2^16-1>; // vector of DNs, each DN is opaque<1..2^16-1>
// } CertificateRequest;

function build_certificate_request(params) {
  let v = params && params.version || TLS_VERSION.TLS1_3;

  if (v === TLS_VERSION.TLS1_3) {
    let ctx = toU8((params && params.request_context) || new Uint8Array(0));
    let extsBuf = Array.isArray(params && params.extensions)
      ? build_extensions(params.extensions)
      : (params && params.extensions) || veclen(2, new Uint8Array(0));

    let ctxVec = veclen(1, ctx);
    return concatUint8Arrays([ctxVec, extsBuf]);
  }

  // TLS 1.2 / 1.0 / 1.1
  let typesArr = (params && params.certificate_types) || [1]; // rsa_sign(1) as default
  const typesBuf = new Uint8Array(typesArr.length);
  for (let i = 0; i < typesArr.length; i++) typesBuf[i] = typesArr[i] & 0xFF;
  let typesVec = veclen(1, typesBuf);

  let sigalgs = (params && params.signature_algorithms) || [];
  const sigBuf = new Uint8Array(sigalgs.length * 2);
  let o = 0;
  for (let j = 0; j < sigalgs.length; j++) o = w_u16(sigBuf, o, sigalgs[j]);
  let sigVec = sigalgs.length ? veclen(2, sigBuf) : new Uint8Array(0);

  let cas = (params && params.certificate_authorities) || [];
  let caParts = [];
  let caTotal = 0;
  for (let k = 0; k < cas.length; k++) {
    let dn = toU8(cas[k]);
    const ent = new Uint8Array(2 + dn.length);
    let oo = 0; oo = w_u16(ent, oo, dn.length); oo = w_bytes(ent, oo, dn);
    caParts.push(ent); caTotal += ent.length;
  }
  let caVec = veclen(2, caParts.length ? concatUint8Arrays(caParts) : new Uint8Array(0));

  return concatUint8Arrays([typesVec, sigVec, caVec]);
}

function parse_certificate_request(body) {
  // Try TLS 1.3 form first: ctx<1> + extensions<2>
  if (body.length >= 3) {
    let ctxLen = body[0];
    if (1 + ctxLen + 2 <= body.length) {
      let extLen = (body[1 + ctxLen] << 8) | body[2 + ctxLen];
      if (1 + ctxLen + 2 + extLen === body.length) {
        let ctx = body.subarray(1, 1 + ctxLen);
        let extBuf = body.subarray(1 + ctxLen + 2);
        return {
          version: TLS_VERSION.TLS1_3,
          request_context: ctx,
          extensions: parse_extensions(extBuf)
        };
      }
    }
  }

  // Otherwise TLS 1.2/1.1/1.0
  let off = 0;

  let typesBytes, off1;
  [typesBytes, off1] = readVec(body, off, 1);
  off = off1;
  let certificate_types = [];
  for (let i = 0; i < typesBytes.length; i++) certificate_types.push(typesBytes[i] >>> 0);

  let signature_algorithms = [];
  if (off + 2 <= body.length) {
    let sigLen = (body[off] << 8) | body[off + 1];
    if (off + 2 + sigLen <= body.length) {
      off += 2;
      let endSig = off + sigLen;
      while (off < endSig) {
        let alg;
        [alg, off] = r_u16(body, off);
        signature_algorithms.push(alg);
      }
    }
  }

  let cas = [];
  if (off + 2 <= body.length) {
    let caLen;
    [caLen, off] = r_u16(body, off);
    let end = off + caLen;
    while (off < end) {
      let dnLen;
      [dnLen, off] = r_u16(body, off);
      let dn;
      [dn, off] = r_bytes(body, off, dnLen);
      cas.push(dn);
    }
  }

  return {
    version: TLS_VERSION.TLS1_2,
    certificate_types: certificate_types,
    signature_algorithms: signature_algorithms,
    certificate_authorities: cas
  };
}



/* ============================== TLS 1.3 HelloRetryRequest ============================== */
function build_hello_retry_request(params) {
  // params: { cipher_suite, selected_version, selected_group, session_id?, cookie?, other_exts? }
  let rnd = TLS13_HRR_RANDOM;
  let sid = (params && params.session_id) ? toU8(params.session_id) : new Uint8Array(0);
  let legacy_version = TLS_VERSION.TLS1_2;

  let extList = [];
  // supported_versions (selected)
  extList.push({ type: 'SUPPORTED_VERSIONS', value: (params && params.selected_version) || TLS_VERSION.TLS1_3 });
  // key_share: HRR format = just NamedGroup (2 bytes), NOT ServerHello format
  if (params && params.selected_group != null) {
    let ks_data = new Uint8Array(2);
    ks_data[0] = (params.selected_group >> 8) & 0xff;
    ks_data[1] = params.selected_group & 0xff;
    extList.push({ type: 0x0033, data: ks_data });
  }
  // cookie if supplied
  if (params && params.cookie) {
    extList.push({ type: 'COOKIE', value: params.cookie });
  }
  // other extensions passthrough
  if (params && Array.isArray(params.other_exts)) {
    for (let i=0;i<params.other_exts.length;i++) extList.push(params.other_exts[i]);
  }

  let extsBuf = build_extensions(extList);
  let cipher_suite = (params && typeof params.cipher_suite==='number') ? params.cipher_suite : 0x1301;

  // Wire = legacy_version + random + sid_len + sid + cipher_suite + compression(0) + extensions
  const out = new Uint8Array(2 + 32 + 1 + sid.length + 2 + 1 + extsBuf.length);
  let off = 0;
  off = w_u16(out, off, legacy_version);
  off = w_bytes(out, off, rnd);
  off = w_u8(out, off, sid.length);
  if (sid.length > 0) off = w_bytes(out, off, sid);
  off = w_u16(out, off, cipher_suite);
  off = w_u8(out, off, 0);
  off = w_bytes(out, off, extsBuf);
  return out;
}

/* ============================== TLS 1.2 ServerKeyExchange ============================== */
// We'll implement the common ECDHE form and basic DHE form.
// ECDHE ServerKeyExchange:
//   struct {
//     ECParameters curve;          // curve_type(1)=3, named_curve(2)
//     opaque ec_point<1..2^8-1>;   // server's ephemeral ECDH public key
//     digitally-signed struct { .. } // in TLS1.2: SignatureAndHashAlgorithm(2) + signature<2>
//   }
function build_server_key_exchange_ecdhe(p) {
  // p: { group:u16, public:Uint8Array|string, sig_alg:u16, signature:Uint8Array|string }
  let pub = toU8(p.public_key||new Uint8Array(0));

  const head = new Uint8Array(1+2 + 1 + pub.length);
  let off = 0;
  off = w_u8(head, off, 3);                // curve_type = named_curve
  off = w_u16(head, off, p.group>>>0);     // named group
  off = w_u8(head, off, pub.length);       // ec_point length
  off = w_bytes(head, off, pub);

  let sig = toU8(p.signature||new Uint8Array(0));
  const sigpart = new Uint8Array(2 + 2 + sig.length);
  let o2 = 0;
  o2 = w_u16(sigpart, o2, p.sig_alg>>>0);
  o2 = w_u16(sigpart, o2, sig.length);
  o2 = w_bytes(sigpart, o2, sig);

  return concatUint8Arrays([head, sigpart]);
}

function parse_server_key_exchange(body) {
  let off = 0;
  let curve_type;
  [curve_type, off] = r_u8(body, off);

  if (curve_type === 3) { // named_curve (ECDHE)
    let group;
    [group, off] = r_u16(body, off);

    let plen;
    [plen, off] = r_u8(body, off);

    let pub;
    [pub, off] = r_bytes(body, off, plen);

    let sig_alg;
    [sig_alg, off] = r_u16(body, off);

    let slen;
    [slen, off] = r_u16(body, off);

    let sig;
    [sig, off] = r_bytes(body, off, slen);

    return { kex: 'ECDHE', group: group, public_key: pub, sig_alg: sig_alg, signature: sig };
  }

  // Basic DHE: dh_p<2>, dh_g<2>, dh_Ys<2>, then SignatureAndHashAlgorithm + signature<2>
  let pLen;
  [pLen, off] = r_u16(body, off);
  let dh_p;
  [dh_p, off] = r_bytes(body, off, pLen);

  let gLen;
  [gLen, off] = r_u16(body, off);
  let dh_g;
  [dh_g, off] = r_bytes(body, off, gLen);

  let yLen;
  [yLen, off] = r_u16(body, off);
  let dh_Ys;
  [dh_Ys, off] = r_bytes(body, off, yLen);

  let sig_alg2;
  [sig_alg2, off] = r_u16(body, off);

  let s2len;
  [s2len, off] = r_u16(body, off);
  let sig2;
  [sig2, off] = r_bytes(body, off, s2len);

  return { kex: 'DHE', dh_p: dh_p, dh_g: dh_g, dh_Ys: dh_Ys, sig_alg: sig_alg2, signature: sig2 };
}

/* ============================== TLS 1.2 ClientKeyExchange ============================== */
// Two common forms:
// 1) ECDHE: opaque ec_point<1..2^8-1>
// 2) RSA  : EncryptedPreMasterSecret opaque<2>
function build_client_key_exchange_ecdhe(pubkey) {
  let p = toU8(pubkey||new Uint8Array(0));
  return veclen(1, p);
}
function parse_client_key_exchange_ecdhe(body) {
  let off=0; let v; [v,off]=readVec(body,0,1); return v;
}

function build_client_key_exchange_rsa(enc_pms) {
  let e = toU8(enc_pms||new Uint8Array(0));
  return veclen(2, e);
}
function parse_client_key_exchange_rsa(body) {
  let off=0; let v; [v,off]=readVec(body,0,2); return v;
}

/* ============================== TLS 1.2 NewSessionTicket ============================== */
// struct {
//   uint32 ticket_lifetime_hint;
//   opaque ticket<0..2^16-1>;
// } NewSessionTicket;
function build_new_session_ticket_tls12(p) {
  let hint = (p && p.ticket_lifetime_hint) >>> 0;
  let ticket = toU8(p && p.ticket || new Uint8Array(0));
  const out = new Uint8Array(4 + 2 + ticket.length);
  let off = 0;
  off = w_u8(out, off, (hint>>>24)&0xFF);
  off = w_u8(out, off, (hint>>>16)&0xFF);
  off = w_u8(out, off, (hint>>>8)&0xFF);
  off = w_u8(out, off, (hint)&0xFF);
  off = w_u16(out, off, ticket.length);
  off = w_bytes(out, off, ticket);
  return out;
}
function parse_new_session_ticket_tls12(body) {
  let off=0;
  let hint = (body[off]<<24 | body[off+1]<<16 | body[off+2]<<8 | body[off+3])>>>0; off+=4;
  let tlen; [tlen,off]=r_u16(body,off); let t; [t,off]=r_bytes(body,off,tlen);
  return { ticket_lifetime_hint: hint, ticket: t };
}

/* ============================= Handshake message ============================= */


function build_message(type,body) {

  const out = new Uint8Array(4 + body.length);
  let off = 0;

  off = w_u8(out, off, type);
  off = w_u24(out, off, body.length);
  off = w_bytes(out, off, body);

  return out;
}

function parse_message(buf) {
  let off = 0;
  let t;
  [t, off] = r_u8(buf, off);

  let l;
  [l, off] = r_u24(buf, off);

  let b;
  [b, off] = r_bytes(buf, off, l);

  return { type: t, body: b };
}


// Build ServerECDHParams structure for ECDHE in TLS 1.2
// group: u16 (e.g. 0x001D or 0x0017)
// public_key: Uint8Array (already normalized for wire format)
function build_server_ecdh_params(group, public_key) {
  const params = new Uint8Array(1 + 2 + 1 + public_key.length);
  let off = 0;
  off = w_u8(params, off, 3);                 // curve_type = named_curve
  off = w_u16(params, off, group >>> 0);      // namedcurve
  off = w_u8(params, off, public_key.length); // pubkey length
  off = w_bytes(params, off, public_key);     // pubkey
  return params;
}


/* ========================= KeyUpdate (RFC 8446 §4.6.3) ========================= */

/**
 * Build KeyUpdate message body.
 * request_update: 0 = update_not_requested, 1 = update_requested
 */
function build_key_update(request_update) {
  return new Uint8Array([request_update ? 1 : 0]);
}

/**
 * Parse KeyUpdate message body.
 * Returns { request_update: 0|1 }
 */
function parse_key_update(body) {
  return { request_update: body[0] || 0 };
}


/* ============================== DTLS Handshake Message ============================== */

/**
 * Build a DTLS handshake message from a TLS message.
 * Adds 8-byte reconstruction header: msg_seq(2) + frag_offset(3) + frag_length(3).
 *
 * tls_msg: Uint8Array — TLS format: type(1) + length(3) + body
 * msg_seq: u16 — handshake message sequence number
 * frag_offset: optional, defaults to 0
 * frag_length: optional, defaults to full body length
 */
function build_dtls_handshake(tls_msg, msg_seq, frag_offset, frag_length) {
  let type = tls_msg[0];
  let total_length = (tls_msg[1] << 16) | (tls_msg[2] << 8) | tls_msg[3];
  let body = tls_msg.subarray(4);

  if (frag_offset === undefined) frag_offset = 0;
  if (frag_length === undefined) frag_length = body.length;

  let frag_body = body.subarray(frag_offset, frag_offset + frag_length);

  let out = new Uint8Array(12 + frag_body.length);
  let off = 0;
  off = w_u8(out, off, type);
  off = w_u24(out, off, total_length);
  off = w_u16(out, off, msg_seq);
  off = w_u24(out, off, frag_offset);
  off = w_u24(out, off, frag_length);
  off = w_bytes(out, off, frag_body);
  return out;
}

/**
 * Parse a DTLS handshake message.
 * Returns { type, length, msg_seq, frag_offset, frag_length, body }.
 */
function parse_dtls_handshake(buf) {
  let off = 0;
  let type;       [type, off]       = r_u8(buf, off);
  let length;     [length, off]     = r_u24(buf, off);
  let msg_seq;    [msg_seq, off]    = r_u16(buf, off);
  let frag_offset;[frag_offset, off]= r_u24(buf, off);
  let frag_length;[frag_length, off]= r_u24(buf, off);
  let body;       [body, off]       = r_bytes(buf, off, frag_length);
  return { type, length, msg_seq, frag_offset, frag_length, body };
}


/* ============================== DTLS 1.2 HelloVerifyRequest ============================== */

/**
 * Build HelloVerifyRequest body (DTLS 1.2 — message type 3).
 * params: { server_version?, cookie: Uint8Array }
 */
function build_hello_verify_request(params) {
  let version = (params && params.server_version) || DTLS_VERSION.DTLS1_2;
  let cookie = toU8(params && params.cookie || new Uint8Array(0));
  let out = new Uint8Array(2 + 1 + cookie.length);
  let off = 0;
  off = w_u16(out, off, version);
  off = w_u8(out, off, cookie.length);
  if (cookie.length > 0) off = w_bytes(out, off, cookie);
  return out;
}

/**
 * Parse HelloVerifyRequest body.
 * Returns { server_version, cookie }.
 */
function parse_hello_verify_request(body) {
  let off = 0;
  let server_version; [server_version, off] = r_u16(body, off);
  let cookieLen;      [cookieLen, off] = r_u8(body, off);
  let cookie = new Uint8Array(0);
  if (cookieLen > 0) { [cookie, off] = r_bytes(body, off, cookieLen); }
  return { server_version, cookie };
}


/* ================================ Exports ================================= */
export {
  TLS_VERSION,
  DTLS_VERSION,
  TLS_CONTENT_TYPE,
  TLS_ALERT_LEVEL,
  TLS_ALERT,
  TLS_MESSAGE_TYPE,
  TLS_EXT,

  w_u8,
  w_u16,
  w_u24,
  w_u48,
  w_bytes,
  r_u8,
  r_u16,
  r_u24,
  r_bytes,
  veclen,
  readVec,

  exts,
  build_extensions,
  parse_extensions,

  build_message,
  parse_message,
  build_hello,
  parse_hello,

  build_certificate,
  parse_certificate,

  build_certificate_verify,
  parse_certificate_verify,

  build_new_session_ticket,
  parse_new_session_ticket,

  build_certificate_request,
  parse_certificate_request,

  build_hello_retry_request,
  TLS13_HRR_RANDOM,

  build_server_key_exchange_ecdhe,
  parse_server_key_exchange,

  build_client_key_exchange_ecdhe,
  parse_client_key_exchange_ecdhe,

  build_client_key_exchange_rsa,
  parse_client_key_exchange_rsa,

  build_new_session_ticket_tls12,
  parse_new_session_ticket_tls12,

  build_server_ecdh_params,

  build_key_update,
  parse_key_update,

  // DTLS
  build_dtls_handshake,
  parse_dtls_handshake,
  build_hello_verify_request,
  parse_hello_verify_request,
};