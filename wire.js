
import {
  concatUint8Arrays
} from './utils.js';


var TLS_VERSION = {
  TLS1_0: 0x0301,
  TLS1_1: 0x0302,
  TLS1_2: 0x0303,
  TLS1_3: 0x0304
};

var TLS_MESSAGE_TYPE = {
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

var TLS_EXT = {
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

function w_bytes(buf, off, b) {
  buf.set(b, off);
  return off + b.length;
}

/* ============================ Binary read helpers ============================ */
function r_u8(buf, off) {
  return [buf[off++] >>> 0, off];
}

function r_u16(buf, off) {
  var v = ((buf[off] << 8) | buf[off + 1]) >>> 0;
  return [v, off + 2];
}

function r_u24(buf, off) {
  var v = ((buf[off] << 16) | (buf[off + 1] << 8) | buf[off + 2]) >>> 0;
  return [v, off + 3];
}

function r_bytes(buf, off, n) {
  var slice;
  if (buf instanceof Uint8Array) {
    // חיתוך אמיתי מתוך Uint8Array
    slice = buf.slice(off, off + n);
  } else if (typeof Buffer !== "undefined" && Buffer.isBuffer && Buffer.isBuffer(buf)) {
    // Node Buffer → slice מחזיר view, אז נעשה copy ל־Uint8Array
    var tmp = buf.slice(off, off + n);
    slice = new Uint8Array(tmp);
  } else if (Array.isArray(buf)) {
    // מערך רגיל
    var tmp = buf.slice(off, off + n);
    slice = new Uint8Array(tmp);
  } else {
    throw new Error("r_bytes: unsupported buffer type " + (typeof buf));
  }
  return [slice, off + n];
}


/* ================================= Vectors ================================= */
function veclen(lenBytes, inner) {
  var out, off = 0;

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
  var n, off2 = off;

  if (lenBytes === 1) {
    [n, off2] = r_u8(buf, off2);
  } else if (lenBytes === 2) {
    [n, off2] = r_u16(buf, off2);
  } else {
    [n, off2] = r_u24(buf, off2);
  }

  var b;
  [b, off2] = r_bytes(buf, off2, n);
  return [b, off2];
}

/* =========================== Extensions registry =========================== */
var exts = {};

// Predeclare wanted entries
exts.SERVER_NAME = { encode: null, decode: null };
exts.SUPPORTED_VERSIONS = { encode: null, decode: null };
exts.SUPPORTED_GROUPS = { encode: null, decode: null };
exts.SIGNATURE_ALGORITHMS = { encode: null, decode: null };
exts.PSK_KEY_EXCHANGE_MODES = { encode: null, decode: null };
exts.KEY_SHARE = { encode: null, decode: null };
exts.ALPN = { encode: null, decode: null };
exts.RENEGOTIATION_INFO = { encode: null, decode: null };

/* ------------------------------ SERVER_NAME (0) ------------------------------ */
exts.SERVER_NAME.encode = function (value) {
  var host = toU8(value || "");

  // one name: type(1)=0, len(2), bytes
  var inner = new Uint8Array(1 + 2 + host.length);
  var off = 0;

  off = w_u8(inner, off, 0);
  off = w_u16(inner, off, host.length);
  off = w_bytes(inner, off, host);

  // ServerNameList is vector<2>
  return veclen(2, inner);
};

exts.SERVER_NAME.decode = function (data) {
  var off = 0;
  var list;
  [list, off] = readVec(data, off, 2);

  var off2 = 0;
  var host = "";

  while (off2 < list.length) {
    var typ;
    [typ, off2] = r_u8(list, off2);

    var l;
    [l, off2] = r_u16(list, off2);

    var v;
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
    var out = new Uint8Array(2);
    var off = 0;
    off = w_u16(out, off, value);
    return out;
  }

  // ClientHello form: array of versions
  var arr = Array.isArray(value) ? value : [TLS_VERSION.TLS1_3, TLS_VERSION.TLS1_2];

  var body = new Uint8Array(1 + arr.length * 2);
  var off2 = 0;

  off2 = w_u8(body, off2, arr.length * 2);
  for (var i = 0; i < arr.length; i++) {
    off2 = w_u16(body, off2, arr[i]);
  }
  return body;
};

exts.SUPPORTED_VERSIONS.decode = function (data) {
  // ServerHello form: 2 bytes
  if (data.length === 2) {
    var v, off = 0;
    [v, off] = r_u16(data, off);
    return v; // return the selected version (number)
  }

  // ClientHello form: vector<1> of versions (u16 each)
  var off2 = 0;
  var n;
  [n, off2] = r_u8(data, off2);

  var out = [];
  for (var i = 0; i < n; i += 2) {
    var vv;
    [vv, off2] = r_u16(data, off2);
    out.push(vv);
  }
  return out; // return the array directly
};

/* ---------------------------- SUPPORTED_GROUPS (10) ---------------------------- */
exts.SUPPORTED_GROUPS.encode = function (value) {
  var groups = Array.isArray(value) ? value : [23, 29]; // secp256r1, x25519

  var body = new Uint8Array(2 + groups.length * 2);
  var off = 0;

  off = w_u16(body, off, groups.length * 2);
  for (var i = 0; i < groups.length; i++) {
    off = w_u16(body, off, groups[i]);
  }
  return body;
};

exts.SUPPORTED_GROUPS.decode = function (data) {
  var off = 0;
  var n;
  [n, off] = r_u16(data, off);

  var out = [];
  for (var i = 0; i < n; i += 2) {
    var g;
    [g, off] = r_u16(data, off);
    out.push(g);
  }
  return out; // array of named groups
};

/* -------------------------- SIGNATURE_ALGORITHMS (13) -------------------------- */
exts.SIGNATURE_ALGORITHMS.encode = function (value) {
  var algs = Array.isArray(value) ? value : [0x0403, 0x0804, 0x0401];

  var body = new Uint8Array(2 + algs.length * 2);
  var off = 0;

  off = w_u16(body, off, algs.length * 2);
  for (var i = 0; i < algs.length; i++) {
    off = w_u16(body, off, algs[i]);
  }
  return body;
};

exts.SIGNATURE_ALGORITHMS.decode = function (data) {
  var off = 0;
  var n;
  [n, off] = r_u16(data, off);

  var out = [];
  for (var i = 0; i < n; i += 2) {
    var a;
    [a, off] = r_u16(data, off);
    out.push(a);
  }
  return out; // array of sigalgs (u16)
};

/* ------------------------ PSK_KEY_EXCHANGE_MODES (45) ------------------------ */
exts.PSK_KEY_EXCHANGE_MODES.encode = function (value) {
  var modes = Array.isArray(value) ? value : [1]; // 0=psk_ke, 1=psk_dhe_ke

  var body = new Uint8Array(1 + modes.length);
  var off = 0;

  off = w_u8(body, off, modes.length);
  for (var i = 0; i < modes.length; i++) {
    off = w_u8(body, off, modes[i]);
  }
  return body;
};

exts.PSK_KEY_EXCHANGE_MODES.decode = function (data) {
  var off = 0;
  var n;
  [n, off] = r_u8(data, off);

  var out = [];
  for (var i = 0; i < n; i++) {
    var m;
    [m, off] = r_u8(data, off);
    out.push(m);
  }
  return out; // array of modes (u8)
};

/* --------------------------------- KEY_SHARE (51) -------------------------------- */
exts.KEY_SHARE.encode = function (value) {
  // ServerHello form: { group:number, key_exchange:Uint8Array }
  if (value && typeof value.group === 'number' && value.key_exchange) {
    var ke = toU8(value.key_exchange);

    var out = new Uint8Array(2 + 2 + ke.length);
    var off = 0;

    off = w_u16(out, off, value.group);
    off = w_u16(out, off, ke.length);
    off = w_bytes(out, off, ke);

    return out;
  }

  // ClientHello form: [{ group:number, key_exchange:Uint8Array }, ...]
  var list = Array.isArray(value) ? value : [];

  var parts = [];
  for (var i = 0; i < list.length; i++) {
    var e = list[i];
    var ke2 = toU8(e.key_exchange || new Uint8Array(0));

    var ent = new Uint8Array(2 + 2 + ke2.length);
    var o2 = 0;

    o2 = w_u16(ent, o2, e.group >>> 0);
    o2 = w_u16(ent, o2, ke2.length);
    o2 = w_bytes(ent, o2, ke2);

    parts.push(ent);
  }

  return veclen(2, concatUint8Arrays(parts));
};

exts.KEY_SHARE.decode = function (data) {
  // Try ServerHello form: group(2) + len(2) + key
  if (data.length >= 4) {
    var g, off = 0;
    [g, off] = r_u16(data, off);

    var l;
    [l, off] = r_u16(data, off);

    if (4 + l === data.length) {
      var ke;
      [ke, off] = r_bytes(data, off, l);
      // Two fields required → return object
      return { group: g, key_exchange: ke };
    }
  }

  // ClientHello form: vector<2> of KeyShareEntry
  var off2 = 0;
  var listBytes;
  [listBytes, off2] = r_u16(data, off2);

  var end = off2 + listBytes;
  var out = [];

  while (off2 < end) {
    var g2;
    [g2, off2] = r_u16(data, off2);

    var l2;
    [l2, off2] = r_u16(data, off2);

    var ke2;
    [ke2, off2] = r_bytes(data, off2, l2);

    out.push({ group: g2, key_exchange: ke2 });
  }

  return out; // array of entries
};

/* ------------------------------------ ALPN (16) ----------------------------------- */
exts.ALPN.encode = function (value) {
  var list = Array.isArray(value) ? value : [];

  var total = 2; // vec16 length
  var items = [];

  for (var i = 0; i < list.length; i++) {
    var p = toU8(list[i]);
    items.push(p);
    total += 1 + p.length;
  }

  var out = new Uint8Array(total);
  var off = 0;

  off = w_u16(out, off, total - 2);
  for (var j = 0; j < items.length; j++) {
    off = w_u8(out, off, items[j].length);
    off = w_bytes(out, off, items[j]);
  }

  return out;
};

exts.ALPN.decode = function (data) {
  var off = 0;
  var n;
  [n, off] = r_u16(data, off);

  var end = off + n;
  var out = [];

  while (off < end) {
    var l;
    [l, off] = r_u8(data, off);

    var v;
    [v, off] = r_bytes(data, off, l);

    out.push((new TextDecoder()).decode(v));
  }

  return out; // array of protocol strings
};

/* ----------------------------- RENEGOTIATION_INFO (FF01) ----------------------------- */
exts.RENEGOTIATION_INFO.encode = function (value) {
  // value is Uint8Array of renegotiated_connection data
  var rb = toU8(value || new Uint8Array(0));
  return veclen(1, rb);
};

exts.RENEGOTIATION_INFO.decode = function (data) {
  var off = 0;
  var v;
  [v, off] = readVec(data, off, 1);
  return v; // return raw bytes (Uint8Array)
};

/* ============================= Extensions helpers ============================= */
function ext_name_by_code(code) {
  // best-effort pretty name
  for (var k in TLS_EXT) {
    if ((TLS_EXT[k] >>> 0) === (code >>> 0)) return k;
  }
  return 'EXT_' + code;
}

function build_extensions(list) {
  // list items may be {type:number|string, value:any, data?:Uint8Array}
  if (!list || !list.length) {
    var e = new Uint8Array(2);
    w_u16(e, 0, 0);
    return e;
  }

  var parts = [];
  var total = 2; // vec16

  for (var i = 0; i < list.length; i++) {
    var t = list[i].type;

    // allow symbolic name e.g. 'SERVER_NAME'
    if (typeof t === 'string') {
      t = TLS_EXT[t];
    }

    var payload;
    if (list[i].data) {
      payload = list[i].data;
    } else {
      // try registry
      var regKey = ext_name_by_code(t);
      var enc = exts[regKey] && exts[regKey].encode;
      payload = enc ? enc(list[i].value) : new Uint8Array(0);
    }

    var rec = new Uint8Array(4 + payload.length);
    var off = 0;

    off = w_u16(rec, off, t >>> 0);
    off = w_u16(rec, off, payload.length);
    off = w_bytes(rec, off, payload);

    parts.push(rec);
    total += rec.length;
  }

  var out = new Uint8Array(total);
  var off2 = 0;

  off2 = w_u16(out, off2, total - 2);

  for (var j = 0; j < parts.length; j++) {
    off2 = w_bytes(out, off2, parts[j]);
  }

  return out;
}

function parse_extensions(buf) {
  var off = 0;
  var n;
  [n, off] = r_u16(buf, off);

  var end = off + n;
  var out = [];

  while (off < end) {
    var t;
    [t, off] = r_u16(buf, off);

    var l;
    [l, off] = r_u16(buf, off);

    var d;
    [d, off] = r_bytes(buf, off, l);

    var name = ext_name_by_code(t);
    var dec = exts[name] && exts[name].decode;
    var val = dec ? dec(d) : null;

    out.push({ type: t, name: name, data: d, value: val });
  }

  return out;
}


/* ================================ Hello I/O ================================ */
function build_hello(kind, params) {
  params = params || {};

  var legacy_version = TLS_VERSION.TLS1_2; // even for TLS1.3 legacy fields

  var sid = toU8(params.session_id || "");
  if (sid.length > 32) sid = sid.subarray(0, 32);

  var extsBuf = build_extensions(params.extensions || []);

  if (kind === 'client') {
    var cs = params.cipher_suites || [0x1301, 0x1302, 0x1303, 0xC02F, 0xC02B];

    var csBlock = new Uint8Array(2 + cs.length * 2);
    var o = 0;
    o = w_u16(csBlock, o, cs.length * 2);
    for (var i = 0; i < cs.length; i++) {
      o = w_u16(csBlock, o, cs[i]);
    }

    var comp = params.legacy_compression || [0]; // for TLS1.3 must be [0]
    var compBlock = new Uint8Array(1 + comp.length);
    var oc = 0;
    oc = w_u8(compBlock, oc, comp.length);
    for (var j = 0; j < comp.length; j++) {
      oc = w_u8(compBlock, oc, comp[j]);
    }

    var out = new Uint8Array(
      2 + 32 + 1 + sid.length + csBlock.length + compBlock.length + extsBuf.length
    );

    var off = 0;
    off = w_u16(out, off, legacy_version);
    off = w_bytes(out, off, params.random);
    off = w_u8(out, off, sid.length);
    off = w_bytes(out, off, sid);
    off = w_bytes(out, off, csBlock);
    off = w_bytes(out, off, compBlock);
    off = w_bytes(out, off, extsBuf);

    return out;
  }

  if (kind === 'server') {
    var cipher_suite = (typeof params.cipher_suite === 'number') ? params.cipher_suite : 0x1301;

    var out2 = new Uint8Array(2 + 32 + 1 + sid.length + 2 + 1 + extsBuf.length);
    var off2 = 0;

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

function parse_hello(hsType, body) {
  var isClient = (hsType === TLS_MESSAGE_TYPE.CLIENT_HELLO || hsType === 'client_hello');

  var off = 0;

  var legacy_version;
  [legacy_version, off] = r_u16(body, off);

  var random;
  [random, off] = r_bytes(body, off, 32);

  var sidLen;
  [sidLen, off] = r_u8(body, off);

  var session_id;
  [session_id, off] = r_bytes(body, off, sidLen);

  if (isClient) {
    var csLen;
    [csLen, off] = r_u16(body, off);

    var csEnd = off + csLen;
    var cipher_suites = [];

    while (off < csEnd) {
      var cs;
      [cs, off] = r_u16(body, off);
      cipher_suites.push(cs);
    }

    var compLen;
    [compLen, off] = r_u8(body, off);

    var legacy_compression = [];
    for (var i = 0; i < compLen; i++) {
      var c;
      [c, off] = r_u8(body, off);
      legacy_compression.push(c);
    }

    var extRaw = (body.length > off) ? body.subarray(off) : new Uint8Array(0);
    var extensions = extRaw.length ? parse_extensions(extRaw) : [];

    // version hint: if supported_versions includes TLS1.3, prefer it
    var ver = legacy_version;
    for (var k = 0; k < extensions.length; k++) {
      var e = extensions[k];
      if (e.type === TLS_EXT.SUPPORTED_VERSIONS && Array.isArray(e.value)) {
        for (var t = 0; t < e.value.length; t++) {
          if (e.value[t] === TLS_VERSION.TLS1_3) {
            ver = TLS_VERSION.TLS1_3;
            break;
          }
        }
      }
    }

    return {
      message: 'client_hello',
      legacy_version: legacy_version,
      version_hint: ver,
      random: random,
      session_id: session_id,
      cipher_suites: cipher_suites,
      legacy_compression: legacy_compression,
      extensions: extensions
    };
  }

  // ServerHello
  var cipher_suite;
  [cipher_suite, off] = r_u16(body, off);

  var comp;
  [comp, off] = r_u8(body, off);

  var extRaw2 = (body.length > off) ? body.subarray(off) : new Uint8Array(0);
  var extensions2 = extRaw2.length ? parse_extensions(extRaw2) : [];

  var ver2 = legacy_version;
  for (var z = 0; z < extensions2.length; z++) {
    var ex = extensions2[z];
    if (ex.type === TLS_EXT.SUPPORTED_VERSIONS && typeof ex.value === 'number') {
      ver2 = ex.value; // selected version
    }
  }

  return {
    message: 'server_hello',
    legacy_version: legacy_version,
    version: ver2,
    random: random,
    session_id: session_id,
    cipher_suite: cipher_suite,
    legacy_compression: comp,
    extensions: extensions2
  };
}

function isVec2(u8){
  if (!(u8 instanceof Uint8Array) || u8.length < 2) return false;
  var len = (u8[0] << 8) | u8[1];
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

  var v = params.version || TLS_VERSION.TLS1_2;

  // Normalize to entries[] always
  var entries = Array.isArray(params.entries) ? params.entries.slice() : null;
  if (!entries && Array.isArray(params.certs)) {
    // backward-compat: { certs:[...] } → entries:[{cert},...]
    entries = params.certs.map(function (c) { return { cert: c }; });
  }
  if (!entries) entries = [];

  if (v === TLS_VERSION.TLS1_3) {
    var ctx = toU8(params.request_context || new Uint8Array(0));

    var entryParts = [];
    for (var i = 0; i < entries.length; i++) {
      var certBytes = toU8(entries[i].cert || new Uint8Array(0));
      var certVec   = veclen(3, certBytes); // cert_data vec<3>

      var extRaw = entries[i].extensions;
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

    var ctxVec  = veclen(1, ctx);
    var listVec = veclen(3, concatUint8Arrays(entryParts));
    return concatUint8Arrays([ctxVec, listVec]);

  } else {
    // TLS 1.2: only certificate_list (vec<3> of cert(vec<3>)*), ignore per-entry extensions & request_context
    var certListParts = [];
    for (var j = 0; j < entries.length; j++) {
      var c = toU8(entries[j].cert || new Uint8Array(0));
      certListParts.push(veclen(3, c));
    }
    return veclen(3, concatUint8Arrays(certListParts));
  }
}

function parse_certificate(body) {
  // תמיד מחזיר:
  // {
  //   version: TLS_VERSION.TLS1_2 | TLS_VERSION.TLS1_3,
  //   request_context?: Uint8Array,         // רק ב-1.3
  //   entries: [ { cert: Uint8Array, extensions?: any[] } ]  // ב-1.2 אין extensions
  // }

  // נסה לזהות TLS 1.3: rc(vec<1>) ואז list(vec<3> של [cert(vec<3>) || exts(vec<2>)]*)
  if (body && body.length >= 4) {
    let off = 0;
    let rcLen; [rcLen, off] = r_u8(body, off);              // 1 byte
    const afterCtx = off + rcLen;                           // off מצביע אחרי rcLen (כלומר 1)
    if (afterCtx + 3 <= body.length) {
      let listLen, off2 = afterCtx;                         // התחלת certificate_list
      [listLen, off2] = r_u24(body, off2);                  // 3 bytes
      if (afterCtx + 3 + listLen === body.length) {
        // נראה כמו 1.3 תקני
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

  // אחרת: TLS 1.2 — certificate_list(vec<3>) של cert(vec<3>)* ללא הרחבות
  let off3 = 0;
  let listLen2; [listLen2, off3] = r_u24(body, off3);

  const end2 = off3 + listLen2;
  if (end2 !== body.length) {
    // התאוששות קלה: אם האורך לא תואם, ננסה לפחות לא לקרוס (אפשר גם לזרוק שגיאה)
    // throw new Error('Bad TLS1.2 Certificate length');
  }

  const entries12 = [];
  while (off3 < Math.min(end2, body.length)) {
    let len3; [len3, off3] = r_u24(body, off3);
    let cert; [cert, off3] = r_bytes(body, off3, len3);
    entries12.push({ cert }); // אין extensions ב-1.2
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
  var sig = toU8(signature || new Uint8Array(0));
  var alg = scheme >>> 0;

  var out = new Uint8Array(2 + 2 + sig.length);
  var off = 0;

  off = w_u16(out, off, alg);
  off = w_u16(out, off, sig.length);
  off = w_bytes(out, off, sig);

  return out;
}

function parse_certificate_verify(body) {
  var off = 0;

  var alg;
  [alg, off] = r_u16(body, off);

  var slen;
  [slen, off] = r_u16(body, off);

  var sig;
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
  var lifetime = (p && p.ticket_lifetime) >>> 0;
  var age_add  = (p && p.ticket_age_add) >>> 0;
  var nonce    = toU8(p && p.ticket_nonce || new Uint8Array(0));
  var ticket   = toU8(p && p.ticket || new Uint8Array(0));
  var extsBuf  = Array.isArray(p && p.extensions) ? build_extensions(p.extensions) : (p && p.extensions) || veclen(2, new Uint8Array(0));

  var out = new Uint8Array(4 + 4 + 1 + nonce.length + 2 + ticket.length + extsBuf.length);
  var off = 0;

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
  var off = 0;

  var lifetime = (body[off]<<24 | body[off+1]<<16 | body[off+2]<<8 | body[off+3]) >>> 0; off+=4;
  var age_add  = (body[off]<<24 | body[off+1]<<16 | body[off+2]<<8 | body[off+3]) >>> 0; off+=4;

  var nlen;
  [nlen, off] = r_u8(body, off);
  var nonce;
  [nonce, off] = r_bytes(body, off, nlen);

  var tlen;
  [tlen, off] = r_u16(body, off);
  var ticket;
  [ticket, off] = r_bytes(body, off, tlen);

  var extBuf = body.subarray(off);
  var extensions = extBuf.length ? parse_extensions(extBuf) : [];

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
  var v = params && params.version || TLS_VERSION.TLS1_3;

  if (v === TLS_VERSION.TLS1_3) {
    var ctx = toU8((params && params.request_context) || new Uint8Array(0));
    var extsBuf = Array.isArray(params && params.extensions)
      ? build_extensions(params.extensions)
      : (params && params.extensions) || veclen(2, new Uint8Array(0));

    var ctxVec = veclen(1, ctx);
    return concatUint8Arrays([ctxVec, extsBuf]);
  }

  // TLS 1.2 / 1.0 / 1.1
  var typesArr = (params && params.certificate_types) || [1]; // rsa_sign(1) as default
  var typesBuf = new Uint8Array(typesArr.length);
  for (var i = 0; i < typesArr.length; i++) typesBuf[i] = typesArr[i] & 0xFF;
  var typesVec = veclen(1, typesBuf);

  var sigalgs = (params && params.signature_algorithms) || [];
  var sigBuf = new Uint8Array(sigalgs.length * 2);
  var o = 0;
  for (var j = 0; j < sigalgs.length; j++) o = w_u16(sigBuf, o, sigalgs[j]);
  var sigVec = sigalgs.length ? veclen(2, sigBuf) : new Uint8Array(0);

  var cas = (params && params.certificate_authorities) || [];
  var caParts = [];
  var caTotal = 0;
  for (var k = 0; k < cas.length; k++) {
    var dn = toU8(cas[k]);
    var ent = new Uint8Array(2 + dn.length);
    var oo = 0; oo = w_u16(ent, oo, dn.length); oo = w_bytes(ent, oo, dn);
    caParts.push(ent); caTotal += ent.length;
  }
  var caVec = veclen(2, caParts.length ? concatUint8Arrays(caParts) : new Uint8Array(0));

  return concatUint8Arrays([typesVec, sigVec, caVec]);
}

function parse_certificate_request(body) {
  // Try TLS 1.3 form first: ctx<1> + extensions<2>
  if (body.length >= 3) {
    var ctxLen = body[0];
    if (1 + ctxLen + 2 <= body.length) {
      var extLen = (body[1 + ctxLen] << 8) | body[2 + ctxLen];
      if (1 + ctxLen + 2 + extLen === body.length) {
        var ctx = body.subarray(1, 1 + ctxLen);
        var extBuf = body.subarray(1 + ctxLen + 2);
        return {
          version: TLS_VERSION.TLS1_3,
          request_context: ctx,
          extensions: parse_extensions(extBuf)
        };
      }
    }
  }

  // Otherwise TLS 1.2/1.1/1.0
  var off = 0;

  var typesBytes, off1;
  [typesBytes, off1] = readVec(body, off, 1);
  off = off1;
  var certificate_types = [];
  for (var i = 0; i < typesBytes.length; i++) certificate_types.push(typesBytes[i] >>> 0);

  var signature_algorithms = [];
  if (off + 2 <= body.length) {
    var sigLen = (body[off] << 8) | body[off + 1];
    if (off + 2 + sigLen <= body.length) {
      off += 2;
      var endSig = off + sigLen;
      while (off < endSig) {
        var alg;
        [alg, off] = r_u16(body, off);
        signature_algorithms.push(alg);
      }
    }
  }

  var cas = [];
  if (off + 2 <= body.length) {
    var caLen;
    [caLen, off] = r_u16(body, off);
    var end = off + caLen;
    while (off < end) {
      var dnLen;
      [dnLen, off] = r_u16(body, off);
      var dn;
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
  // params: { cipher_suite, selected_version, selected_group, cookie?: Uint8Array|string, other_exts?: list }
  var rnd = TLS13_HRR_RANDOM;
  var sid = new Uint8Array(0);
  var legacy_version = TLS_VERSION.TLS1_2;

  var extList = [];
  // supported_versions (selected)
  extList.push({ type: 'SUPPORTED_VERSIONS', value: (params && params.selected_version) || TLS_VERSION.TLS1_3 });
  // key_share: only selected_group (no key)
  if (params && params.selected_group != null) {
    extList.push({ type: 'KEY_SHARE', value: { selected_group: params.selected_group, key_exchange: new Uint8Array(0) } });
  }
  // cookie if supplied
  if (params && params.cookie) {
    if (!exts.COOKIE) { exts.COOKIE = { encode: function(v){ return veclen(2, toU8(v||'')); }, decode: function(d){ var off=0,v; [v,off]=readVec(d,0,2); return v; } }; }
    extList.push({ type: 'COOKIE', value: params.cookie });
  }
  // other extensions passthrough
  if (params && Array.isArray(params.other_exts)) {
    for (var i=0;i<params.other_exts.length;i++) extList.push(params.other_exts[i]);
  }

  var extsBuf = build_extensions(extList);
  var cipher_suite = (params && typeof params.cipher_suite==='number') ? params.cipher_suite : 0x1301;

  // Wire = legacy_version + random + sid + cipher_suite + compression(0) + extensions
  var out = new Uint8Array(2 + 32 + 1 + 0 + 2 + 1 + extsBuf.length);
  var off = 0;
  off = w_u16(out, off, legacy_version);
  off = w_bytes(out, off, rnd);
  off = w_u8(out, off, 0);
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
  var pub = toU8(p.public||u8(0));

  var head = new Uint8Array(1+2 + 1 + pub.length);
  var off = 0;
  off = w_u8(head, off, 3);                // curve_type = named_curve
  off = w_u16(head, off, p.group>>>0);     // named group
  off = w_u8(head, off, pub.length);       // ec_point length
  off = w_bytes(head, off, pub);

  var sig = toU8(p.signature||u8(0));
  var sigpart = new Uint8Array(2 + 2 + sig.length);
  var o2 = 0;
  o2 = w_u16(sigpart, o2, p.sig_alg>>>0);
  o2 = w_u16(sigpart, o2, sig.length);
  o2 = w_bytes(sigpart, o2, sig);

  return concatUint8Arrays([head, sigpart]);
}

function parse_server_key_exchange(body) {
  var off = 0;
  var curve_type;
  [curve_type, off] = r_u8(body, off);

  if (curve_type === 3) { // named_curve (ECDHE)
    var group;
    [group, off] = r_u16(body, off);

    var plen;
    [plen, off] = r_u8(body, off);

    var pub;
    [pub, off] = r_bytes(body, off, plen);

    var sig_alg;
    [sig_alg, off] = r_u16(body, off);

    var slen;
    [slen, off] = r_u16(body, off);

    var sig;
    [sig, off] = r_bytes(body, off, slen);

    return { kex: 'ECDHE', group: group, public: pub, sig_alg: sig_alg, signature: sig };
  }

  // Basic DHE: dh_p<2>, dh_g<2>, dh_Ys<2>, then SignatureAndHashAlgorithm + signature<2>
  var pLen;
  [pLen, off] = r_u16(body, off);
  var dh_p;
  [dh_p, off] = r_bytes(body, off, pLen);

  var gLen;
  [gLen, off] = r_u16(body, off);
  var dh_g;
  [dh_g, off] = r_bytes(body, off, gLen);

  var yLen;
  [yLen, off] = r_u16(body, off);
  var dh_Ys;
  [dh_Ys, off] = r_bytes(body, off, yLen);

  var sig_alg2;
  [sig_alg2, off] = r_u16(body, off);

  var s2len;
  [s2len, off] = r_u16(body, off);
  var sig2;
  [sig2, off] = r_bytes(body, off, s2len);

  return { kex: 'DHE', dh_p: dh_p, dh_g: dh_g, dh_Ys: dh_Ys, sig_alg: sig_alg2, signature: sig2 };
}

/* ============================== TLS 1.2 ClientKeyExchange ============================== */
// Two common forms:
// 1) ECDHE: opaque ec_point<1..2^8-1>
// 2) RSA  : EncryptedPreMasterSecret opaque<2>
function build_client_key_exchange_ecdhe(pubkey) {
  var p = toU8(pubkey||u8(0));
  return veclen(1, p);
}
function parse_client_key_exchange_ecdhe(body) {
  var off=0; var v; [v,off]=readVec(body,0,1); return v;
}

function build_client_key_exchange_rsa(enc_pms) {
  var e = toU8(enc_pms||u8(0));
  return veclen(2, e);
}
function parse_client_key_exchange_rsa(body) {
  var off=0; var v; [v,off]=readVec(body,0,2); return v;
}

/* ============================== TLS 1.2 NewSessionTicket ============================== */
// struct {
//   uint32 ticket_lifetime_hint;
//   opaque ticket<0..2^16-1>;
// } NewSessionTicket;
function build_new_session_ticket_tls12(p) {
  var hint = (p && p.ticket_lifetime_hint) >>> 0;
  var ticket = toU8(p && p.ticket || new Uint8Array(0));
  var out = new Uint8Array(4 + 2 + ticket.length);
  var off = 0;
  off = w_u8(out, off, (hint>>>24)&0xFF);
  off = w_u8(out, off, (hint>>>16)&0xFF);
  off = w_u8(out, off, (hint>>>8)&0xFF);
  off = w_u8(out, off, (hint)&0xFF);
  off = w_u16(out, off, ticket.length);
  off = w_bytes(out, off, ticket);
  return out;
}
function parse_new_session_ticket_tls12(body) {
  var off=0;
  var hint = (body[off]<<24 | body[off+1]<<16 | body[off+2]<<8 | body[off+3])>>>0; off+=4;
  var tlen; [tlen,off]=r_u16(body,off); var t; [t,off]=r_bytes(body,off,tlen);
  return { ticket_lifetime_hint: hint, ticket: t };
}

/* ============================= Handshake message ============================= */
function build_message(params) {

  var type=0;
  var body=null;

  if(params.type=='server_hello'){
    type=TLS_MESSAGE_TYPE.SERVER_HELLO;
    body=build_hello('server', params);
  }else if(params.type=='client_hello'){
    type=TLS_MESSAGE_TYPE.SERVER_HELLO;
    body=build_hello('client', params);
  }else if(params.type=='encrypted_extensions'){
    type=TLS_MESSAGE_TYPE.ENCRYPTED_EXTENSIONS;
    body=build_extensions(params.extensions);
  }else if(params.type=='certificate'){
    type=TLS_MESSAGE_TYPE.CERTIFICATE;
    body=build_certificate(params);
  }else if(params.type=='certificate_verify'){
    type=TLS_MESSAGE_TYPE.CERTIFICATE_VERIFY;
    body=build_certificate_verify(params.scheme,params.signature);
  }else if(params.type=='finished'){
    type=TLS_MESSAGE_TYPE.FINISHED;
    body=params.data;
  }

  var out = new Uint8Array(4 + body.length);
  var off = 0;

  off = w_u8(out, off, type);
  off = w_u24(out, off, body.length);
  off = w_bytes(out, off, body);

  return out;
}

function parse_message(buf) {
  var off = 0;
  var t;
  [t, off] = r_u8(buf, off);

  var l;
  [l, off] = r_u24(buf, off);

  var b;
  [b, off] = r_bytes(buf, off, l);

  return { type: t, body: b };
}




/* ================================ Exports ================================= */
export {
  TLS_VERSION,
  TLS_MESSAGE_TYPE,
  TLS_EXT,

  w_u8,
  w_u16,
  w_u24,
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

  build_server_key_exchange_ecdhe,
  parse_server_key_exchange,

  build_client_key_exchange_ecdhe,
  parse_client_key_exchange_ecdhe,

  build_client_key_exchange_rsa,
  parse_client_key_exchange_rsa,

  build_new_session_ticket_tls12,
  parse_new_session_ticket_tls12
};




/*
function build_extensions(exts){
  // מרכיבים את רשימת ההרחבות (ללא שדה האורך הראשי)
  var list = [];
  for (var i=0; i<exts.length; i++){
    var t = exts[i].type|0;
    var d = exts[i].data instanceof Uint8Array ? exts[i].data
            : (exts[i].data && exts[i].data.buffer) ? new Uint8Array(exts[i].data)
            : new Uint8Array(0);

    // type (2B)
    list.push((t>>>8)&0xFF, t&0xFF);
    // len  (2B)
    list.push((d.length>>>8)&0xFF, d.length&0xFF);
    // data
    for (var k=0; k<d.length; k++) list.push(d[k]);
  }

  // עוטפים באורך כולל דו־בתי
  var out = [];
  var L = list.length;
  out.push((L>>>8)&0xFF, L&0xFF);
  for (var j=0; j<list.length; j++) out.push(list[j]);

  return new Uint8Array(out);
}

function parse_extensions(data) {
  var ptr = 0;
  if (data.length < 2) return [];

  var totalLen = (data[ptr++] << 8) | data[ptr++];
  if (ptr + totalLen > data.length) totalLen = data.length - ptr; // גידור

  var exts = [];
  var end = ptr + totalLen;

  while (ptr + 4 <= end) {
    var type = (data[ptr++] << 8) | data[ptr++];
    var len  = (data[ptr++] << 8) | data[ptr++];
    if (ptr + len > end) break; // שבור – עוצרים

    var extData = data.subarray(ptr, ptr + len);
    ptr += len;

    exts.push({ type, data: extData });
  }

  return exts;
}






function parse_client_hello(data) {
  var ptr = 0;

  var legacy_version = (data[ptr++] << 8) | data[ptr++];
  var random = data.slice(ptr, ptr + 32); ptr += 32;
  var session_id_len = data[ptr++];
  var session_id = data.slice(ptr, ptr + session_id_len); ptr += session_id_len;

  var cipher_suites_len = (data[ptr++] << 8) | data[ptr++];
  var cipher_suites = [];
  for (var i = 0; i < cipher_suites_len; i += 2) {
      var code = (data[ptr++] << 8) | data[ptr++];
      cipher_suites.push(code);
  }

  var compression_methods_len = data[ptr++];
  var compression_methods = data.slice(ptr, ptr + compression_methods_len); ptr += compression_methods_len;

  var extensions_len = (data[ptr++] << 8) | data[ptr++];
  var extensions = [];
  var ext_end = ptr + extensions_len;
  while (ptr < ext_end) {
      var ext_type = (data[ptr++] << 8) | data[ptr++];
      var ext_len = (data[ptr++] << 8) | data[ptr++];
      var ext_data = data.slice(ptr, ptr + ext_len); ptr += ext_len;
      extensions.push({ type: ext_type, data: ext_data });
  }

  var sni = null;
  var key_shares = [];
  var supported_versions = [];
  var supported_groups = [];
  var signature_algorithms = [];
  var alpn = [];
  var max_fragment_length = null;
  var padding = null;
  var cookie = null;
  var psk_key_exchange_modes = [];
  var pre_shared_key = null;
  var renegotiation_info = null;
  var unknown_extensions = null;

  for (var ext of extensions) {
    var ext_data = new Uint8Array(ext.data);
    if (ext.type === 0x00) { // SNI
        var list_len = (ext_data[0] << 8) | ext_data[1];
        var name_type = ext_data[2];
        var name_len = (ext_data[3] << 8) | ext_data[4];
        var name = new TextDecoder().decode(ext_data.slice(5, 5 + name_len));
        sni = name;
    }
    if (ext.type === 0x33) {
        var ptr2 = 0;
        var list_len = (ext_data[ptr2++] << 8) | ext_data[ptr2++];
        var end = ptr2 + list_len;
        while (ptr2 < end) {
            var group = (ext_data[ptr2++] << 8) | ext_data[ptr2++];
            var key_len = (ext_data[ptr2++] << 8) | ext_data[ptr2++];
            var pubkey = ext_data.slice(ptr2, ptr2 + key_len);
            ptr2 += key_len;
            key_shares.push({ group, pubkey });
        }
    
    }
    if (ext.type === 0x2b) { // supported_versions
        var len = ext_data[0];
        for (var i = 1; i < 1 + len; i += 2) {
            var ver = (ext_data[i] << 8) | ext_data[i + 1];
            supported_versions.push(ver);
        }
    }
    if (ext.type === 0x0a) { // supported_groups
        var len = (ext_data[0] << 8) | ext_data[1];
        for (var i = 2; i < 2 + len; i += 2) {
            supported_groups.push((ext_data[i] << 8) | ext_data[i + 1]);
        }
    }
    if (ext.type === 0x0d) { // signature_algorithms
        var len = (ext_data[0] << 8) | ext_data[1];
        for (var i = 2; i < 2 + len; i += 2) {
            signature_algorithms.push((ext_data[i] << 8) | ext_data[i + 1]);
        }
    }
    if (ext.type === 0x10) { // ALPN
        var list_len = (ext_data[0] << 8) | ext_data[1];
        var i = 2;
        while (i < 2 + list_len) {
            var name_len = ext_data[i++];
            var proto = new TextDecoder().decode(ext_data.slice(i, i + name_len));
            alpn.push(proto);
            i += name_len;
        }
    }
    if (ext.type === 0x39) { // quic_transport_parameters
      unknown_extensions = ext.data;
    }
    if (ext.type === 0x01) { // Max Fragment Length
        max_fragment_length = ext_data[0];
    }
    if (ext.type === 0x15) { // Padding
        padding = ext_data;
    }
    if (ext.type === 0x002a) { // Cookie
        var len = (ext_data[0] << 8) | ext_data[1];
        cookie = ext_data.slice(2, 2 + len);
    }
    if (ext.type === 0x2d) { // PSK Key Exchange Modes
        var len = ext_data[0];
        for (var i = 1; i <= len; i++) {
            psk_key_exchange_modes.push(ext_data[i]);
        }
    }
    if (ext.type === 0x29) { // PreSharedKey (placeholder)
        pre_shared_key = ext_data;
    }
    if (ext.type === 0xff01) { // Renegotiation Info
        renegotiation_info = ext_data;
    }
  }

  return {
    legacy_version,
    random,
    session_id,
    cipher_suites,
    compression_methods,
    extensions,
    sni,
    key_shares,
    supported_versions,
    supported_groups,
    signature_algorithms,
    alpn,
    max_fragment_length,
    padding,
    cookie,
    psk_key_exchange_modes,
    pre_shared_key,
    renegotiation_info,
    unknown_extensions
  };
}




function build_server_hello(params){
  var version = params.version|0;
  var body = [];

  // 1) legacy_version
  var legacy_version = (version === 0x0304) ? 0x0303 : 0x0303;
  body.push((legacy_version>>>8)&0xFF, legacy_version&0xFF);

  // 2) random
  var rnd = params.server_random;
  for (var i=0;i<rnd.length;i++) body.push(rnd[i]);

  // 3) legacy_session_id
  var sid = params.legacy_session_id || new Uint8Array(0);
  body.push(sid.length & 0xFF);
  for (var i=0;i<sid.length;i++) body.push(sid[i]);

  // 4) cipher_suite
  var cs = params.cipher_suite|0;
  body.push((cs>>>8)&0xFF, cs&0xFF);

  // 5) legacy_compression_method
  body.push(params.compression_method|0);

  // 6) extensions
  var exts = [];

  if (version === 0x0304){
    // --- TLS 1.3 extensions ---

    // supported_versions (0x002b)
    exts.push(0x00,0x2b); // type
    exts.push(0x00,0x02); // len=2
    exts.push(0x03,0x04); // TLS1.3

    // key_share (0x0033)
    var group = params.selected_group|0;
    var pub   = params.server_key_share;
    var ks = [];
    ks.push((group>>>8)&0xFF, group&0xFF);
    ks.push((pub.length>>>8)&0xFF, pub.length&0xFF);
    for (var j=0;j<pub.length;j++) ks.push(pub[j]);

    exts.push(0x00,0x33); // type
    exts.push((ks.length>>>8)&0xFF, ks.length&0xFF);
    for (var j=0;j<ks.length;j++) exts.push(ks[j]);

  } else if (version === 0x0303){
    // --- TLS 1.2 extensions (אופציונלי) ---

    if (params.secure_renegotiation){
      // renegotiation_info (0xFF01), length=1, value=0x00
      exts.push(0xFF,0x01);
      exts.push(0x00,0x01);
      exts.push(0x00);
    }
    if (params.extended_master_secret){
      // extended_master_secret (0x0017), empty
      exts.push(0x00,0x17);
      exts.push(0x00,0x00);
    }
  }

  if (params.extra_extensions && params.extra_extensions.length){
    for (var e=0;e<params.extra_extensions.length;e++){
      var ext = params.extra_extensions[e];
      var et = ext.type|0;
      var ed = ext.data;
      exts.push((et>>>8)&0xFF, et&0xFF);
      exts.push((ed.length>>>8)&0xFF, ed.length&0xFF);
      for (var k=0;k<ed.length;k++) exts.push(ed[k]);
    }
  }

  body.push((exts.length>>>8)&0xFF, exts.length&0xFF);
  for (var i=0;i<exts.length;i++) body.push(exts[i]);

  // 7) Handshake header (ServerHello=2)
  var sh = [];
  sh.push(2); // msg_type=server_hello
  var len = body.length;
  sh.push((len>>>16)&0xFF, (len>>>8)&0xFF, len&0xFF);
  for (var i=0;i<body.length;i++) sh.push(body[i]);

  return new Uint8Array(sh);
}


*/