/**
 * A certificate's descriptive fields as node:crypto's X509Certificate gives
 * them — subject, issuer, subjectAltName, validFrom, validTo, fingerprint,
 * fingerprint256, serialNumber — read by cryptographic-formats and written
 * here in the same text: what getPeerCertificate() and getCertificate()
 * hand out, and what tls.checkServerIdentity() and applications compare.
 *
 * The text is OpenSSL's, as Node prints it:
 *   subject, issuer   cryptographic-formats's 'openssl' name style.
 *   subjectAltName    Node's own printer: "DNS:a, IP Address:1.2.3.4, ...";
 *                     a value with a character that could confuse a reader
 *                     of the list ("\\ , ' or a control character) is
 *                     quoted, JSON-style.
 *   validFrom/To      ASN1_TIME_print: "Nov  7 09:03:20 2026 GMT".
 *   serialNumber      BN_bn2hex: upper-case hex, no leading zero bytes.
 *   fingerprint*      the hash of the DER, "AB:CD:..".
 */

import * as X509 from 'cryptographic-formats/x509';
import { sha1_sync } from 'cryptographic-primitives/sha1.js';
import { sha256_sync } from 'cryptographic-primitives/sha2.js';

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const UTF8 = new TextDecoder('utf-8');

// Node's subject/issuer text, and a DirName inside subjectAltName before
// Node's quoting goes around it (alt_name): cryptographic-formats's OpenSSL
// styles.
function name_multiline(name) { return X509.name_to_string(name, { style: 'openssl' }); }
function name_rfc2253(name) { return X509.name_to_string(name, { style: 'openssl-rfc2253' }); }

// Node's PrintAltName: a value with nothing that could confuse a reader of
// the comma-separated list is printed as it is; any other is quoted, " and
// \ escaped, and what is not printable (anything outside ASCII too, unless
// the value is UTF-8) as \u00XX. `inner` is a label Node puts inside the
// quotes (an otherName's: othername:"UPN:a\u002cb"); the labels of the
// other kinds come before them (DNS:"a\u002cb").
function alt_name(v, utf8, inner) {
  let safe = true;
  for (let i = 0; i < v.length && safe; i++) {
    let c = v.charCodeAt(i);
    if (v[i] === '"' || v[i] === '\\' || v[i] === ',' || v[i] === '\'') safe = false;
    else if (utf8 ? (c < 0x20 || c === 0x7f) : (c < 0x20 || c > 0x7e)) safe = false;
  }
  let head = inner ? inner + ':' : '';
  if (safe) return head + v;
  // Quoted: the value's bytes (UTF-8, or one per character), " and \
  // escaped, other bytes outside printable ASCII as \u00xx — except, in
  // UTF-8, the bytes of a multi-byte character, which stay.
  let bytes = utf8 ? new TextEncoder().encode(v) : Uint8Array.from(v, function (ch) { return ch.charCodeAt(0) & 0xff; });
  let body = '', run = [];
  let flush = function () { if (run.length) { body += UTF8.decode(Uint8Array.from(run)); run = []; } };
  for (let i = 0; i < bytes.length; i++) {
    let c = bytes[i];
    if (utf8 && c >= 0x80) { run.push(c); continue; }
    flush();
    if (c === 0x5c) body += '\\\\';
    else if (c === 0x22) body += '\\"';
    else if (c >= 0x20 && c !== 0x2c && c <= 0x7e) body += String.fromCharCode(c);
    else body += '\\u00' + c.toString(16).padStart(2, '0');
  }
  flush();
  return '"' + head + body + '"';
}

// otherName types Node prints (OpenSSL's names), and whether the value is
// a UTF8String (else an IA5String); any other is <unsupported>.
const OTHER_NAMES = {
  '1.3.6.1.5.5.7.8.9': ['SmtpUTF8Mailbox', true], '1.3.6.1.5.5.7.8.5': ['XmppAddr', true],
  '1.3.6.1.5.5.7.8.7': ['SRVName', false], '1.3.6.1.4.1.311.20.2.3': ['UPN', true],
  '1.3.6.1.5.5.7.8.8': ['NAIRealm', true],
};

function general_name(g) {
  switch (g.type) {
    case 'dns': return 'DNS:' + alt_name(g.value, false);
    case 'email': return 'email:' + alt_name(g.value, false);
    case 'uri': return 'URI:' + alt_name(g.value, false);
    case 'ip': {
      // Not 4 or 16 bytes: cryptographic-formats reads it with a warning.
      let b = g.value;
      if (g.invalid) return 'IP Address:<invalid length=' + b.length + '>';
      if (b.length === 4) return 'IP Address:' + b.join('.');
      if (b.length === 16) {
        let parts = [];
        for (let i = 0; i < 16; i += 2) parts.push(((b[i] << 8) | b[i + 1]).toString(16).toUpperCase());
        return 'IP Address:' + parts.join(':');
      }
      return 'IP Address:<invalid length=' + b.length + '>';
    }
    case 'registered-id': return 'Registered ID:' + g.value;
    case 'directory': return 'DirName:' + alt_name(name_rfc2253(g.value), true);
    case 'other': {
      let o = OTHER_NAMES[g.id];
      if (!o || g.value[0] !== (o[1] ? 0x0c : 0x16)) return 'othername:<unsupported>';
      return 'othername:' + alt_name(X509.attribute_text(g.value, { lenient: true }).value, o[1], o[0]);
    }
    case 'other-tag':
      if (g.tag === 0xA3) return 'X400Name:<unsupported>';
      // Node cannot print one: its subjectAltName throws, and so does this.
      if (g.tag === 0xA5) throw new Error('Failed to format subject alternative name');
      return '<unsupported>';
    default: return '<unsupported>';
  }
}

function hex(bytes, sep) {
  let out = [];
  for (let i = 0; i < bytes.length; i++) out.push(bytes[i].toString(16).toUpperCase().padStart(2, '0'));
  return out.join(sep);
}

function time_text(t) {
  let pad = function (n) { return String(n).padStart(2, '0'); };
  return MONTHS[t.month - 1] + ' ' + String(t.day).padStart(2, ' ') + ' ' + pad(t.hour) + ':' + pad(t.minute) + ':' +
         pad(t.second) + ' ' + t.year + ' GMT';
}

// The serial number as BN_bn2hex prints it: upper-case hex without leading
// zero bytes, "0" for zero; a negative one (cryptographic-formats reads it
// with a 'negative-serial' warning) as "-" and its magnitude: "-05".
function serial_text(b) {
  if (b.length > 0 && (b[0] & 0x80)) {
    let n = 0n;
    for (let i = 0; i < b.length; i++) n = n * 256n + BigInt(b[i]);
    let h = ((1n << BigInt(8 * b.length)) - n).toString(16).toUpperCase();
    return '-' + (h.length % 2 ? '0' : '') + h;
  }
  let i = 0;
  while (i < b.length && b[i] === 0) i++;
  return hex(b.subarray(i), '') || '0';
}

/**
 * The fields of the certificate `der` (Buffer or Uint8Array) as
 * X509Certificate names them; throws on a DER that is not a certificate.
 */
function x509_info(der) {
  let c = X509.from_der(der);
  let san = null;
  let ext = X509.extension(c, 'subjectAltName');
  if (ext && ext.parsed) san = ext.parsed.map(general_name).join(', ');
  return {
    subject: name_multiline(c.subject),
    issuer: name_multiline(c.issuer),
    subjectAltName: san === null ? undefined : san,
    validFrom: time_text(c.validity.not_before),
    validTo: time_text(c.validity.not_after),
    fingerprint: hex(sha1_sync(der), ':'),
    fingerprint256: hex(sha256_sync(der), ':'),
    serialNumber: serial_text(c.serial),
  };
}

export { x509_info };
