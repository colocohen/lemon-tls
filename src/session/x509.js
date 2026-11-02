// ============================================================
//  X.509 path checks (RFC 5280 §4.2, §6.1) on a chain already built
// ============================================================
//
// tls_session.js builds the path — leaf, the intermediates the peer sent,
// a trust anchor — and checks each signature and validity window. What a
// signature does not say is what a certificate may be used for. This module
// reads the extensions that say it, from the DER, and checks the path
// against them:
//
//   basicConstraints   every issuer a CA (an anchor too: one that is not —
//                      an end-entity certificate given as `ca` — vouched for
//                      any name); pathLenConstraint; a leaf that is a CA
//                      (CA/B Forum BR §7.1.2.7.8: cA MUST be false) refused
//   keyUsage           an issuer may sign certificates (keyCertSign); a leaf
//                      may sign or agree a key (OpenSSL's TLS purpose rule)
//   extKeyUsage        when present, on the leaf and the intermediates, the
//                      purpose asked for (serverAuth, clientAuth) or any
//   nameConstraints    each CA's, on every certificate below it (dNSName,
//                      iPAddress, rfc822Name, URI, directoryName); a
//                      constraint of a kind not read here refuses a name of
//                      that kind (§4.2.1.10: "MUST" be able to process)
//   critical           an extension marked critical that is not one of these
//                      (or of the policy ones, which need no processing here)
//                      refuses the certificate (§4.2) — the CT precertificate
//                      poison among them; OpenSSL's list
//   signature          a certificate below the anchor signed with MD5 or
//                      SHA-1 is refused (CA_MD_TOO_WEAK, OpenSSL's level 1)
//
// None of this was checked: a sub-CA limited to one domain could issue for
// any (x509-limbo: 2,384 cases; CVE-2025-61727's class), a certificate
// without serverAuth was taken for a server, an end-entity certificate in
// `ca` signed for every name.
//
// The codes are OpenSSL's names (as node:tls reports them).

import crypto from 'node:crypto';

const OID = {
  KU: '2.5.29.15', SAN: '2.5.29.17', BC: '2.5.29.19', NC: '2.5.29.30', EKU: '2.5.29.37',
  ANY_EKU: '2.5.29.37.0', SERVER_AUTH: '1.3.6.1.5.5.7.3.1', CLIENT_AUTH: '1.3.6.1.5.5.7.3.2',
};
// Extensions that may be marked critical: OpenSSL's list
// (X509_supported_extension) — those processed here, the policy ones (this
// verifier requires no policy, so a policy extension restricts nothing it
// relies on), and CRL distribution points. Any other critical:
// UNHANDLED_CRITICAL_EXTENSION, as OpenSSL answers (error 34). The key
// identifiers, freshest CRL, AIA, SIA, issuer alt name, subject directory
// attributes and TLS feature were taken critical too — RFC 5280 has the
// key identifiers and AIA non-critical ("MUST", §4.2.1.1, .2, §4.2.2.1),
// and a certificate that marks AIA critical says a verifier that does not
// fetch from it must not use it (x509-limbo; BoringSSL refuses them too).
const KNOWN = new Set([
  OID.KU, OID.SAN, OID.BC, OID.NC, OID.EKU,
  '2.5.29.32', '2.5.29.33', '2.5.29.36', '2.5.29.54',   // policies, mappings, constraints, inhibitAnyPolicy
  '2.5.29.31',                              // CRL distribution points
]);
// Signature algorithms too weak to sign a certificate: MD2, MD4, MD5, SHA-1
// — under RSA (and the old OIW OID), DSA, ECDSA, and RSASSA-PSS whose hash
// is SHA-1 (its default). OpenSSL refuses them from security level 1 —
// node:tls's default: "CA signature digest algorithm too weak" — as does
// BoringSSL's libpki. They were taken (x509-limbo, bettertls).
const WEAK_SIG = new Set([
  '1.2.840.113549.1.1.2', '1.2.840.113549.1.1.3', '1.2.840.113549.1.1.4', '1.2.840.113549.1.1.5',
  '1.3.14.3.2.29', '1.3.14.3.2.27', '1.2.840.10040.4.3', '1.2.840.10045.4.1',
]);
const RSA_PSS = '1.2.840.113549.1.1.10', SHA1 = '1.3.14.3.2.26';
const KU_DIGITAL_SIGNATURE = 0x80, KU_KEY_ENCIPHERMENT = 0x20, KU_KEY_AGREEMENT = 0x08, KU_KEY_CERT_SIGN = 0x04;

// ---- DER ----
function DerError(msg) { let e = new Error('certificate: ' + msg); e.code = 'CERTIFICATE_PARSE_ERROR'; return e; }

// One TLV at `off` of `buf`: { tag, cons, start (of the value), end, next }.
function tlv(buf, off, limit) {
  if (limit === undefined) limit = buf.length;
  if (off + 2 > limit) throw DerError('truncated');
  let tag = buf[off], p = off + 1;
  if ((tag & 0x1f) === 0x1f) throw DerError('high tag number');
  let len = buf[p++];
  if (len & 0x80) {
    let n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > limit) throw DerError('bad length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[p++];
  }
  if (p + len > limit) throw DerError('truncated');
  return { tag: tag, cons: (tag & 0x20) !== 0, start: p, end: p + len, next: p + len, hdr: off };
}
function children(buf, t) {
  let out = [], p = t.start;
  while (p < t.end) { let c = tlv(buf, p, t.end); out.push(c); p = c.next; }
  return out;
}
function oidString(buf, t) {
  if (t.tag !== 0x06 || t.end === t.start) throw DerError('expected an OID');
  let parts = [], v = 0, first = true;
  for (let i = t.start; i < t.end; i++) {
    v = v * 128 + (buf[i] & 0x7f);
    if (!(buf[i] & 0x80)) {
      if (first) { parts.push(v < 80 ? Math.floor(v / 40) : 2, v < 80 ? v % 40 : v - 80); first = false; }
      else parts.push(v);
      v = 0;
    }
  }
  return parts.join('.');
}
function ascii(buf, t) { return buf.toString('latin1', t.start, t.end); }

// A GeneralName (RFC 5280 §4.2.1.6): { type, value }.
//   type: 'dns' | 'ip' | 'email' | 'uri' | 'dn' | 'other' (otherName, x400,
//   ediParty, registeredID — not read here)
function generalName(buf, t) {
  switch (t.tag) {
    case 0x81: return { type: 'email', value: ascii(buf, t) };
    case 0x82: return { type: 'dns', value: ascii(buf, t) };
    case 0x86: return { type: 'uri', value: ascii(buf, t) };
    case 0x87: return { type: 'ip', value: buf.subarray(t.start, t.end) };
    case 0xa4: { let n = children(buf, t); if (n.length !== 1 || n[0].tag !== 0x30) throw DerError('directoryName');
                 return { type: 'dn', value: rdns(buf, n[0]) }; }
    default: return { type: 'other', value: t.tag };
  }
}
// A Name, as its RDNs' encodings (compared byte for byte: RFC 5280 §7.1's
// comparison, for names encoded the same way — as issuers encode them).
function rdns(buf, nameT) {
  return children(buf, nameT).map(function (r) { return buf.subarray(r.hdr, r.end); });
}

/**
 * The extensions of a certificate (DER Buffer) that the path checks read.
 * Throws CERTIFICATE_PARSE_ERROR on DER that does not hold one, and on an
 * extension present twice (§4.2: "MUST NOT include more than one instance").
 */
// Whether a certificate's signatureAlgorithm (an AlgorithmIdentifier TLV)
// is one of WEAK_SIG, or RSASSA-PSS over SHA-1.
function weakSignature(der, algT) {
  if (!algT || algT.tag !== 0x30) throw DerError('no signatureAlgorithm');
  let a = children(der, algT), oid = oidString(der, a[0]);
  if (WEAK_SIG.has(oid)) return true;
  if (oid !== RSA_PSS) return false;
  // RSASSA-PSS-params: hashAlgorithm [0] DEFAULT sha1 (RFC 4055 §3.1).
  let params = a[1];
  if (!params || params.tag !== 0x30) return true;
  let h = children(der, params).find(function (t) { return t.tag === 0xa0; });
  if (!h) return true;
  let hAlg = children(der, h)[0];
  return !!hAlg && oidString(der, children(der, hAlg)[0]) === SHA1;
}

function parse_extensions(der) {
  let cert = tlv(der, 0);
  if (cert.tag !== 0x30 || cert.end !== der.length) throw DerError('not a certificate');
  let top = children(der, cert);
  let tbs = top[0];
  if (!tbs || tbs.tag !== 0x30) throw DerError('no tbsCertificate');
  let f = children(der, tbs), i = 0;
  let version = 1;
  if (f[i] && f[i].tag === 0xa0) { let v = children(der, f[i])[0]; version = der[v.end - 1] + 1; i++; }
  i += 3;                                    // serialNumber, signature, issuer
  let issuerT = f[i - 1];
  i += 1;                                    // validity
  let subjectT = f[i++];
  i += 1;                                    // subjectPublicKeyInfo
  if (!subjectT || subjectT.tag !== 0x30 || !issuerT || issuerT.tag !== 0x30) throw DerError('no subject');
  let out = {
    version: version,
    subject: rdns(der, subjectT),
    subjectEmpty: subjectT.end === subjectT.start,
    subjectAttrs: children(der, subjectT).reduce(function (n, r) { return n + children(der, r).length; }, 0),
    selfIssued: der.subarray(subjectT.hdr, subjectT.end).equals(der.subarray(issuerT.hdr, issuerT.end)),
    critical: [], bc: null, ku: null, eku: null, san: null, nc: null,
    weakSig: weakSignature(der, top[1]),
  };
  let extT = null;
  for (; i < f.length; i++) if (f[i].tag === 0xa3) extT = f[i];
  if (!extT) return out;
  let list = children(der, extT)[0];
  if (!list || list.tag !== 0x30) throw DerError('extensions');
  let seen = new Set();
  for (const e of children(der, list)) {
    let parts = children(der, e);
    let oid = oidString(der, parts[0]);
    if (seen.has(oid)) throw DerError('extension ' + oid + ' twice');
    seen.add(oid);
    let critical = false, k = 1;
    if (parts[k] && parts[k].tag === 0x01) { critical = der[parts[k].start] !== 0; k++; }
    let octets = parts[k];
    if (!octets || octets.tag !== 0x04) throw DerError('extension value');
    if (critical) out.critical.push(oid);
    let v = tlv(der, octets.start, octets.end);
    if (v.next !== octets.end) throw DerError('extension ' + oid + ': trailing bytes');
    if (oid === OID.BC) {
      let c = children(der, v), ca = false, pathLen = null, j = 0;
      if (c[j] && c[j].tag === 0x01) { ca = der[c[j].start] !== 0; j++; }
      if (c[j] && c[j].tag === 0x02) {
        if (c[j].end - c[j].start > 4 || der[c[j].start] & 0x80) throw DerError('pathLenConstraint');
        pathLen = 0; for (let b = c[j].start; b < c[j].end; b++) pathLen = pathLen * 256 + der[b];
      }
      out.bc = { ca: ca, pathLen: pathLen };
    } else if (oid === OID.KU) {
      if (v.tag !== 0x03 || v.end - v.start < 2) throw DerError('keyUsage');
      out.ku = der[v.start + 1];
    } else if (oid === OID.EKU) {
      out.eku = children(der, v).map(function (o) { return oidString(der, o); });
    } else if (oid === OID.SAN) {
      out.san = children(der, v).map(function (g) { return generalName(der, g); });
    } else if (oid === OID.NC) {
      out.nc = { permitted: null, excluded: null };
      for (const s of children(der, v)) {
        let subtrees = children(der, s).map(function (gs) {
          let g = children(der, gs);
          if (!g[0]) throw DerError('GeneralSubtree');
          // minimum other than 0, or a maximum: "MUST" not be used (§4.2.1.10).
          if (g.length > 1) return { type: 'bad' };
          return generalName(der, g[0]);
        });
        if (s.tag === 0xa0) out.nc.permitted = subtrees;
        else if (s.tag === 0xa1) out.nc.excluded = subtrees;
        else throw DerError('nameConstraints');
      }
    }
  }
  return out;
}

// ---- name constraints (§4.2.1.10) ----
function lower(s) { return String(s).toLowerCase(); }
function dnsWithin(name, base) {
  name = lower(name).replace(/\.$/, ''); base = lower(base).replace(/\.$/, '');
  if (base === '') return true;
  if (base[0] === '.') return name.endsWith(base);
  return name === base || name.endsWith('.' + base);
}
function hostWithin(host, base) {          // URI and mail hosts: ".x" subdomains only, "x" itself
  host = lower(host); base = lower(base);
  if (base === '') return true;
  if (base[0] === '.') return host.endsWith(base);
  return host === base;
}
function emailWithin(addr, base) {
  addr = String(addr); base = String(base);
  let at = addr.lastIndexOf('@');
  if (at < 0) return false;
  if (base.indexOf('@') >= 0) return addr.slice(0, at) === base.slice(0, base.lastIndexOf('@')) &&
                                     lower(addr.slice(at + 1)) === lower(base.slice(base.lastIndexOf('@') + 1));
  return hostWithin(addr.slice(at + 1), base);
}
function uriHost(uri) {
  let m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@/?#]*@)?(\[[^\]]*\]|[^:/?#]*)/i.exec(String(uri));
  return m ? m[1] : null;
}
// The mask of an iPAddress constraint must be a run of ones then zeros: one
// that is not names no subnet (x509-limbo refuses such a constraint).
function ipMaskOk(mask) {
  let zero = false;
  for (let i = 0; i < mask.length; i++) for (let b = 7; b >= 0; b--) {
    let one = (mask[i] >> b) & 1;
    if (one && zero) return false;
    if (!one) zero = true;
  }
  return true;
}
function ipWithin(ip, c) {
  if (c.length !== ip.length * 2) return false;
  for (let i = 0; i < ip.length; i++) if ((ip[i] & c[ip.length + i]) !== (c[i] & c[ip.length + i])) return false;
  return true;
}
function dnWithin(subject, base) {
  if (base.length > subject.length) return false;
  for (let i = 0; i < base.length; i++) if (!subject[i].equals(base[i])) return false;
  return true;
}
function within(n, c) {
  switch (n.type) {
    case 'dns': return dnsWithin(n.value, c.value);
    case 'email': return emailWithin(n.value, c.value);
    case 'uri': { let h = uriHost(n.value); return h !== null && hostWithin(h, c.value); }
    case 'ip': return ipWithin(n.value, c.value);
    case 'dn': return dnWithin(n.value, c.value);
  }
  return false;
}
// The cost of name constraints: names × constraints, both chosen by the
// certificates. Bounded as OpenSSL bounds it — NAME_CHECK_MAX (2^20)
// comparisons of one certificate's names against one CA's constraints, the
// names counted as OpenSSL counts them (each subject attribute, each
// subjectAltName) — and over the whole path by NAME_CHECK_PATH_MAX:
// five times one pair's. OpenSSL bounds each pair alone, so CAs stacked
// under one another multiply the cost: four of 1,024 subtrees, a leaf of
// 1,023 names under each, kept every pair under 2^20 and cost them all.
// Five pairs' worth takes that path still — four maximal pairs and the CAs'
// own names under one another (2^22 refused it by a few thousand
// comparisons, where OpenSSL takes it) — and is the most the
// constraints of any path can cost now (~100 ms); a path past it is refused
// (x509-limbo nc-dos). Past either bound: X509_V_ERR_UNSPECIFIED,
// node:tls's 'UNSPECIFIED'.
const NAME_CHECK_MAX = 1 << 20;
const NAME_CHECK_PATH_MAX = 5 * NAME_CHECK_MAX;

// A CA's nameConstraints, prepared once for the names checked against them:
// by name type, DNS bases lowercased and without a trailing dot (each
// comparison lowercased both again).
function preparedConstraints(nc) {
  if (nc._prepared) return nc._prepared;
  let byType = function (list) {
    let out = {};
    for (const c of list || []) {
      let v = c.type === 'dns' ? lower(c.value).replace(/\.$/, '') : c.value;
      (out[c.type] || (out[c.type] = [])).push({ type: c.type, value: v });
    }
    return out;
  };
  let all = (nc.permitted || []).concat(nc.excluded || []);
  nc._prepared = { all: all, permitted: byType(nc.permitted), excluded: byType(nc.excluded),
                   hasUri: all.some(function (c) { return c.type === 'uri'; }) };
  return nc._prepared;
}
// A DNS name within a prepared base (dnsWithin, with the base normalized).
function dnsWithinPrepared(name, base) {
  if (base === '') return true;
  if (base[0] === '.') return name.endsWith(base);
  return name === base || (name.length > base.length && name.endsWith(base) && name[name.length - base.length - 1] === '.');
}
function withinPrepared(n, nv, c) {
  return n.type === 'dns' ? dnsWithinPrepared(nv, c.value) : within(n, c);
}

// Whether `names` (of one certificate, namesOf) stand within `nc`; null
// when they do, else the error code. `budget` ({ left }) is what is left of
// the path's comparisons. A constraint this check cannot read (otherName,
// x400Address, ediPartyName, registeredID) and a name of such a kind meet:
// refused — whether the name is within it is unknown. A subtree with a
// minimum or maximum, or an iPAddress constraint that is no address and
// mask, is malformed (§4.2.1.10): the certificate carrying it is refused.
function checkNames(names, nc, budget) {
  let pc = preparedConstraints(nc), all = pc.all, unread = false;
  let count = names.count, cost = count * all.length;
  if (count > NAME_CHECK_MAX || (all.length > 0 && count > NAME_CHECK_MAX / all.length)) return 'UNSPECIFIED';
  if (budget) { if (cost > budget.left) return 'UNSPECIFIED'; budget.left -= cost; }
  for (const c of all) {
    if (c.type === 'bad') return 'UNSUPPORTED_CONSTRAINT_SYNTAX';
    if (c.type === 'ip' && (!(c.value.length === 8 || c.value.length === 32) || !ipMaskOk(c.value.subarray(c.value.length / 2)))) {
      return 'UNSUPPORTED_CONSTRAINT_SYNTAX';
    }
    if (c.type === 'other') unread = true;
  }
  for (const n of names) {
    if (n.type === 'other') { if (unread) return 'UNSUPPORTED_NAME_SYNTAX'; continue; }
    if (n.type === 'uri' && uriHost(n.value) === null && pc.hasUri) return 'UNSUPPORTED_NAME_SYNTAX';
    let nv = n.type === 'dns' ? lower(n.value).replace(/\.$/, '') : n.value;
    for (const c of pc.excluded[n.type] || []) if (withinPrepared(n, nv, c)) return 'EXCLUDED_VIOLATION';
    let perm = pc.permitted[n.type];
    if (perm && perm.length > 0) {
      let ok = false;
      for (let k = 0; k < perm.length && !ok; k++) ok = withinPrepared(n, nv, perm[k]);
      if (!ok) return 'PERMITTED_VIOLATION';
    }
  }
  return null;
}
// The names a certificate is checked under: its subjectAltName, and its
// subject (a directoryName). Its common name is not a name here — a host is
// matched against the subjectAltName only (checkHost subject: 'never').
// `count`: as OpenSSL counts them for NAME_CHECK_MAX — the subject's
// attributes one by one, and each subjectAltName.
function namesOf(p) {
  let names = (p.san || []).slice();
  if (!p.subjectEmpty) names.push({ type: 'dn', value: p.subject });
  names.count = (p.san ? p.san.length : 0) + p.subjectAttrs;
  return names;
}

/**
 * The path checks: `path` is [leaf, …, anchor] as crypto.X509Certificate
 * objects, `purpose` 'server' (we are the client, checking a server) or
 * 'client'. Returns null, or the error code.
 */
function check_path(path, purpose) {
  let parsed = [];
  try {
    for (let i = 0; i < path.length; i++) parsed.push(parse_extensions(path[i].raw));
  } catch (e) { return e.code || 'CERTIFICATE_PARSE_ERROR'; }
  let want = purpose === 'client' ? OID.CLIENT_AUTH : OID.SERVER_AUTH;
  let last = path.length - 1;
  let budget = { left: NAME_CHECK_PATH_MAX };   // the path's name-constraint comparisons

  for (let i = 0; i <= last; i++) {
    let p = parsed[i];
    for (const oid of p.critical) if (!KNOWN.has(oid)) return 'UNHANDLED_CRITICAL_EXTENSION';
    // Its signature, unless it is the anchor (whose own signature nothing
    // checks — the caller trusts it as it is): not by a weak digest.
    if (i < last && p.weakSig) return 'CA_MD_TOO_WEAK';
    // extendedKeyUsage, where present, on the leaf and the intermediates
    // (the anchor's is the caller's to trust).
    if (i < last && p.eku && p.eku.indexOf(want) < 0 && p.eku.indexOf(OID.ANY_EKU) < 0) return 'INVALID_PURPOSE';
    if (i === 0) {
      // The leaf: not a CA (a path of one — the leaf is the anchor itself —
      // is the caller's own trust in it, and never reaches here).
      if (p.bc && p.bc.ca) return 'INVALID_PURPOSE';
      if (p.ku !== null && !(p.ku & (KU_DIGITAL_SIGNATURE | KU_KEY_ENCIPHERMENT | KU_KEY_AGREEMENT))) return 'INVALID_PURPOSE';
      continue;
    }
    // An issuer: a CA (a version 1 self-signed root is one by convention,
    // as OpenSSL takes it), allowed to sign certificates.
    if (!(p.bc && p.bc.ca) && !(p.version === 1 && i === last && p.selfIssued)) return 'INVALID_CA';
    if (p.ku !== null && !(p.ku & KU_KEY_CERT_SIGN)) return 'INVALID_CA';
    // pathLenConstraint: the intermediates below it, self-issued ones aside.
    if (p.bc && p.bc.pathLen !== null) {
      let below = 0;
      for (let j = 1; j < i; j++) if (!parsed[j].selfIssued) below++;
      if (below > p.bc.pathLen) return 'PATH_LENGTH_EXCEEDED';
    }
    // Its name constraints, on every certificate below it — a self-issued
    // intermediate's own names aside (§6.1.3 b).
    if (p.nc) {
      for (let j = 0; j < i; j++) {
        if (j > 0 && parsed[j].selfIssued) continue;
        let err = checkNames(namesOf(parsed[j]), p.nc, budget);
        if (err) return err;
      }
    }
  }
  return null;
}

/**
 * The certificate for `host`? The one identity check — the handshake's
 * (tls_session) and tls.checkServerIdentity's (compat) both: a host name
 * against the subjectAltName's DNS names only — the subject's common name is
 * not one (RFC 9525 §6.3: it was, when the certificate had no DNS SAN) — and
 * a wildcard a whole leftmost label (*.example.com, not ba*.example.com);
 * an address against its iPAddress names. `x509` is a crypto.X509Certificate
 * (or DER). True or false.
 */
// An IPv4 or IPv6 address literal (IPv6 with or without brackets) — what
// SNI may never carry, and what a certificate is checked against by IP SAN.
function is_ip_literal(host) {
  host = String(host);
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) ||
         (host.indexOf(':') >= 0 && /^[0-9a-fA-F:.\[\]]+$/.test(host));
}
function matches_host(x509, host) {
  if (!(x509 instanceof crypto.X509Certificate)) x509 = new crypto.X509Certificate(Buffer.from(x509));
  host = String(host);
  return is_ip_literal(host)
    ? !!x509.checkIP(host.replace(/^\[|\]$/g, ''))
    : !!x509.checkHost(host, { subject: 'never', partialWildcards: false });
}

// The same rules over node:tls's subjectaltname string ('DNS:a.example,
// IP Address:192.0.2.1'), for a certificate object without its DER — as
// tls.checkServerIdentity is given by callers that build one themselves.
// A wildcard only as the whole leftmost label, and not alone over a public
// suffix of one label ('*.com').
function matches_altnames(san, host) {
  host = String(host).toLowerCase().replace(/\.$/, '');
  let ip = is_ip_literal(host) ? canonical_ip(host.replace(/^\[|\]$/g, '')) : null;
  let entries = String(san || '').split(/,\s*/);
  for (let i = 0; i < entries.length; i++) {
    let e = entries[i], c = e.indexOf(':');
    if (c < 0) continue;
    let kind = e.slice(0, c), value = e.slice(c + 1).trim().toLowerCase().replace(/\.$/, '');
    if (ip !== null) {
      if (kind === 'IP Address' && canonical_ip(value) === ip) return true;
      continue;
    }
    if (kind !== 'DNS') continue;
    if (value === host) return true;
    if (value.startsWith('*.') && value.indexOf('.', 2) > 0) {
      let dot = host.indexOf('.');
      if (dot > 0 && host.slice(dot + 1) === value.slice(2)) return true;
    }
  }
  return false;
}
function canonical_ip(s) {
  try { return new URL('http://' + (s.indexOf(':') >= 0 ? '[' + s + ']' : s)).hostname; } catch (e) { return null; }
}

export { check_path, parse_extensions, matches_host, matches_altnames, is_ip_literal };
