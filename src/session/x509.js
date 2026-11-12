// ============================================================
//  X.509 for the handshake: certificates read, issuers matched,
//  signatures checked, and the path checks (RFC 5280 §4.2, §6.1)
// ============================================================
//
// The certificate FORMAT is cryptographic-formats': the DER, the extensions, names
// and their comparison (RFC 5280 §7.1, as OpenSSL canonicalizes them), name
// constraints, host names. This module holds what a TLS verifier decides on
// top of it, and the signature check, which is node:crypto's:
//
//   parse_cert         a certificate, read once per DER object
//   issued_by          the issuer's name, and its key identifier where the
//                      certificate names one (OpenSSL's X509_check_issued,
//                      less the keyUsage test — check_path reports that as
//                      INVALID_CA, which is OpenSSL's answer too)
//   signed_by          the signature, by the issuer's key
//   check_path         what each certificate of a built path may do:
//
//   basicConstraints   every issuer a CA (an anchor too: one that is not —
//                      an end-entity certificate given as `ca` — vouched for
//                      any name); pathLenConstraint; a leaf that is a CA
//                      (CA/B Forum BR §7.1.2.7.8: cA MUST be false) refused
//   keyUsage           an issuer may sign certificates (keyCertSign); a leaf
//                      may sign or agree a key (OpenSSL's TLS purpose rule)
//   extKeyUsage        when present, on the leaf and the intermediates, the
//                      purpose asked for (serverAuth, clientAuth) or any
//   nameConstraints    each CA's, on every certificate below it — the
//                      subject, its emailAddress attributes, every
//                      subjectAltName, and the leaf's common name when it has
//                      no DNS name (OpenSSL's NAME_CONSTRAINTS_check_CN)
//   critical           an extension marked critical that is not one this
//                      verifier enforces refuses the certificate (§4.2)
//   signature          a certificate below the anchor signed with MD2, MD4,
//                      MD5 or SHA-1 is refused (CA_MD_TOO_WEAK, OpenSSL's
//                      security level 1, node:tls's default)
//
// The codes are OpenSSL's names (as node:tls reports them).
//
// This module had its own DER reader and its own name-constraint matching.
// Moving them to cryptographic-formats fixed what they had wrong against OpenSSL: a
// subject's emailAddress was never checked against email constraints, a
// leaf's common name never against DNS ones, directory names were compared
// byte for byte (O=Acme did not match O=ACME), a non-prefix IP mask and a
// subtree minimum were reported as UNSUPPORTED_CONSTRAINT_SYNTAX where
// OpenSSL matches the first and says SUBTREE_MINMAX for the second.

import crypto from 'node:crypto';
import * as X509 from 'cryptographic-formats/x509';

const ANY_EKU = '2.5.29.37.0', SERVER_AUTH = '1.3.6.1.5.5.7.3.1', CLIENT_AUTH = '1.3.6.1.5.5.7.3.2';

// The extensions this verifier enforces, so the only ones that may be marked
// critical — any other critical: UNHANDLED_CRITICAL_EXTENSION, OpenSSL's
// error 34. keyUsage, subjectAltName, basicConstraints, nameConstraints and
// extKeyUsage are checked here; the policy ones restrict nothing this
// verifier relies on (it requires no policy), and CRL distribution points
// say where to look, not what to refuse. OpenSSL takes a few more critical
// (nsCertType, RFC 3779's, proxyCertInfo) because it enforces them by rules
// of its own; they are not read here, so refused here.
//
// The key identifiers, freshest CRL, AIA, SIA, issuer alt name, subject
// directory attributes and TLS feature are refused critical as well — RFC
// 5280 has the key identifiers and AIA non-critical ("MUST", §4.2.1.1, .2,
// §4.2.2.1), and a certificate that marks AIA critical says a verifier that
// does not fetch from it must not use it (x509-limbo; BoringSSL refuses
// them too).
const ENFORCED = X509.enforced_set([
  '2.5.29.15', '2.5.29.17', '2.5.29.19', '2.5.29.30', '2.5.29.37',   // KU, SAN, BC, NC, EKU
  '2.5.29.32', '2.5.29.33', '2.5.29.36', '2.5.29.54',                // policies, mappings, constraints, inhibitAnyPolicy
  '2.5.29.31',                                                       // CRL distribution points
]);

// ---- certificates ----

// Read once per DER object: the anchors are the same objects on every
// handshake, and the peer's leaf is read by the chain check, the identity
// check and the handshake signature. Strings (PEM) are not keys here — the
// caller turns them into DER first.
const PARSED = new WeakMap();
// …and once per DER content, a bounded number of them: a client that
// connects with a `ca` makes a new secure context — new objects for the
// same CA — every time, and a server presents the same chain to every
// client. Reading them again cost a quarter of a millisecond a handshake.
// A certificate is immutable, so its reading is too. Full: cleared, as the
// anchor cache in tls_session.
const PARSED_BY_CONTENT = new Map();
const PARSED_BY_CONTENT_MAX = 1024;

function bytes_equal(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * A certificate from its DER (Buffer or Uint8Array), or null when it is not
 * one cryptographic-formats can read. The result:
 *   raw          Buffer, the DER
 *   cf           cryptographic-formats' x509.from_der
 *   subjectKey,  the names as one string each, equal when the names match
 *   issuerKey    (RFC 5280 §7.1 as OpenSSL compares them) — for an index
 *   notBefore,   ms
 *   notAfter
 *   selfIssued   subject and issuer the same name
 *   bc, ku, eku, nc, ski, aki   the extensions' parsed values, or null
 *   publicKey()  a crypto.KeyObject, made on first use; null when node:crypto
 *                cannot use the key
 */
function parse_cert(der) {
  if (der == null || typeof der !== 'object') return null;
  let hit = PARSED.get(der);
  if (hit !== undefined) return hit;
  let content = Buffer.from(der.buffer, der.byteOffset, der.byteLength).toString('latin1');
  let out = PARSED_BY_CONTENT.get(content);
  if (out === undefined) {
    try { out = make_cert(X509.from_der(der)); } catch (e) { out = null; }
    if (PARSED_BY_CONTENT.size >= PARSED_BY_CONTENT_MAX) PARSED_BY_CONTENT.clear();
    PARSED_BY_CONTENT.set(content, out);
  }
  PARSED.set(der, out);
  return out;
}

function make_cert(cf) {
  let ext = function (name) { let e = X509.extension(cf, name); return e ? e.parsed : null; };
  let subjectKey = X509.name_key(cf.subject), issuerKey = X509.name_key(cf.issuer);
  let key;
  return {
    raw: Buffer.from(cf.der.buffer, cf.der.byteOffset, cf.der.byteLength),
    cf: cf,
    subjectKey: subjectKey,
    issuerKey: issuerKey,
    notBefore: cf.validity.not_before.date.getTime(),
    notAfter: cf.validity.not_after.date.getTime(),
    selfIssued: subjectKey === issuerKey,
    bc: ext('basicConstraints'),
    ku: ext('keyUsage'),
    eku: ext('extKeyUsage'),
    nc: ext('nameConstraints'),
    ski: ext('subjectKeyId'),
    aki: ext('authorityKeyId'),
    publicKey: function () {
      if (key === undefined) {
        try { key = crypto.createPublicKey({ key: Buffer.from(cf.public_key.der), format: 'der', type: 'spki' }); }
        catch (e) { key = null; }
      }
      return key;
    },
  };
}

/** Inside its validity window at `now` (a Date): both ends inclusive (§4.1.2.5). */
function valid_at(cert, now) {
  let t = now.getTime();
  return t >= cert.notBefore && t <= cert.notAfter;
}
/** The node:tls (OpenSSL) code for a certificate outside its window. */
function validity_error(cert, now) {
  return now.getTime() < cert.notBefore ? 'CERT_NOT_YET_VALID' : 'CERT_HAS_EXPIRED';
}

/**
 * Could `issuer` have issued `cert`? Its subject is the certificate's issuer
 * name, and where the certificate's authorityKeyIdentifier names a key
 * identifier, a serial or an issuer, the candidate is that one — OpenSSL's
 * X509_check_akid. That is what picks the right CA of two with one name.
 * Not the signature (signed_by), and not the issuer's keyUsage (check_path).
 */
function issued_by(cert, issuer) {
  if (cert.issuerKey !== issuer.subjectKey) return false;
  let aki = cert.aki;
  if (!aki) return true;
  if (aki.key_id && issuer.ski && !bytes_equal(aki.key_id, issuer.ski)) return false;
  if (aki.serial && !bytes_equal(aki.serial, issuer.cf.serial)) return false;
  if (aki.issuer) {
    let dns = aki.issuer.filter(function (g) { return g.type === 'directory'; });
    if (dns.length > 0 && !dns.some(function (g) { return X509.name_key(g.value) === issuer.issuerKey; })) return false;
  }
  return true;
}

/**
 * Is `cert`'s signature `issuer`'s? The algorithm as cryptographic-formats
 * describes it, the check node:crypto's. An algorithm node:crypto cannot
 * check — RSASSA-PSS whose mask hash is not its message hash (node:crypto
 * takes one hash for both), MD2 — is a signature that does not verify.
 */
function signed_by(cert, issuer) {
  let key = issuer.publicKey();
  if (!key) return false;
  let p = cert.cf.signature_params, tbs = cert.cf.tbs_bytes, sig = cert.cf.signature;
  try {
    switch (p.scheme) {
      case 'pkcs1':
        return crypto.verify(p.hash, tbs, { key: key, padding: crypto.constants.RSA_PKCS1_PADDING }, sig);
      case 'pss':
        if (p.pss.mgf !== 'mgf1' || p.pss.mgf_hash !== p.pss.hash) return false;
        return crypto.verify(p.pss.hash, tbs, { key: key, padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
                                                saltLength: p.pss.salt_length }, sig);
      case 'ecdsa':
      case 'dsa':
        return crypto.verify(p.hash, tbs, key, sig);
      case 'eddsa':
      case 'ml-dsa':
      case 'slh-dsa':
        return crypto.verify(null, tbs, key, sig);
      default:
        return false;
    }
  } catch (e) {
    return false;
  }
}

/** Issued by itself, and signed by its own key. */
function self_signed(cert) {
  return issued_by(cert, cert) && signed_by(cert, cert);
}

// ---- name constraints (§4.2.1.10) ----

// The cost of name constraints: names × constraints, both chosen by the
// certificates. Bounded as OpenSSL bounds it — NAME_CHECK_MAX (2^20)
// comparisons of one certificate's names against one CA's constraints
// (cryptographic-formats counts the names as OpenSSL does) — and over the whole
// path by NAME_CHECK_PATH_MAX: five times one pair's. OpenSSL bounds each
// pair alone, so CAs stacked under one another multiply the cost: four of
// 1,024 subtrees, a leaf of 1,023 names under each, kept every pair under
// 2^20 and cost them all. Five pairs' worth takes that path still — four
// maximal pairs and the CAs' own names under one another — and is the most
// the constraints of any path can cost (~100 ms); a path past it is refused
// (x509-limbo nc-dos). Past either bound: X509_V_ERR_UNSPECIFIED, node:tls's
// 'UNSPECIFIED'.
const NAME_CHECK_MAX = 1 << 20;
const NAME_CHECK_PATH_MAX = 5 * NAME_CHECK_MAX;

// `cert`'s names within `nc` (a CA's): null, or the error code. `isLeaf`:
// the common name counts as a DNS name when there is none other (OpenSSL
// does this for the leaf). `budget` ({ left }): the path's comparisons.
function name_constraints_error(cert, nc, isLeaf, budget) {
  let r;
  try {
    r = X509.name_constraints_check(cert.cf, nc, {
      common_name: isLeaf, max_checks: Math.min(NAME_CHECK_MAX, budget.left),
    });
  } catch (e) {
    // A subtree with a minimum or maximum: OpenSSL's error 49, whatever
    // the names. Over the bound: UNSPECIFIED, as there.
    return e && e.code === 'subtree-minmax' ? 'SUBTREE_MINMAX' : 'UNSPECIFIED';
  }
  budget.left -= r.checks;
  if (r.ok === false) {
    // Which rule refused it: OpenSSL says EXCLUDED_VIOLATION (48) for a name
    // inside an excluded subtree, PERMITTED_VIOLATION (47) for one outside
    // every permitted subtree of its kind.
    for (const n of r.refused) if (n.reason === 'excluded') return 'EXCLUDED_VIOLATION';
    return 'PERMITTED_VIOLATION';
  }
  // A name of a kind a constraint covers and nothing here can compare — a
  // URI without a host, an otherName: refused, as OpenSSL's error 53.
  if (r.ok === null) return 'UNSUPPORTED_NAME_SYNTAX';
  return null;
}

// ---- the path ----

/**
 * The path checks: `path` is [leaf, …, anchor] as parse_cert returns them,
 * `purpose` 'server' (we are the client, checking a server) or 'client'.
 * Returns null, or the error code.
 */
function check_path(path, purpose) {
  let want = purpose === 'client' ? CLIENT_AUTH : SERVER_AUTH;
  let last = path.length - 1;
  let budget = { left: NAME_CHECK_PATH_MAX };   // the path's name-constraint comparisons

  for (let i = 0; i <= last; i++) {
    let p = path[i];
    // Once per certificate (it is read once, and kept): the answer is the
    // certificate's.
    if (p.unenforced === undefined) p.unenforced = X509.unenforced_critical(p.cf, ENFORCED).length > 0;
    if (p.unenforced) return 'UNHANDLED_CRITICAL_EXTENSION';
    // Its signature, unless it is the anchor (whose own signature nothing
    // checks — the caller trusts it as it is): not by a weak digest.
    if (i < last && p.cf.signature_params.weak) return 'CA_MD_TOO_WEAK';
    // extendedKeyUsage, where present, on the leaf and the intermediates
    // (the anchor's is the caller's to trust).
    if (i < last && p.eku && !p.eku.some(function (u) { return u.id === want || u.id === ANY_EKU; })) return 'INVALID_PURPOSE';
    if (i === 0) {
      // The leaf: not a CA (a path of one — the leaf is the anchor itself —
      // is the caller's own trust in it, and never reaches here).
      if (p.bc && p.bc.ca) return 'INVALID_PURPOSE';
      if (p.ku && !(p.ku.digitalSignature || p.ku.keyEncipherment || p.ku.keyAgreement)) return 'INVALID_PURPOSE';
      continue;
    }
    // An issuer: a CA (a version 1 self-signed root is one by convention,
    // as OpenSSL takes it). An intermediate that is not one fails OpenSSL's
    // purpose check (a TLS CA) first — INVALID_PURPOSE, as node:tls reports
    // it; an anchor that is not one, INVALID_CA.
    if (!(p.bc && p.bc.ca) && !(p.cf.version === 1 && i === last && p.selfIssued)) {
      return i < last ? 'INVALID_PURPOSE' : 'INVALID_CA';
    }
    // …allowed to sign certificates.
    if (p.ku && !p.ku.keyCertSign) return 'INVALID_CA';
    // pathLenConstraint: the intermediates below it, self-issued ones aside.
    if (p.bc && p.bc.path_len !== null && p.bc.path_len !== undefined) {
      let below = 0;
      for (let j = 1; j < i; j++) if (!path[j].selfIssued) below++;
      if (below > p.bc.path_len) return 'PATH_LENGTH_EXCEEDED';
    }
    // Its name constraints, on every certificate below it — a self-issued
    // intermediate's own names aside (§6.1.3 b).
    if (p.nc) {
      for (let j = 0; j < i; j++) {
        if (j > 0 && path[j].selfIssued) continue;
        let err = name_constraints_error(path[j], p.nc, j === 0, budget);
        if (err) return err;
      }
    }
  }
  return null;
}

// ---- the host ----

// An IPv4 or IPv6 address literal (IPv6 with or without brackets) — what
// SNI may never carry, and what a certificate is checked against by IP SAN.
function is_ip_literal(host) {
  host = String(host);
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) ||
         (host.indexOf(':') >= 0 && /^[0-9a-fA-F:.\[\]]+$/.test(host));
}

/**
 * The certificate for `host`? The one identity check — the handshake's
 * (tls_session) and tls.checkServerIdentity's (compat) both: cryptographic-formats'
 * RFC 9525 rules. A host name against the subjectAltName's DNS names only —
 * the subject's common name is not one (RFC 9525 §6.3: it was, when the
 * certificate had no DNS SAN) — and a wildcard a whole leftmost label
 * (*.example.com, not ba*.example.com, not *.com); an address against its
 * iPAddress names. `cert` is parse_cert's, or DER. True or false: a host
 * that is not ASCII (not in A-labels) matches nothing.
 */
function matches_host(cert, host) {
  if (cert && !cert.cf) cert = parse_cert(cert);
  if (!cert) return false;
  host = String(host);
  if (is_ip_literal(host)) host = host.replace(/^\[|\]$/g, '');
  try { return X509.hostname_matches(cert.cf, host); } catch (e) { return false; }
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

export {
  parse_cert, issued_by, signed_by, self_signed, valid_at, validity_error,
  check_path, matches_host, matches_altnames, is_ip_literal,
};
