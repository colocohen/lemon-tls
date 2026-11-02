// ============================================================
//  The default trust anchors: Node's CA bundle (Mozilla's)
// ============================================================
//
// One store for every session that is given no `ca` — client or server,
// TLS over TCP, QUIC (a TLSSession used directly) — and the one
// tls.setDefaultCACertificates() replaces. It lived in compat.js, and only
// connect() handed it on: a server (createServer, requestCert) and a session
// built directly had no anchors at all, and "no anchors" authorized every
// certificate.
//
// Parsing all ~144 certificates costs a few tens of milliseconds, so it is
// done once, lazily, and only if something actually needs it.
import nodeTls from 'node:tls';

let _rootPems = null;
function getRootCertificates() {
  if (_rootPems === null) {
    try { _rootPems = nodeTls.rootCertificates.slice(); }
    catch (e) { _rootPems = []; }   // a build without the bundle
  }
  return _rootPems;
}

/** tls.setDefaultCACertificates(certs): the store, for every later session. */
function setRootCertificates(certs) {
  if (!Array.isArray(certs)) throw new TypeError('certs must be an array');
  _rootPems = certs.slice();
}

export { getRootCertificates, setRootCertificates };
