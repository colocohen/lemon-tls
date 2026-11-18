import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as PEM from 'cryptographic-formats/pem';
import { parse_cert } from './session/x509.js';
import * as keys from './session/keys.js';

function looksLikePath(x) {
  return typeof x === 'string' && (x.indexOf('\n') === -1) && (x.length < 4096) &&
         (x.indexOf('-----BEGIN') === -1);
}

function readMaybeFile(x) {
  if (x == null) return null;
  if (looksLikePath(x)) return fs.readFileSync(path.resolve(String(x)));
  if (Buffer.isBuffer(x)) return x;
  if (x instanceof Uint8Array) return Buffer.from(x);
  if (typeof x === 'string') return Buffer.from(x, 'utf8');
  throw new Error('Unsupported input type (expected path/string/Buffer/Uint8Array).');
}

function isPEM(buf) {
  if (!buf) return false;
  let s = buf.toString('utf8');
  return s.indexOf('-----BEGIN ') !== -1 && s.indexOf('-----END ') !== -1;
}

// The PEM blocks of a text (cryptographic-formats, RFC 7468): [{ type, der, block }].
// Text between blocks — the comments of a CA bundle — is passed over. A
// block that does not decode fails the whole text: nothing is taken from a
// file that is not what it says (see normalizeCA).
function splitPEMBlocks(pemText) {
  return PEM.decode(pemText).map(function (b) { return { type: b.label, der: b.der, block: b }; });
}
// A certificate block's label: 'CERTIFICATE', and the 'X509 CERTIFICATE' /
// 'TRUSTED CERTIFICATE' spellings (OpenSSL's aux form, whose trailing trust
// data the certificate reader then refuses).
function isCertificateBlock(b) { return b.type.indexOf('CERTIFICATE') !== -1; }

function ensureArray(x) { return x == null ? [] : (Array.isArray(x) ? x : [x]); }

// The `ca` certificates, as DER. A PEM block that does not decode is
// skipped, as node:tls skips it — not silently: each is in `skipped`
// ({ label, line, code, detail }, cryptographic-formats' decode_skipping), which
// createSecureContext returns as `caSkipped`.
function normalizeCA(caOption, skipped) {
  let arr = ensureArray(caOption);
  let ders = [];
  for (let i = 0; i < arr.length; i++) {
    let raw = readMaybeFile(arr[i]);
    if (!raw) continue;
    if (isPEM(raw)) {
      let read;
      try { read = PEM.decode_skipping(raw.toString('utf8')); } catch (e) { read = { blocks: [], skipped: [] }; }
      for (let j = 0; j < read.skipped.length; j++) skipped.push(read.skipped[j]);
      for (let j = 0; j < read.blocks.length; j++) {
        if (read.blocks[j].label.indexOf('CERTIFICATE') !== -1) ders.push(read.blocks[j].der);
      }
    } else {
      ders.push(new Uint8Array(raw));
    }
  }
  return ders;
}

// node:tls's X509Certificate, for the `certObjs` this returns (an API
// field). Everything decided here reads the certificate with cryptographic-formats.
// undefined where the runtime has none (a browser polyfill of node:crypto, a
// WASM build): certObjs is only an API convenience, and a server must still
// start without it.
function makeX509FromDerOrPem(buf) {
  if (typeof crypto.X509Certificate !== 'function') return undefined;
  try { return new crypto.X509Certificate(Buffer.from(buf)); } catch (e) { return undefined; }
}

// A certificate's public key (session/keys.js), for pairing a private key
// with it: keys.same_public_key compares the key, not its encoding, so a
// compressed point and an uncompressed one are one key.
function certPublicKey(der) {
  let cert = parse_cert(der);
  if (!cert) {
    let e = new Error('createSecureContext: the certificate does not parse');
    e.code = 'ERR_INVALID_CERTIFICATE';
    throw e;
  }
  return cert.publicKey();
}

// A private key from PEM or DER of any form node:tls takes (PKCS#8, plain or
// encrypted; PKCS#1; SEC 1; RFC 1421 encrypted PEM): its PKCS#8 DER and the
// key that signs with it.
function makePrivateKeyFromDerOrPem(buf, passphrase) {
  let input = isPEM(buf) ? buf.toString('utf8') : new Uint8Array(buf);
  let der = keys.private_key_pkcs8(input, passphrase == null ? null : passphrase);
  return { der: der, key: keys.private_key(der) };
}

function u8eq(a,b){ if (a.length!==b.length) return false; for (let i=0;i<a.length;i++) if (a[i]!==b[i]) return false; return true; }
function dedupeDerArray(arr) {
  let out = [];
  for (let i=0;i<arr.length;i++) {
    let keep = true;
    for (let j=0;j<out.length;j++) { if (u8eq(arr[i], out[j])) { keep = false; break; } }
    if (keep) out.push(arr[i]);
  }
  return out;
}

/**
 * createSecureContext(options)
 * key/cert/ca יכולים להיות: path | Buffer | Uint8Array | string(PEM)
 * מחזיר:
 *  - certificateChain: [{ cert: Uint8Array }, ...]  // leaf תחילה, אח"כ intermediates
 *  - privateKey: Uint8Array                          // PKCS#8 DER
 *  - ca: Uint8Array[]                                // Trust store (לא משולח ללקוח)
 *  - ocsp: Uint8Array|null
 *  - ticketKeys: Uint8Array|null
 *  - certObjs, keyObj (עזרי debug/לוגיקה)
 */
function createSecureContext(options) {
  if (!options) options = {};

  // `pfx`: PKCS#12 files (a Buffer, or { buf, passphrase }; or an array of
  // them), as node:tls takes them — each opened (session/keys.js pfx_open)
  // into its key and its chain, added after `key` / `cert`, so the pairs
  // below take them like any other: the first pair is the default.
  if (options.pfx != null) {
    let keysIn = Array.isArray(options.key) ? options.key.slice() : (options.key != null ? [options.key] : []);
    let certsIn = Array.isArray(options.cert) ? options.cert.slice() : (options.cert != null ? [options.cert] : []);
    let pfxs = Array.isArray(options.pfx) ? options.pfx : [options.pfx];
    for (let i = 0; i < pfxs.length; i++) {
      let p = pfxs[i];
      let plain = Buffer.isBuffer(p) || p instanceof Uint8Array || typeof p === 'string';
      let opened = keys.pfx_open(readMaybeFile(plain ? p : p.buf), !plain && p.passphrase != null ? p.passphrase : options.passphrase);
      keysIn.push(Buffer.from(opened.key));
      certsIn.push(opened.certs.map(function (d) { return PEM.encode(d, 'CERTIFICATE'); }).join(''));
    }
    options = Object.assign({}, options, { pfx: null,
      key: keysIn.length === 1 ? keysIn[0] : keysIn, cert: certsIn.length === 1 ? certsIn[0] : certsIn });
  }

  // Several key/certificate pairs — node:tls's arrays: `key` an array of
  // keys (or { pem, passphrase }), `cert` an array of chains, one per key —
  // for a server that holds certificates of more than one kind: an ML-DSA one
  // for clients that ask for post-quantum authentication, an ECDSA or RSA one
  // for everyone else. Each key is paired with the chain whose leaf carries
  // its public key, in whatever order they were given; the first key's pair
  // is the default, the others `alternates`. Which one a handshake presents
  // is the client's signature_algorithms' to decide (tls_session).
  if (Array.isArray(options.key) && options.key.length > 1) {
    let certs = Array.isArray(options.cert) ? options.cert : [options.cert];
    let contexts = options.key.map(function (k, i) {
      let keyIn = (k && typeof k === 'object' && !Buffer.isBuffer(k) && !(k instanceof Uint8Array) && k.pem) ? k.pem : k;
      let pass = (k && typeof k === 'object' && k.passphrase != null) ? k.passphrase : options.passphrase;
      let pub = makePrivateKeyFromDerOrPem(readMaybeFile(keyIn), pass).key.public;
      let cert = null;
      for (let j = 0; j < certs.length && cert === null; j++) {
        let raw = readMaybeFile(certs[j]);
        let first = isPEM(raw) ? splitPEMBlocks(raw.toString('utf8')).filter(isCertificateBlock)[0] : { der: new Uint8Array(raw) };
        if (!first) continue;
        if (keys.same_public_key(pub, certPublicKey(first.der))) cert = certs[j];
      }
      if (cert === null) throw new Error('createSecureContext: no certificate in `cert` for key ' + i);
      return createSecureContext(Object.assign({}, options, { key: keyIn, passphrase: pass, cert: cert }));
    });
    let primary = contexts[0];
    primary.alternates = contexts.slice(1).map(function (c) {
      return { certificateChain: c.certificateChain, privateKey: c.privateKey, keyObj: c.keyObj, certObjs: c.certObjs };
    });
    return primary;
  }
  if (Array.isArray(options.key)) options = Object.assign({}, options, { key: options.key[0] && options.key[0].pem ? options.key[0].pem : options.key[0] });
  if (Array.isArray(options.cert) && options.cert.length === 1) options = Object.assign({}, options, { cert: options.cert[0] });

  // --- תעודות (כולל שרשרת בתוך cert אם קיימת) ---
  let certBlocksDer = [];
  let certObjs = [];
  if (options.cert != null) {
    let cRaw = readMaybeFile(options.cert);
    if (isPEM(cRaw)) {
      let blocks = splitPEMBlocks(cRaw.toString('utf8'));
      for (let i=0;i<blocks.length;i++) {
        if (isCertificateBlock(blocks[i])) {
          certBlocksDer.push(blocks[i].der);
          let x509 = makeX509FromDerOrPem(blocks[i].der);
          if (x509) certObjs.push(x509);
        }
      }
    } else {
      const der = new Uint8Array(cRaw);
      certBlocksDer.push(der);
      let x509 = makeX509FromDerOrPem(der);
      if (x509) certObjs.push(x509);
    }
  }

  // --- מפתח פרטי ---
  let keyObj = null;
  let privateKey = null;
  if (options.key != null) {
    let kRaw = readMaybeFile(options.key);
    let made = makePrivateKeyFromDerOrPem(kRaw, options.passphrase);
    keyObj = made.key;
    privateKey = made.der;
  }

  // אימות בסיסי (מ-PFX המפתח והתעודה כבר נלקחו למעלה)
  if (certBlocksDer.length === 0) throw new Error('createSecureContext: missing cert.');
  if (!privateKey) throw new Error('createSecureContext: missing private key.');

  // The key must be the certificate's — node:tls throws on this too
  // (KEY_VALUES_MISMATCH). Unchecked, a renewal that paired the new key with
  // the old certificate went in without a word, and every handshake after it
  // failed at the client's signature check.
  if (keyObj && certBlocksDer.length > 0) {
    if (!keys.same_public_key(keyObj.public, certPublicKey(certBlocksDer[0]))) {
      let e = new Error('createSecureContext: the private key does not match the certificate');
      e.code = 'ERR_OSSL_X509_KEY_VALUES_MISMATCH';
      throw e;
    }
  }

  // --- CA (Trust store) ---
  let caSkipped = [];
  let ca = normalizeCA(options.ca, caSkipped);

  // --- OCSP stapling (אופציונלי) ---
  let ocsp = null;
  if (options.ocsp != null) ocsp = new Uint8Array(readMaybeFile(options.ocsp));

  // --- Ticket keys (אופציונלי) ---
  let ticketKeys = null;
  if (options.ticketKeys != null) ticketKeys = new Uint8Array(readMaybeFile(options.ticketKeys));
  // אפשרות: ליצור מפתחי ברירת מחדל כאן אם תרצה

  // --- בניית שרשרת לשיגור ללקוח (leaf → intermediates) ---
  let chainDer = dedupeDerArray(certBlocksDer);
  let certificateChain = [];
  for (let c=0;c<chainDer.length;c++) {
    certificateChain.push({ cert: chainDer[c] });
  }

  // מידע עזר לזיהוי סוג המפתח הציבורי של ה-leaf
  let leafPublicKeyType = null;
  let leafCert = certBlocksDer.length > 0 ? parse_cert(certBlocksDer[0]) : null;
  if (leafCert && leafCert.publicKey()) leafPublicKeyType = leafCert.publicKey().asymmetricKeyType || null;

  return {
    // חומר לשכבת ההנדשייק/רקורד:
    certificateChain: certificateChain,  // [{ cert: DER(Uint8Array) }, ...]
    privateKey: privateKey,              // PKCS#8 DER (Uint8Array)
    ca: ca,                              // Trust store (DER)
    caSkipped: caSkipped,                // PEM blocks of `ca` that did not decode: [{ label, line, code, detail }]
    ocsp: ocsp,                          // DER (אם הוגדר)
    ticketKeys: ticketKeys,              // Uint8Array (אם הוגדר)

    // עזרי debug/לוגיקה:
    certObjs: certObjs,                  // [X509Certificate...]
    keyObj: keyObj,                      // the signing key (session/keys.js)
    leafPublicKeyType: leafPublicKeyType,

    // פרמטרים פרוטוקוליים (אחסון; אתה מפרש בזמן ה-handshake):
    minVersion: String(options.minVersion || 'TLSv1.2'),
    maxVersion: String(options.maxVersion || 'TLSv1.3'),
    ciphers: options.ciphers || null,
    sigalgs: options.sigalgs || null,
    ecdhCurve: options.ecdhCurve || null,
    honorCipherOrder: !!options.honorCipherOrder,

    passphrase: options.passphrase ? String(options.passphrase) : null
  };
}

export default createSecureContext;
