import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as PEM from 'cryptographic-formats/pem';
import * as PKCS8 from 'cryptographic-formats/pkcs8';
import { parse_cert } from './session/x509.js';

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
function makeX509FromDerOrPem(buf) {
  return new crypto.X509Certificate(Buffer.from(buf));
}

// A certificate's public key as node:crypto exports it (SPKI DER): the form
// a private key's public half is compared in. Through a KeyObject, so two
// encodings of one key — named or explicit curve parameters, a compressed
// point — compare equal, as they did.
function certPublicKeyDer(der) {
  let cert = parse_cert(der);
  if (!cert) {
    let e = new Error('createSecureContext: the certificate does not parse');
    e.code = 'ERR_INVALID_CERTIFICATE';
    throw e;
  }
  let key = cert.publicKey();
  return key ? key.export({ type: 'spki', format: 'der' }) : null;
}

// The DER form of a private key, by what cryptographic-formats reads it as:
// PKCS#8 (plain or encrypted), PKCS#1 (RSA) or SEC 1 (EC) — node:crypto is
// told which, rather than tried with each in turn.
function derKeyType(der) {
  let readers = [['pkcs8', PKCS8.from_der], ['pkcs8', PKCS8.encrypted_from_der],
                 ['pkcs1', PKCS8.pkcs1_from_der], ['sec1', PKCS8.sec1_from_der]];
  for (let i = 0; i < readers.length; i++) {
    try { readers[i][1](der); return readers[i][0]; } catch (e) { /* the next */ }
  }
  return null;
}
// The same, from a PEM label (RFC 7468 §10, §11; OpenSSL's traditional ones)
const PEM_KEY_TYPES = {
  'PRIVATE KEY': 'pkcs8', 'ENCRYPTED PRIVATE KEY': 'pkcs8',
  'RSA PRIVATE KEY': 'pkcs1', 'EC PRIVATE KEY': 'sec1',
};

function makePrivateKeyFromDerOrPem(buf, passphrase) {
  // node:crypto rejects an explicit `passphrase: null` with ERR_INVALID_ARG_VALUE
  // — for an unencrypted key the property must be ABSENT, not present-and-null.
  // Callers that forward an optional option straight through would otherwise
  // break every unencrypted key, which is the overwhelmingly common case.
  let pass = (passphrase === null || passphrase === undefined) ? undefined : passphrase;
  let withPass = function (o) { if (pass !== undefined) o.passphrase = pass; return o; };

  let der, type;
  if (isPEM(buf)) {
    // The key's block (a file from `openssl ecparam -genkey` starts with an
    // EC PARAMETERS block), read by cryptographic-formats.
    let blocks = splitPEMBlocks(buf.toString('utf8'));
    let block = null;
    for (let i = 0; i < blocks.length && !block; i++) if (PEM_KEY_TYPES[blocks[i].type]) block = blocks[i];
    if (!block) throw new Error('createSecureContext: no private key in the PEM (' +
                                blocks.map(function (b) { return b.type; }).join(', ') + ')');
    // RFC 1421's encrypted form (Proc-Type / DEK-Info headers): its
    // decryption is node:crypto's, and node:crypto reads it only as PEM.
    if (block.block.encrypted) return crypto.createPrivateKey(withPass({ key: buf, format: 'pem' }));
    der = Buffer.from(block.der);
    type = PEM_KEY_TYPES[block.type];
  } else {
    der = Buffer.from(buf);
    type = derKeyType(der);
    if (type === null) throw new Error('createSecureContext: the key is not PKCS#8, PKCS#1 or SEC 1 DER');
  }
  return crypto.createPrivateKey(withPass({ key: der, format: 'der', type: type }));
}

function exportKeyPkcs8Der(keyObj) {
  return new Uint8Array(keyObj.export({ format: 'der', type: 'pkcs8' }));
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
      let pub = crypto.createPublicKey(makePrivateKeyFromDerOrPem(readMaybeFile(keyIn), pass)).export({ type: 'spki', format: 'der' });
      let cert = null;
      for (let j = 0; j < certs.length && cert === null; j++) {
        let raw = readMaybeFile(certs[j]);
        let first = isPEM(raw) ? splitPEMBlocks(raw.toString('utf8')).filter(isCertificateBlock)[0] : { der: new Uint8Array(raw) };
        if (!first) continue;
        let leafPub = certPublicKeyDer(first.der);
        if (leafPub && Buffer.compare(Buffer.from(leafPub), Buffer.from(pub)) === 0) cert = certs[j];
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
          certObjs.push(makeX509FromDerOrPem(blocks[i].der));
        }
      }
    } else {
      const der = new Uint8Array(cRaw);
      certBlocksDer.push(der);
      certObjs.push(makeX509FromDerOrPem(der));
    }
  }

  // --- מפתח פרטי ---
  let keyObj = null;
  let privateKey = null;
  if (options.key != null) {
    let kRaw = readMaybeFile(options.key);
    keyObj = makePrivateKeyFromDerOrPem(kRaw, options.passphrase);
    privateKey = exportKeyPkcs8Der(keyObj);
  }

  // אימות בסיסי (כאשר לא משתמשים ב־PFX)
  if (!options.pfx) {
    if (certBlocksDer.length === 0) throw new Error('createSecureContext: missing cert.');
    if (!privateKey) throw new Error('createSecureContext: missing private key.');
  }

  // The key must be the certificate's — node:tls throws on this too
  // (KEY_VALUES_MISMATCH). Unchecked, a renewal that paired the new key with
  // the old certificate went in without a word, and every handshake after it
  // failed at the client's signature check.
  if (keyObj && certBlocksDer.length > 0) {
    let fromKey = crypto.createPublicKey(keyObj).export({ type: 'spki', format: 'der' });
    let fromCert = certPublicKeyDer(certBlocksDer[0]);
    if (!fromCert || Buffer.compare(Buffer.from(fromKey), Buffer.from(fromCert)) !== 0) {
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
    keyObj: keyObj,                      // KeyObject
    leafPublicKeyType: leafPublicKeyType,

    // פרמטרים פרוטוקוליים (אחסון; אתה מפרש בזמן ה-handshake):
    minVersion: String(options.minVersion || 'TLSv1.2'),
    maxVersion: String(options.maxVersion || 'TLSv1.3'),
    ciphers: options.ciphers || null,
    sigalgs: options.sigalgs || null,
    ecdhCurve: options.ecdhCurve || null,
    honorCipherOrder: !!options.honorCipherOrder,

    // תמיכה ב־PFX אם תרצה לטפל בזה בשכבה אחרת:
    pfx: options.pfx ? new Uint8Array(readMaybeFile(options.pfx)) : null,
    passphrase: options.passphrase ? String(options.passphrase) : null
  };
}

export default createSecureContext;
