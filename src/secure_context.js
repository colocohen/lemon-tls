import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

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

function splitPEMBlocks(pemText) {
  let out = [];
  let re = /-----BEGIN ([A-Z0-9 \-]+)-----([\s\S]*?)-----END \1-----/g;
  let m;
  while ((m = re.exec(pemText)) !== null) {
    let typ = m[1].trim();
    let b64 = m[2].replace(/[\r\n\s]/g, '');
    let derBuf = Buffer.from(b64, 'base64');
    out.push({ type: typ, der: new Uint8Array(derBuf) });
  }
  return out;
}

function ensureArray(x) { return x == null ? [] : (Array.isArray(x) ? x : [x]); }

function normalizeCA(caOption) {
  let arr = ensureArray(caOption);
  let ders = [];
  for (let i = 0; i < arr.length; i++) {
    let raw = readMaybeFile(arr[i]);
    if (!raw) continue;
    if (isPEM(raw)) {
      let blocks = splitPEMBlocks(raw.toString('utf8'));
      for (let j = 0; j < blocks.length; j++) {
        if (blocks[j].type.indexOf('CERTIFICATE') !== -1) ders.push(blocks[j].der);
      }
    } else {
      ders.push(new Uint8Array(raw));
    }
  }
  return ders;
}

function makeX509FromDerOrPem(buf) {
  return new crypto.X509Certificate(Buffer.from(buf));
}

function makePrivateKeyFromDerOrPem(buf, passphrase) {
  // node:crypto rejects an explicit `passphrase: null` with ERR_INVALID_ARG_VALUE
  // — for an unencrypted key the property must be ABSENT, not present-and-null.
  // Callers that forward an optional option straight through would otherwise
  // break every unencrypted key, which is the overwhelmingly common case.
  let pass = (passphrase === null || passphrase === undefined) ? undefined : passphrase;

  if (isPEM(buf)) {
    let opts = { key: buf, format: 'pem' };
    if (pass !== undefined) opts.passphrase = pass;
    return crypto.createPrivateKey(opts);
  } else {
    let der = Buffer.from(buf), keyObj = null;
    try {
      keyObj = crypto.createPrivateKey(Object.assign({ key: der, format: 'der', type: 'pkcs8' },
                                        pass !== undefined ? { passphrase: pass } : {}));
    } catch (e1) {
      try {
        keyObj = crypto.createPrivateKey(Object.assign({ key: der, format: 'der', type: 'pkcs1' },
                                        pass !== undefined ? { passphrase: pass } : {}));
      } catch (e2) {
        keyObj = crypto.createPrivateKey(Object.assign({ key: der, format: 'der', type: 'sec1' },
                                        pass !== undefined ? { passphrase: pass } : {}));
      }
    }
    return keyObj;
  }
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
        let first = isPEM(raw) ? splitPEMBlocks(raw.toString('utf8')).filter(function (b) { return b.type.indexOf('CERTIFICATE') !== -1; })[0] : { der: new Uint8Array(raw) };
        if (!first) continue;
        let leafPub = makeX509FromDerOrPem(first.der).publicKey.export({ type: 'spki', format: 'der' });
        if (Buffer.compare(Buffer.from(leafPub), Buffer.from(pub)) === 0) cert = certs[j];
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
        if (blocks[i].type.indexOf('CERTIFICATE') !== -1) {
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

  // --- CA (Trust store) ---
  let ca = normalizeCA(options.ca);

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
  if (certObjs.length > 0 && certObjs[0].publicKey) {
    try { leafPublicKeyType = certObjs[0].publicKey.asymmetricKeyType || null; } catch (e) { leafPublicKeyType = null; }
  }

  return {
    // חומר לשכבת ההנדשייק/רקורד:
    certificateChain: certificateChain,  // [{ cert: DER(Uint8Array) }, ...]
    privateKey: privateKey,              // PKCS#8 DER (Uint8Array)
    ca: ca,                              // Trust store (DER)
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
