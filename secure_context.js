var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

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
  var s = buf.toString('utf8');
  return s.indexOf('-----BEGIN ') !== -1 && s.indexOf('-----END ') !== -1;
}

function splitPEMBlocks(pemText) {
  var out = [];
  var re = /-----BEGIN ([A-Z0-9 \-]+)-----([\s\S]*?)-----END \1-----/g;
  var m;
  while ((m = re.exec(pemText)) !== null) {
    var typ = m[1].trim();
    var b64 = m[2].replace(/[\r\n\s]/g, '');
    var derBuf = Buffer.from(b64, 'base64');
    out.push({ type: typ, der: new Uint8Array(derBuf) });
  }
  return out;
}

function ensureArray(x) { return x == null ? [] : (Array.isArray(x) ? x : [x]); }

function normalizeCA(caOption) {
  var arr = ensureArray(caOption);
  var ders = [];
  for (var i = 0; i < arr.length; i++) {
    var raw = readMaybeFile(arr[i]);
    if (!raw) continue;
    if (isPEM(raw)) {
      var blocks = splitPEMBlocks(raw.toString('utf8'));
      for (var j = 0; j < blocks.length; j++) {
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
  if (isPEM(buf)) {
    return crypto.createPrivateKey({ key: buf, format: 'pem', passphrase: passphrase });
  } else {
    var der = Buffer.from(buf), keyObj = null;
    try {
      keyObj = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs8', passphrase: passphrase });
    } catch (e1) {
      try {
        keyObj = crypto.createPrivateKey({ key: der, format: 'der', type: 'pkcs1', passphrase: passphrase });
      } catch (e2) {
        keyObj = crypto.createPrivateKey({ key: der, format: 'der', type: 'sec1', passphrase: passphrase });
      }
    }
    return keyObj;
  }
}

function exportKeyPkcs8Der(keyObj) {
  return new Uint8Array(keyObj.export({ format: 'der', type: 'pkcs8' }));
}

function u8eq(a,b){ if (a.length!==b.length) return false; for (var i=0;i<a.length;i++) if (a[i]!==b[i]) return false; return true; }
function dedupeDerArray(arr) {
  var out = [];
  for (var i=0;i<arr.length;i++) {
    var keep = true;
    for (var j=0;j<out.length;j++) { if (u8eq(arr[i], out[j])) { keep = false; break; } }
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

  // --- תעודות (כולל שרשרת בתוך cert אם קיימת) ---
  var certBlocksDer = [];
  var certObjs = [];
  if (options.cert != null) {
    var cRaw = readMaybeFile(options.cert);
    if (isPEM(cRaw)) {
      var blocks = splitPEMBlocks(cRaw.toString('utf8'));
      for (var i=0;i<blocks.length;i++) {
        if (blocks[i].type.indexOf('CERTIFICATE') !== -1) {
          certBlocksDer.push(blocks[i].der);
          certObjs.push(makeX509FromDerOrPem(blocks[i].der));
        }
      }
    } else {
      var der = new Uint8Array(cRaw);
      certBlocksDer.push(der);
      certObjs.push(makeX509FromDerOrPem(der));
    }
  }

  // --- מפתח פרטי ---
  var keyObj = null;
  var privateKey = null;
  if (options.key != null) {
    var kRaw = readMaybeFile(options.key);
    keyObj = makePrivateKeyFromDerOrPem(kRaw, options.passphrase);
    privateKey = exportKeyPkcs8Der(keyObj);
  }

  // אימות בסיסי (כאשר לא משתמשים ב־PFX)
  if (!options.pfx) {
    if (certBlocksDer.length === 0) throw new Error('createSecureContext: missing cert.');
    if (!privateKey) throw new Error('createSecureContext: missing private key.');
  }

  // --- CA (Trust store) ---
  var ca = normalizeCA(options.ca);

  // --- OCSP stapling (אופציונלי) ---
  var ocsp = null;
  if (options.ocsp != null) ocsp = new Uint8Array(readMaybeFile(options.ocsp));

  // --- Ticket keys (אופציונלי) ---
  var ticketKeys = null;
  if (options.ticketKeys != null) ticketKeys = new Uint8Array(readMaybeFile(options.ticketKeys));
  // אפשרות: ליצור מפתחי ברירת מחדל כאן אם תרצה

  // --- בניית שרשרת לשיגור ללקוח (leaf → intermediates) ---
  var chainDer = dedupeDerArray(certBlocksDer);
  var certificateChain = [];
  for (var c=0;c<chainDer.length;c++) {
    certificateChain.push({ cert: chainDer[c] });
  }

  // מידע עזר לזיהוי סוג המפתח הציבורי של ה-leaf
  var leafPublicKeyType = null;
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

module.exports = createSecureContext;
