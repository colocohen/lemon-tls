import crypto from 'node:crypto';

function concatUint8Arrays(arrays) {
    let totalLength = 0;
    for (let i = 0; i < arrays.length; i++) {
        totalLength += arrays[i].length;
    }

    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (let i = 0; i < arrays.length; i++) {
        result.set(arrays[i], offset);
        offset += arrays[i].length;
    }

    return result;
}

function arraybufferEqual(buf1, buf2) {
  //if (buf1 === buf2) {
  //return true;
  //}

  if (buf1.byteLength !== buf2.byteLength) {
  return false;
  }

  const view1 = new DataView(buf1);
  const view2 = new DataView(buf2);

  for (let i = 0; i < buf1.byteLength; i++) {
    if (view1.getUint8(i) !== view2.getUint8(i)) {
      return false;
    }
  }

  return true;
}

function arraysEqual(a, b) {
  //if (a === b) return true;
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;

  // If you don't care about the order of the elements inside
  // the array, you should sort both arrays here.
  // Please note that calling sort on an array will modify that array.
  // you might want to clone your array first.

  for (let i = 0; i < a.length; ++i) {
    if(typeof a[i] !== 'undefined' && typeof b[i] !== 'undefined' && a[i]!==null && b[i]!==null && typeof a[i].byteLength == 'number' && typeof b[i].byteLength == 'number'){
      if(arraybufferEqual(a[i],b[i])==false){
        return false;
      }
    }else{
      // Either element may be null/undefined here: the branch above requires
      // BOTH to be non-null typed arrays, so a null slips through to this
      // side and the `.constructor` reads below threw a TypeError. Settle
      // those cases by identity before anything is dereferenced.
      if(a[i]==null || b[i]==null){
        if(a[i]!==b[i]) return false;
      }else if(typeof a[i]=='string' && typeof b[i]=='string'){
        if (a[i] !== b[i]){
          return false;
        }
      }else if(a[i].constructor==RegExp && typeof b[i]=='string'){
        if(a[i].test(b[i])==false){
          return false;
        }
      }else if(typeof a[i]=='string' && b[i].constructor==RegExp){
        if(b[i].test(a[i])==false){
          return false;
        }
      //}else if(a[i] instanceof Object && b[i] instanceof Object && Object.keys(a[i]).length>0 && Object.keys(b[i]).length>0){
        //if(_this.objectEquals(a[i],b[i])==false){
        //	return false;
        //}
      }else{
        if (a[i] !== b[i]){
          return false;
        }
      }
      
    }
  }
  return true;
};



function uint8Equal(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}


/**
 * Constant-time equality for two byte arrays.
 *
 * Unlike uint8Equal (which short-circuits on the first differing byte and
 * therefore leaks — via timing — how many leading bytes matched), this always
 * compares the full length. Use it wherever a mismatch would otherwise be
 * exploitable as an oracle: Finished verify_data, PSK binders, ticket key_name,
 * and any MAC/tag comparison.
 *
 * Returns false immediately (and safely) on length mismatch — that's public
 * information, not a secret, so short-circuiting there is fine.
 *
 * Note: crypto.timingSafeEqual requires two equal-length Buffers. We wrap the
 * inputs as Buffer views over the same memory (no copy) via byteOffset/length.
 */
function timingSafeEqualU8(a, b) {
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;
  if (a.length === 0) return true;
  let ba = Buffer.isBuffer(a) ? a : Buffer.from(a.buffer, a.byteOffset, a.length);
  let bb = Buffer.isBuffer(b) ? b : Buffer.from(b.buffer, b.byteOffset, b.length);
  return crypto.timingSafeEqual(ba, bb);
}


/**
 * Parse an X509Certificate DN string into the object shape Node's certificate
 * objects use.
 *
 * crypto.X509Certificate gives `subject`/`issuer` as newline-separated
 * "KEY=value" text, but Node documents them on a certificate object as objects
 * keyed by RDN type: { C, ST, L, O, OU, CN }. Passing the raw string through
 * meant tls.checkServerIdentity() — which reads cert.subject.CN — could never
 * find a Common Name, so any certificate without a SAN was rejected outright
 * even when its CN matched. The exported identity check did not work against
 * this library's own getPeerCertificate() output, which is exactly the pairing
 * Node documents.
 *
 * A type may legitimately repeat (OU is the common case); Node represents a
 * repeat as an array and a single occurrence as a plain string.
 *
 * Idempotent: an already-parsed object is returned unchanged, so callers can
 * pass either form.
 */
function parseDN(dn) {
  if (dn == null) return {};
  if (typeof dn === 'object') return dn;
  let out = {};
  let lines = String(dn).split('\n');
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    if (!line) continue;
    let eq = line.indexOf('=');
    if (eq < 1) continue;
    let k = line.slice(0, eq).trim();
    let v = line.slice(eq + 1);
    if (!Object.prototype.hasOwnProperty.call(out, k)) out[k] = v;
    else if (Array.isArray(out[k])) out[k].push(v);
    else out[k] = [out[k], v];
  }
  return out;
}


export {
  concatUint8Arrays,
  arraybufferEqual,
  arraysEqual,
  uint8Equal,
  timingSafeEqualU8,
  parseDN
};