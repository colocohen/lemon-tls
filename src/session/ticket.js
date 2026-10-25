/**
 * Session ticket / session blob encoding & decoding.
 *
 * Two distinct blob types:
 *
 * 1. SERVER blob (encrypted) — issued by server to client (TLS 1.3 NewSessionTicket,
 *    TLS 1.2 NewSessionTicket), or to user's store (TLS 1.2 Session IDs via 'newSession' event).
 *    Client/store returns it back; server decrypts with its ticketKeys.
 *
 *    Format: key_name(16) | IV(12) | Ciphertext(AES-256-GCM) | Tag(16)
 *    ticketKeys layout: [0:16]=key_name, [16:48]=AES-256-GCM key
 *
 * 2. CLIENT blob (plaintext) — returned by TLSSocket to the user via 'session' event;
 *    user passes it back in tls.connect({ session }). JSON-encoded, not encrypted —
 *    user is responsible for secure storage (same convention as Node.js).
 */

import * as crypto from 'node:crypto';
import { timingSafeEqualU8 } from '../utils.js';

/* =========================================================================
 *                      SERVER-SIDE ENCRYPTED BLOB
 * ========================================================================= */

const KEY_NAME_LEN = 16;
const IV_LEN       = 12;
const TAG_LEN      = 16;

/**
 * Split ticketKeys (48 bytes) into key_name (16) + aes key (32).
 * Throws if ticketKeys is malformed.
 */
function split_ticket_keys(ticketKeys) {
    if (!ticketKeys) throw new Error('ticketKeys is required');
    let buf = Buffer.isBuffer(ticketKeys) ? ticketKeys : Buffer.from(ticketKeys);
    if (buf.length !== 48) throw new Error('ticketKeys must be exactly 48 bytes');
    return {
        key_name: buf.slice(0, 16),
        aes_key:  buf.slice(16, 48),
    };
}

/**
 * Encrypt a server-side session state into an opaque blob.
 *
 * @param {Object} state       — session state (version, cipher, master_secret, ...)
 * @param {Buffer} ticketKeys  — 48 bytes (key_name + aes_key)
 * @returns {Uint8Array}       — key_name(16) | IV(12) | CT | Tag(16)
 */
function encrypt_session_blob(state, ticketKeys) {
    let { key_name, aes_key } = split_ticket_keys(ticketKeys);

    // Serialize state → JSON with Uint8Array fields base64-encoded
    let serialized = Buffer.from(JSON.stringify(serialize_state(state)));

    let iv = crypto.randomBytes(IV_LEN);
    let cipher = crypto.createCipheriv('aes-256-gcm', aes_key, iv);
    let ct = cipher.update(serialized);
    cipher.final();
    let tag = cipher.getAuthTag();

    let out = Buffer.concat([key_name, iv, ct, tag]);
    return new Uint8Array(out);
}

/**
 * Decrypt a server-side session blob.
 *
 * @param {Uint8Array} blob        — encrypted blob
 * @param {Buffer}     ticketKeys  — 48 bytes. Must match the key_name embedded in blob.
 * @returns {Object|null}          — state, or null if decryption failed (wrong key_name, tampered data, etc).
 */
function decrypt_session_blob(blob, ticketKeys) {
    try {
        if (!blob || blob.length < KEY_NAME_LEN + IV_LEN + TAG_LEN) return null;
        let buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);

        let blob_key_name = buf.slice(0, KEY_NAME_LEN);
        let iv            = buf.slice(KEY_NAME_LEN, KEY_NAME_LEN + IV_LEN);
        let tag           = buf.slice(buf.length - TAG_LEN);
        let ct            = buf.slice(KEY_NAME_LEN + IV_LEN, buf.length - TAG_LEN);

        let { key_name, aes_key } = split_ticket_keys(ticketKeys);

        // Verify key_name matches (allows rotation — caller may try multiple keys).
        // Constant-time: utils.js names "ticket key_name" explicitly in the list
        // of comparisons that must not short-circuit, but this call site was
        // still using uint8Equal, which returns on the first differing byte.
        if (!timingSafeEqualU8(blob_key_name, key_name)) return null;

        let decipher = crypto.createDecipheriv('aes-256-gcm', aes_key, iv);
        decipher.setAuthTag(tag);
        let pt = decipher.update(ct);
        decipher.final(); // throws on tag mismatch

        let state = deserialize_state(JSON.parse(pt.toString('utf8')));
        return state;
    } catch (e) {
        return null;
    }
}

/* =========================================================================
 *                      CLIENT-SIDE PLAINTEXT BLOB
 * ========================================================================= */

/**
 * Encode a client-side session blob. JSON-serialized, NOT encrypted.
 * User is responsible for secure storage (this contains the master_secret).
 *
 * @param {Object} state
 * @returns {Uint8Array} — utf-8 encoded JSON
 */
function encode_client_session(state) {
    let serialized = JSON.stringify(serialize_state(state));
    return new Uint8Array(Buffer.from(serialized, 'utf8'));
}

/**
 * Decode a client-side session blob.
 *
 * @param {Uint8Array|Buffer} blob
 * @returns {Object|null}
 */
/**
 * What an application may know of a client session blob ('session' event)
 * without its secrets: { version, servername, alpn, created, expiresAt (ms),
 * earlyData (whether its ticket allows 0-RTT) } — or null for a blob that is
 * not one. For a cache to drop what has expired.
 */
function client_session_info(blob) {
    let s = decode_client_session(blob);
    if (!s) return null;
    return {
        version: s.v === 13 ? 'TLSv1.3' : s.v === 12 ? 'TLSv1.2' : null,
        servername: s.sni != null ? s.sni : null,
        alpn: s.alpn != null ? s.alpn : null,
        created: typeof s.created === 'number' ? s.created : null,
        expiresAt: typeof s.created === 'number' && typeof s.lifetime === 'number' ? s.created + s.lifetime * 1000 : null,
        earlyData: !!(s.max_early_data > 0),
    };
}

function decode_client_session(blob) {
    try {
        if (!blob || blob.length === 0) return null;
        let buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
        return deserialize_state(JSON.parse(buf.toString('utf8')));
    } catch (e) {
        return null;
    }
}

/* =========================================================================
 *                      SERIALIZATION HELPERS
 * ========================================================================= */

/**
 * Convert state object to JSON-safe form.
 * Uint8Array/Buffer values → { $b: base64 }, inside objects and arrays alike
 * (a client blob holds the server's certificate chain: an array of DER).
 */
function serialize_value(v) {
    if (v == null) return null;
    if (v instanceof Uint8Array || Buffer.isBuffer(v)) return { $b: Buffer.from(v).toString('base64') };
    if (Array.isArray(v)) return v.map(serialize_value);
    if (typeof v === 'object') return serialize_state(v);
    return v;
}
function serialize_state(state) {
    let out = {};
    for (let k in state) out[k] = serialize_value(state[k]);
    return out;
}

/**
 * Convert JSON-decoded form back to state object.
 * { $b: base64 } → Uint8Array
 */
function deserialize_value(v) {
    if (v == null) return null;
    if (Array.isArray(v)) return v.map(deserialize_value);
    if (typeof v === 'object' && typeof v.$b === 'string' && Object.keys(v).length === 1) return new Uint8Array(Buffer.from(v.$b, 'base64'));
    if (typeof v === 'object') return deserialize_state(v);
    return v;
}
function deserialize_state(obj) {
    if (obj == null) return null;
    let out = {};
    for (let k in obj) out[k] = deserialize_value(obj[k]);
    return out;
}

export {
    encrypt_session_blob,
    decrypt_session_blob,
    encode_client_session,
    client_session_info,
    decode_client_session,
    split_ticket_keys,
};
