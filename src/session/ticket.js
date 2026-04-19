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
import { uint8Equal } from '../utils.js';

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

        // Verify key_name matches (allows rotation — caller may try multiple keys)
        if (!uint8Equal(blob_key_name, key_name)) return null;

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
 * Uint8Array/Buffer fields → { $b: base64 }
 */
function serialize_state(state) {
    let out = {};
    for (let k in state) {
        let v = state[k];
        if (v == null) {
            out[k] = null;
        } else if (v instanceof Uint8Array || Buffer.isBuffer(v)) {
            out[k] = { $b: Buffer.from(v).toString('base64') };
        } else if (typeof v === 'object' && !Array.isArray(v)) {
            out[k] = serialize_state(v);
        } else {
            out[k] = v;
        }
    }
    return out;
}

/**
 * Convert JSON-decoded form back to state object.
 * { $b: base64 } → Uint8Array
 */
function deserialize_state(obj) {
    if (obj == null) return null;
    let out = {};
    for (let k in obj) {
        let v = obj[k];
        if (v == null) {
            out[k] = null;
        } else if (typeof v === 'object' && typeof v.$b === 'string' && Object.keys(v).length === 1) {
            out[k] = new Uint8Array(Buffer.from(v.$b, 'base64'));
        } else if (typeof v === 'object' && !Array.isArray(v)) {
            out[k] = deserialize_state(v);
        } else {
            out[k] = v;
        }
    }
    return out;
}

export {
    encrypt_session_blob,
    decrypt_session_blob,
    encode_client_session,
    decode_client_session,
    split_ticket_keys,
};
