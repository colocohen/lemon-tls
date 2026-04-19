/**
 * TLS handshake message building, parsing, and hello normalization.
 * Wraps wire.js functions with higher-level type-driven dispatch.
 */

import * as wire from '../wire.js';


/**
 * Normalize a parsed hello into a flat object with named extension fields.
 */
function normalize_hello(hello) {
  let out = {};

  for (let key in hello) {
    out[key] = hello[key];
  }

  if ('extensions' in hello && Array.isArray(hello.extensions)) {
    for (let i = 0; i < hello.extensions.length; i++) {
      let e = hello.extensions[i];
      let name = e.name;
      let value = e.value;

      if (name === 'SERVER_NAME') {
        out.sni = value;
      } else if (name === 'ALPN') {
        out.alpn = value;
      } else if (name === 'KEY_SHARE') {
        if (!('key_groups' in out)) out.key_groups = [];
        if (!('supported_groups' in out)) out.supported_groups = [];
        for (let i2 in value) {
          if (out.supported_groups.indexOf(value[i2].group) < 0) {
            out.supported_groups.push(value[i2].group);
          }
          out.key_groups.push({
            group: value[i2].group,
            public_key: value[i2].key_exchange
          });
        }
      } else if (name === 'SUPPORTED_VERSIONS') {
        out.supported_versions = value;
      } else if (name === 'SIGNATURE_ALGORITHMS') {
        out.signature_algorithms = value;
      } else if (name === 'SIGNATURE_ALGORITHMS_CERT') {
        out.signature_algorithms_cert = value;
      } else if (name === 'SUPPORTED_GROUPS') {
        out.supported_groups = value;
      } else if (name === 'COOKIE') {
        out.cookie = value;
      } else if (name === 'EARLY_DATA') {
        out.early_data = value;
      } else if (name === 'PSK_KEY_EXCHANGE_MODES') {
        out.psk_modes = value;
      } else if (name === 'PRE_SHARED_KEY') {
        out.pre_shared_key = value;
      } else if (name === 'RENEGOTIATION_INFO') {
        out.renegotiation_info = value;
      } else if (name === 'STATUS_REQUEST') {
        out.status_request = value;
      } else if (name === 'MAX_FRAGMENT_LENGTH') {
        out.max_fragment_length = value;
      } else if (name === 'CERTIFICATE_AUTHORITIES') {
        out.certificate_authorities = value;
      } else if (name === 'SCT') {
        out.sct = value;
      } else if (name === 'HEARTBEAT') {
        out.heartbeat = value;
      } else if (name === 'USE_SRTP') {
        out.use_srtp = value;
      } else if (name === 'SESSION_TICKET') {
        // RFC 5077: opaque ticket bytes (TLS 1.2)
        // Empty in ClientHello = client supports tickets / non-empty = resume using this ticket
        // Empty in ServerHello = server will send NewSessionTicket
        out.session_ticket = value;
        out.session_ticket_supported = true;
      } else if (name === 'EXTENDED_MASTER_SECRET') {
        // RFC 7627: presence signals EMS support
        out.extended_master_secret = true;
      } else {
        if (!('unknown' in out)) out.unknown = [];
        out.unknown.push(e);
      }
    }
  }

  if (!('supported_versions' in out)) {
    out.supported_versions = [];
  }

  if (out.supported_versions.indexOf(out.version) < 0) {
    out.supported_versions.push(out.version);
  }

  return out;
}


/**
 * Build a TLS handshake message from a high-level params object.
 * Returns a Uint8Array with handshake header + body.
 */
function build_tls_message(params) {
  let type = 0;
  let body = null;

  if (params.type == 'server_hello') {
    type = wire.TLS_MESSAGE_TYPE.SERVER_HELLO;
    params.kind = 'server';
    body = wire.build_hello(params);
  } else if (params.type == 'client_hello') {
    type = wire.TLS_MESSAGE_TYPE.CLIENT_HELLO;
    params.kind = 'client';
    body = wire.build_hello(params);
  } else if (params.type == 'server_key_exchange') {
    type = wire.TLS_MESSAGE_TYPE.SERVER_KEY_EXCHANGE;
    body = wire.build_server_key_exchange_ecdhe(params);
  } else if (params.type == 'client_key_exchange') {
    type = wire.TLS_MESSAGE_TYPE.CLIENT_KEY_EXCHANGE;
    body = wire.build_client_key_exchange_ecdhe(params.public_key);
  } else if (params.type == 'server_hello_done') {
    type = wire.TLS_MESSAGE_TYPE.SERVER_HELLO_DONE;
    body = new Uint8Array(0);
  } else if (params.type == 'encrypted_extensions') {
    type = wire.TLS_MESSAGE_TYPE.ENCRYPTED_EXTENSIONS;
    body = wire.build_extensions(params.extensions);
  } else if (params.type == 'certificate') {
    type = wire.TLS_MESSAGE_TYPE.CERTIFICATE;
    body = wire.build_certificate(params);
  } else if (params.type == 'certificate_verify') {
    type = wire.TLS_MESSAGE_TYPE.CERTIFICATE_VERIFY;
    body = wire.build_certificate_verify(params.scheme, params.signature);
  } else if (params.type == 'finished') {
    type = wire.TLS_MESSAGE_TYPE.FINISHED;
    body = params.data;
  } else if (params.type == 'key_update') {
    type = wire.TLS_MESSAGE_TYPE.KEY_UPDATE;
    body = wire.build_key_update(params.request_update);
  } else if (params.type == 'certificate_request') {
    type = wire.TLS_MESSAGE_TYPE.CERTIFICATE_REQUEST;
    body = wire.build_certificate_request(params);
  } else if (params.type == 'hello_retry_request') {
    type = wire.TLS_MESSAGE_TYPE.SERVER_HELLO; // HRR uses ServerHello type with magic random
    body = wire.build_hello_retry_request(params);
  } else if (params.type == 'new_session_ticket_tls12') {
    type = wire.TLS_MESSAGE_TYPE.NEW_SESSION_TICKET;
    body = wire.build_new_session_ticket_tls12(params);
  } else if (params.type == 'new_session_ticket') {
    type = wire.TLS_MESSAGE_TYPE.NEW_SESSION_TICKET;
    body = wire.build_new_session_ticket(params);
  }

  return wire.build_message(type, body);
}


/**
 * Parse a raw TLS handshake message into a typed object.
 * @param {Uint8Array} data            — handshake message bytes
 * @param {number}     [negotiatedVersion] — optional; 0x0303 for TLS 1.2, 0x0304 for TLS 1.3.
 *                                           Needed to disambiguate NewSessionTicket wire format.
 */
function parse_tls_message(data, negotiatedVersion) {
  let out = {};
  let message = wire.parse_message(data);

  if (message.type == wire.TLS_MESSAGE_TYPE.CLIENT_HELLO || message.type == wire.TLS_MESSAGE_TYPE.SERVER_HELLO) {
    let kind = (message.type == wire.TLS_MESSAGE_TYPE.CLIENT_HELLO) ? 'client' : 'server';
    let hello = wire.parse_hello({ kind: kind, body: message.body });
    out = normalize_hello(hello);

  } else if (message.type == wire.TLS_MESSAGE_TYPE.SERVER_KEY_EXCHANGE) {
    out = wire.parse_server_key_exchange(message.body);
    out.type = 'server_key_exchange';

  } else if (message.type == wire.TLS_MESSAGE_TYPE.CLIENT_KEY_EXCHANGE) {
    out.body = message.body;
    out.public_key = message.body.slice(1);
    out.type = 'client_key_exchange';

  } else if (message.type == wire.TLS_MESSAGE_TYPE.SERVER_HELLO_DONE) {
    out.body = message.body;
    out.type = 'server_hello_done';

  } else if (message.type == wire.TLS_MESSAGE_TYPE.ENCRYPTED_EXTENSIONS) {
    out = normalize_hello({
      extensions: wire.parse_extensions(message.body)
    });
    out.type = 'encrypted_extensions';

  } else if (message.type == wire.TLS_MESSAGE_TYPE.CERTIFICATE) {
    out = wire.parse_certificate(message.body);
    out.type = 'certificate';

  } else if (message.type == wire.TLS_MESSAGE_TYPE.CERTIFICATE_VERIFY) {
    out.type = 'certificate_verify';
    out.body = message.body;

  } else if (message.type == wire.TLS_MESSAGE_TYPE.FINISHED) {
    out.type = 'finished';
    out.body = message.body;

  } else if (message.type == wire.TLS_MESSAGE_TYPE.NEW_SESSION_TICKET) {
    // TLS 1.2 and 1.3 have different wire formats for this message.
    // TLS 1.3: ticket_lifetime | ticket_age_add | ticket_nonce | ticket | extensions
    // TLS 1.2: ticket_lifetime_hint | ticket                     (RFC 5077)
    if (negotiatedVersion === 0x0303) {
      out = wire.parse_new_session_ticket_tls12(message.body);
    } else {
      out = wire.parse_new_session_ticket(message.body);
    }
    out.type = 'new_session_ticket';

  } else if (message.type == wire.TLS_MESSAGE_TYPE.KEY_UPDATE) {
    out = wire.parse_key_update(message.body);
    out.type = 'key_update';

  } else if (message.type == wire.TLS_MESSAGE_TYPE.CERTIFICATE_REQUEST) {
    out = wire.parse_certificate_request(message.body);
    out.type = 'certificate_request';
  }

  return out;
}


export {
  normalize_hello,
  build_tls_message,
  parse_tls_message
};
