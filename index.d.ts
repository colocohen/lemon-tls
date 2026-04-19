/// <reference types="node" />

import { Duplex } from 'node:stream';
import { EventEmitter } from 'node:events';
import type { Server as NetServer } from 'node:net';
import type { X509Certificate } from 'node:crypto';

// ======================== Types ========================

export interface SecureContext {
  certificateChain: Array<{ cert: Buffer }>;
  privateKey: any;
}

export interface CipherInfo {
  name: string;
  standardName: string;
  version: string;
}

export interface PeerCertificate {
  subject: any;
  issuer: any;
  subjectaltname?: string;
  valid_from: string;
  valid_to: string;
  fingerprint: string;
  fingerprint256: string;
  serialNumber: string;
  raw: Buffer;
}

export interface EphemeralKeyInfo {
  type: 'X25519' | 'ECDH' | 'DH';
  name?: string;
  size: number;
}

export interface JA3Result {
  hash: string;
  raw: string;
}

export interface NegotiationResult {
  version: number | null;
  versionName: string | null;
  cipher: number | null;
  cipherName: string | null;
  group: number | null;
  groupName: string | null;
  signatureAlgorithm: number | null;
  alpn: string | null;
  sni: string | null;
  resumed: boolean;
  helloRetried: boolean;
  handshakeDuration: number | null;
}

/**
 * Payload of the 'session' event on TLSSession (raw internal form).
 * The TLSSocket-level 'session' event emits an opaque Buffer (Node-compatible).
 */
export interface SessionTicketData {
  ticket: Buffer;
  ticket_nonce: Buffer;
  psk: Buffer;
  cipher: number;
  lifetime: number;
  age_add: number;
  maxEarlyDataSize: number;
}

export interface CertificateCallbackInfo {
  servername: string | null;
  version: number | null;
  ciphers: number[];
  sigalgs: number[];
  groups: number[];
  alpns: string[];
}

// ======================== TLSSocket Options ========================

export interface TLSSocketOptions {
  isServer?: boolean;
  servername?: string;
  SNICallback?: (servername: string, cb: (err: Error | null, ctx: SecureContext | null) => void) => void;
  minVersion?: 'TLSv1.2' | 'TLSv1.3';
  maxVersion?: 'TLSv1.2' | 'TLSv1.3';
  ALPNProtocols?: string[];
  rejectUnauthorized?: boolean;
  ca?: Buffer | string;
  ticketKeys?: Buffer;
  /**
   * Opaque serialized session from a previous 'session' event.
   * Pass this back to resume a TLS 1.2/1.3 session.
   */
  session?: Buffer | Uint8Array;
  requestCert?: boolean;
  cert?: Buffer | string;
  key?: Buffer | string;

  // LemonTLS-only options
  noTickets?: boolean;
  sessionTickets?: boolean;
  ticketLifetime?: number;
  signatureAlgorithms?: number[];
  groups?: number[];
  prioritizeChaCha?: boolean;
  maxRecordSize?: number;
  allowedCipherSuites?: number[];
  pins?: string[];
  handshakeTimeout?: number;
  maxHandshakeSize?: number;
  certificateCallback?: (info: CertificateCallbackInfo, cb: (err: Error | null, ctx: SecureContext | null) => void) => void;
  customExtensions?: Array<{ type: number; data: Uint8Array }>;
}

// ======================== TLSSocket ========================

export class TLSSocket extends Duplex {
  constructor(transport: Duplex | null, options: TLSSocketOptions);

  // ------- Node.js tls.TLSSocket compatible API -------
  getProtocol(): string | null;
  getCipher(): CipherInfo | null;
  getPeerCertificate(): PeerCertificate | null;
  /** Returns our LOCAL cert (what we presented). Empty object if none. */
  getCertificate(): PeerCertificate | {};
  /** Returns the peer cert as a native crypto.X509Certificate object (Node 15.9+). */
  getPeerX509Certificate(): X509Certificate | undefined;
  /** Returns our LOCAL cert as a native crypto.X509Certificate object. */
  getX509Certificate(): X509Certificate | undefined;
  isSessionReused(): boolean;
  getFinished(): Buffer | null;
  getPeerFinished(): Buffer | null;
  exportKeyingMaterial(length: number, label: string, context: Buffer): Buffer;
  getEphemeralKeyInfo(): EphemeralKeyInfo;
  disableRenegotiation(): void;
  setServername(name: string): void;
  /** Returns the opaque serialized session Buffer, or undefined. */
  getSession(): Buffer | undefined;
  /** Returns the TLS 1.2 session ticket as a Buffer, or undefined (incl. for TLS 1.3). */
  getTLSTicket(): Buffer | undefined;
  /** Returns signature algorithm names shared between client and server (server side). */
  getSharedSigalgs(): string[];
  /** Caps outgoing plaintext fragment size. Must be in [512, 16384]. */
  setMaxSendFragment(size: number): boolean;
  /** Node-compat no-op (we don't wrap OpenSSL). Use 'keylog' / 'handshakeMessage' for insight. */
  enableTrace(): void;
  setSocket(transport: Duplex): void;

  readonly authorized: boolean;
  readonly authorizationError: string | null;
  /** The negotiated ALPN protocol string (e.g. 'h2'), or false. */
  readonly alpnProtocol: string | false;
  /** Always true for TLSSocket. */
  readonly encrypted: boolean;
  /** SNI value — on server, the name the client sent; on client, the name we sent. */
  readonly servername: string | false;

  // net.Socket compat (delegated to underlying transport)
  readonly remoteAddress: string | undefined;
  readonly remotePort: number | undefined;
  readonly remoteFamily: string | undefined;
  readonly localAddress: string | undefined;
  readonly localPort: number | undefined;
  readonly localFamily: string | undefined;
  readonly bytesRead: number;
  readonly bytesWritten: number;
  setNoDelay(noDelay?: boolean): this;
  setKeepAlive(enable?: boolean, initialDelay?: number): this;
  setTimeout(timeout: number, callback?: () => void): this;
  ref(): this;
  unref(): this;

  // ------- LemonTLS-only extensions -------
  readonly isResumed: boolean;
  /** Returns the underlying TLSSession for low-level access. */
  session: TLSSession;
  readonly handshakeDuration: number | null;
  getJA3(): JA3Result | null;
  getSharedSecret(): Buffer | null;
  getNegotiationResult(): NegotiationResult | null;
  rekeySend(): void;
  rekeyBoth(): void;

  // ------- Events -------
  on(event: 'secureConnect', listener: () => void): this;
  on(event: 'data', listener: (data: Buffer) => void): this;
  /**
   * Emits an opaque Buffer (Node-compatible). Pass it back into tls.connect({ session })
   * to resume. The Buffer is our internal encoded session blob.
   */
  on(event: 'session', listener: (data: Buffer) => void): this;
  on(event: 'keylog', listener: (line: Buffer) => void): this;
  on(event: 'keyUpdate', listener: (direction: 'send' | 'receive') => void): this;
  on(event: 'clienthello', listener: (raw: Buffer, parsed: any) => void): this;
  on(event: 'handshakeMessage', listener: (type: string, raw: Buffer, parsed: any) => void): this;
  on(event: 'certificateRequest', listener: (msg: any) => void): this;
  on(event: 'newSession', listener: (id: Buffer, data: Buffer, cb: () => void) => void): this;
  on(event: 'resumeSession', listener: (id: Buffer, cb: (err: Error | null, data: Buffer | null) => void) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: 'close', listener: () => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

// ======================== Server ========================

/**
 * Node.js tls.Server compatible server. Returned by createServer().
 * Extends EventEmitter and wraps a net.Server internally.
 */
export class Server extends EventEmitter {
  listen(port: number, host?: string, callback?: () => void): this;
  listen(port: number, callback?: () => void): this;
  listen(options: { port?: number; host?: string }, callback?: () => void): this;
  close(callback?: (err?: Error) => void): this;
  address(): { port: number; family: string; address: string } | string | null;

  /** Replace the server's key/cert at runtime (Let's Encrypt renewals, etc.). */
  setSecureContext(options: { key: Buffer | string; cert: Buffer | string }): void;
  /** Returns the 48-byte TLS session ticket encryption keys. */
  getTicketKeys(): Buffer;
  /** Sets the 48-byte TLS session ticket encryption keys (for clustered deployments). */
  setTicketKeys(keys: Buffer): void;

  readonly listening: boolean;

  // Events
  on(event: 'secureConnection', listener: (socket: TLSSocket) => void): this;
  on(event: 'tlsClientError', listener: (err: Error, socket: TLSSocket | null) => void): this;
  on(event: 'keylog', listener: (line: Buffer, socket: TLSSocket) => void): this;
  on(event: 'newSession', listener: (id: Buffer, data: Buffer, cb: () => void) => void): this;
  on(event: 'resumeSession', listener: (id: Buffer, cb: (err: Error | null, data: Buffer | null) => void) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: 'close', listener: () => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

// ======================== TLSSession ========================

export interface TLSSessionOptions {
  isServer?: boolean;
  servername?: string;
  ALPNProtocols?: string[];
  SNICallback?: (servername: string, cb: (err: Error | null, ctx: SecureContext | null) => void) => void;
  ticketKeys?: Buffer;
  session?: Buffer | Uint8Array | SessionTicketData;
  psk?: any;
  rejectUnauthorized?: boolean;
  ca?: Buffer | string;
  noTickets?: boolean;
  sessionTickets?: boolean;
  maxHandshakeSize?: number;
  customExtensions?: Array<{ type: number; data: Uint8Array }>;
  requestCert?: boolean;
  cert?: Buffer | string;
  key?: Buffer | string;
}

export interface TrafficSecrets {
  isServer: boolean;
  version: number | null;
  cipher: number | null;
  localAppSecret: Uint8Array | null;
  remoteAppSecret: Uint8Array | null;
  masterSecret: Uint8Array | null;
  localRandom: Uint8Array | null;
  remoteRandom: Uint8Array | null;
}

export interface HandshakeSecrets {
  localSecret: Uint8Array | null;
  remoteSecret: Uint8Array | null;
  cipher: number | null;
}

export class TLSSession extends EventEmitter {
  constructor(options: TLSSessionOptions);

  readonly isServer: boolean;
  readonly isResumed: boolean;
  readonly handshakeDuration: number | null;
  readonly authorized: boolean;
  readonly authorizationError: string | null;
  readonly context: any;

  message(data: Uint8Array | Buffer): void;
  set_context(options: Record<string, any>): void;
  close(): void;
  sendAlert(level: number, description: number): void;

  getVersion(): number | null;
  getCipher(): number | null;
  getALPN(): string | null;
  getPeerCertificate(): Array<{ cert: Buffer }> | null;
  getTrafficSecrets(): TrafficSecrets;
  getHandshakeSecrets(): HandshakeSecrets;
  exportKeyingMaterial(length: number, label: string, context: Uint8Array): Uint8Array;
  getFinished(): Buffer | null;
  getPeerFinished(): Buffer | null;
  getSharedSecret(): Buffer | null;
  getNegotiationResult(): NegotiationResult;
  getJA3(): JA3Result | null;
  requestKeyUpdate(requestPeer?: boolean): void;

  // Events
  on(event: 'message', listener: (epoch: number, seq: number, type: string, data: Uint8Array) => void): this;
  on(event: 'hello', listener: () => void): this;
  on(event: 'secureConnect', listener: () => void): this;
  /** Emits the raw internal session blob (Buffer/Uint8Array — encoded session state). */
  on(event: 'session', listener: (data: Buffer) => void): this;
  on(event: 'psk', listener: (identity: Buffer, callback: (result: { psk: Buffer; cipher: number } | null) => void) => void): this;
  on(event: 'keyUpdate', listener: (info: { direction: 'send' | 'receive'; secret: Uint8Array }) => void): this;
  on(event: 'keylog', listener: (line: Buffer) => void): this;
  on(event: 'clienthello', listener: (raw: Buffer, parsed: any) => void): this;
  on(event: 'handshakeMessage', listener: (type: string, raw: Buffer, parsed: any) => void): this;
  on(event: 'certificateRequest', listener: (msg: any) => void): this;
  on(event: 'newSession', listener: (id: Uint8Array, data: Uint8Array, cb: () => void) => void): this;
  on(event: 'resumeSession', listener: (id: Uint8Array, cb: (err: Error | null, data: Uint8Array | null) => void) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

// ======================== Module Functions ========================

export function createSecureContext(options: { key: Buffer | string; cert: Buffer | string }): SecureContext;

export function connect(port: number, host: string, options?: TLSSocketOptions, callback?: () => void): TLSSocket;
export function connect(port: number, host: string, callback?: () => void): TLSSocket;
export function connect(options: TLSSocketOptions & { port: number; host?: string }, callback?: () => void): TLSSocket;

export function createServer(
  options: TLSSocketOptions & { key?: Buffer | string; cert?: Buffer | string },
  connectionListener?: (socket: TLSSocket) => void
): Server;

export function getCiphers(): string[];

/**
 * Validates that the peer certificate matches the hostname (RFC 6125).
 * Returns undefined on success, or an Error on mismatch.
 * This is the default check used when rejectUnauthorized is true; apps can
 * override it via the checkServerIdentity option in tls.connect.
 */
export function checkServerIdentity(hostname: string, cert: PeerCertificate): Error | undefined;

export const DEFAULT_MIN_VERSION: string;
export const DEFAULT_MAX_VERSION: string;
/** Node-compat: default colon-separated cipher string. */
export const DEFAULT_CIPHERS: string;
/** Node-compat: default ECDH curve selection policy ('auto'). */
export const DEFAULT_ECDH_CURVE: string;

// ======================== Submodules ========================

export declare const crypto: {
  TLS_CIPHER_SUITES: Record<number, any>;
  getHashFn: (name: string) => any;
  getHashLen: (name: string) => number;
  hkdf_extract: (hash: string, salt: Uint8Array, ikm: Uint8Array) => Uint8Array;
  hkdf_expand: (hash: string, prk: Uint8Array, info: Uint8Array, length: number) => Uint8Array;
  hkdf_expand_label: (hash: string, secret: Uint8Array, label: string, context: Uint8Array, length: number) => Uint8Array;
  hmac: (hash: string, key: Uint8Array, data: Uint8Array) => Uint8Array;
};

export declare const wire: any;
export declare const record: {
  getAeadAlgo: (cipher: number) => string;
  deriveKeys: (secret: Uint8Array, cipher: number) => { key: Uint8Array; iv: Uint8Array };
  getNonce: (iv: Uint8Array, seq: number) => Uint8Array;
  encryptRecord: (contentType: number, plaintext: Uint8Array, key: Uint8Array, nonce: Uint8Array, algo: string) => Uint8Array;
  decryptRecord: (ciphertext: Uint8Array, key: Uint8Array, nonce: Uint8Array, algo: string) => Uint8Array;
};

// ======================== DTLS ========================
// DTLS bindings are exported from the package but typed loosely here —
// use the JS source directly for exact signatures.

export declare class DTLSSession extends EventEmitter {
  constructor(options: any);
}
export declare class DTLSSocket extends EventEmitter {
  constructor(options: any);
}
export declare function createDTLSServer(options: any, connectionListener?: (socket: DTLSSocket) => void): any;
export declare function connectDTLS(options: any, callback?: () => void): DTLSSocket;

// ======================== Default Export ========================

declare const _default: {
  TLSSocket: typeof TLSSocket;
  TLSSession: typeof TLSSession;
  Server: typeof Server;
  createSecureContext: typeof createSecureContext;
  connect: typeof connect;
  createServer: typeof createServer;
  getCiphers: typeof getCiphers;
  checkServerIdentity: typeof checkServerIdentity;
  DEFAULT_MIN_VERSION: string;
  DEFAULT_MAX_VERSION: string;
  DEFAULT_CIPHERS: string;
  DEFAULT_ECDH_CURVE: string;
  crypto: typeof crypto;
  wire: typeof wire;
  record: typeof record;
  DTLSSession: typeof DTLSSession;
  DTLSSocket: typeof DTLSSocket;
  createDTLSServer: typeof createDTLSServer;
  connectDTLS: typeof connectDTLS;
};

export default _default;
