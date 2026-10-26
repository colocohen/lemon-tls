/// <reference types="node" />

import { Duplex } from 'node:stream';
import { EventEmitter } from 'node:events';
import type { Server as NetServer } from 'node:net';
import type { X509Certificate } from 'node:crypto';

// ======================== Types ========================

/** A key or certificate: PEM or DER bytes, or a file path. */
export type PemInput = Buffer | Uint8Array | string;

/**
 * createSecureContext()'s options. `key` and `cert` as arrays — node:tls's
 * form — for several certificates of different kinds (an ML-DSA one for
 * clients that ask for post-quantum authentication, an ECDSA or RSA one for
 * the rest): each key is paired with the chain whose leaf carries its public
 * key, the first being the default.
 */
export interface SecureContextOptions {
  key?: PemInput | Array<PemInput | { pem: PemInput; passphrase?: string }>;
  cert?: PemInput | PemInput[];
  ca?: PemInput | PemInput[];
  passphrase?: string;
  pfx?: PemInput;
  /** A stapled OCSP response (DER) for the leaf. */
  ocsp?: PemInput;
  ticketKeys?: Buffer | Uint8Array;
  [option: string]: any;
}

export interface SecureContext {
  certificateChain: Array<{ cert: Buffer }>;
  privateKey: any;
  ca?: any[];
  /** The other key/certificate pairs (key/cert arrays). */
  alternates?: Array<{ certificateChain: Array<{ cert: Buffer }>; privateKey: any }>;
}

/** An Encrypted Client Hello key (RFC 9849), from generateEchKey(). */
export interface EchKey {
  config: Uint8Array;
  privateKey: Uint8Array;
  configList: Uint8Array;
  /** The value of `ech=` in the domain's HTTPS record. */
  configListBase64: string;
}

/** A server's `ech` option. `retry: false`: still accepted, no longer offered to clients. */
export interface EchServerOption {
  keys: Array<{ config: Uint8Array | Buffer | string; privateKey: Uint8Array | Buffer | string; retry?: boolean }>;
}

/** A saved session ('session' event's Buffer) described without its secrets: sessionInfo(). */
export interface SessionInfo {
  version: 'TLSv1.3' | 'TLSv1.2' | null;
  servername: string | null;
  alpn: string | null;
  created: number | null;
  expiresAt: number | null;
  earlyData: boolean;
}

export interface CipherInfo {
  name: string;
  standardName: string;
  version: string;
}

export interface PeerCertificate {
  /** RDN fields as node:tls has them: { C, ST, L, O, OU, CN }. */
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
  /** 'TLSGroup' for a group that is not a plain curve, as Node reports it —
   *  X25519MLKEM768 among them (no size). Client side only; {} on a server. */
  type: 'X25519' | 'ECDH' | 'DH' | 'TLSGroup';
  name?: string;
  size?: number;
}

/** A TLS fingerprint: `hash` is the fingerprint, `raw` what was hashed. */
export interface FingerprintResult {
  hash: string;
  raw: string;
}

export interface FingerprintOptions {
  /** Transport character, for a caller driving the session from a transport
   *  it cannot see: 't' TCP (default), 'q' QUIC, 'd' DTLS. */
  protocol?: 't' | 'q' | 'd';
}

/**
 * Server: this connection's session ticket, from the first connection on.
 * `data` is what the ticketData option put in the ticket — the one this
 * connection resumed with, or, on a full handshake, the one made for the
 * ticket issued to it (null until the server's Finished is sent).
 * `offered && !resumed`: the client presented a ticket that was turned away
 * (expired, issued before a restart, no compatible cipher).
 */
export interface TicketInfo {
  data: any;
  resumed: boolean;
  offered: boolean;
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
  SNICallback?: (servername: string, cb: (err: Error | null, ctx?: SecureContext | null) => void) => void;
  /** Server, node:tls's: pick the protocol from what the client offers (exclusive with ALPNProtocols on a Server). */
  ALPNCallback?: (info: { servername: string | null; protocols: string[] }) => string | undefined;
  minVersion?: 'TLSv1.2' | 'TLSv1.3';
  maxVersion?: 'TLSv1.2' | 'TLSv1.3';
  ALPNProtocols?: string[];
  rejectUnauthorized?: boolean;
  /** Client: the identity check (node:tls's); undefined for a match, an Error otherwise. */
  checkServerIdentity?: (hostname: string, cert: PeerCertificate) => Error | undefined;
  ca?: PemInput | PemInput[];
  /** A context from createSecureContext(), in place of key/cert/ca. */
  secureContext?: SecureContext;
  passphrase?: string;
  ticketKeys?: Buffer;
  /**
   * Server: what to carry inside each session ticket issued. Called once per
   * connection as ticketData(resumed) — `resumed` is the data of the ticket
   * this connection resumed with, null on a full handshake. The return value
   * (JSON-safe, at most 256 bytes serialized) rides in the ticket, encrypted
   * with ticketKeys; read it back with getTicketInfo().
   */
  ticketData?: (resumed: any) => any;
  /**
   * Opaque serialized session from a previous 'session' event.
   * Pass this back to resume a TLS 1.2/1.3 session.
   */
  session?: Buffer | Uint8Array;
  requestCert?: boolean;
  cert?: PemInput;
  key?: PemInput;

  // node:tls's option strings — taken as Node takes them. lemon-tls's code
  // lists (allowedCipherSuites, groups, signatureAlgorithms) win when given.
  /** 'TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256…' */
  ciphers?: string;
  /** 'X25519:P-256', or 'auto'. */
  ecdhCurve?: string;
  /** 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256…' */
  sigalgs?: string;
  /** Server: the cipher suite by the server's order (default: the client's). */
  honorCipherOrder?: boolean;

  // ---- Encrypted Client Hello (RFC 9849) ----
  /** Server: { keys }. Client: the server's ECHConfigList (bytes, or base64 — `ech=` of its HTTPS record). */
  ech?: EchServerOption | Uint8Array | Buffer | string;
  /** Client: GREASE ECH, without a config. */
  echGrease?: boolean;

  // ---- OCSP stapling ----
  /** Server: asked when a client requests status; callback(null, response DER) or (null, null). */
  ocspRequest?: (certificate: Buffer, issuer: Buffer | null, callback: (err: Error | null, response: Buffer | Uint8Array | null) => void) => void;
  /** Client: ask the server for a stapled response ('OCSPResponse'). */
  requestOCSP?: boolean;

  /** RFC 8879: ['brotli', 'zlib', 'zstd'] in order, true (all this build has) or false (none). */
  certificateCompression?: Array<'brotli' | 'zlib' | 'zstd'> | boolean;

  // ---- 0-RTT (RFC 8446 §4.2.10) ----
  /** Server: issue tickets that allow it, and take it. Client: with `session`, what is written before 'secureConnect' goes early. */
  earlyData?: boolean;
  /** Server: ms the client's ticket age may differ from ours. */
  earlyDataMaxAge?: number;
  /** Server: the anti-replay store — cb(null, true) when `id` is new (keep it `ttl` ms). */
  earlyDataReplay?: (id: string, ttl: number, cb: (err: Error | null, fresh: boolean) => void) => void;
  /** Server: bytes of early data a ticket allows (16 KB). */
  maxEarlyData?: number;

  // ---- ClientHello shaping (client) ----
  grease?: boolean;
  permuteExtensions?: boolean;

  /** Client: trust the bundled CAs when no `ca` is given (default: true). */
  useDefaultCA?: boolean;
  allowHalfOpen?: boolean;
  highWaterMark?: number;

  // TCP options, as in node:net. connect() passes them (and the rest of
  // net.connect's: localAddress, localPort, family, lookup, timeout) to
  // net.connect; createServer() applies noDelay/keepAlive to every
  // connection it accepts. Defaults as in Node: off.
  /** Disable Nagle's algorithm (TCP_NODELAY). Default: false. */
  noDelay?: boolean;
  /** Enable TCP keep-alive. Default: false. */
  keepAlive?: boolean;
  /** Milliseconds before the first keep-alive probe. Default: 0. */
  keepAliveInitialDelay?: number;
  localAddress?: string;
  localPort?: number;
  family?: number;
  timeout?: number;

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

/** connect()'s: the socket's options, where, and node:net's. */
export interface ConnectOptions extends TLSSocketOptions {
  port?: number;
  host?: string;
  /** STARTTLS: an existing socket to run TLS on (no net.connect). */
  socket?: Duplex;
  lookup?: (...args: any[]) => void;
  [option: string]: any;
}

/** createServer()'s: the server side of TLSSocketOptions, and node:tls's server ones. */
export interface ServerOptions extends Omit<TLSSocketOptions, 'key' | 'cert'> {
  key?: SecureContextOptions['key'];
  cert?: SecureContextOptions['cert'];
  /** Seconds a session stays good — tickets and TLS 1.2 Session IDs (Node's default, 300). */
  sessionTimeout?: number;
  /** Sessions under one context do not resume under another. */
  sessionIdContext?: string | Buffer;
  pauseOnConnect?: boolean;
}

// ======================== TLSSocket ========================

export class TLSSocket extends Duplex {
  constructor(transport: Duplex | null, options: TLSSocketOptions);

  // ------- Node.js tls.TLSSocket compatible API -------
  getProtocol(): string | null;
  getCipher(): CipherInfo | null;
  /** `detailed` is accepted for node:tls's signature; the leaf is described either way. */
  getPeerCertificate(detailed?: boolean): PeerCertificate | null;
  /** Returns our LOCAL cert (what we presented). Empty object if none. */
  getCertificate(): PeerCertificate | {};
  /** Returns the peer cert as a native crypto.X509Certificate object (Node 15.9+). */
  getPeerX509Certificate(): X509Certificate | undefined;
  /** Returns our LOCAL cert as a native crypto.X509Certificate object. */
  getX509Certificate(): X509Certificate | undefined;
  isSessionReused(): boolean;
  getFinished(): Buffer | null;
  getPeerFinished(): Buffer | null;
  /** null before the handshake completes (Node throws). */
  exportKeyingMaterial(length: number, label: string, context?: Buffer | Uint8Array): Buffer | null;
  /** null on a server socket, as in Node. */
  getEphemeralKeyInfo(): EphemeralKeyInfo | {} | null;
  /** On sockets from connect() and createServer() (compat layer). */
  disableRenegotiation(): void;
  /** On sockets from connect() and createServer() (compat layer). */
  setServername(name: string): void;
  /** The transport's bound address, as node:tls's. */
  address(): { port?: number; family?: string; address?: string };
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
  /** 0-RTT. Server: what is read now came early (it may be a replay). Client: it is sending early. */
  readonly isEarlyData: boolean;
  readonly earlyDataBytes: number;
  readonly earlyDataStatus: 'offered' | 'accepted' | 'rejected' | null;
  /** Encrypted Client Hello: what happened to it on this connection. */
  readonly echStatus: string | null;
  readonly echAccepted: boolean;
  /** Server: the certificate to present, from inside ALPNCallback (a context or { key, cert }). */
  setKeyCert(context: SecureContext | SecureContextOptions): void;
  /** The peer's hello extensions: [{ type, name, data, value }]. */
  getRemoteExtensions(): Array<{ type: number; name: string | null; data: Uint8Array; value: any }>;
  getRemoteExtension(type: number): { type: number; name: string | null; data: Uint8Array; value: any } | null;
  /** JA4 of the ClientHello — the published format, what fingerprint
   *  databases match. Changes when a client resumes (pre_shared_key). */
  getJA4(opts?: FingerprintOptions): FingerprintResult | null;
  /** JA5 of the ClientHello (ntop's draft): as JA4 without the extensions that
   *  vary per connection, plus supported_groups — the same for a client
   *  whether it resumed or not. */
  getJA5(opts?: FingerprintOptions): FingerprintResult | null;
  /** JA4S of the ServerHello. */
  getJA4S(opts?: FingerprintOptions): FingerprintResult | null;
  /** Server: this connection's session ticket — see TicketInfo. */
  getTicketInfo(): TicketInfo;
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
  /** Client: the server's stapled OCSP response (requestOCSP). */
  on(event: 'OCSPResponse', listener: (response: Buffer) => void): this;
  /** 0-RTT decided: whether the server took it. */
  on(event: 'earlyData', listener: (accepted: boolean) => void): this;
  on(event: 'alert', listener: (alert: { level: number; description: number }) => void): this;
  on(event: 'secure', listener: () => void): this;
  on(event: 'psk', listener: (identity: any, callback: (result: { psk: Buffer; cipher: number } | null) => void) => void): this;
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

  getConnections(callback: (err: Error | null, count: number) => void): void;
  /** Node's documented injection of a Duplex into the server ('connection'), as a method. */
  injectConnection(stream: Duplex): this;
  ref(): this;
  unref(): this;

  /** Replace the server's key/cert at runtime (Let's Encrypt renewals, etc.). Throws on a bad one; the old stays. */
  setSecureContext(options: SecureContextOptions | { secureContext: SecureContext }): void;
  /** A certificate for an SNI name or wildcard ('*.example.com': one label). The latest wins; an exact name beats a wildcard. */
  addContext(hostname: string, context: SecureContext | SecureContextOptions): this;
  /** Encrypted Client Hello keys, rotated without a restart. */
  getEchKeys(): EchServerOption | null;
  setEchKeys(ech: EchServerOption | null): void;
  /** Returns the 48-byte TLS session ticket encryption keys. */
  getTicketKeys(): Buffer;
  /** Sets the 48-byte TLS session ticket encryption keys (for clustered deployments). */
  setTicketKeys(keys: Buffer): void;

  readonly listening: boolean;

  // Events
  on(event: 'secureConnection', listener: (socket: TLSSocket) => void): this;
  on(event: 'tlsClientError', listener: (err: Error, socket: TLSSocket | null) => void): this;
  on(event: 'keylog', listener: (line: Buffer, socket: TLSSocket) => void): this;
  /** Before the TLS handshake: the raw socket. */
  on(event: 'connection', listener: (socket: Duplex) => void): this;
  on(event: 'OCSPRequest', listener: (certificate: Buffer, issuer: Buffer | null, callback: (err: Error | null, response: Buffer | Uint8Array | null) => void) => void): this;
  on(event: 'listening', listener: () => void): this;
  on(event: 'drop', listener: (data: any) => void): this;
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
  /** See TLSSocketOptions.ticketData. */
  ticketData?: (resumed: any) => any;
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
  /** Our own certificate chain — the one this connection presents. */
  getCertificate(): Array<{ cert: Buffer }> | null;
  getTrafficSecrets(): TrafficSecrets;
  getHandshakeSecrets(): HandshakeSecrets;
  exportKeyingMaterial(length: number, label: string, context: Uint8Array): Uint8Array;
  getFinished(): Buffer | null;
  getPeerFinished(): Buffer | null;
  getSharedSecret(): Buffer | null;
  getNegotiationResult(): NegotiationResult;
  getJA4(opts?: FingerprintOptions): FingerprintResult | null;
  getJA5(opts?: FingerprintOptions): FingerprintResult | null;
  getJA4S(opts?: FingerprintOptions): FingerprintResult | null;
  /** Server: this connection's session ticket — see TicketInfo. */
  getTicketInfo(): TicketInfo;
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

export function createSecureContext(options: SecureContextOptions): SecureContext;

export function connect(port: number, host: string, options?: ConnectOptions, callback?: () => void): TLSSocket;
export function connect(port: number, host: string, callback?: () => void): TLSSocket;
export function connect(options: ConnectOptions, callback?: () => void): TLSSocket;

export function createServer(options: ServerOptions, connectionListener?: (socket: TLSSocket) => void): Server;
export function createServer(connectionListener?: (socket: TLSSocket) => void): Server;

// ---- node:tls's option strings → code lists (null when unset). They throw
//      on a name they do not know, as Node's createServer does.
export function parseCiphers(ciphers: string | null | undefined): number[] | null;
export function parseEcdhCurve(ecdhCurve: string | null | undefined): number[] | null;
export function parseSigalgs(sigalgs: string | null | undefined): number[] | null;
export function parseTlsVersion(version: string | null | undefined, optionName?: string): number | null;
export function parseCertificateCompression(value: Array<'brotli' | 'zlib' | 'zstd'> | boolean | null | undefined): number[] | null;

/** A server's certificate chain compressed now, in the background (RFC 8879), so the first handshake does not wait for it. */
export function precompressCertificate(secureContext: SecureContext, algorithms?: Array<'brotli' | 'zlib' | 'zstd'> | boolean, callback?: () => void): void;
export function precompressCertificate(secureContext: SecureContext, callback?: () => void): void;

/** The key-exchange groups a server offers by default, in order (code points). */
export const DEFAULT_SERVER_GROUPS: readonly number[];
/** The signature schemes offered by default, in order (code points). */
export const DEFAULT_SIGNATURE_SCHEMES: readonly number[];

/** A saved session described without its secrets; null if it is not one. */
export function sessionInfo(session: Buffer | Uint8Array): SessionInfo | null;
/** A certificate (DER) as getPeerCertificate() describes it. */
export function certificateObject(der: Buffer | Uint8Array): PeerCertificate | { raw: Buffer | Uint8Array } | null;

/** A new ECH key for a server. publicName: the name the outer hello carries (the server holds a certificate for it). */
export function generateEchKey(options: { publicName: string; configId?: number; maxNameLength?: number; kem?: string | number }): EchKey;
/** Throws, saying what is wrong, if a server's `ech` option would not work. */
export function checkEchKeys(ech: EchServerOption | null | undefined): void;

export function getCiphers(): string[];

/** Node-compat: the shipped CA bundle (PEM strings) — tls.rootCertificates. */
export const rootCertificates: readonly string[];
/**
 * Node-compat: tls.getCACertificates([type]). 'default' and 'bundled' return
 * the CA set clients verify against when given no `ca` (the shipped bundle,
 * or what setDefaultCACertificates put in its place); 'extra' and 'system'
 * are not sourced here and return [].
 */
export function getCACertificates(type?: 'default' | 'bundled' | 'extra' | 'system'): string[];
/** Node-compat: tls.setDefaultCACertificates(certs) — replaces that set for
 *  every later connection that passes no `ca`. Throws if not an array. */
export function setDefaultCACertificates(certs: string[]): void;

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
  /** TLS 1.2 PRF (RFC 5246 §5). */
  tls12_prf: (secret: Uint8Array, label: string, seed: Uint8Array, length: number, hash: string) => Uint8Array;
  /** RFC 5705 exporter over a TLS 1.2 master secret. */
  tls12_exporter: (hash: string, masterSecret: Uint8Array, label: string, clientRandom: Uint8Array,
                   serverRandom: Uint8Array, context: Uint8Array | null, length: number) => Uint8Array;
  /** RFC 8446 §7.5 exporter; labelPrefix defaults to TLS 1.3's ('tls13 '). */
  tls13_exporter: (hash: string, exporterMasterSecret: Uint8Array, label: string,
                   context: Uint8Array | null, length: number, labelPrefix?: string) => Uint8Array;
  /** HPKE (RFC 9180) — what ECH encrypts with. */
  hpke: {
    suite: (...args: any[]) => any;
    setupSender: (...args: any[]) => any;
    setupRecipient: (...args: any[]) => any;
    seal: (...args: any[]) => any;
    open: (...args: any[]) => any;
    generateKeyPair: (...args: any[]) => any;
    deriveKeyPair: (...args: any[]) => any;
  };
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
  getCACertificates: typeof getCACertificates;
  setDefaultCACertificates: typeof setDefaultCACertificates;
  rootCertificates: typeof rootCertificates;
  DEFAULT_MIN_VERSION: string;
  DEFAULT_MAX_VERSION: string;
  DEFAULT_CIPHERS: string;
  DEFAULT_ECDH_CURVE: string;
  crypto: typeof crypto;
  wire: typeof wire;
  record: typeof record;
  parseCiphers: typeof parseCiphers;
  parseEcdhCurve: typeof parseEcdhCurve;
  parseSigalgs: typeof parseSigalgs;
  parseTlsVersion: typeof parseTlsVersion;
  parseCertificateCompression: typeof parseCertificateCompression;
  precompressCertificate: typeof precompressCertificate;
  DEFAULT_SERVER_GROUPS: typeof DEFAULT_SERVER_GROUPS;
  DEFAULT_SIGNATURE_SCHEMES: typeof DEFAULT_SIGNATURE_SCHEMES;
  sessionInfo: typeof sessionInfo;
  certificateObject: typeof certificateObject;
  generateEchKey: typeof generateEchKey;
  checkEchKeys: typeof checkEchKeys;
  DTLSSession: typeof DTLSSession;
  DTLSSocket: typeof DTLSSocket;
  createDTLSServer: typeof createDTLSServer;
  connectDTLS: typeof connectDTLS;
};

export default _default;