/// <reference types="node" />

import { Duplex } from 'node:stream';
import { EventEmitter } from 'node:events';
import type { Server as NetServer } from 'node:net';

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
  subject: string;
  issuer: string;
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
  session?: SessionTicketData;
  requestCert?: boolean;
  cert?: Buffer | string;
  key?: Buffer | string;

  // LemonTLS-only options
  noTickets?: boolean;
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

  // Node.js compatible
  getProtocol(): string | null;
  getCipher(): CipherInfo | null;
  getPeerCertificate(): PeerCertificate | null;
  isSessionReused(): boolean;
  getFinished(): Buffer | null;
  getPeerFinished(): Buffer | null;
  exportKeyingMaterial(length: number, label: string, context: Buffer): Buffer;
  getEphemeralKeyInfo(): EphemeralKeyInfo;
  disableRenegotiation(): void;
  setServername(name: string): void;
  setSocket(transport: Duplex): void;

  readonly isResumed: boolean;
  readonly authorized: boolean;
  readonly authorizationError: string | null;
  readonly alpnProtocol: string | false;
  readonly encrypted: boolean;

  // LemonTLS-only
  getSession(): TLSSession;
  readonly handshakeDuration: number | null;
  getJA3(): JA3Result | null;
  getSharedSecret(): Buffer | null;
  getNegotiationResult(): NegotiationResult | null;
  rekeySend(): void;
  rekeyBoth(): void;

  // Events
  on(event: 'secureConnect', listener: () => void): this;
  on(event: 'data', listener: (data: Buffer) => void): this;
  on(event: 'session', listener: (data: SessionTicketData) => void): this;
  on(event: 'keyUpdate', listener: (direction: 'send' | 'receive') => void): this;
  on(event: 'keylog', listener: (line: Buffer) => void): this;
  on(event: 'clienthello', listener: (raw: Buffer, parsed: any) => void): this;
  on(event: 'handshakeMessage', listener: (type: string, raw: Buffer, parsed: any) => void): this;
  on(event: 'certificateRequest', listener: (msg: any) => void): this;
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
  session?: SessionTicketData;
  psk?: any;
  rejectUnauthorized?: boolean;
  ca?: Buffer | string;
  noTickets?: boolean;
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
  on(event: 'session', listener: (data: SessionTicketData) => void): this;
  on(event: 'psk', listener: (identity: Buffer, callback: (result: { psk: Buffer; cipher: number } | null) => void) => void): this;
  on(event: 'keyUpdate', listener: (info: { direction: 'send' | 'receive'; secret: Uint8Array }) => void): this;
  on(event: 'clienthello', listener: (raw: Buffer, parsed: any) => void): this;
  on(event: 'handshakeMessage', listener: (type: string, raw: Buffer, parsed: any) => void): this;
  on(event: 'certificateRequest', listener: (msg: any) => void): this;
  on(event: 'error', listener: (err: Error) => void): this;
  on(event: string, listener: (...args: any[]) => void): this;
}

// ======================== Module Functions ========================

export function createSecureContext(options: { key: Buffer | string; cert: Buffer | string }): SecureContext;
export function connect(port: number, host: string, options?: TLSSocketOptions, callback?: () => void): TLSSocket;
export function connect(options: TLSSocketOptions & { port: number; host?: string }, callback?: () => void): TLSSocket;
export function createServer(options: TLSSocketOptions & { key?: Buffer | string; cert?: Buffer | string }, connectionListener?: (socket: TLSSocket) => void): NetServer;
export function getCiphers(): string[];

export const DEFAULT_MIN_VERSION: string;
export const DEFAULT_MAX_VERSION: string;

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

// ======================== Default Export ========================

declare const _default: {
  TLSSocket: typeof TLSSocket;
  TLSSession: typeof TLSSession;
  createSecureContext: typeof createSecureContext;
  connect: typeof connect;
  createServer: typeof createServer;
  getCiphers: typeof getCiphers;
  DEFAULT_MIN_VERSION: string;
  DEFAULT_MAX_VERSION: string;
  crypto: typeof crypto;
  wire: typeof wire;
  record: typeof record;
};

export default _default;
