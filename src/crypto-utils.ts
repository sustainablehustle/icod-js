import { CryptoAPIUnavailableError } from './errors';

/**
 * PBKDF2 iteration count for v2 payloads.
 *
 * OWASP's current floor for PBKDF2-SHA256 is 600,000. v1 shipped 100,000, which is
 * why `decrypt` reads the iteration count from the payload's `version` rather than a
 * module constant — see `iterationsForVersion`.
 */
export const PBKDF2_ITERATIONS = 600000;

/** Iteration count used by v1 payloads. Retained so v1 blobs stay readable forever. */
export const PBKDF2_ITERATIONS_V1 = 100000;

export const SALT_LENGTH = 16;
export const IV_LENGTH = 12;
export const KEY_LENGTH = 32;
export const CURRENT_VERSION = 2;

/** RSA-OAEP parameters. 3072 is the floor; 2048 is not acceptable for this use. */
export const RSA_MODULUS_LENGTH = 3072;
export const RSA_HASH = 'SHA-256';
export const RSA_JWK_ALG = 'RSA-OAEP-256';

/**
 * Bytes of SHA-256 output retained in a public key fingerprint.
 *
 * 15 bytes is 120 bits, which base32-encodes to exactly 24 characters with no
 * padding — six groups of four, which is what a human reads aloud over the phone.
 * 120 bits is far beyond what a second-preimage attack could reach.
 */
export const FINGERPRINT_BYTES = 15;

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Resolve the PBKDF2 iteration count for a payload version.
 *
 * Unknown (future) versions fall through to the current count rather than throwing,
 * so an older reader fails at the authentication tag with a clear error instead of
 * refusing to look at the payload at all.
 */
export function iterationsForVersion(version: number | undefined): number {
  return version === 1 ? PBKDF2_ITERATIONS_V1 : PBKDF2_ITERATIONS;
}

function getCrypto(): Crypto | undefined {
  if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    return globalThis.crypto;
  }
  if (typeof global !== 'undefined' && global.crypto) {
    return global.crypto;
  }
  if (typeof window !== 'undefined' && window.crypto) {
    return window.crypto;
  }
  return undefined;
}

export function isWebCryptoAvailable(): boolean {
  const cryptoObj = getCrypto();
  return cryptoObj !== undefined && cryptoObj.subtle !== undefined;
}

export function ensureWebCrypto(): void {
  if (!isWebCryptoAvailable()) {
    throw new CryptoAPIUnavailableError();
  }
}

export function getWebCrypto(): Crypto {
  ensureWebCrypto();
  return getCrypto()!;
}

export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export function stringToArrayBuffer(str: string): ArrayBuffer {
  const encoder = new TextEncoder();
  return encoder.encode(str).buffer as ArrayBuffer;
}

export function arrayBufferToString(buffer: ArrayBuffer): string {
  const decoder = new TextDecoder();
  return decoder.decode(buffer);
}

export function generateRandomBytes(length: number): Uint8Array {
  const crypto = getWebCrypto();
  return crypto.getRandomValues(new Uint8Array(length));
}

export function constantTimeCompare(a: ArrayBuffer, b: ArrayBuffer): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  const aBytes = new Uint8Array(a);
  const bBytes = new Uint8Array(b);
  let result = 0;
  for (let i = 0; i < aBytes.length; i++) {
    result |= aBytes[i] ^ bBytes[i];
  }
  return result === 0;
}

/**
 * Normalise `EncryptionOptions.additionalData` into the ArrayBuffer that Web Crypto
 * expects, encoding strings as UTF-8.
 *
 * Accepting a string directly removes a real footgun: ICOD's AAD values are context
 * strings, and leaving each caller to encode them invites two call sites that encode
 * differently and produce payloads that will not decrypt against each other.
 */
export function normaliseAdditionalData(
  additionalData: ArrayBuffer | Uint8Array | string | undefined
): ArrayBuffer | undefined {
  if (additionalData === undefined) {
    return undefined;
  }
  if (typeof additionalData === 'string') {
    return stringToArrayBuffer(additionalData);
  }
  if (additionalData instanceof Uint8Array) {
    return additionalData.buffer.slice(
      additionalData.byteOffset,
      additionalData.byteOffset + additionalData.byteLength
    ) as ArrayBuffer;
  }
  return additionalData;
}

/**
 * Encode bytes as unpadded RFC 4648 base32.
 *
 * Base32 rather than hex because the output is read aloud between two humans
 * verifying a public key, and its alphabet excludes the characters people confuse
 * when doing that (0/O, 1/I/L).
 */
export function toBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/** Render a base32 fingerprint as six hyphenated groups of four, for reading aloud. */
export function groupFingerprint(base32: string): string {
  const groups: string[] = [];
  for (let i = 0; i < base32.length; i += 4) {
    groups.push(base32.slice(i, i + 4));
  }
  return groups.join('-');
}
