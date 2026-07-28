import { CryptoAPIUnavailableError } from './errors';

export const PBKDF2_ITERATIONS = 100000;
export const SALT_LENGTH = 16;
export const IV_LENGTH = 12;
export const KEY_LENGTH = 32;
export const CURRENT_VERSION = 1;

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
  return encoder.encode(str).buffer;
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
