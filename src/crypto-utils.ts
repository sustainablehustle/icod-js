import { CryptoAPIUnavailableError } from './errors';

// Constants
export const PBKDF2_ITERATIONS = 100000;
export const SALT_LENGTH = 16; // 128 bits
export const IV_LENGTH = 12; // 96 bits for AES-GCM
export const KEY_LENGTH = 32; // 256 bits
export const CURRENT_VERSION = 1;

// Get crypto object that works in both browser and Node.js
declare const globalThis: any;

/**
 * Get the crypto object for the current environment
 */
function getCrypto(): Crypto | undefined {
  if (typeof globalThis !== 'undefined' && globalThis.crypto) {
    return globalThis.crypto;
  }
  if (typeof global !== 'undefined' && (global as any).crypto) {
    return (global as any).crypto;
  }
  if (typeof window !== 'undefined' && window.crypto) {
    return window.crypto;
  }
  return undefined;
}

/**
 * Check if the Web Crypto API is available in the current environment
 * @returns {boolean} True if Web Crypto API is available, false otherwise
 */
export function isWebCryptoAvailable(): boolean {
  const cryptoObj = getCrypto();
  return cryptoObj !== undefined && cryptoObj.subtle !== undefined;
}

/**
 * Ensure Web Crypto API is available, throw error if not
 * @throws {CryptoAPIUnavailableError} If Web Crypto API is not available
 */
export function ensureWebCrypto(): void {
  if (!isWebCryptoAvailable()) {
    throw new CryptoAPIUnavailableError();
  }
}

/**
 * Get the crypto object, ensuring it's available
 */
export function getWebCrypto(): Crypto {
  ensureWebCrypto();
  return getCrypto()!;
}

/**
 * Convert ArrayBuffer to Base64 string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert string to ArrayBuffer using UTF-8 encoding
 */
export function stringToArrayBuffer(str: string): ArrayBuffer {
  const encoder = new TextEncoder();
  return encoder.encode(str).buffer;
}

/**
 * Convert ArrayBuffer to string using UTF-8 decoding
 */
export function arrayBufferToString(buffer: ArrayBuffer): string {
  const decoder = new TextDecoder();
  return decoder.decode(buffer);
}

/**
 * Generate cryptographically secure random bytes
 */
export function generateRandomBytes(length: number): Uint8Array {
  const crypto = getWebCrypto();
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Constant-time comparison of two ArrayBuffers
 */
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