/// <reference lib="dom" />

import { EncryptedData, EncryptionOptions } from './types';
import {
  IcodError,
  CryptoAPIUnavailableError,
  InvalidPassphraseError,
  CorruptedDataError,
  MissingFieldError,
  DecryptionFailedError,
  EncryptionFailedError
} from './errors';
import {
  isWebCryptoAvailable,
  ensureWebCrypto,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  stringToArrayBuffer,
  arrayBufferToString,
  generateRandomBytes,
  constantTimeCompare,
  PBKDF2_ITERATIONS,
  SALT_LENGTH,
  IV_LENGTH,
  KEY_LENGTH,
  CURRENT_VERSION
} from './crypto-utils';

/**
 * Derive an encryption key from a passphrase using PBKDF2
 * @param passphrase - The user's passphrase
 * @param salt - The salt for key derivation
 * @returns The derived CryptoKey
 */
async function deriveKey(passphrase: string, salt: ArrayBuffer): Promise<CryptoKey> {
  ensureWebCrypto();

  const passphraseKey = await crypto.subtle.importKey(
    'raw',
    stringToArrayBuffer(passphrase),
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    passphraseKey,
    { name: 'AES-GCM', length: KEY_LENGTH * 8 },
    true, // Make key extractable so we can compute its hash
    ['encrypt', 'decrypt']
  );
}

/**
 * Compute SHA-256 hash of a key for verification
 * @param key - The CryptoKey to hash
 * @returns Base64-encoded hash
 */
async function computeKeyHash(key: CryptoKey): Promise<string> {
  // Export the key to raw format
  const rawKey = await crypto.subtle.exportKey('raw', key);
  // Hash the raw key
  const hashBuffer = await crypto.subtle.digest('SHA-256', rawKey);
  return arrayBufferToBase64(hashBuffer);
}

/**
 * Verify if the provided passphrase matches the stored key hash
 * @param passphrase - The user's passphrase
 * @param salt - The salt used for key derivation
 * @param storedKeyHash - The stored key hash to compare against
 * @returns True if the passphrase is correct
 */
async function verifyPassphrase(
  passphrase: string,
  salt: ArrayBuffer,
  storedKeyHash: string
): Promise<boolean> {
  const key = await deriveKey(passphrase, salt);
  const computedHash = await computeKeyHash(key);
  const storedHashBuffer = base64ToArrayBuffer(storedKeyHash);
  const computedHashBuffer = base64ToArrayBuffer(computedHash);
  
  return constantTimeCompare(storedHashBuffer, computedHashBuffer);
}

/**
 * Check if the Web Crypto API is available in the current environment
 * @returns {boolean} True if Web Crypto API is available, false otherwise
 */
export { isWebCryptoAvailable };

/**
 * Encrypt plaintext using AES-GCM with a passphrase-derived key
 * @param plaintext - The text to encrypt
 * @param passphrase - The passphrase for encryption
 * @param options - Optional encryption options
 * @returns The encrypted data structure
 * @throws {CryptoAPIUnavailableError} If Web Crypto API is not available
 * @throws {EncryptionFailedError} If encryption fails
 */
export async function encrypt(
  plaintext: string,
  passphrase: string,
  options?: EncryptionOptions
): Promise<EncryptedData> {
  try {
    ensureWebCrypto();

    // Generate random salt and IV
    const salt = generateRandomBytes(SALT_LENGTH);
    const iv = generateRandomBytes(IV_LENGTH);

    // Derive key from passphrase
    const key = await deriveKey(passphrase, salt.buffer);

    // Compute key hash for verification
    const keyHash = await computeKeyHash(key);

    // Convert plaintext to ArrayBuffer
    const plaintextBuffer = stringToArrayBuffer(plaintext);

    // Encrypt using AES-GCM
    const ciphertextBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        additionalData: options?.additionalData
      },
      key,
      plaintextBuffer
    );

    // Return encrypted data structure
    return {
      ciphertext: arrayBufferToBase64(ciphertextBuffer),
      iv: arrayBufferToBase64(iv.buffer),
      salt: arrayBufferToBase64(salt.buffer),
      keyHash: keyHash,
      version: CURRENT_VERSION
    };
  } catch (error) {
    if (error instanceof IcodError) {
      throw error;
    }
    throw new EncryptionFailedError(error instanceof Error ? error.message : 'Unknown error');
  }
}

/**
 * Decrypt ciphertext using AES-GCM with a passphrase-derived key
 * @param encryptedData - The encrypted data structure
 * @param passphrase - The passphrase for decryption
 * @param options - Optional decryption options (must match encryption options)
 * @returns The decrypted plaintext
 * @throws {CryptoAPIUnavailableError} If Web Crypto API is not available
 * @throws {InvalidPassphraseError} If the passphrase is incorrect
 * @throws {MissingFieldError} If required fields are missing
 * @throws {CorruptedDataError} If the data appears corrupted
 * @throws {DecryptionFailedError} If decryption fails
 */
export async function decrypt(
  encryptedData: EncryptedData,
  passphrase: string,
  options?: EncryptionOptions
): Promise<string> {
  try {
    ensureWebCrypto();

    // Validate required fields
    const requiredFields: (keyof EncryptedData)[] = ['ciphertext', 'iv', 'salt', 'keyHash', 'version'];
    for (const field of requiredFields) {
      if (!encryptedData[field]) {
        throw new MissingFieldError(field);
      }
    }

    // Check version compatibility
    if (encryptedData.version !== CURRENT_VERSION) {
      throw new CorruptedDataError(`Unsupported version: ${encryptedData.version}`);
    }

    // Convert base64 strings to ArrayBuffers
    let saltBuffer: ArrayBuffer;
    let ivBuffer: ArrayBuffer;
    let ciphertextBuffer: ArrayBuffer;

    try {
      saltBuffer = base64ToArrayBuffer(encryptedData.salt);
      ivBuffer = base64ToArrayBuffer(encryptedData.iv);
      ciphertextBuffer = base64ToArrayBuffer(encryptedData.ciphertext);
    } catch (error) {
      throw new CorruptedDataError('Invalid base64 encoding');
    }

    // Verify passphrase before attempting decryption
    const isValid = await verifyPassphrase(passphrase, saltBuffer, encryptedData.keyHash);
    if (!isValid) {
      throw new InvalidPassphraseError();
    }

    // Derive key from passphrase
    const key = await deriveKey(passphrase, saltBuffer);

    // Decrypt using AES-GCM
    let plaintextBuffer: ArrayBuffer;
    try {
      plaintextBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: ivBuffer,
          additionalData: options?.additionalData
        },
        key,
        ciphertextBuffer
      );
    } catch (error) {
      // If decryption fails after key verification passed, data is likely corrupted
      throw new CorruptedDataError('AES-GCM authentication failed');
    }

    // Convert ArrayBuffer back to string
    return arrayBufferToString(plaintextBuffer);
  } catch (error) {
    if (error instanceof IcodError) {
      throw error;
    }
    throw new DecryptionFailedError(error instanceof Error ? error.message : 'Unknown error');
  }
}

// Export all error types for consumer use
export {
  IcodError,
  CryptoAPIUnavailableError,
  InvalidPassphraseError,
  CorruptedDataError,
  MissingFieldError,
  DecryptionFailedError,
  EncryptionFailedError
};

// Export types
export type { EncryptedData, EncryptionOptions } from './types';