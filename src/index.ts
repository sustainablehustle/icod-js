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
  getWebCrypto,
  ensureWebCrypto,
  isWebCryptoAvailable,
  stringToArrayBuffer,
  arrayBufferToString,
  arrayBufferToBase64,
  base64ToArrayBuffer,
  generateRandomBytes,
  constantTimeCompare,
  PBKDF2_ITERATIONS,
  SALT_LENGTH,
  IV_LENGTH,
  KEY_LENGTH,
  CURRENT_VERSION
} from './crypto-utils';

async function deriveKey(passphrase: string, salt: ArrayBuffer): Promise<CryptoKey> {
  const crypto = getWebCrypto();

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
    true,
    ['encrypt', 'decrypt']
  );
}

async function computeKeyHash(key: CryptoKey): Promise<string> {
  const crypto = getWebCrypto();
  const rawKey = await crypto.subtle.exportKey('raw', key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', rawKey);
  return arrayBufferToBase64(hashBuffer);
}

export async function verifyPassphrase(
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

export { isWebCryptoAvailable };

export async function encrypt(
  plaintext: string,
  passphrase: string,
  options?: EncryptionOptions
): Promise<EncryptedData> {
  try {
    ensureWebCrypto();

    const salt = generateRandomBytes(SALT_LENGTH);

    const iv = generateRandomBytes(IV_LENGTH);

    const key = await deriveKey(passphrase, salt.buffer);

    const keyHash = await computeKeyHash(key);

    const plaintextBuffer = stringToArrayBuffer(plaintext);

    const crypto = getWebCrypto();
    const algorithmParams: any = {
      name: 'AES-GCM',
      iv: iv
    };

    if (options?.additionalData) {
      algorithmParams.additionalData = options.additionalData;
    }

    const ciphertextBuffer = await crypto.subtle.encrypt(
      algorithmParams,
      key,
      plaintextBuffer
    );

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

export async function decrypt(
  encryptedData: EncryptedData,
  passphrase: string,
  options?: EncryptionOptions
): Promise<string> {
  try {
    ensureWebCrypto();

    const requiredFields: (keyof EncryptedData)[] = ['ciphertext', 'iv', 'salt'];
    for (const field of requiredFields) {
      if (!encryptedData[field]) {
        throw new MissingFieldError(field);
      }
    }

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

    const key = await deriveKey(passphrase, saltBuffer);

    let plaintextBuffer: ArrayBuffer;
    try {
      const crypto = getWebCrypto();
      const algorithmParams: any = {
        name: 'AES-GCM',
        iv: ivBuffer
      };

      if (options?.additionalData) {
        algorithmParams.additionalData = options.additionalData;
      }

      plaintextBuffer = await crypto.subtle.decrypt(
        algorithmParams,
        key,
        ciphertextBuffer
      );
    } catch (error) {
      throw new CorruptedDataError('AES-GCM authentication failed');
    }

    return arrayBufferToString(plaintextBuffer);
  } catch (error) {
    if (error instanceof IcodError) {
      throw error;
    }
    throw new DecryptionFailedError(error instanceof Error ? error.message : 'Unknown error');
  }
}

export {
  IcodError,
  CryptoAPIUnavailableError,
  InvalidPassphraseError,
  CorruptedDataError,
  MissingFieldError,
  DecryptionFailedError,
  EncryptionFailedError
};

export type { EncryptedData, EncryptionOptions } from './types';

export { base64ToArrayBuffer } from './crypto-utils';
