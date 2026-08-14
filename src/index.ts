import { EncryptedData, EncryptionMode, EncryptionOptions, GeneratedKeyPair } from './types';
import {
  IcodError,
  CryptoAPIUnavailableError,
  InvalidPassphraseError,
  InvalidKeyError,
  CorruptedDataError,
  MissingFieldError,
  DecryptionFailedError,
  EncryptionFailedError,
  KeyWrapError
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
  normaliseAdditionalData,
  iterationsForVersion,
  toBase32,
  groupFingerprint,
  SALT_LENGTH,
  IV_LENGTH,
  KEY_LENGTH,
  CURRENT_VERSION,
  RSA_MODULUS_LENGTH,
  RSA_HASH,
  RSA_JWK_ALG,
  FINGERPRINT_BYTES
} from './crypto-utils';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

async function deriveKey(
  passphrase: string,
  salt: ArrayBuffer,
  iterations: number
): Promise<CryptoKey> {
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
      iterations: iterations,
      hash: 'SHA-256'
    },
    passphraseKey,
    { name: 'AES-GCM', length: KEY_LENGTH * 8 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function sha256Base64(bytes: ArrayBuffer): Promise<string> {
  const crypto = getWebCrypto();
  return arrayBufferToBase64(await crypto.subtle.digest('SHA-256', bytes));
}

async function computeKeyHash(key: CryptoKey): Promise<string> {
  const crypto = getWebCrypto();
  return sha256Base64(await crypto.subtle.exportKey('raw', key));
}

/** Which decrypt path a payload belongs to. v1 payloads predate the field and are always passphrase-mode. */
function resolveMode(data: EncryptedData): EncryptionMode {
  return data.mode ?? 'passphrase';
}

function assertMode(data: EncryptedData, expected: EncryptionMode): void {
  const actual = resolveMode(data);
  if (actual !== expected) {
    throw new IcodError(
      expected === 'passphrase'
        ? 'This payload was encrypted with a raw key. Use decryptWithKey() instead of decrypt().'
        : 'This payload was encrypted with a passphrase. Use decrypt() instead of decryptWithKey().',
      'WRONG_DECRYPT_MODE'
    );
  }
}

function requireFields(data: EncryptedData, fields: (keyof EncryptedData)[]): void {
  for (const field of fields) {
    if (!data[field]) {
      throw new MissingFieldError(field);
    }
  }
}

function aesParams(iv: ArrayBuffer | Uint8Array, options?: EncryptionOptions): AesGcmParams {
  const params: AesGcmParams = { name: 'AES-GCM', iv: iv as BufferSource };
  const additionalData = normaliseAdditionalData(options?.additionalData);
  if (additionalData) {
    params.additionalData = additionalData;
  }
  return params;
}

// ---------------------------------------------------------------------------
// Raw-key material
// ---------------------------------------------------------------------------

/**
 * Generate a fresh 256-bit data encryption key, base64-encoded.
 *
 * In ICOD this is a vault's DEK: generated once, never rotated, and never sent to a
 * server in plaintext. Changing a password re-wraps this key; it does not replace it.
 */
export function generateDek(): string {
  return arrayBufferToBase64(generateRandomBytes(KEY_LENGTH).buffer as ArrayBuffer);
}

/**
 * base64 SHA-256 of a raw key, matching the `keyHash` written into every payload.
 *
 * This is what lets a writer assert it holds the right key *before* appending to an
 * append-only history. Without that check, a key that is wrong in memory produces a
 * version that is silently unreadable forever.
 */
export async function keyHashOf(keyB64: string): Promise<string> {
  ensureWebCrypto();
  return sha256Base64(base64ToArrayBuffer(keyB64));
}

async function importAesKey(keyB64: string): Promise<CryptoKey> {
  const raw = base64ToArrayBuffer(keyB64);
  if (raw.byteLength !== KEY_LENGTH) {
    throw new IcodError(
      `Expected a ${KEY_LENGTH}-byte key, got ${raw.byteLength} bytes.`,
      'INVALID_KEY_LENGTH'
    );
  }
  const crypto = getWebCrypto();
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt'
  ]);
}

// ---------------------------------------------------------------------------
// Passphrase-based encryption (v1-compatible on read, v2 on write)
// ---------------------------------------------------------------------------

export async function encrypt(
  plaintext: string,
  passphrase: string,
  options?: EncryptionOptions
): Promise<EncryptedData> {
  try {
    ensureWebCrypto();

    const salt = generateRandomBytes(SALT_LENGTH);
    const iv = generateRandomBytes(IV_LENGTH);

    const key = await deriveKey(
      passphrase,
      salt.buffer as ArrayBuffer,
      iterationsForVersion(CURRENT_VERSION)
    );
    const keyHash = await computeKeyHash(key);

    const crypto = getWebCrypto();
    const ciphertextBuffer = await crypto.subtle.encrypt(
      aesParams(iv, options),
      key,
      stringToArrayBuffer(plaintext)
    );

    return {
      ciphertext: arrayBufferToBase64(ciphertextBuffer),
      iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
      salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
      keyHash: keyHash,
      version: CURRENT_VERSION,
      mode: 'passphrase'
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
    assertMode(encryptedData, 'passphrase');
    requireFields(encryptedData, ['ciphertext', 'iv', 'salt']);

    let saltBuffer: ArrayBuffer;
    let ivBuffer: ArrayBuffer;
    let ciphertextBuffer: ArrayBuffer;

    try {
      saltBuffer = base64ToArrayBuffer(encryptedData.salt!);
      ivBuffer = base64ToArrayBuffer(encryptedData.iv);
      ciphertextBuffer = base64ToArrayBuffer(encryptedData.ciphertext);
    } catch (error) {
      throw new CorruptedDataError('Invalid base64 encoding');
    }

    const key = await deriveKey(
      passphrase,
      saltBuffer,
      iterationsForVersion(encryptedData.version)
    );

    // Verify the key before touching the ciphertext, so that a wrong passphrase
    // surfaces as InvalidPassphraseError rather than as an indistinguishable
    // AES-GCM tag failure. The comparison is constant-time. Because the key derives
    // from both passphrase and salt, a tampered salt or keyHash also fails here.
    if (encryptedData.keyHash) {
      const computedKeyHash = await computeKeyHash(key);
      if (
        !constantTimeCompare(
          base64ToArrayBuffer(encryptedData.keyHash),
          base64ToArrayBuffer(computedKeyHash)
        )
      ) {
        throw new InvalidPassphraseError();
      }
    }

    let plaintextBuffer: ArrayBuffer;
    try {
      const crypto = getWebCrypto();
      plaintextBuffer = await crypto.subtle.decrypt(
        aesParams(ivBuffer, options),
        key,
        ciphertextBuffer
      );
    } catch (error) {
      // The key is verified correct, so this is genuine corruption, tampering, or a
      // mismatched AAD context.
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

// ---------------------------------------------------------------------------
// Raw-key encryption — used for vault content, which is protected by the DEK
// ---------------------------------------------------------------------------

/**
 * Encrypt under a raw 256-bit key.
 *
 * Vault content is protected by the DEK, not by a passphrase, so running PBKDF2 over
 * an already-random key on every save would be both wasteful and semantically wrong.
 * No derivation happens here, so the result carries no `salt`.
 */
export async function encryptWithKey(
  plaintext: string,
  keyB64: string,
  options?: EncryptionOptions
): Promise<EncryptedData> {
  try {
    ensureWebCrypto();

    const key = await importAesKey(keyB64);
    const iv = generateRandomBytes(IV_LENGTH);

    const crypto = getWebCrypto();
    const ciphertextBuffer = await crypto.subtle.encrypt(
      aesParams(iv, options),
      key,
      stringToArrayBuffer(plaintext)
    );

    return {
      ciphertext: arrayBufferToBase64(ciphertextBuffer),
      iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
      keyHash: await keyHashOf(keyB64),
      version: CURRENT_VERSION,
      mode: 'key'
    };
  } catch (error) {
    if (error instanceof IcodError) {
      throw error;
    }
    throw new EncryptionFailedError(error instanceof Error ? error.message : 'Unknown error');
  }
}

export async function decryptWithKey(
  encryptedData: EncryptedData,
  keyB64: string,
  options?: EncryptionOptions
): Promise<string> {
  try {
    ensureWebCrypto();
    assertMode(encryptedData, 'key');
    requireFields(encryptedData, ['ciphertext', 'iv']);

    let ivBuffer: ArrayBuffer;
    let ciphertextBuffer: ArrayBuffer;

    try {
      ivBuffer = base64ToArrayBuffer(encryptedData.iv);
      ciphertextBuffer = base64ToArrayBuffer(encryptedData.ciphertext);
    } catch (error) {
      throw new CorruptedDataError('Invalid base64 encoding');
    }

    // Same discipline as the passphrase path: establish the key is right before
    // blaming the data.
    if (encryptedData.keyHash) {
      const computedKeyHash = await keyHashOf(keyB64);
      if (
        !constantTimeCompare(
          base64ToArrayBuffer(encryptedData.keyHash),
          base64ToArrayBuffer(computedKeyHash)
        )
      ) {
        throw new InvalidKeyError();
      }
    }

    const key = await importAesKey(keyB64);

    let plaintextBuffer: ArrayBuffer;
    try {
      const crypto = getWebCrypto();
      plaintextBuffer = await crypto.subtle.decrypt(
        aesParams(ivBuffer, options),
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

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Check a passphrase against a payload's stored `keyHash`, without decrypting.
 *
 * Takes the whole payload rather than a bare salt so it has `salt`, `keyHash` and
 * `version` in one argument, which is what makes it correctly version-aware — a
 * signature taking only a salt cannot know how many iterations to run and would
 * silently return false for every v1 payload once the iteration count changed.
 */
export async function verifyPassphrase(
  passphrase: string,
  data: EncryptedData
): Promise<boolean> {
  ensureWebCrypto();
  requireFields(data, ['salt', 'keyHash']);

  const key = await deriveKey(
    passphrase,
    base64ToArrayBuffer(data.salt!),
    iterationsForVersion(data.version)
  );

  return constantTimeCompare(
    base64ToArrayBuffer(data.keyHash),
    base64ToArrayBuffer(await computeKeyHash(key))
  );
}

/**
 * Check a raw key against a payload's stored `keyHash`, without decrypting.
 *
 * This is the write-path assertion: call it with the in-memory DEK before appending a
 * new version, and refuse the write if it fails.
 *
 * Returns a promise rather than a plain boolean because Web Crypto's digest is
 * asynchronous — there is no synchronous SHA-256 available without shipping our own.
 */
export async function verifyKey(keyB64: string, data: EncryptedData): Promise<boolean> {
  ensureWebCrypto();
  requireFields(data, ['keyHash']);

  return constantTimeCompare(
    base64ToArrayBuffer(data.keyHash),
    base64ToArrayBuffer(await keyHashOf(keyB64))
  );
}

// ---------------------------------------------------------------------------
// Asymmetric key wrapping
// ---------------------------------------------------------------------------

function publicJwkForImport(jwk: JsonWebKey): JsonWebKey {
  if (jwk?.kty !== 'RSA' || !jwk.n || !jwk.e) {
    throw new KeyWrapError('Not an RSA public JWK');
  }
  // Rebuild a minimal JWK rather than importing whatever was handed to us. Extraneous
  // or inconsistent fields (key_ops, use, alg from a different curve) make importKey
  // throw, and a canonical shape keeps the fingerprint stable across round-trips.
  return { kty: 'RSA', n: jwk.n, e: jwk.e, alg: RSA_JWK_ALG, ext: true };
}

async function importPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
  const crypto = getWebCrypto();
  return crypto.subtle.importKey(
    'jwk',
    publicJwkForImport(jwk),
    { name: 'RSA-OAEP', hash: RSA_HASH },
    true,
    ['encrypt']
  );
}

/**
 * Generate a fresh RSA-OAEP-3072 keypair.
 *
 * This is the only mechanism that moves a DEK from an owner's browser to a trustee's
 * browser through a server that must not be able to read it, without the owner acting
 * as a courier for a shared secret.
 *
 * RSA-OAEP rather than ECDH+HKDF: Web Crypto supports it natively with no extra
 * derivation step, so there is less implementation surface to get wrong.
 */
export async function generateKeyPair(): Promise<GeneratedKeyPair> {
  try {
    const crypto = getWebCrypto();

    const pair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: RSA_MODULUS_LENGTH,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: RSA_HASH
      },
      true,
      ['encrypt', 'decrypt']
    );

    const publicKeyJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', pair.privateKey);

    return {
      publicKeyJwk: publicJwkForImport(publicKeyJwk),
      privateKeyB64: arrayBufferToBase64(privateKeyBuffer)
    };
  } catch (error) {
    if (error instanceof IcodError) {
      throw error;
    }
    throw new KeyWrapError(error instanceof Error ? error.message : 'Unknown error');
  }
}

/** Encrypt a raw key to someone's public key. The result is safe to hand to the server. */
export async function wrapKey(keyB64: string, publicKeyJwk: JsonWebKey): Promise<string> {
  try {
    const crypto = getWebCrypto();
    const publicKey = await importPublicKey(publicKeyJwk);
    const wrapped = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      publicKey,
      base64ToArrayBuffer(keyB64)
    );
    return arrayBufferToBase64(wrapped);
  } catch (error) {
    if (error instanceof IcodError) {
      throw error;
    }
    throw new KeyWrapError(error instanceof Error ? error.message : 'Unknown error');
  }
}

/** Recover a raw key from its wrapped form using the matching private key. */
export async function unwrapKey(wrapped: string, privateKeyB64: string): Promise<string> {
  try {
    const crypto = getWebCrypto();
    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      base64ToArrayBuffer(privateKeyB64),
      { name: 'RSA-OAEP', hash: RSA_HASH },
      false,
      ['decrypt']
    );
    const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, base64ToArrayBuffer(wrapped));
    return arrayBufferToBase64(raw);
  } catch (error) {
    if (error instanceof IcodError) {
      throw error;
    }
    throw new KeyWrapError(error instanceof Error ? error.message : 'Unknown error');
  }
}

/**
 * A short, human-readable fingerprint of a public key.
 *
 * This is the entire defence against a compromised server substituting its own public
 * key at arming time and receiving a DEK it can decrypt. Two humans compare this
 * string over a channel that is not ICOD; nothing else in the system can detect that
 * substitution.
 *
 * Computed over the SPKI encoding rather than the JWK so it is independent of JSON
 * field ordering and of any extraneous JWK members.
 */
export async function publicKeyFingerprint(publicKeyJwk: JsonWebKey): Promise<string> {
  try {
    const crypto = getWebCrypto();
    const publicKey = await importPublicKey(publicKeyJwk);
    const spki = await crypto.subtle.exportKey('spki', publicKey);
    const digest = await crypto.subtle.digest('SHA-256', spki);
    const truncated = new Uint8Array(digest).slice(0, FINGERPRINT_BYTES);
    return groupFingerprint(toBase32(truncated));
  } catch (error) {
    if (error instanceof IcodError) {
      throw error;
    }
    throw new KeyWrapError(error instanceof Error ? error.message : 'Unknown error');
  }
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export { isWebCryptoAvailable };

export {
  IcodError,
  CryptoAPIUnavailableError,
  InvalidPassphraseError,
  InvalidKeyError,
  CorruptedDataError,
  MissingFieldError,
  DecryptionFailedError,
  EncryptionFailedError,
  KeyWrapError
};

export type {
  EncryptedData,
  EncryptionMode,
  EncryptionOptions,
  GeneratedKeyPair
} from './types';

export {
  base64ToArrayBuffer,
  arrayBufferToBase64,
  CURRENT_VERSION,
  PBKDF2_ITERATIONS,
  PBKDF2_ITERATIONS_V1
} from './crypto-utils';
