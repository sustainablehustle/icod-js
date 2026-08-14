export class IcodError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'IcodError';
  }
}

export class CryptoAPIUnavailableError extends IcodError {
  constructor() {
    super(
      'Web Crypto API is not available in this environment. Please ensure you are using HTTPS and a modern browser.',
      'CRYPTO_API_UNAVAILABLE'
    );
    this.name = 'CryptoAPIUnavailableError';
  }
}

/**
 * The supplied passphrase does not match the payload's `keyHash`.
 *
 * Distinct from `CorruptedDataError` on purpose: on a product whose worst failure
 * mode is permanent data loss, telling someone who mistyped their password that
 * their data looks tampered with is unacceptable. Nothing is wrong with the data.
 */
export class InvalidPassphraseError extends IcodError {
  constructor() {
    super(
      'The provided passphrase is incorrect. The key hash verification failed.',
      'INVALID_PASSPHRASE'
    );
    this.name = 'InvalidPassphraseError';
  }
}

/**
 * The supplied raw key does not match the payload's `keyHash`.
 *
 * The raw-key counterpart of `InvalidPassphraseError`. Kept separate because the two
 * mean different things to the caller: a wrong passphrase is a human mistyping, while
 * a wrong key is a bug, a stale tab, or the wrong vault's key in memory — and those
 * want different copy and different handling.
 */
export class InvalidKeyError extends IcodError {
  constructor() {
    super(
      'The provided key does not match this payload. The key hash verification failed.',
      'INVALID_KEY'
    );
    this.name = 'InvalidKeyError';
  }
}

/**
 * The key was verified correct and the ciphertext still failed to authenticate.
 *
 * This is the real corruption path: the data is damaged or has been tampered with.
 * Callers should alert, log, refuse to overwrite, and surface support contact.
 */
export class CorruptedDataError extends IcodError {
  constructor(details: string) {
    super(
      `The encrypted data appears to be corrupted or tampered with: ${details}`,
      'CORRUPTED_DATA'
    );
    this.name = 'CorruptedDataError';
  }
}

export class MissingFieldError extends IcodError {
  constructor(fieldName: string) {
    super(
      `Required field '${fieldName}' is missing from the encrypted data structure.`,
      'MISSING_FIELD'
    );
    this.name = 'MissingFieldError';
  }
}

export class DecryptionFailedError extends IcodError {
  constructor(details?: string) {
    super(
      `Decryption failed${details ? `: ${details}` : '. This may be due to corrupted data or incorrect parameters.'}`,
      'DECRYPTION_FAILED'
    );
    this.name = 'DecryptionFailedError';
  }
}

export class EncryptionFailedError extends IcodError {
  constructor(details?: string) {
    super(`Encryption failed${details ? `: ${details}` : '.'}`, 'ENCRYPTION_FAILED');
    this.name = 'EncryptionFailedError';
  }
}

/** An RSA-OAEP wrap or unwrap failed — a malformed key, or the wrong private key. */
export class KeyWrapError extends IcodError {
  constructor(details?: string) {
    super(
      `Key wrapping operation failed${details ? `: ${details}` : '.'}`,
      'KEY_WRAP_FAILED'
    );
    this.name = 'KeyWrapError';
  }
}
