/**
 * Base error class for icod-js errors
 */
export class IcodError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = 'IcodError';
  }
}

/**
 * Thrown when the Web Crypto API is not available
 */
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
 * Thrown when an invalid passphrase is provided during decryption
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
 * Thrown when encrypted data is corrupted or tampered with
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

/**
 * Thrown when required fields are missing from encrypted data
 */
export class MissingFieldError extends IcodError {
  constructor(fieldName: string) {
    super(
      `Required field '${fieldName}' is missing from the encrypted data structure.`,
      'MISSING_FIELD'
    );
    this.name = 'MissingFieldError';
  }
}

/**
 * Thrown when decryption fails due to cryptographic errors
 */
export class DecryptionFailedError extends IcodError {
  constructor(details?: string) {
    super(
      `Decryption failed${details ? `: ${details}` : '. This may be due to corrupted data or incorrect parameters.'}`,
      'DECRYPTION_FAILED'
    );
    this.name = 'DecryptionFailedError';
  }
}

/**
 * Thrown when encryption fails
 */
export class EncryptionFailedError extends IcodError {
  constructor(details?: string) {
    super(
      `Encryption failed${details ? `: ${details}` : '.'}`,
      'ENCRYPTION_FAILED'
    );
    this.name = 'EncryptionFailedError';
  }
}