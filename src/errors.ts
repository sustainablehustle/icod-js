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

export class InvalidPassphraseError extends IcodError {
  constructor() {
    super(
      'The provided passphrase is incorrect. The key hash verification failed.',
      'INVALID_PASSPHRASE'
    );
    this.name = 'InvalidPassphraseError';
  }
}

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
