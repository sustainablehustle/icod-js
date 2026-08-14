"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.KeyWrapError = exports.EncryptionFailedError = exports.DecryptionFailedError = exports.MissingFieldError = exports.CorruptedDataError = exports.InvalidKeyError = exports.InvalidPassphraseError = exports.CryptoAPIUnavailableError = exports.IcodError = void 0;
class IcodError extends Error {
    constructor(message, code) {
        super(message);
        this.code = code;
        this.name = 'IcodError';
    }
}
exports.IcodError = IcodError;
class CryptoAPIUnavailableError extends IcodError {
    constructor() {
        super('Web Crypto API is not available in this environment. Please ensure you are using HTTPS and a modern browser.', 'CRYPTO_API_UNAVAILABLE');
        this.name = 'CryptoAPIUnavailableError';
    }
}
exports.CryptoAPIUnavailableError = CryptoAPIUnavailableError;
/**
 * The supplied passphrase does not match the payload's `keyHash`.
 *
 * Distinct from `CorruptedDataError` on purpose: on a product whose worst failure
 * mode is permanent data loss, telling someone who mistyped their password that
 * their data looks tampered with is unacceptable. Nothing is wrong with the data.
 */
class InvalidPassphraseError extends IcodError {
    constructor() {
        super('The provided passphrase is incorrect. The key hash verification failed.', 'INVALID_PASSPHRASE');
        this.name = 'InvalidPassphraseError';
    }
}
exports.InvalidPassphraseError = InvalidPassphraseError;
/**
 * The supplied raw key does not match the payload's `keyHash`.
 *
 * The raw-key counterpart of `InvalidPassphraseError`. Kept separate because the two
 * mean different things to the caller: a wrong passphrase is a human mistyping, while
 * a wrong key is a bug, a stale tab, or the wrong vault's key in memory — and those
 * want different copy and different handling.
 */
class InvalidKeyError extends IcodError {
    constructor() {
        super('The provided key does not match this payload. The key hash verification failed.', 'INVALID_KEY');
        this.name = 'InvalidKeyError';
    }
}
exports.InvalidKeyError = InvalidKeyError;
/**
 * The key was verified correct and the ciphertext still failed to authenticate.
 *
 * This is the real corruption path: the data is damaged or has been tampered with.
 * Callers should alert, log, refuse to overwrite, and surface support contact.
 */
class CorruptedDataError extends IcodError {
    constructor(details) {
        super(`The encrypted data appears to be corrupted or tampered with: ${details}`, 'CORRUPTED_DATA');
        this.name = 'CorruptedDataError';
    }
}
exports.CorruptedDataError = CorruptedDataError;
class MissingFieldError extends IcodError {
    constructor(fieldName) {
        super(`Required field '${fieldName}' is missing from the encrypted data structure.`, 'MISSING_FIELD');
        this.name = 'MissingFieldError';
    }
}
exports.MissingFieldError = MissingFieldError;
class DecryptionFailedError extends IcodError {
    constructor(details) {
        super(`Decryption failed${details ? `: ${details}` : '. This may be due to corrupted data or incorrect parameters.'}`, 'DECRYPTION_FAILED');
        this.name = 'DecryptionFailedError';
    }
}
exports.DecryptionFailedError = DecryptionFailedError;
class EncryptionFailedError extends IcodError {
    constructor(details) {
        super(`Encryption failed${details ? `: ${details}` : '.'}`, 'ENCRYPTION_FAILED');
        this.name = 'EncryptionFailedError';
    }
}
exports.EncryptionFailedError = EncryptionFailedError;
/** An RSA-OAEP wrap or unwrap failed — a malformed key, or the wrong private key. */
class KeyWrapError extends IcodError {
    constructor(details) {
        super(`Key wrapping operation failed${details ? `: ${details}` : '.'}`, 'KEY_WRAP_FAILED');
        this.name = 'KeyWrapError';
    }
}
exports.KeyWrapError = KeyWrapError;
//# sourceMappingURL=errors.js.map