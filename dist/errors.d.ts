export declare class IcodError extends Error {
    readonly code: string;
    constructor(message: string, code: string);
}
export declare class CryptoAPIUnavailableError extends IcodError {
    constructor();
}
/**
 * The supplied passphrase does not match the payload's `keyHash`.
 *
 * Distinct from `CorruptedDataError` on purpose: on a product whose worst failure
 * mode is permanent data loss, telling someone who mistyped their password that
 * their data looks tampered with is unacceptable. Nothing is wrong with the data.
 */
export declare class InvalidPassphraseError extends IcodError {
    constructor();
}
/**
 * The supplied raw key does not match the payload's `keyHash`.
 *
 * The raw-key counterpart of `InvalidPassphraseError`. Kept separate because the two
 * mean different things to the caller: a wrong passphrase is a human mistyping, while
 * a wrong key is a bug, a stale tab, or the wrong vault's key in memory — and those
 * want different copy and different handling.
 */
export declare class InvalidKeyError extends IcodError {
    constructor();
}
/**
 * The key was verified correct and the ciphertext still failed to authenticate.
 *
 * This is the real corruption path: the data is damaged or has been tampered with.
 * Callers should alert, log, refuse to overwrite, and surface support contact.
 */
export declare class CorruptedDataError extends IcodError {
    constructor(details: string);
}
export declare class MissingFieldError extends IcodError {
    constructor(fieldName: string);
}
export declare class DecryptionFailedError extends IcodError {
    constructor(details?: string);
}
export declare class EncryptionFailedError extends IcodError {
    constructor(details?: string);
}
/** An RSA-OAEP wrap or unwrap failed — a malformed key, or the wrong private key. */
export declare class KeyWrapError extends IcodError {
    constructor(details?: string);
}
//# sourceMappingURL=errors.d.ts.map