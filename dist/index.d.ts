import { EncryptedData, EncryptionOptions, GeneratedKeyPair } from './types';
import { IcodError, CryptoAPIUnavailableError, InvalidPassphraseError, InvalidKeyError, CorruptedDataError, MissingFieldError, DecryptionFailedError, EncryptionFailedError, KeyWrapError } from './errors';
import { isWebCryptoAvailable } from './crypto-utils';
/**
 * Generate a fresh 256-bit data encryption key, base64-encoded.
 *
 * In ICOD this is a vault's DEK: generated once, never rotated, and never sent to a
 * server in plaintext. Changing a password re-wraps this key; it does not replace it.
 */
export declare function generateDek(): string;
/**
 * base64 SHA-256 of a raw key, matching the `keyHash` written into every payload.
 *
 * This is what lets a writer assert it holds the right key *before* appending to an
 * append-only history. Without that check, a key that is wrong in memory produces a
 * version that is silently unreadable forever.
 */
export declare function keyHashOf(keyB64: string): Promise<string>;
export declare function encrypt(plaintext: string, passphrase: string, options?: EncryptionOptions): Promise<EncryptedData>;
export declare function decrypt(encryptedData: EncryptedData, passphrase: string, options?: EncryptionOptions): Promise<string>;
/**
 * Encrypt under a raw 256-bit key.
 *
 * Vault content is protected by the DEK, not by a passphrase, so running PBKDF2 over
 * an already-random key on every save would be both wasteful and semantically wrong.
 * No derivation happens here, so the result carries no `salt`.
 */
export declare function encryptWithKey(plaintext: string, keyB64: string, options?: EncryptionOptions): Promise<EncryptedData>;
export declare function decryptWithKey(encryptedData: EncryptedData, keyB64: string, options?: EncryptionOptions): Promise<string>;
/**
 * Check a passphrase against a payload's stored `keyHash`, without decrypting.
 *
 * Takes the whole payload rather than a bare salt so it has `salt`, `keyHash` and
 * `version` in one argument, which is what makes it correctly version-aware — a
 * signature taking only a salt cannot know how many iterations to run and would
 * silently return false for every v1 payload once the iteration count changed.
 */
export declare function verifyPassphrase(passphrase: string, data: EncryptedData): Promise<boolean>;
/**
 * Check a raw key against a payload's stored `keyHash`, without decrypting.
 *
 * This is the write-path assertion: call it with the in-memory DEK before appending a
 * new version, and refuse the write if it fails.
 *
 * Returns a promise rather than a plain boolean because Web Crypto's digest is
 * asynchronous — there is no synchronous SHA-256 available without shipping our own.
 */
export declare function verifyKey(keyB64: string, data: EncryptedData): Promise<boolean>;
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
export declare function generateKeyPair(): Promise<GeneratedKeyPair>;
/** Encrypt a raw key to someone's public key. The result is safe to hand to the server. */
export declare function wrapKey(keyB64: string, publicKeyJwk: JsonWebKey): Promise<string>;
/** Recover a raw key from its wrapped form using the matching private key. */
export declare function unwrapKey(wrapped: string, privateKeyB64: string): Promise<string>;
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
export declare function publicKeyFingerprint(publicKeyJwk: JsonWebKey): Promise<string>;
export { isWebCryptoAvailable };
export { IcodError, CryptoAPIUnavailableError, InvalidPassphraseError, InvalidKeyError, CorruptedDataError, MissingFieldError, DecryptionFailedError, EncryptionFailedError, KeyWrapError };
export type { EncryptedData, EncryptionMode, EncryptionOptions, GeneratedKeyPair } from './types';
export { base64ToArrayBuffer, arrayBufferToBase64, CURRENT_VERSION, PBKDF2_ITERATIONS, PBKDF2_ITERATIONS_V1 } from './crypto-utils';
//# sourceMappingURL=index.d.ts.map