/**
 * How the AES-GCM key protecting a payload was obtained.
 *
 * - `passphrase` — derived from a human-chosen secret via PBKDF2. Carries a `salt`.
 * - `key`        — a raw 256-bit key supplied by the caller (ICOD's DEK). No salt,
 *                  because no derivation happened.
 *
 * The discriminator exists so that any validator, client or server, can tell the
 * two shapes apart without inferring it from the presence of `salt`.
 */
export type EncryptionMode = 'passphrase' | 'key';

export interface EncryptedData {
  ciphertext: string;
  iv: string;
  /**
   * PBKDF2 salt, base64. Present only in `passphrase` mode — raw-key encryption
   * derives nothing and so has no salt.
   */
  salt?: string;
  /**
   * base64 SHA-256 of the AES key. Lets a caller distinguish "wrong key" from
   * "damaged ciphertext" before attempting a decrypt, and lets a writer assert it
   * holds the right key before appending to an append-only history.
   */
  keyHash: string;
  version: number;
  /**
   * Absent on v1 payloads, which predate the discriminator and are always
   * passphrase-mode. Readers should treat `undefined` as `'passphrase'`.
   */
  mode?: EncryptionMode;
}

/**
 * Additional authenticated data. Not encrypted, but bound to the ciphertext: if it
 * differs at decrypt time, authentication fails. ICOD uses it to bind each payload
 * to its identity and position so a payload cannot be swapped, replayed, or rolled
 * back undetected.
 *
 * Strings are encoded as UTF-8, which is what ICOD's context strings assume.
 */
export interface EncryptionOptions {
  additionalData?: ArrayBuffer | Uint8Array | string;
}

/** An RSA-OAEP-3072 keypair, as returned by `generateKeyPair()`. */
export interface GeneratedKeyPair {
  /** Public half, safe to publish. Sent to the server so an owner can wrap a DEK to it. */
  publicKeyJwk: JsonWebKey;
  /** Private half as base64 PKCS#8. Must be encrypted before it leaves the browser. */
  privateKeyB64: string;
}

export interface DecryptionResult {
  plaintext: string;
  keyVerified: boolean;
}
