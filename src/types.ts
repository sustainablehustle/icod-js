/**
 * Encrypted data structure containing all necessary components for decryption
 */
export interface EncryptedData {
  /** Base64-encoded ciphertext */
  ciphertext: string;
  /** Base64-encoded initialization vector (12 bytes) */
  iv: string;
  /** Base64-encoded salt for PBKDF2 key derivation */
  salt: string;
  /** Base64-encoded SHA-256 hash of the derived key for verification */
  keyHash: string;
  /** Version identifier for future compatibility */
  version: number;
}

/**
 * Options for encryption operations
 */
export interface EncryptionOptions {
  /** Optional additional authenticated data (AAD) for AES-GCM */
  additionalData?: ArrayBuffer;
}

/**
 * Result of a decryption operation
 */
export interface DecryptionResult {
  /** The decrypted plaintext */
  plaintext: string;
  /** Whether the key verification succeeded */
  keyVerified: boolean;
}