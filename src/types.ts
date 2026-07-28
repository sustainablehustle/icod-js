export interface EncryptedData {
  ciphertext: string;
  iv: string;
  salt: string;
  keyHash: string;
  version: number;
}

export interface EncryptionOptions {
  additionalData?: ArrayBuffer;
}

export interface DecryptionResult {
  plaintext: string;
  keyVerified: boolean;
}
