/**
 * PBKDF2 iteration count for v2 payloads.
 *
 * OWASP's current floor for PBKDF2-SHA256 is 600,000. v1 shipped 100,000, which is
 * why `decrypt` reads the iteration count from the payload's `version` rather than a
 * module constant — see `iterationsForVersion`.
 */
export declare const PBKDF2_ITERATIONS = 600000;
/** Iteration count used by v1 payloads. Retained so v1 blobs stay readable forever. */
export declare const PBKDF2_ITERATIONS_V1 = 100000;
export declare const SALT_LENGTH = 16;
export declare const IV_LENGTH = 12;
export declare const KEY_LENGTH = 32;
export declare const CURRENT_VERSION = 2;
/** RSA-OAEP parameters. 3072 is the floor; 2048 is not acceptable for this use. */
export declare const RSA_MODULUS_LENGTH = 3072;
export declare const RSA_HASH = "SHA-256";
export declare const RSA_JWK_ALG = "RSA-OAEP-256";
/**
 * Bytes of SHA-256 output retained in a public key fingerprint.
 *
 * 15 bytes is 120 bits, which base32-encodes to exactly 24 characters with no
 * padding — six groups of four, which is what a human reads aloud over the phone.
 * 120 bits is far beyond what a second-preimage attack could reach.
 */
export declare const FINGERPRINT_BYTES = 15;
/**
 * Resolve the PBKDF2 iteration count for a payload version.
 *
 * Unknown (future) versions fall through to the current count rather than throwing,
 * so an older reader fails at the authentication tag with a clear error instead of
 * refusing to look at the payload at all.
 */
export declare function iterationsForVersion(version: number | undefined): number;
export declare function isWebCryptoAvailable(): boolean;
export declare function ensureWebCrypto(): void;
export declare function getWebCrypto(): Crypto;
export declare function arrayBufferToBase64(buffer: ArrayBuffer): string;
export declare function base64ToArrayBuffer(base64: string): ArrayBuffer;
export declare function stringToArrayBuffer(str: string): ArrayBuffer;
export declare function arrayBufferToString(buffer: ArrayBuffer): string;
export declare function generateRandomBytes(length: number): Uint8Array;
export declare function constantTimeCompare(a: ArrayBuffer, b: ArrayBuffer): boolean;
/**
 * Normalise `EncryptionOptions.additionalData` into the ArrayBuffer that Web Crypto
 * expects, encoding strings as UTF-8.
 *
 * Accepting a string directly removes a real footgun: ICOD's AAD values are context
 * strings, and leaving each caller to encode them invites two call sites that encode
 * differently and produce payloads that will not decrypt against each other.
 */
export declare function normaliseAdditionalData(additionalData: ArrayBuffer | Uint8Array | string | undefined): ArrayBuffer | undefined;
/**
 * Encode bytes as unpadded RFC 4648 base32.
 *
 * Base32 rather than hex because the output is read aloud between two humans
 * verifying a public key, and its alphabet excludes the characters people confuse
 * when doing that (0/O, 1/I/L).
 */
export declare function toBase32(bytes: Uint8Array): string;
/** Render a base32 fingerprint as six hyphenated groups of four, for reading aloud. */
export declare function groupFingerprint(base32: string): string;
//# sourceMappingURL=crypto-utils.d.ts.map