"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PBKDF2_ITERATIONS_V1 = exports.PBKDF2_ITERATIONS = exports.CURRENT_VERSION = exports.arrayBufferToBase64 = exports.base64ToArrayBuffer = exports.KeyWrapError = exports.EncryptionFailedError = exports.DecryptionFailedError = exports.MissingFieldError = exports.CorruptedDataError = exports.InvalidKeyError = exports.InvalidPassphraseError = exports.CryptoAPIUnavailableError = exports.IcodError = exports.isWebCryptoAvailable = void 0;
exports.generateDek = generateDek;
exports.keyHashOf = keyHashOf;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.encryptWithKey = encryptWithKey;
exports.decryptWithKey = decryptWithKey;
exports.verifyPassphrase = verifyPassphrase;
exports.verifyKey = verifyKey;
exports.generateKeyPair = generateKeyPair;
exports.wrapKey = wrapKey;
exports.unwrapKey = unwrapKey;
exports.publicKeyFingerprint = publicKeyFingerprint;
const errors_1 = require("./errors");
Object.defineProperty(exports, "IcodError", { enumerable: true, get: function () { return errors_1.IcodError; } });
Object.defineProperty(exports, "CryptoAPIUnavailableError", { enumerable: true, get: function () { return errors_1.CryptoAPIUnavailableError; } });
Object.defineProperty(exports, "InvalidPassphraseError", { enumerable: true, get: function () { return errors_1.InvalidPassphraseError; } });
Object.defineProperty(exports, "InvalidKeyError", { enumerable: true, get: function () { return errors_1.InvalidKeyError; } });
Object.defineProperty(exports, "CorruptedDataError", { enumerable: true, get: function () { return errors_1.CorruptedDataError; } });
Object.defineProperty(exports, "MissingFieldError", { enumerable: true, get: function () { return errors_1.MissingFieldError; } });
Object.defineProperty(exports, "DecryptionFailedError", { enumerable: true, get: function () { return errors_1.DecryptionFailedError; } });
Object.defineProperty(exports, "EncryptionFailedError", { enumerable: true, get: function () { return errors_1.EncryptionFailedError; } });
Object.defineProperty(exports, "KeyWrapError", { enumerable: true, get: function () { return errors_1.KeyWrapError; } });
const crypto_utils_1 = require("./crypto-utils");
Object.defineProperty(exports, "isWebCryptoAvailable", { enumerable: true, get: function () { return crypto_utils_1.isWebCryptoAvailable; } });
// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
async function deriveKey(passphrase, salt, iterations) {
    const crypto = (0, crypto_utils_1.getWebCrypto)();
    const passphraseKey = await crypto.subtle.importKey('raw', (0, crypto_utils_1.stringToArrayBuffer)(passphrase), 'PBKDF2', false, ['deriveBits', 'deriveKey']);
    return crypto.subtle.deriveKey({
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: 'SHA-256'
    }, passphraseKey, { name: 'AES-GCM', length: crypto_utils_1.KEY_LENGTH * 8 }, true, ['encrypt', 'decrypt']);
}
async function sha256Base64(bytes) {
    const crypto = (0, crypto_utils_1.getWebCrypto)();
    return (0, crypto_utils_1.arrayBufferToBase64)(await crypto.subtle.digest('SHA-256', bytes));
}
async function computeKeyHash(key) {
    const crypto = (0, crypto_utils_1.getWebCrypto)();
    return sha256Base64(await crypto.subtle.exportKey('raw', key));
}
/** Which decrypt path a payload belongs to. v1 payloads predate the field and are always passphrase-mode. */
function resolveMode(data) {
    return data.mode ?? 'passphrase';
}
function assertMode(data, expected) {
    const actual = resolveMode(data);
    if (actual !== expected) {
        throw new errors_1.IcodError(expected === 'passphrase'
            ? 'This payload was encrypted with a raw key. Use decryptWithKey() instead of decrypt().'
            : 'This payload was encrypted with a passphrase. Use decrypt() instead of decryptWithKey().', 'WRONG_DECRYPT_MODE');
    }
}
function requireFields(data, fields) {
    for (const field of fields) {
        if (!data[field]) {
            throw new errors_1.MissingFieldError(field);
        }
    }
}
function aesParams(iv, options) {
    const params = { name: 'AES-GCM', iv: iv };
    const additionalData = (0, crypto_utils_1.normaliseAdditionalData)(options?.additionalData);
    if (additionalData) {
        params.additionalData = additionalData;
    }
    return params;
}
// ---------------------------------------------------------------------------
// Raw-key material
// ---------------------------------------------------------------------------
/**
 * Generate a fresh 256-bit data encryption key, base64-encoded.
 *
 * In ICOD this is a vault's DEK: generated once, never rotated, and never sent to a
 * server in plaintext. Changing a password re-wraps this key; it does not replace it.
 */
function generateDek() {
    return (0, crypto_utils_1.arrayBufferToBase64)((0, crypto_utils_1.generateRandomBytes)(crypto_utils_1.KEY_LENGTH).buffer);
}
/**
 * base64 SHA-256 of a raw key, matching the `keyHash` written into every payload.
 *
 * This is what lets a writer assert it holds the right key *before* appending to an
 * append-only history. Without that check, a key that is wrong in memory produces a
 * version that is silently unreadable forever.
 */
async function keyHashOf(keyB64) {
    (0, crypto_utils_1.ensureWebCrypto)();
    return sha256Base64((0, crypto_utils_1.base64ToArrayBuffer)(keyB64));
}
async function importAesKey(keyB64) {
    const raw = (0, crypto_utils_1.base64ToArrayBuffer)(keyB64);
    if (raw.byteLength !== crypto_utils_1.KEY_LENGTH) {
        throw new errors_1.IcodError(`Expected a ${crypto_utils_1.KEY_LENGTH}-byte key, got ${raw.byteLength} bytes.`, 'INVALID_KEY_LENGTH');
    }
    const crypto = (0, crypto_utils_1.getWebCrypto)();
    return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [
        'encrypt',
        'decrypt'
    ]);
}
// ---------------------------------------------------------------------------
// Passphrase-based encryption (v1-compatible on read, v2 on write)
// ---------------------------------------------------------------------------
async function encrypt(plaintext, passphrase, options) {
    try {
        (0, crypto_utils_1.ensureWebCrypto)();
        const salt = (0, crypto_utils_1.generateRandomBytes)(crypto_utils_1.SALT_LENGTH);
        const iv = (0, crypto_utils_1.generateRandomBytes)(crypto_utils_1.IV_LENGTH);
        const key = await deriveKey(passphrase, salt.buffer, (0, crypto_utils_1.iterationsForVersion)(crypto_utils_1.CURRENT_VERSION));
        const keyHash = await computeKeyHash(key);
        const crypto = (0, crypto_utils_1.getWebCrypto)();
        const ciphertextBuffer = await crypto.subtle.encrypt(aesParams(iv, options), key, (0, crypto_utils_1.stringToArrayBuffer)(plaintext));
        return {
            ciphertext: (0, crypto_utils_1.arrayBufferToBase64)(ciphertextBuffer),
            iv: (0, crypto_utils_1.arrayBufferToBase64)(iv.buffer),
            salt: (0, crypto_utils_1.arrayBufferToBase64)(salt.buffer),
            keyHash: keyHash,
            version: crypto_utils_1.CURRENT_VERSION,
            mode: 'passphrase'
        };
    }
    catch (error) {
        if (error instanceof errors_1.IcodError) {
            throw error;
        }
        throw new errors_1.EncryptionFailedError(error instanceof Error ? error.message : 'Unknown error');
    }
}
async function decrypt(encryptedData, passphrase, options) {
    try {
        (0, crypto_utils_1.ensureWebCrypto)();
        assertMode(encryptedData, 'passphrase');
        requireFields(encryptedData, ['ciphertext', 'iv', 'salt']);
        let saltBuffer;
        let ivBuffer;
        let ciphertextBuffer;
        try {
            saltBuffer = (0, crypto_utils_1.base64ToArrayBuffer)(encryptedData.salt);
            ivBuffer = (0, crypto_utils_1.base64ToArrayBuffer)(encryptedData.iv);
            ciphertextBuffer = (0, crypto_utils_1.base64ToArrayBuffer)(encryptedData.ciphertext);
        }
        catch (error) {
            throw new errors_1.CorruptedDataError('Invalid base64 encoding');
        }
        const key = await deriveKey(passphrase, saltBuffer, (0, crypto_utils_1.iterationsForVersion)(encryptedData.version));
        // Verify the key before touching the ciphertext, so that a wrong passphrase
        // surfaces as InvalidPassphraseError rather than as an indistinguishable
        // AES-GCM tag failure. The comparison is constant-time. Because the key derives
        // from both passphrase and salt, a tampered salt or keyHash also fails here.
        if (encryptedData.keyHash) {
            const computedKeyHash = await computeKeyHash(key);
            if (!(0, crypto_utils_1.constantTimeCompare)((0, crypto_utils_1.base64ToArrayBuffer)(encryptedData.keyHash), (0, crypto_utils_1.base64ToArrayBuffer)(computedKeyHash))) {
                throw new errors_1.InvalidPassphraseError();
            }
        }
        let plaintextBuffer;
        try {
            const crypto = (0, crypto_utils_1.getWebCrypto)();
            plaintextBuffer = await crypto.subtle.decrypt(aesParams(ivBuffer, options), key, ciphertextBuffer);
        }
        catch (error) {
            // The key is verified correct, so this is genuine corruption, tampering, or a
            // mismatched AAD context.
            throw new errors_1.CorruptedDataError('AES-GCM authentication failed');
        }
        return (0, crypto_utils_1.arrayBufferToString)(plaintextBuffer);
    }
    catch (error) {
        if (error instanceof errors_1.IcodError) {
            throw error;
        }
        throw new errors_1.DecryptionFailedError(error instanceof Error ? error.message : 'Unknown error');
    }
}
// ---------------------------------------------------------------------------
// Raw-key encryption — used for vault content, which is protected by the DEK
// ---------------------------------------------------------------------------
/**
 * Encrypt under a raw 256-bit key.
 *
 * Vault content is protected by the DEK, not by a passphrase, so running PBKDF2 over
 * an already-random key on every save would be both wasteful and semantically wrong.
 * No derivation happens here, so the result carries no `salt`.
 */
async function encryptWithKey(plaintext, keyB64, options) {
    try {
        (0, crypto_utils_1.ensureWebCrypto)();
        const key = await importAesKey(keyB64);
        const iv = (0, crypto_utils_1.generateRandomBytes)(crypto_utils_1.IV_LENGTH);
        const crypto = (0, crypto_utils_1.getWebCrypto)();
        const ciphertextBuffer = await crypto.subtle.encrypt(aesParams(iv, options), key, (0, crypto_utils_1.stringToArrayBuffer)(plaintext));
        return {
            ciphertext: (0, crypto_utils_1.arrayBufferToBase64)(ciphertextBuffer),
            iv: (0, crypto_utils_1.arrayBufferToBase64)(iv.buffer),
            keyHash: await keyHashOf(keyB64),
            version: crypto_utils_1.CURRENT_VERSION,
            mode: 'key'
        };
    }
    catch (error) {
        if (error instanceof errors_1.IcodError) {
            throw error;
        }
        throw new errors_1.EncryptionFailedError(error instanceof Error ? error.message : 'Unknown error');
    }
}
async function decryptWithKey(encryptedData, keyB64, options) {
    try {
        (0, crypto_utils_1.ensureWebCrypto)();
        assertMode(encryptedData, 'key');
        requireFields(encryptedData, ['ciphertext', 'iv']);
        let ivBuffer;
        let ciphertextBuffer;
        try {
            ivBuffer = (0, crypto_utils_1.base64ToArrayBuffer)(encryptedData.iv);
            ciphertextBuffer = (0, crypto_utils_1.base64ToArrayBuffer)(encryptedData.ciphertext);
        }
        catch (error) {
            throw new errors_1.CorruptedDataError('Invalid base64 encoding');
        }
        // Same discipline as the passphrase path: establish the key is right before
        // blaming the data.
        if (encryptedData.keyHash) {
            const computedKeyHash = await keyHashOf(keyB64);
            if (!(0, crypto_utils_1.constantTimeCompare)((0, crypto_utils_1.base64ToArrayBuffer)(encryptedData.keyHash), (0, crypto_utils_1.base64ToArrayBuffer)(computedKeyHash))) {
                throw new errors_1.InvalidKeyError();
            }
        }
        const key = await importAesKey(keyB64);
        let plaintextBuffer;
        try {
            const crypto = (0, crypto_utils_1.getWebCrypto)();
            plaintextBuffer = await crypto.subtle.decrypt(aesParams(ivBuffer, options), key, ciphertextBuffer);
        }
        catch (error) {
            throw new errors_1.CorruptedDataError('AES-GCM authentication failed');
        }
        return (0, crypto_utils_1.arrayBufferToString)(plaintextBuffer);
    }
    catch (error) {
        if (error instanceof errors_1.IcodError) {
            throw error;
        }
        throw new errors_1.DecryptionFailedError(error instanceof Error ? error.message : 'Unknown error');
    }
}
// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------
/**
 * Check a passphrase against a payload's stored `keyHash`, without decrypting.
 *
 * Takes the whole payload rather than a bare salt so it has `salt`, `keyHash` and
 * `version` in one argument, which is what makes it correctly version-aware — a
 * signature taking only a salt cannot know how many iterations to run and would
 * silently return false for every v1 payload once the iteration count changed.
 */
async function verifyPassphrase(passphrase, data) {
    (0, crypto_utils_1.ensureWebCrypto)();
    requireFields(data, ['salt', 'keyHash']);
    const key = await deriveKey(passphrase, (0, crypto_utils_1.base64ToArrayBuffer)(data.salt), (0, crypto_utils_1.iterationsForVersion)(data.version));
    return (0, crypto_utils_1.constantTimeCompare)((0, crypto_utils_1.base64ToArrayBuffer)(data.keyHash), (0, crypto_utils_1.base64ToArrayBuffer)(await computeKeyHash(key)));
}
/**
 * Check a raw key against a payload's stored `keyHash`, without decrypting.
 *
 * This is the write-path assertion: call it with the in-memory DEK before appending a
 * new version, and refuse the write if it fails.
 *
 * Returns a promise rather than a plain boolean because Web Crypto's digest is
 * asynchronous — there is no synchronous SHA-256 available without shipping our own.
 */
async function verifyKey(keyB64, data) {
    (0, crypto_utils_1.ensureWebCrypto)();
    requireFields(data, ['keyHash']);
    return (0, crypto_utils_1.constantTimeCompare)((0, crypto_utils_1.base64ToArrayBuffer)(data.keyHash), (0, crypto_utils_1.base64ToArrayBuffer)(await keyHashOf(keyB64)));
}
// ---------------------------------------------------------------------------
// Asymmetric key wrapping
// ---------------------------------------------------------------------------
function publicJwkForImport(jwk) {
    if (jwk?.kty !== 'RSA' || !jwk.n || !jwk.e) {
        throw new errors_1.KeyWrapError('Not an RSA public JWK');
    }
    // Rebuild a minimal JWK rather than importing whatever was handed to us. Extraneous
    // or inconsistent fields (key_ops, use, alg from a different curve) make importKey
    // throw, and a canonical shape keeps the fingerprint stable across round-trips.
    return { kty: 'RSA', n: jwk.n, e: jwk.e, alg: crypto_utils_1.RSA_JWK_ALG, ext: true };
}
async function importPublicKey(jwk) {
    const crypto = (0, crypto_utils_1.getWebCrypto)();
    return crypto.subtle.importKey('jwk', publicJwkForImport(jwk), { name: 'RSA-OAEP', hash: crypto_utils_1.RSA_HASH }, true, ['encrypt']);
}
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
async function generateKeyPair() {
    try {
        const crypto = (0, crypto_utils_1.getWebCrypto)();
        const pair = await crypto.subtle.generateKey({
            name: 'RSA-OAEP',
            modulusLength: crypto_utils_1.RSA_MODULUS_LENGTH,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: crypto_utils_1.RSA_HASH
        }, true, ['encrypt', 'decrypt']);
        const publicKeyJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
        const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
        return {
            publicKeyJwk: publicJwkForImport(publicKeyJwk),
            privateKeyB64: (0, crypto_utils_1.arrayBufferToBase64)(privateKeyBuffer)
        };
    }
    catch (error) {
        if (error instanceof errors_1.IcodError) {
            throw error;
        }
        throw new errors_1.KeyWrapError(error instanceof Error ? error.message : 'Unknown error');
    }
}
/** Encrypt a raw key to someone's public key. The result is safe to hand to the server. */
async function wrapKey(keyB64, publicKeyJwk) {
    try {
        const crypto = (0, crypto_utils_1.getWebCrypto)();
        const publicKey = await importPublicKey(publicKeyJwk);
        const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, (0, crypto_utils_1.base64ToArrayBuffer)(keyB64));
        return (0, crypto_utils_1.arrayBufferToBase64)(wrapped);
    }
    catch (error) {
        if (error instanceof errors_1.IcodError) {
            throw error;
        }
        throw new errors_1.KeyWrapError(error instanceof Error ? error.message : 'Unknown error');
    }
}
/** Recover a raw key from its wrapped form using the matching private key. */
async function unwrapKey(wrapped, privateKeyB64) {
    try {
        const crypto = (0, crypto_utils_1.getWebCrypto)();
        const privateKey = await crypto.subtle.importKey('pkcs8', (0, crypto_utils_1.base64ToArrayBuffer)(privateKeyB64), { name: 'RSA-OAEP', hash: crypto_utils_1.RSA_HASH }, false, ['decrypt']);
        const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privateKey, (0, crypto_utils_1.base64ToArrayBuffer)(wrapped));
        return (0, crypto_utils_1.arrayBufferToBase64)(raw);
    }
    catch (error) {
        if (error instanceof errors_1.IcodError) {
            throw error;
        }
        throw new errors_1.KeyWrapError(error instanceof Error ? error.message : 'Unknown error');
    }
}
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
async function publicKeyFingerprint(publicKeyJwk) {
    try {
        const crypto = (0, crypto_utils_1.getWebCrypto)();
        const publicKey = await importPublicKey(publicKeyJwk);
        const spki = await crypto.subtle.exportKey('spki', publicKey);
        const digest = await crypto.subtle.digest('SHA-256', spki);
        const truncated = new Uint8Array(digest).slice(0, crypto_utils_1.FINGERPRINT_BYTES);
        return (0, crypto_utils_1.groupFingerprint)((0, crypto_utils_1.toBase32)(truncated));
    }
    catch (error) {
        if (error instanceof errors_1.IcodError) {
            throw error;
        }
        throw new errors_1.KeyWrapError(error instanceof Error ? error.message : 'Unknown error');
    }
}
var crypto_utils_2 = require("./crypto-utils");
Object.defineProperty(exports, "base64ToArrayBuffer", { enumerable: true, get: function () { return crypto_utils_2.base64ToArrayBuffer; } });
Object.defineProperty(exports, "arrayBufferToBase64", { enumerable: true, get: function () { return crypto_utils_2.arrayBufferToBase64; } });
Object.defineProperty(exports, "CURRENT_VERSION", { enumerable: true, get: function () { return crypto_utils_2.CURRENT_VERSION; } });
Object.defineProperty(exports, "PBKDF2_ITERATIONS", { enumerable: true, get: function () { return crypto_utils_2.PBKDF2_ITERATIONS; } });
Object.defineProperty(exports, "PBKDF2_ITERATIONS_V1", { enumerable: true, get: function () { return crypto_utils_2.PBKDF2_ITERATIONS_V1; } });
//# sourceMappingURL=index.js.map