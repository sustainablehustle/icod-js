'use strict';

// Test suite for icod-js.
//
// Runs with Node's built-in test runner and assertion library (no third-party
// dependencies), keeping the suite simple and auditable. It exercises the
// compiled output in ./dist — i.e. exactly what ships to npm — via:
//
//   node test.js        (see package.json "test", which builds first)
//
// The suite treats the library as a black box and asserts on its public
// contract: round-trip correctness for both the passphrase and raw-key paths,
// the shape of EncryptedData, randomness, authenticated-encryption guarantees
// (tamper/wrong-key detection), additional authenticated data, backward
// compatibility with v1 payloads, asymmetric key wrapping, public key
// fingerprints, and the error taxonomy.

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const {
  encrypt,
  decrypt,
  encryptWithKey,
  decryptWithKey,
  generateDek,
  keyHashOf,
  verifyPassphrase,
  verifyKey,
  generateKeyPair,
  wrapKey,
  unwrapKey,
  publicKeyFingerprint,
  isWebCryptoAvailable,
  base64ToArrayBuffer,
  CURRENT_VERSION,
  PBKDF2_ITERATIONS,
  PBKDF2_ITERATIONS_V1,
  IcodError,
  CryptoAPIUnavailableError,
  InvalidPassphraseError,
  InvalidKeyError,
  CorruptedDataError,
  MissingFieldError,
  DecryptionFailedError,
  EncryptionFailedError,
  KeyWrapError,
} = require('./dist/index.js');

const PASS = 'correct horse battery staple';

// A genuine v1 payload: PBKDF2 at 100,000 iterations, version 1, and no `mode`
// field, which did not exist at the time. Frozen here so the version-aware read
// path is tested against real v1 output rather than a re-derivation of it.
const V1_PAYLOAD = {
  ciphertext: '2nN8wSD2/byuxzgKVB6WIi+5rdrHnv3Q1bJ5sg==',
  iv: 'ugiGxm7AexwWtipg',
  salt: 'r0LPdMehzyTEmuIJIhDQ2g==',
  keyHash: 'gif9F13qZPTDeHY69kbi+GCikH3ncEFPmDKQKj2HLqs=',
  version: 1,
};
const V1_PLAINTEXT = 'a v1 payload';

// Decode a base64 field from EncryptedData into raw bytes.
function bytesOf(base64) {
  return new Uint8Array(base64ToArrayBuffer(base64));
}

// Flip the first byte of a base64-encoded value, returning a same-length,
// still-valid base64 string that decodes to different bytes.
function tamper(base64) {
  const bytes = bytesOf(base64);
  bytes[0] ^= 0xff;
  return Buffer.from(bytes).toString('base64');
}

// RSA-3072 keygen is slow, so generate one pair and share it across the suite.
let sharedKeyPair;
function keyPair() {
  if (!sharedKeyPair) {
    sharedKeyPair = generateKeyPair();
  }
  return sharedKeyPair;
}

describe('environment', () => {
  test('isWebCryptoAvailable() is true under Node 22+', () => {
    assert.equal(isWebCryptoAvailable(), true);
  });

  test('ships v2 constants', () => {
    assert.equal(CURRENT_VERSION, 2);
    assert.equal(PBKDF2_ITERATIONS, 600000);
    assert.equal(PBKDF2_ITERATIONS_V1, 100000);
  });
});

describe('encrypt / decrypt round-trip', () => {
  test('round-trips ASCII text', async () => {
    const enc = await encrypt('Hello, World!', PASS);
    assert.equal(await decrypt(enc, PASS), 'Hello, World!');
  });

  test('round-trips the empty string', async () => {
    const enc = await encrypt('', PASS);
    assert.equal(await decrypt(enc, PASS), '');
  });

  test('round-trips multi-byte UTF-8 (accents, CJK, emoji)', async () => {
    const message = 'café ☕ 日本語 🔐 Ñoño';
    const enc = await encrypt(message, PASS);
    assert.equal(await decrypt(enc, PASS), message);
  });

  test('round-trips whitespace and control characters', async () => {
    const message = 'line1\nline2\ttab\r\n\0null';
    const enc = await encrypt(message, PASS);
    assert.equal(await decrypt(enc, PASS), message);
  });

  test('round-trips a passphrase containing multi-byte characters', async () => {
    const passphrase = 'pÀsſwörd–🔑';
    const enc = await encrypt('secret', passphrase);
    assert.equal(await decrypt(enc, passphrase), 'secret');
  });
});

describe('EncryptedData structure', () => {
  test('passphrase mode has exactly the documented fields with the documented types', async () => {
    const enc = await encrypt('data', PASS);
    assert.deepEqual(
      Object.keys(enc).sort(),
      ['ciphertext', 'iv', 'keyHash', 'mode', 'salt', 'version']
    );
    assert.equal(typeof enc.ciphertext, 'string');
    assert.equal(typeof enc.iv, 'string');
    assert.equal(typeof enc.salt, 'string');
    assert.equal(typeof enc.keyHash, 'string');
    assert.equal(enc.version, 2);
    assert.equal(enc.mode, 'passphrase');
  });

  test('key mode carries no salt, because nothing was derived', async () => {
    const enc = await encryptWithKey('data', generateDek());
    assert.deepEqual(
      Object.keys(enc).sort(),
      ['ciphertext', 'iv', 'keyHash', 'mode', 'version']
    );
    assert.equal(enc.salt, undefined);
    assert.equal(enc.mode, 'key');
    assert.equal(enc.version, 2);
  });

  test('salt is 16 bytes and iv is 12 bytes', async () => {
    const enc = await encrypt('data', PASS);
    assert.equal(bytesOf(enc.salt).length, 16);
    assert.equal(bytesOf(enc.iv).length, 12);
  });

  test('keyHash is a 32-byte (SHA-256) digest in both modes', async () => {
    const passphraseEnc = await encrypt('data', PASS);
    const keyEnc = await encryptWithKey('data', generateDek());
    assert.equal(bytesOf(passphraseEnc.keyHash).length, 32);
    assert.equal(bytesOf(keyEnc.keyHash).length, 32);
  });
});

describe('v1 backward compatibility', () => {
  // The whole point of the `version` field: v2 raised PBKDF2 from 100,000 to
  // 600,000 iterations, and a reader that ignored the version would silently
  // fail to derive the right key for every payload written before the change.
  test('decrypts a genuine v1 payload using v1 iterations', async () => {
    assert.equal(await decrypt(V1_PAYLOAD, PASS), V1_PLAINTEXT);
  });

  test('a v1 payload with no `mode` field is treated as passphrase mode', async () => {
    assert.equal(V1_PAYLOAD.mode, undefined);
    assert.equal(await decrypt(V1_PAYLOAD, PASS), V1_PLAINTEXT);
  });

  test('verifyPassphrase is version-aware across v1 and v2 payloads', async () => {
    const v2 = await encrypt('secret', PASS);
    assert.equal(await verifyPassphrase(PASS, V1_PAYLOAD), true);
    assert.equal(await verifyPassphrase(PASS, v2), true);
    assert.equal(await verifyPassphrase('wrong', V1_PAYLOAD), false);
    assert.equal(await verifyPassphrase('wrong', v2), false);
  });

  test('a wrong passphrase against a v1 payload still reports InvalidPassphraseError', async () => {
    await assert.rejects(() => decrypt(V1_PAYLOAD, 'wrong'), InvalidPassphraseError);
  });
});

describe('non-determinism', () => {
  test('the same plaintext + passphrase produces a fresh salt, iv and ciphertext each call', async () => {
    const a = await encrypt('same message', PASS);
    const b = await encrypt('same message', PASS);
    assert.notEqual(a.salt, b.salt);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.ciphertext, b.ciphertext);
    assert.equal(await decrypt(a, PASS), 'same message');
    assert.equal(await decrypt(b, PASS), 'same message');
  });

  test('the same plaintext + key produces a fresh iv and ciphertext each call', async () => {
    const dek = generateDek();
    const a = await encryptWithKey('same message', dek);
    const b = await encryptWithKey('same message', dek);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.ciphertext, b.ciphertext);
    // The keyHash is stable, because the key is.
    assert.equal(a.keyHash, b.keyHash);
  });

  test('generateDek() returns 32 distinct random bytes each call', () => {
    const a = generateDek();
    const b = generateDek();
    assert.equal(bytesOf(a).length, 32);
    assert.equal(bytesOf(b).length, 32);
    assert.notEqual(a, b);
  });
});

describe('error semantics: wrong key vs damaged data', () => {
  // The distinction the product depends on. A mistyped password must never be
  // reported as "your data appears to be corrupted or tampered with".
  test('a wrong passphrase is rejected with InvalidPassphraseError, not corruption', async () => {
    const enc = await encrypt('secret', PASS);
    await assert.rejects(
      () => decrypt(enc, 'wrong passphrase'),
      (err) => {
        assert.ok(err instanceof InvalidPassphraseError);
        assert.ok(err instanceof IcodError);
        assert.equal(err.code, 'INVALID_PASSPHRASE');
        assert.doesNotMatch(err.message, /corrupt|tamper/i);
        return true;
      }
    );
  });

  test('a wrong raw key is rejected with InvalidKeyError, not corruption', async () => {
    const enc = await encryptWithKey('secret', generateDek());
    await assert.rejects(
      () => decryptWithKey(enc, generateDek()),
      (err) => {
        assert.ok(err instanceof InvalidKeyError);
        assert.equal(err.code, 'INVALID_KEY');
        assert.doesNotMatch(err.message, /corrupt|tamper/i);
        return true;
      }
    );
  });

  test('the right key with damaged ciphertext IS reported as corruption', async () => {
    const enc = await encrypt('secret', PASS);
    await assert.rejects(
      () => decrypt({ ...enc, ciphertext: tamper(enc.ciphertext) }, PASS),
      (err) => {
        assert.ok(err instanceof CorruptedDataError);
        assert.match(err.message, /corrupted or tampered/i);
        return true;
      }
    );
  });

  test('the right raw key with damaged ciphertext IS reported as corruption', async () => {
    const dek = generateDek();
    const enc = await encryptWithKey('secret', dek);
    await assert.rejects(
      () => decryptWithKey({ ...enc, ciphertext: tamper(enc.ciphertext) }, dek),
      CorruptedDataError
    );
  });

  // The key derives from passphrase AND salt, so a tampered salt yields a key
  // that no longer matches the stored keyHash.
  test('a tampered salt is reported as InvalidPassphraseError', async () => {
    const enc = await encrypt('secret', PASS);
    await assert.rejects(
      () => decrypt({ ...enc, salt: tamper(enc.salt) }, PASS),
      InvalidPassphraseError
    );
  });

  test('a tampered keyHash is reported as InvalidPassphraseError', async () => {
    const enc = await encrypt('secret', PASS);
    await assert.rejects(
      () => decrypt({ ...enc, keyHash: tamper(enc.keyHash) }, PASS),
      InvalidPassphraseError
    );
  });

  test('without a keyHash, a wrong passphrase falls back to CorruptedDataError', async () => {
    const enc = await encrypt('secret', PASS);
    delete enc.keyHash;
    await assert.rejects(() => decrypt(enc, 'wrong passphrase'), CorruptedDataError);
  });

  test('a tampered iv is rejected with CorruptedDataError', async () => {
    const enc = await encrypt('secret', PASS);
    await assert.rejects(() => decrypt({ ...enc, iv: tamper(enc.iv) }, PASS), CorruptedDataError);
  });
});

describe('mode discrimination', () => {
  test('decrypt() refuses a key-mode payload and names the right function', async () => {
    const enc = await encryptWithKey('secret', generateDek());
    await assert.rejects(
      () => decrypt(enc, PASS),
      (err) => {
        assert.equal(err.code, 'WRONG_DECRYPT_MODE');
        assert.match(err.message, /decryptWithKey/);
        return true;
      }
    );
  });

  test('decryptWithKey() refuses a passphrase-mode payload and names the right function', async () => {
    const enc = await encrypt('secret', PASS);
    await assert.rejects(
      () => decryptWithKey(enc, generateDek()),
      (err) => {
        assert.equal(err.code, 'WRONG_DECRYPT_MODE');
        assert.match(err.message, /decrypt\(\)/);
        return true;
      }
    );
  });
});

describe('malformed input', () => {
  for (const field of ['ciphertext', 'iv', 'salt']) {
    test(`decrypt throws MissingFieldError when '${field}' is absent`, async () => {
      const enc = await encrypt('secret', PASS);
      delete enc[field];
      await assert.rejects(
        () => decrypt(enc, PASS),
        (err) => {
          assert.ok(err instanceof MissingFieldError);
          assert.equal(err.code, 'MISSING_FIELD');
          assert.match(err.message, new RegExp(field));
          return true;
        }
      );
    });
  }

  for (const field of ['ciphertext', 'iv']) {
    test(`decryptWithKey throws MissingFieldError when '${field}' is absent`, async () => {
      const dek = generateDek();
      const enc = await encryptWithKey('secret', dek);
      delete enc[field];
      await assert.rejects(() => decryptWithKey(enc, dek), MissingFieldError);
    });
  }

  test('decrypt still succeeds when keyHash is absent (pre-check is skipped)', async () => {
    const enc = await encrypt('secret', PASS);
    delete enc.keyHash;
    assert.equal(await decrypt(enc, PASS), 'secret');
  });

  test('decrypt throws CorruptedDataError on invalid base64', async () => {
    const enc = await encrypt('secret', PASS);
    await assert.rejects(
      () => decrypt({ ...enc, ciphertext: '@@@ not base64 @@@' }, PASS),
      (err) => {
        assert.ok(err instanceof CorruptedDataError);
        assert.match(err.message, /base64/i);
        return true;
      }
    );
  });

  test('encryptWithKey rejects a key that is not 32 bytes', async () => {
    const short = Buffer.from('too short').toString('base64');
    await assert.rejects(
      () => encryptWithKey('secret', short),
      (err) => {
        assert.equal(err.code, 'INVALID_KEY_LENGTH');
        return true;
      }
    );
  });
});

describe('additional authenticated data (AAD)', () => {
  const aad = new TextEncoder().encode('context:user-42').buffer;
  const otherAad = new TextEncoder().encode('context:user-99').buffer;

  test('round-trips when the same additionalData is supplied to encrypt and decrypt', async () => {
    const enc = await encrypt('secret', PASS, { additionalData: aad });
    assert.equal(await decrypt(enc, PASS, { additionalData: aad }), 'secret');
  });

  test('decryption fails when additionalData is omitted', async () => {
    const enc = await encrypt('secret', PASS, { additionalData: aad });
    await assert.rejects(() => decrypt(enc, PASS), CorruptedDataError);
  });

  test('decryption fails when additionalData differs', async () => {
    const enc = await encrypt('secret', PASS, { additionalData: aad });
    await assert.rejects(
      () => decrypt(enc, PASS, { additionalData: otherAad }),
      CorruptedDataError
    );
  });

  test('decryption fails when additionalData is supplied but none was used at encryption', async () => {
    const enc = await encrypt('secret', PASS);
    await assert.rejects(() => decrypt(enc, PASS, { additionalData: aad }), CorruptedDataError);
  });

  // ICOD binds every ciphertext to a context string, so strings must be accepted
  // directly and must encode identically to their UTF-8 bytes.
  test('accepts a string and treats it as its UTF-8 bytes', async () => {
    const context = 'icod:v2:vault:01ABC:version:01DEF';
    const enc = await encrypt('secret', PASS, { additionalData: context });
    assert.equal(await decrypt(enc, PASS, { additionalData: context }), 'secret');
    // A string and its encoded form are interchangeable in both directions.
    const bytes = new TextEncoder().encode(context).buffer;
    assert.equal(await decrypt(enc, PASS, { additionalData: bytes }), 'secret');
  });

  test('binds raw-key payloads too, and a changed context fails', async () => {
    const dek = generateDek();
    const context = 'icod:v2:vault:01ABC:version:01DEF';
    const enc = await encryptWithKey('secret', dek, { additionalData: context });
    assert.equal(await decryptWithKey(enc, dek, { additionalData: context }), 'secret');
    await assert.rejects(
      () => decryptWithKey(enc, dek, { additionalData: 'icod:v2:vault:01ABC:version:01XYZ' }),
      CorruptedDataError
    );
  });
});

describe('raw-key encryption', () => {
  test('round-trips content under a DEK', async () => {
    const dek = generateDek();
    const document = JSON.stringify({ schema: 1, body_markdown: '## Bank accounts\n\n...' });
    const enc = await encryptWithKey(document, dek);
    assert.equal(await decryptWithKey(enc, dek), document);
  });

  test('round-trips a large (100 KB) payload', async () => {
    const dek = generateDek();
    const message = 'A'.repeat(100_000);
    const enc = await encryptWithKey(message, dek);
    assert.equal(await decryptWithKey(enc, dek), message);
  });

  test('round-trips multi-byte UTF-8', async () => {
    const dek = generateDek();
    const message = 'café ☕ 日本語 🔐';
    const enc = await encryptWithKey(message, dek);
    assert.equal(await decryptWithKey(enc, dek), message);
  });
});

describe('key verification', () => {
  test('verifyPassphrase returns true for the passphrase used at encryption', async () => {
    const enc = await encrypt('secret', PASS);
    assert.equal(await verifyPassphrase(PASS, enc), true);
  });

  test('verifyPassphrase returns false for a different passphrase', async () => {
    const enc = await encrypt('secret', PASS);
    assert.equal(await verifyPassphrase('not the passphrase', enc), false);
  });

  test('verifyPassphrase returns false when salt and keyHash do not correspond', async () => {
    const a = await encrypt('secret', PASS);
    const b = await encrypt('secret', PASS); // different random salt
    assert.equal(await verifyPassphrase(PASS, { ...b, keyHash: a.keyHash }), false);
  });

  // The write-path assertion: refuse to append a version unless the in-memory key
  // is provably the one the vault's history is already encrypted under.
  test('verifyKey returns true for the key used at encryption and false otherwise', async () => {
    const dek = generateDek();
    const enc = await encryptWithKey('secret', dek);
    assert.equal(await verifyKey(dek, enc), true);
    assert.equal(await verifyKey(generateDek(), enc), false);
  });

  test('keyHashOf matches the keyHash written into a payload', async () => {
    const dek = generateDek();
    const enc = await encryptWithKey('secret', dek);
    assert.equal(await keyHashOf(dek), enc.keyHash);
  });

  test('keyHashOf is stable for the same key and differs across keys', async () => {
    const dek = generateDek();
    assert.equal(await keyHashOf(dek), await keyHashOf(dek));
    assert.notEqual(await keyHashOf(dek), await keyHashOf(generateDek()));
  });
});

describe('asymmetric key wrapping', () => {
  test('generateKeyPair returns a public JWK and a base64 private key', async () => {
    const { publicKeyJwk, privateKeyB64 } = await keyPair();
    assert.equal(publicKeyJwk.kty, 'RSA');
    assert.equal(publicKeyJwk.alg, 'RSA-OAEP-256');
    assert.equal(typeof publicKeyJwk.n, 'string');
    assert.equal(publicKeyJwk.e, 'AQAB');
    assert.equal(typeof privateKeyB64, 'string');
    // 3072-bit modulus is 384 bytes, which base64url-encodes to 512 characters.
    assert.equal(publicKeyJwk.n.length, 512);
  });

  test('the public JWK carries no private material', async () => {
    const { publicKeyJwk } = await keyPair();
    for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      assert.equal(publicKeyJwk[field], undefined, `public JWK must not contain '${field}'`);
    }
  });

  test('wrap then unwrap recovers the exact DEK', async () => {
    const { publicKeyJwk, privateKeyB64 } = await keyPair();
    const dek = generateDek();
    const wrapped = await wrapKey(dek, publicKeyJwk);
    assert.notEqual(wrapped, dek);
    assert.equal(await unwrapKey(wrapped, privateKeyB64), dek);
  });

  test('the unwrapped DEK actually decrypts content encrypted under the original', async () => {
    const { publicKeyJwk, privateKeyB64 } = await keyPair();
    const dek = generateDek();
    const enc = await encryptWithKey('the vault contents', dek);

    // This is the trustee's post-release path end to end.
    const recovered = await unwrapKey(await wrapKey(dek, publicKeyJwk), privateKeyB64);
    assert.equal(await decryptWithKey(enc, recovered), 'the vault contents');
  });

  test('wrapping is non-deterministic (OAEP is randomised)', async () => {
    const { publicKeyJwk } = await keyPair();
    const dek = generateDek();
    assert.notEqual(await wrapKey(dek, publicKeyJwk), await wrapKey(dek, publicKeyJwk));
  });

  test('a different private key cannot unwrap', async () => {
    const { publicKeyJwk } = await keyPair();
    const other = await generateKeyPair();
    const wrapped = await wrapKey(generateDek(), publicKeyJwk);
    await assert.rejects(() => unwrapKey(wrapped, other.privateKeyB64), KeyWrapError);
  });

  test('wrapKey rejects a JWK that is not an RSA public key', async () => {
    await assert.rejects(
      () => wrapKey(generateDek(), { kty: 'EC', crv: 'P-256', x: 'a', y: 'b' }),
      KeyWrapError
    );
  });
});

describe('public key fingerprints', () => {
  test('renders as six hyphenated groups of four base32 characters', async () => {
    const { publicKeyJwk } = await keyPair();
    const fingerprint = await publicKeyFingerprint(publicKeyJwk);
    assert.match(fingerprint, /^[A-Z2-7]{4}(-[A-Z2-7]{4}){5}$/);
    assert.equal(fingerprint.length, 29); // 24 characters + 5 hyphens
  });

  test('excludes the characters humans confuse when reading aloud', async () => {
    const { publicKeyJwk } = await keyPair();
    const fingerprint = await publicKeyFingerprint(publicKeyJwk);
    assert.doesNotMatch(fingerprint, /[01890]/);
  });

  test('is stable for the same key across calls', async () => {
    const { publicKeyJwk } = await keyPair();
    assert.equal(
      await publicKeyFingerprint(publicKeyJwk),
      await publicKeyFingerprint(publicKeyJwk)
    );
  });

  // The fingerprint is computed over the SPKI encoding, so it must not shift
  // because a JSON round-trip reordered the JWK's members or added a field.
  test('is independent of JWK field ordering and extraneous members', async () => {
    const { publicKeyJwk } = await keyPair();
    const expected = await publicKeyFingerprint(publicKeyJwk);

    const reordered = { e: publicKeyJwk.e, alg: publicKeyJwk.alg, n: publicKeyJwk.n, kty: 'RSA' };
    const withExtras = { ...publicKeyJwk, key_ops: ['encrypt'], use: 'enc', ext: true };

    assert.equal(await publicKeyFingerprint(reordered), expected);
    assert.equal(await publicKeyFingerprint(withExtras), expected);
    assert.equal(await publicKeyFingerprint(JSON.parse(JSON.stringify(publicKeyJwk))), expected);
  });

  // The property the entire arming gate rests on: a substituted key must produce
  // a visibly different code for the two humans comparing it.
  test('differs for a different key', async () => {
    const { publicKeyJwk } = await keyPair();
    const other = await generateKeyPair();
    assert.notEqual(
      await publicKeyFingerprint(publicKeyJwk),
      await publicKeyFingerprint(other.publicKeyJwk)
    );
  });
});

describe('base64ToArrayBuffer', () => {
  test('decodes to the correct bytes', () => {
    const buffer = base64ToArrayBuffer('aGVsbG8='); // "hello"
    assert.deepEqual([...new Uint8Array(buffer)], [...Buffer.from('hello')]);
  });

  test('round-trips against the values produced by encrypt', async () => {
    const enc = await encrypt('secret', PASS);
    const bytes = new Uint8Array(base64ToArrayBuffer(enc.salt));
    assert.equal(Buffer.from(bytes).toString('base64'), enc.salt);
  });
});

describe('error taxonomy', () => {
  test('every icod error extends IcodError and Error with a stable name and code', () => {
    const cases = [
      [new CryptoAPIUnavailableError(), 'CryptoAPIUnavailableError', 'CRYPTO_API_UNAVAILABLE'],
      [new InvalidPassphraseError(), 'InvalidPassphraseError', 'INVALID_PASSPHRASE'],
      [new InvalidKeyError(), 'InvalidKeyError', 'INVALID_KEY'],
      [new CorruptedDataError('detail'), 'CorruptedDataError', 'CORRUPTED_DATA'],
      [new MissingFieldError('field'), 'MissingFieldError', 'MISSING_FIELD'],
      [new DecryptionFailedError(), 'DecryptionFailedError', 'DECRYPTION_FAILED'],
      [new EncryptionFailedError(), 'EncryptionFailedError', 'ENCRYPTION_FAILED'],
      [new KeyWrapError(), 'KeyWrapError', 'KEY_WRAP_FAILED'],
    ];
    for (const [err, name, code] of cases) {
      assert.ok(err instanceof IcodError, `${name} should extend IcodError`);
      assert.ok(err instanceof Error, `${name} should extend Error`);
      assert.equal(err.name, name);
      assert.equal(err.code, code);
      assert.ok(err.message.length > 0, `${name} should have a message`);
    }
  });

  test('IcodError carries the code passed to its constructor', () => {
    const err = new IcodError('boom', 'CUSTOM_CODE');
    assert.equal(err.message, 'boom');
    assert.equal(err.code, 'CUSTOM_CODE');
    assert.equal(err.name, 'IcodError');
  });
});
