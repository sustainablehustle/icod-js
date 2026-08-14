# ICOD JS

A client-side encryption library for envelope encryption in the browser. Content is
encrypted under a raw data key, that key is wrapped either under a passphrase or under
someone else's public key, and the server holds only ciphertext. It never sees a
passphrase, a data key, a private key, or plaintext.

## Features

- 🔐 **AES-GCM-256** content encryption, under a passphrase-derived key or a raw key
- 🔑 **PBKDF2-SHA256** at 600,000 iterations (v2), version-aware on read
- 🤝 **RSA-OAEP-3072 key wrapping**, so a key can travel through an untrusted server
- 🔗 **Authenticated associated data**, binding every ciphertext to its context
- 👀 **Human-readable key fingerprints** for out-of-band verification
- ✅ **Key verification without decrypting**, distinguishing a wrong key from damaged data
- 📦 **`icod-restore` CLI** — decrypt an exported archive offline, with zero dependencies
- 🛡️ **TypeScript** definitions throughout
- 🌐 **Web Crypto API** based (modern browsers and Node.js 22+)

## Installation

```bash
npm install icod-js
```

## Concepts

The library supports two encryption modes, and every payload says which one it is via
its `mode` field.

| Mode | Key comes from | Carries a `salt` | Used for |
|---|---|---|---|
| `passphrase` | PBKDF2 over a human-chosen secret | yes | Wrapping key material |
| `key` | A raw 256-bit key you supply | no | Bulk content |

The intended shape is: generate one data key, encrypt all content under it with
`encryptWithKey`, and protect *that key* — under a passphrase with `encrypt`, or under
a recipient's public key with `wrapKey`. Changing a password re-wraps the key rather
than re-encrypting the content.

## Usage

### Passphrase encryption

```javascript
import { encrypt, decrypt, isWebCryptoAvailable } from 'icod-js';

if (!isWebCryptoAvailable()) {
  throw new Error('Web Crypto is unavailable — a secure context (HTTPS) is required.');
}

const encrypted = await encrypt('Hello, World!', 'my-secret-passphrase');
// {
//   ciphertext: "Z2Fu3fF5Fphu0==",
//   iv:         "A12k38v911aMuH==",
//   salt:       "Pq9dX6tVkU2cJ==",
//   keyHash:    "2Fu3fF5Fphu0==",
//   version:    2,
//   mode:       "passphrase"
// }

await decrypt(encrypted, 'my-secret-passphrase'); // "Hello, World!"
```

### Raw-key encryption

Running PBKDF2 over an already-random key on every save is both wasteful and
semantically wrong, so bulk content uses the key directly.

```javascript
import { generateDek, encryptWithKey, decryptWithKey, verifyKey } from 'icod-js';

const dek = generateDek();                   // 32 random bytes, base64

const encrypted = await encryptWithKey(JSON.stringify(document), dek);
await decryptWithKey(encrypted, dek);

// Before overwriting or appending, prove you hold the right key.
if (!(await verifyKey(dek, encrypted))) {
  throw new Error('Refusing to write: the key in memory is not this payload’s key.');
}
```

### Key wrapping

How a data key reaches someone else's browser through a server that must not be able
to read it.

```javascript
import { generateKeyPair, wrapKey, unwrapKey, publicKeyFingerprint } from 'icod-js';

// Recipient, once:
const { publicKeyJwk, privateKeyB64 } = await generateKeyPair();
// Publish publicKeyJwk. Encrypt privateKeyB64 under their own passphrase before storing it.

// Sender, after verifying the fingerprint out of band:
const wrapped = await wrapKey(dek, publicKeyJwk);

// Recipient, later:
const recovered = await unwrapKey(wrapped, privateKeyB64);
```

**Verify the fingerprint out of band.** A server that can substitute a public key can
receive a data key it is able to decrypt, and no amount of client-side encryption
prevents that. `publicKeyFingerprint()` returns six groups of four base32 characters —
`K7QX-M2PA-9TVR-5NHD-E4WB-3JZS` — designed to be read aloud over a channel that is not
the server in question.

```javascript
await publicKeyFingerprint(publicKeyJwk);
```

The alphabet excludes the characters people confuse when reading aloud (0/O, 1/I/L),
and the digest is taken over the SPKI encoding, so it does not shift because a JSON
round-trip reordered the JWK's fields.

### Binding a ciphertext to its context

`additionalData` is authenticated but not encrypted: if it differs at decrypt time,
decryption fails. Use it to bind a payload to its identity and position so it cannot be
swapped, replayed, or rolled back undetected.

```javascript
const context = `myapp:v2:document:${documentId}:version:${versionId}`;

const encrypted = await encryptWithKey(body, dek, { additionalData: context });
await decryptWithKey(encrypted, dek, { additionalData: context }); // ok
await decryptWithKey(encrypted, dek, { additionalData: 'something else' }); // throws
```

Strings are encoded as UTF-8; `ArrayBuffer` and `Uint8Array` are also accepted.

### Error handling

The library distinguishes **"you used the wrong key"** from **"this data is damaged"**.
That distinction matters: telling someone who mistyped a password that their data looks
tampered with is alarming and wrong.

```javascript
import {
  decrypt,
  InvalidPassphraseError,
  InvalidKeyError,
  CorruptedDataError,
} from 'icod-js';

try {
  await decrypt(encrypted, candidatePassphrase);
} catch (error) {
  if (error instanceof InvalidPassphraseError) {
    // Wrong passphrase. Nothing is wrong with the data.
  } else if (error instanceof CorruptedDataError) {
    // The key was right and the ciphertext failed to authenticate.
    // This is real corruption or tampering: alert, log, do not overwrite.
  }
}
```

This works because each payload stores `keyHash`, a SHA-256 of the AES key, which is
checked in constant time *before* the ciphertext is touched. Storing it costs an
attacker essentially nothing — holding the database, they can already test a candidate
password by trial-decrypting the ciphertext, and PBKDF2 dominates that cost by orders
of magnitude either way — while giving an honest client the ability to verify a key
before using it.

`keyHash` says "this is the right key", not "this data is intact". Both checks run.

## `icod-restore`

A dependency-free CLI that decrypts an exported archive with no network access and no
server. See [FORMAT.md](FORMAT.md) for the archive specification and the manual
decryption procedure.

```bash
npx icod-restore ./vault.json              # latest version
npx icod-restore ./vault.json --list       # inventory, without decrypting
npx icod-restore ./vault.json --all        # full history
npx icod-restore ./vault.json --trustee 01J...
```

## API reference

### Content encryption

| Function | Description |
|---|---|
| `encrypt(plaintext, passphrase, options?)` | Encrypt under a passphrase-derived key |
| `decrypt(data, passphrase, options?)` | Decrypt a `passphrase`-mode payload |
| `encryptWithKey(plaintext, keyB64, options?)` | Encrypt under a raw 256-bit key |
| `decryptWithKey(data, keyB64, options?)` | Decrypt a `key`-mode payload |

### Key material

| Function | Description |
|---|---|
| `generateDek()` | 32 random bytes, base64. Synchronous |
| `keyHashOf(keyB64)` | base64 SHA-256 of a raw key |
| `verifyPassphrase(passphrase, data)` | Check a passphrase against a payload's `keyHash` |
| `verifyKey(keyB64, data)` | Check a raw key against a payload's `keyHash` |

### Asymmetric wrapping

| Function | Description |
|---|---|
| `generateKeyPair()` | RSA-OAEP-3072 keypair as `{ publicKeyJwk, privateKeyB64 }` |
| `wrapKey(keyB64, publicKeyJwk)` | Encrypt a raw key to a public key |
| `unwrapKey(wrapped, privateKeyB64)` | Recover a raw key with the private key |
| `publicKeyFingerprint(publicKeyJwk)` | Six groups of four base32 characters |

### Environment

| Function | Description |
|---|---|
| `isWebCryptoAvailable()` | Whether Web Crypto is usable here |

### Types

```typescript
type EncryptionMode = 'passphrase' | 'key';

interface EncryptedData {
  ciphertext: string;    // base64
  iv: string;            // base64, 12 bytes
  salt?: string;         // base64, 16 bytes — passphrase mode only
  keyHash: string;       // base64 SHA-256 of the AES key
  version: number;       // 2 for anything written by this release
  mode?: EncryptionMode; // absent on v1 payloads, which are always passphrase mode
}

interface EncryptionOptions {
  additionalData?: ArrayBuffer | Uint8Array | string;
}

interface GeneratedKeyPair {
  publicKeyJwk: JsonWebKey;
  privateKeyB64: string;  // PKCS#8, base64. Encrypt before storing.
}
```

### Error types

| Error | Code | Meaning |
|---|---|---|
| `CryptoAPIUnavailableError` | `CRYPTO_API_UNAVAILABLE` | No Web Crypto in this context |
| `InvalidPassphraseError` | `INVALID_PASSPHRASE` | Wrong passphrase. The data is fine |
| `InvalidKeyError` | `INVALID_KEY` | Wrong raw key. The data is fine |
| `CorruptedDataError` | `CORRUPTED_DATA` | Right key, failed authentication |
| `MissingFieldError` | `MISSING_FIELD` | Required field absent from the payload |
| `KeyWrapError` | `KEY_WRAP_FAILED` | A wrap or unwrap operation failed |
| `EncryptionFailedError` | `ENCRYPTION_FAILED` | Encryption failed |
| `DecryptionFailedError` | `DECRYPTION_FAILED` | Decryption failed for another reason |

All extend `IcodError`, which carries a stable `code`.

## Versioning and compatibility

v2 raised PBKDF2 from 100,000 to 600,000 iterations. Every payload carries a `version`,
and `decrypt` reads the iteration count from it, so **v1 payloads remain readable
indefinitely**. Everything written by this release is v2.

`EncryptedData` changed in v2: `salt` became optional and `mode` was added. Readers
should treat a missing `mode` as `'passphrase'`.

## Security considerations

- **HTTPS required.** Web Crypto refuses to operate outside a secure context.
- **Fresh salt and IV per operation.** Never reused.
- **Constant-time comparison** on every key-hash check.
- **Verify fingerprints out of band.** This is the only defence against a server
  substituting a public key. It cannot be automated away.
- **Client-side encryption does not protect you from a hostile server**, which can
  serve modified JavaScript to the browser that runs it. This is inherent to
  browser-delivered cryptography.
- **Private keys must be encrypted before storage.** `generateKeyPair()` hands back raw
  PKCS#8; wrapping it is the caller's job.

## Browser compatibility

Requires Web Crypto API support:

- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 79+
- Node.js 22+

## Development

```bash
npm run build       # compile TypeScript to dist/
npm run typecheck   # type-check without emitting
npm test            # build, then run the library and CLI suites
```

## License

Business Source License 1.1 (BSL-1.1)

This source code is available for inspection and audit purposes only. Redistribution,
modification, or commercial use is prohibited without explicit permission.
