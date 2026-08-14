# ICOD Vault Archive format

This document specifies the on-disk format of an exported ICOD vault, and the
procedure for decrypting one.

It exists so that a vault outlives the company that produced it. Everything needed to
read an archive is either in this document or in this repository. No ICOD server,
account, or continued corporate existence is required. If you can run Node, or
reimplement AES-GCM and PBKDF2 in any language, you can recover the contents.

The reference implementation is [`bin/icod-restore.js`](bin/icod-restore.js), which
uses only Node built-ins.

---

## 1. Container

An archive is a **single UTF-8 JSON file**, conventionally named
`icod-vault-{vault_ulid}.json`.

A single JSON file rather than a zip of separate entries, deliberately: Node has no
built-in zip reader, and a format whose reference decryptor needs a third-party
dependency to open the container is a format with a supply-chain dependency in the
one code path that is supposed to survive everything. The manifest is therefore a
top-level `manifest` key rather than a `manifest.json` member.

The archive contains **no plaintext vault content and no key capable of decrypting
it**. It is exactly as safe to store as the ICOD database rows it was built from.
Store it wherever you store your will.

## 2. Top-level shape

```json
{
  "manifest": { ... },
  "owner_key": { ... },
  "trustees": [ ... ],
  "versions": [ ... ]
}
```

## 3. `manifest`

Self-describing metadata. A decryptor should read its parameters from here rather
than hard-coding them, so that archives written by a future version remain readable.

```json
{
  "format": "icod-vault-archive",
  "format_version": 1,
  "generated_at": "2026-08-14T17:04:11+00:00",
  "generator": "icod/1.0 icod-js/2.0.0",
  "vault": {
    "ulid": "01J...",
    "label": "Vault 1",
    "content_schema_version": 1,
    "key_hash": "base64 SHA-256 of the DEK"
  },
  "crypto": {
    "payload_version": 2,
    "content": {
      "algorithm": "AES-GCM",
      "key_length_bits": 256,
      "iv_length_bytes": 12
    },
    "passphrase_derivation": {
      "algorithm": "PBKDF2",
      "hash": "SHA-256",
      "iterations": 600000,
      "salt_length_bytes": 16
    },
    "key_wrapping": {
      "algorithm": "RSA-OAEP",
      "modulus_length_bits": 3072,
      "hash": "SHA-256"
    }
  },
  "aad": {
    "owner_key": "icod:v2:vault:{vault_ulid}:owner:{user_ulid}",
    "version": "icod:v2:vault:{vault_ulid}:version:{version_ulid}",
    "trustee_private_key": "icod:v2:vault:{vault_ulid}:trustee:{trustee_ulid}:privkey"
  }
}
```

`crypto.passphrase_derivation.iterations` applies to `payload_version` 2. Version 1
payloads, if any appear, use 100,000 iterations. Each payload carries its own
`version` field; always read the count from the payload, not from the manifest.

## 4. `EncryptedData` payloads

Every encrypted blob in the archive has the same shape:

```json
{
  "ciphertext": "base64",
  "iv": "base64, 12 bytes",
  "salt": "base64, 16 bytes — passphrase mode only",
  "keyHash": "base64 SHA-256 of the AES key",
  "version": 2,
  "mode": "passphrase" | "key"
}
```

- **`mode: "passphrase"`** — the AES key was derived from a password with PBKDF2 over
  `salt`. Used for the owner's wrapped DEK and for each trustee's wrapped private key.
- **`mode: "key"`** — the AES key *is* the DEK, supplied directly. No derivation, so no
  `salt`. Used for vault content.

`keyHash` lets you check you hold the right key before attempting to decrypt, which is
what distinguishes "wrong password" from "damaged data". Check it first. It is not a
substitute for the AES-GCM authentication tag; both checks apply.

## 5. Additional authenticated data (AAD)

**Every payload is bound to a context string.** The string is not encrypted, but it is
authenticated: decryption fails if it does not match byte-for-byte at decrypt time.
This is what prevents a payload being swapped between vaults, replayed at a different
position in the history, or rolled back.

You must supply the exact context string as AES-GCM additional data, encoded as UTF-8:

| Payload | Context string |
|---|---|
| Vault content version | `icod:v2:vault:{vault_ulid}:version:{version_ulid}` |
| Owner wrapped DEK | `icod:v2:vault:{vault_ulid}:owner:{user_ulid}` |
| Trustee wrapped private key | `icod:v2:vault:{vault_ulid}:trustee:{trustee_ulid}:privkey` |

Each entry in the archive also carries its own resolved `aad` string, so a decryptor
never has to build one by hand. RSA-OAEP has no AAD, so a trustee's wrapped DEK is not
bound this way — it is bound by the fingerprint the owner pinned at arming time.

## 6. `owner_key`

The DEK, encrypted under the owner's vault password.

```json
{
  "user_ulid": "01J...",
  "wrap_method": "passphrase",
  "aad": "icod:v2:vault:01J...:owner:01J...",
  "payload": { "...EncryptedData, mode: passphrase..." }
}
```

Decrypting `payload` with the owner's vault password yields the **base64 DEK**.

## 7. `trustees[]`

One entry per trustee who was armed at export time.

```json
{
  "ulid": "01J...",
  "name": "Dana",
  "email": "dana@example.com",
  "public_key_fingerprint": "K7QX-M2PA-...",
  "wrapped_private_key": {
    "aad": "icod:v2:vault:01J...:trustee:01J...:privkey",
    "payload": { "...EncryptedData, mode: passphrase..." }
  },
  "wrapped_dek": { "wrapped": "base64 RSA-OAEP ciphertext" }
}
```

A trustee recovers the DEK in two steps:

1. Decrypt `wrapped_private_key.payload` with **their own** vault password (which is
   specific to this vault) to obtain a base64 PKCS#8 RSA private key.
2. RSA-OAEP-decrypt `wrapped_dek.wrapped` with that private key to obtain the base64 DEK.

## 8. `versions[]`

The full content history, oldest first. Append-only: a version is never rewritten.

```json
{
  "ulid": "01J...",
  "version_number": 7,
  "created_at": "2026-08-14T16:59:02+00:00",
  "content_schema_version": 1,
  "aad": "icod:v2:vault:01J...:version:01J...",
  "payload": { "...EncryptedData, mode: key..." }
}
```

Decrypting `payload` with the DEK yields a JSON document:

```json
{ "schema": 1, "body_markdown": "## Bank accounts\n\n..." }
```

Schema 1 is a single markdown body. Later schemas add structure; the `schema` field
tells you which you are holding.

## 9. Decryption procedure

**As the owner:**

1. Read `owner_key.payload` and `owner_key.aad`.
2. Derive an AES-256 key: PBKDF2-SHA256 over the vault password with the payload's
   `salt`, at the iteration count for the payload's `version` (2 → 600,000, 1 → 100,000).
3. Confirm `SHA-256(derived key)` equals the payload's `keyHash`. If it does not, the
   password is wrong — stop, and do not report this as data corruption.
4. AES-GCM-decrypt `ciphertext` with `iv` and the AAD string. The result is the base64 DEK.
5. Confirm `SHA-256(DEK)` equals `manifest.vault.key_hash`.
6. For each version, AES-GCM-decrypt `payload` with the DEK and that version's `aad`.

**As a trustee:** replace steps 1–4 with the two-step recovery in §7, then continue
from step 5.

## 10. Reference CLI

```
npx icod-restore ./icod-vault-01J....json
npx icod-restore ./archive.json --list
npx icod-restore ./archive.json --version 3
npx icod-restore ./archive.json --trustee 01J... --all
```

It prompts for the password without echoing it, makes no network requests, and writes
the decrypted content to stdout. Run it offline; that is the point.
