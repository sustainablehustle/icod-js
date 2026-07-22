# ICOD JS

A client-side encryption library using AES-GCM with passphrase-derived keys (PBKDF2). The library ensures that servers never see plaintext or passphrases—only encrypted payloads.

## Features

- 🔐 **AES-GCM encryption** with 256-bit keys
- 🔑 **PBKDF2 key derivation** (100,000 iterations, SHA-256)
- ✅ **Passphrase verification** without storing the passphrase
- 🛡️ **TypeScript support** with full type definitions
- 🌐 **Web Crypto API** based (works in modern browsers and Node.js)
- 🚨 **Detailed error handling** with specific error types

## Installation

```bash
npm install icod-js
```

## Usage

### Basic Encryption and Decryption

```javascript
import { encrypt, decrypt, isWebCryptoAvailable } from 'icod-js';

// Check if Web Crypto API is available
if (!isWebCryptoAvailable()) {
  console.error('Web Crypto API not available');
  return;
}

// Encrypt
const plaintext = 'Hello, World!';
const passphrase = 'my-secret-passphrase';

const encryptedData = await encrypt(plaintext, passphrase);
console.log(encryptedData);
// {
//   ciphertext: "Z2Fu3fF5Fphu0==",
//   iv: "A12k38v911aMuH==",
//   salt: "Pq9dX6tVkU2cJ==",
//   keyHash: "2Fu3fF5Fphu0==",
//   version: 1
// }

// Decrypt
const decrypted = await decrypt(encryptedData, passphrase);
console.log(decrypted); // "Hello, World!"
```

### Error Handling

The library provides specific error types for different scenarios:

```javascript
import { 
  decrypt, 
  InvalidPassphraseError,
  MissingFieldError,
  CorruptedDataError,
  CryptoAPIUnavailableError
} from 'icod-js';

try {
  const decrypted = await decrypt(encryptedData, wrongPassphrase);
} catch (error) {
  if (error instanceof InvalidPassphraseError) {
    console.error('Wrong passphrase!');
  } else if (error instanceof CorruptedDataError) {
    console.error('Data is corrupted or tampered with');
  } else if (error instanceof MissingFieldError) {
    console.error('Missing required field:', error.message);
  }
}
```

## API Reference

### Functions

#### `isWebCryptoAvailable(): boolean`
Check if the Web Crypto API is available in the current environment.

#### `encrypt(plaintext: string, passphrase: string, options?: EncryptionOptions): Promise<EncryptedData>`
Encrypt plaintext using AES-GCM with a passphrase-derived key.

**Parameters:**
- `plaintext` - The text to encrypt
- `passphrase` - The passphrase for encryption
- `options` - Optional encryption options (e.g., additional authenticated data)

**Returns:** Promise resolving to `EncryptedData`

#### `decrypt(encryptedData: EncryptedData, passphrase: string, options?: EncryptionOptions): Promise<string>`
Decrypt ciphertext using AES-GCM with a passphrase-derived key.

**Parameters:**
- `encryptedData` - The encrypted data structure
- `passphrase` - The passphrase for decryption
- `options` - Optional decryption options (must match encryption options)

**Returns:** Promise resolving to the decrypted plaintext

### Types

#### `EncryptedData`
```typescript
interface EncryptedData {
  ciphertext: string;  // Base64-encoded ciphertext
  iv: string;          // Base64-encoded initialization vector (12 bytes)
  salt: string;        // Base64-encoded salt for PBKDF2
  keyHash: string;     // Base64-encoded SHA-256 hash of derived key
  version: number;     // Version identifier (currently 1)
}
```

### Error Types

- `CryptoAPIUnavailableError` - Web Crypto API is not available
- `InvalidPassphraseError` - Incorrect passphrase provided
- `CorruptedDataError` - Data appears corrupted or tampered with
- `MissingFieldError` - Required field missing from encrypted data
- `EncryptionFailedError` - Encryption operation failed
- `DecryptionFailedError` - Decryption operation failed

## Security Considerations

- **HTTPS Required**: Web Crypto API requires secure contexts (HTTPS)
- **Unique Salt/IV**: Each encryption generates a unique salt and IV
- **No Passphrase Storage**: Passphrases are never stored, only derived key hashes
- **Constant-Time Comparison**: Key verification uses constant-time comparison to prevent timing attacks
- **Version Control**: Encrypted data includes version field for future compatibility

## Browser Compatibility

Requires browsers with Web Crypto API support:
- Chrome 37+
- Firefox 34+
- Safari 11+
- Edge 79+
- Node.js 22+ (with crypto module)

## License

Business Source License 1.1 (BSL-1.1)

This source code is available for inspection and audit purposes only. Redistribution, modification, or commercial use is prohibited without explicit permission.
