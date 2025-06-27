const { 
  encrypt, 
  decrypt, 
  isWebCryptoAvailable,
  InvalidPassphraseError,
  MissingFieldError,
  CorruptedDataError
} = require('./dist/index');

async function runTests() {
  console.log('Running icod-js tests...\n');

  let passedTests = 0;
  let totalTests = 0;

  // Test helper
  async function test(name, fn) {
    totalTests++;
    try {
      await fn();
      console.log(`✓ ${name}`);
      passedTests++;
    } catch (error) {
      console.error(`✗ ${name}`);
      console.error(`  Error: ${error.message}`);
    }
  }

  // Test 1: Web Crypto API availability
  await test('Web Crypto API is available', () => {
    console.assert(isWebCryptoAvailable() === true, 'Web Crypto API should be available in Node.js');
  });

  // Test 2: Basic encryption and decryption
  await test('Basic encryption and decryption', async () => {
    const plaintext = 'Hello, World!';
    const passphrase = 'my-secret-passphrase';
    
    const encrypted = await encrypt(plaintext, passphrase);
    console.assert(encrypted.ciphertext, 'Should have ciphertext');
    console.assert(encrypted.iv, 'Should have IV');
    console.assert(encrypted.salt, 'Should have salt');
    console.assert(encrypted.keyHash, 'Should have keyHash');
    console.assert(encrypted.version === 1, 'Should have version 1');
    
    const decrypted = await decrypt(encrypted, passphrase);
    console.assert(decrypted === plaintext, 'Decrypted text should match original');
  });

  // Test 3: Different passphrases produce different results
  await test('Different passphrases produce different results', async () => {
    const plaintext = 'Test message';
    const passphrase1 = 'passphrase1';
    const passphrase2 = 'passphrase2';
    
    const encrypted1 = await encrypt(plaintext, passphrase1);
    const encrypted2 = await encrypt(plaintext, passphrase2);
    
    console.assert(encrypted1.ciphertext !== encrypted2.ciphertext, 'Different passphrases should produce different ciphertexts');
    console.assert(encrypted1.keyHash !== encrypted2.keyHash, 'Different passphrases should produce different key hashes');
  });

  // Test 4: Same passphrase with different salts produces different results
  await test('Same passphrase with different salts produces different results', async () => {
    const plaintext = 'Test message';
    const passphrase = 'my-passphrase';
    
    const encrypted1 = await encrypt(plaintext, passphrase);
    const encrypted2 = await encrypt(plaintext, passphrase);
    
    console.assert(encrypted1.salt !== encrypted2.salt, 'Each encryption should have a unique salt');
    console.assert(encrypted1.iv !== encrypted2.iv, 'Each encryption should have a unique IV');
    console.assert(encrypted1.ciphertext !== encrypted2.ciphertext, 'Same passphrase with different salts should produce different ciphertexts');
  });

  // Test 5: Wrong passphrase throws InvalidPassphraseError
  await test('Wrong passphrase throws InvalidPassphraseError', async () => {
    const plaintext = 'Secret message';
    const correctPassphrase = 'correct-passphrase';
    const wrongPassphrase = 'wrong-passphrase';
    
    const encrypted = await encrypt(plaintext, correctPassphrase);
    
    try {
      await decrypt(encrypted, wrongPassphrase);
      throw new Error('Should have thrown InvalidPassphraseError');
    } catch (error) {
      console.assert(error instanceof InvalidPassphraseError, 'Should throw InvalidPassphraseError');
      console.assert(error.code === 'INVALID_PASSPHRASE', 'Error should have correct code');
    }
  });

  // Test 6: Missing fields throw MissingFieldError
  await test('Missing fields throw MissingFieldError', async () => {
    const incompleteData = {
      ciphertext: 'test',
      iv: 'test',
      // Missing salt, keyHash, version
    };
    
    try {
      await decrypt(incompleteData, 'passphrase');
      throw new Error('Should have thrown MissingFieldError');
    } catch (error) {
      console.assert(error instanceof MissingFieldError, 'Should throw MissingFieldError');
      console.assert(error.code === 'MISSING_FIELD', 'Error should have correct code');
    }
  });

  // Test 7: Corrupted data throws CorruptedDataError
  await test('Corrupted data throws CorruptedDataError', async () => {
    const plaintext = 'Test message';
    const passphrase = 'test-passphrase';
    
    const encrypted = await encrypt(plaintext, passphrase);
    
    // Corrupt the ciphertext
    const corruptedData = {
      ...encrypted,
      ciphertext: encrypted.ciphertext.slice(0, -4) + 'XXXX'
    };
    
    try {
      await decrypt(corruptedData, passphrase);
      throw new Error('Should have thrown CorruptedDataError');
    } catch (error) {
      console.assert(error instanceof CorruptedDataError, 'Should throw CorruptedDataError');
      console.assert(error.code === 'CORRUPTED_DATA', 'Error should have correct code');
    }
  });

  // Test 8: Invalid base64 throws CorruptedDataError
  await test('Invalid base64 throws CorruptedDataError', async () => {
    const invalidData = {
      ciphertext: 'not-valid-base64!@#$',
      iv: 'test',
      salt: 'test',
      keyHash: 'test',
      version: 1
    };
    
    try {
      await decrypt(invalidData, 'passphrase');
      throw new Error('Should have thrown CorruptedDataError');
    } catch (error) {
      console.assert(error instanceof CorruptedDataError, 'Should throw CorruptedDataError');
      console.assert(error.message.includes('Invalid base64'), 'Error message should mention base64');
    }
  });

  // Test 9: Large text encryption/decryption
  await test('Large text encryption/decryption', async () => {
    const largeText = 'Lorem ipsum '.repeat(1000); // ~12KB of text
    const passphrase = 'test-passphrase';
    
    const encrypted = await encrypt(largeText, passphrase);
    const decrypted = await decrypt(encrypted, passphrase);
    
    console.assert(decrypted === largeText, 'Large text should encrypt and decrypt correctly');
  });

  // Test 10: Empty string encryption/decryption
  await test('Empty string encryption/decryption', async () => {
    const emptyText = '';
    const passphrase = 'test-passphrase';
    
    const encrypted = await encrypt(emptyText, passphrase);
    const decrypted = await decrypt(encrypted, passphrase);
    
    console.assert(decrypted === emptyText, 'Empty string should encrypt and decrypt correctly');
  });

  // Summary
  console.log(`\n${passedTests}/${totalTests} tests passed`);
  
  if (passedTests < totalTests) {
    process.exit(1);
  }
}

// Run tests
runTests().catch(console.error);