'use strict';

// Test suite for the icod-restore CLI.
//
// Separate from test.js because these tests spawn the CLI as a real subprocess and
// assert on its exit codes and stdout, rather than calling library functions.
//
//   node test-cli.js       (see package.json "test", which builds first)
//
// The archive fixture is assembled here with the library itself, following FORMAT.md
// exactly as the server-side exporter must. If this suite passes, an archive really
// can be decrypted with nothing but this repository and a password — which is the
// entire continuity guarantee.

const { test, describe, before } = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  generateDek,
  keyHashOf,
  encrypt,
  encryptWithKey,
  generateKeyPair,
  wrapKey,
  publicKeyFingerprint,
} = require('./dist/index.js');

const CLI = path.join(__dirname, 'bin', 'icod-restore.js');

const OWNER_PASSWORD = 'owner correct horse battery staple';
const TRUSTEE_PASSWORD = 'trustee correct horse battery staple';

const VAULT_ULID = '01JZZZVAULT0000000000000AA';
const OWNER_ULID = '01JZZZOWNER0000000000000BB';
const TRUSTEE_ULID = '01JZZZTRUST0000000000000CC';

const BODIES = [
  '## Bank accounts\n\nFirst Direct, sort code in the safe.',
  '## Bank accounts\n\nFirst Direct, sort code in the safe.\n\n## Pension\n\nCall Dave.',
  '## Bank accounts\n\nFirst Direct, sort code in the safe.\n\n## Pension\n\nCall Dave at Hensley & Co.',
];

let archivePath;
let tempDir;

/** Build an archive exactly as FORMAT.md specifies. */
async function buildArchive() {
  const dek = generateDek();

  const ownerAad = `icod:v2:vault:${VAULT_ULID}:owner:${OWNER_ULID}`;
  const privkeyAad = `icod:v2:vault:${VAULT_ULID}:trustee:${TRUSTEE_ULID}:privkey`;

  const ownerPayload = await encrypt(dek, OWNER_PASSWORD, { additionalData: ownerAad });

  const { publicKeyJwk, privateKeyB64 } = await generateKeyPair();
  const wrappedPrivateKey = await encrypt(privateKeyB64, TRUSTEE_PASSWORD, {
    additionalData: privkeyAad,
  });

  const versions = [];
  for (let i = 0; i < BODIES.length; i++) {
    const versionUlid = `01JZZZVERSION${String(i).padStart(11, '0')}`;
    const aad = `icod:v2:vault:${VAULT_ULID}:version:${versionUlid}`;
    versions.push({
      ulid: versionUlid,
      version_number: i + 1,
      created_at: `2026-08-0${i + 1}T10:00:00+00:00`,
      content_schema_version: 1,
      aad,
      payload: await encryptWithKey(
        JSON.stringify({ schema: 1, body_markdown: BODIES[i] }),
        dek,
        { additionalData: aad }
      ),
    });
  }

  return {
    manifest: {
      format: 'icod-vault-archive',
      format_version: 1,
      generated_at: '2026-08-14T17:04:11+00:00',
      generator: 'icod-js test fixture',
      vault: {
        ulid: VAULT_ULID,
        label: 'Vault 1',
        content_schema_version: 1,
        key_hash: await keyHashOf(dek),
      },
      crypto: {
        payload_version: 2,
        content: { algorithm: 'AES-GCM', key_length_bits: 256, iv_length_bytes: 12 },
        passphrase_derivation: {
          algorithm: 'PBKDF2',
          hash: 'SHA-256',
          iterations: 600000,
          salt_length_bytes: 16,
        },
        key_wrapping: { algorithm: 'RSA-OAEP', modulus_length_bits: 3072, hash: 'SHA-256' },
      },
      aad: {
        owner_key: 'icod:v2:vault:{vault_ulid}:owner:{user_ulid}',
        version: 'icod:v2:vault:{vault_ulid}:version:{version_ulid}',
        trustee_private_key: 'icod:v2:vault:{vault_ulid}:trustee:{trustee_ulid}:privkey',
      },
    },
    owner_key: {
      user_ulid: OWNER_ULID,
      wrap_method: 'passphrase',
      aad: ownerAad,
      payload: ownerPayload,
    },
    trustees: [
      {
        ulid: TRUSTEE_ULID,
        name: 'Dana',
        email: 'dana@example.com',
        public_key_fingerprint: await publicKeyFingerprint(publicKeyJwk),
        wrapped_private_key: { aad: privkeyAad, payload: wrappedPrivateKey },
        wrapped_dek: { wrapped: await wrapKey(dek, publicKeyJwk) },
      },
    ],
    versions,
  };
}

/** Run the CLI, feeding the password over stdin. Never rejects — the tests assert on code. */
function runCli(args, password = '') {
  return new Promise((resolve) => {
    const child = execFile(
      process.execPath,
      [CLI, ...args],
      { encoding: 'utf8' },
      (error, stdout, stderr) => {
        resolve({ code: error ? error.code : 0, stdout, stderr });
      }
    );
    child.stdin.end(password);
  });
}

function writeArchive(name, archive) {
  const file = path.join(tempDir, name);
  fs.writeFileSync(file, JSON.stringify(archive, null, 2));
  return file;
}

before(async () => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'icod-restore-test-'));
  archivePath = writeArchive('vault.json', await buildArchive());
});

describe('icod-restore: owner recovery', () => {
  test('decrypts the latest version with only the archive and the password', async () => {
    const { code, stdout } = await runCli([archivePath, '--password-stdin'], OWNER_PASSWORD);
    assert.equal(code, 0);
    assert.equal(stdout.trim(), BODIES[BODIES.length - 1]);
  });

  test('decrypts a specific version', async () => {
    const { code, stdout } = await runCli(
      [archivePath, '--password-stdin', '--version', '1'],
      OWNER_PASSWORD
    );
    assert.equal(code, 0);
    assert.match(stdout, /First Direct, sort code in the safe\./);
    assert.doesNotMatch(stdout, /Hensley/);
  });

  test('decrypts the whole history with --all, oldest first', async () => {
    const { code, stdout } = await runCli(
      [archivePath, '--password-stdin', '--all'],
      OWNER_PASSWORD
    );
    assert.equal(code, 0);
    for (let i = 1; i <= BODIES.length; i++) {
      assert.match(stdout, new RegExp(`Version ${i}\\b`));
    }
    assert.ok(
      stdout.indexOf('Version 1') < stdout.indexOf('Version 3'),
      'versions should print oldest first'
    );
  });

  test('--json emits the raw content document', async () => {
    const { code, stdout } = await runCli(
      [archivePath, '--password-stdin', '--json'],
      OWNER_PASSWORD
    );
    assert.equal(code, 0);
    const document = JSON.parse(stdout);
    assert.equal(document.schema, 1);
    assert.equal(document.body_markdown, BODIES[BODIES.length - 1]);
  });
});

describe('icod-restore: trustee recovery', () => {
  // The path that matters after the owner has died: a different password, a
  // different key, and two unwrapping steps to reach the same plaintext.
  test('decrypts via wrapped private key and wrapped DEK', async () => {
    const { code, stdout } = await runCli(
      [archivePath, '--password-stdin', '--trustee', TRUSTEE_ULID],
      TRUSTEE_PASSWORD
    );
    assert.equal(code, 0);
    assert.equal(stdout.trim(), BODIES[BODIES.length - 1]);
  });

  test("the owner's password does not work as a trustee", async () => {
    const { code, stderr } = await runCli(
      [archivePath, '--password-stdin', '--trustee', TRUSTEE_ULID],
      OWNER_PASSWORD
    );
    assert.equal(code, 77);
    assert.match(stderr, /didn't unlock this vault/);
  });

  test('an unknown trustee ULID lists the trustees that are present', async () => {
    const { code, stderr } = await runCli(
      [archivePath, '--password-stdin', '--trustee', 'nope'],
      TRUSTEE_PASSWORD
    );
    assert.equal(code, 64);
    assert.match(stderr, /no trustee 'nope'/);
    assert.match(stderr, new RegExp(TRUSTEE_ULID));
  });
});

describe('icod-restore: --list', () => {
  test('lists versions and trustees without asking for a password', async () => {
    const { code, stdout } = await runCli([archivePath, '--list']);
    assert.equal(code, 0);
    assert.match(stdout, new RegExp(VAULT_ULID));
    assert.match(stdout, /Versions \(3\)/);
    assert.match(stdout, /Trustees \(1\)/);
    assert.match(stdout, /Dana/);
    assert.match(stdout, /armed/);
    assert.match(stdout, /fingerprint [A-Z2-7]{4}-/);
    assert.match(stdout, /No content was decrypted/);
  });

  test('reveals no plaintext content', async () => {
    const { stdout } = await runCli([archivePath, '--list']);
    for (const body of BODIES) {
      assert.doesNotMatch(stdout, new RegExp(body.slice(0, 20)));
    }
  });
});

describe('icod-restore: error handling', () => {
  test('a wrong password reports a password problem, not corruption', async () => {
    const { code, stderr } = await runCli([archivePath, '--password-stdin'], 'not the password');
    assert.equal(code, 77);
    assert.match(stderr, /didn't unlock this vault/);
    assert.doesNotMatch(stderr, /corrupt|damaged|tampered/i);
  });

  test('damaged ciphertext reports corruption, not a password problem', async () => {
    const archive = JSON.parse(fs.readFileSync(archivePath, 'utf8'));
    const target = archive.versions[archive.versions.length - 1].payload;
    const bytes = Buffer.from(target.ciphertext, 'base64');
    bytes[0] ^= 0xff;
    target.ciphertext = bytes.toString('base64');
    const damaged = writeArchive('damaged.json', archive);

    const { code, stderr } = await runCli([damaged, '--password-stdin'], OWNER_PASSWORD);
    assert.notEqual(code, 0);
    assert.match(stderr, /integrity check|damaged|altered/i);
    assert.doesNotMatch(stderr, /didn't unlock/);
  });

  // Proves the AAD binding survives into the archive: a version payload moved to a
  // different position in the history no longer decrypts.
  test('a version replayed at another version\'s position fails to decrypt', async () => {
    const archive = JSON.parse(fs.readFileSync(archivePath, 'utf8'));
    archive.versions[2].payload = archive.versions[0].payload;
    const swapped = writeArchive('swapped.json', archive);

    const { code, stderr } = await runCli([swapped, '--password-stdin'], OWNER_PASSWORD);
    assert.notEqual(code, 0);
    assert.match(stderr, /integrity check|damaged|altered/i);
  });

  test('a mismatched vault key_hash is caught before decrypting any version', async () => {
    const archive = JSON.parse(fs.readFileSync(archivePath, 'utf8'));
    archive.manifest.vault.key_hash = Buffer.alloc(32, 7).toString('base64');
    const mismatched = writeArchive('mismatched.json', archive);

    const { code, stderr } = await runCli([mismatched, '--password-stdin'], OWNER_PASSWORD);
    assert.notEqual(code, 0);
    assert.match(stderr, /does not match this vault/);
  });

  test('rejects a file that is not an ICOD archive', async () => {
    const notAnArchive = writeArchive('other.json', { hello: 'world' });
    const { code, stderr } = await runCli([notAnArchive, '--password-stdin'], OWNER_PASSWORD);
    assert.equal(code, 65);
    assert.match(stderr, /does not look like an ICOD vault archive/);
  });

  test('refuses a future format version rather than guessing', async () => {
    const archive = JSON.parse(fs.readFileSync(archivePath, 'utf8'));
    archive.manifest.format_version = 99;
    const future = writeArchive('future.json', archive);

    const { code, stderr } = await runCli([future, '--password-stdin'], OWNER_PASSWORD);
    assert.equal(code, 65);
    assert.match(stderr, /newer than this tool understands/);
    assert.match(stderr, /FORMAT\.md/);
  });

  test('reports a missing file usefully', async () => {
    const { code, stderr } = await runCli(
      [path.join(tempDir, 'absent.json'), '--password-stdin'],
      OWNER_PASSWORD
    );
    assert.equal(code, 64);
    assert.match(stderr, /cannot read/);
  });

  test('shows usage when given no archive', async () => {
    const { code, stderr } = await runCli([]);
    assert.equal(code, 64);
    assert.match(stderr, /Usage: icod-restore/);
  });
});

describe('icod-restore: offline guarantee', () => {
  // The continuity promise is worth nothing if the decryptor phones home. Assert
  // structurally that it cannot: it pulls in no networking module and no dependency
  // outside this package.
  test('imports nothing that could reach the network', () => {
    const source = fs.readFileSync(CLI, 'utf8');
    const required = [...source.matchAll(/require\(['"]([^'"]+)['"]\)/g)].map((m) => m[1]);

    assert.deepEqual(required.sort(), ['../dist/index.js', 'node:fs', 'node:path']);

    for (const forbidden of ['node:http', 'node:https', 'node:net', 'node:dns', 'fetch(']) {
      assert.ok(!source.includes(forbidden), `CLI must not reference ${forbidden}`);
    }
  });

  test('the library itself imports nothing outside the package', () => {
    for (const file of ['index.js', 'crypto-utils.js', 'errors.js', 'types.js']) {
      const source = fs.readFileSync(path.join(__dirname, 'dist', file), 'utf8');
      const required = [...source.matchAll(/require\(['"]([^'"]+)['"]\)/g)].map((m) => m[1]);
      for (const dependency of required) {
        assert.ok(
          dependency.startsWith('.'),
          `dist/${file} should only require relative paths, found '${dependency}'`
        );
      }
    }
  });
});
