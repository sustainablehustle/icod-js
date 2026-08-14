#!/usr/bin/env node
'use strict';

// icod-restore — decrypt an exported ICOD vault archive, offline.
//
// This file is the continuity story in one artefact. It uses only Node built-ins and
// this package's own compiled output, makes no network requests, and needs no ICOD
// server, account, or company. Given an archive and a password, it prints the vault.
//
// The archive format it reads is specified in FORMAT.md.
//
//   icod-restore <archive.json>                  # latest version, as the owner
//   icod-restore <archive.json> --list           # list versions without decrypting content
//   icod-restore <archive.json> --version 3      # a specific version number
//   icod-restore <archive.json> --all            # every version, oldest first
//   icod-restore <archive.json> --trustee <ulid> # recover as that trustee
//   icod-restore <archive.json> --json           # emit the raw content document
//
// The password is read from the terminal without echoing. --password-stdin reads it
// from a pipe instead, for scripted use.

const fs = require('node:fs');
const path = require('node:path');

const {
  decrypt,
  decryptWithKey,
  unwrapKey,
  keyHashOf,
  IcodError,
  InvalidPassphraseError,
  InvalidKeyError,
  CorruptedDataError,
} = require('../dist/index.js');

const EXIT_OK = 0;
const EXIT_USAGE = 64;
const EXIT_DATA = 65;
const EXIT_PASSWORD = 77;

function fail(message, code = EXIT_DATA) {
  process.stderr.write(`icod-restore: ${message}\n`);
  process.exit(code);
}

function usage() {
  process.stderr.write(
    [
      'Usage: icod-restore <archive.json> [options]',
      '',
      'Options:',
      '  --list                 List versions and trustees without decrypting content',
      '  --version <n>          Decrypt a specific version number (default: the latest)',
      '  --all                  Decrypt every version, oldest first',
      '  --trustee <ulid>       Recover as this trustee rather than as the owner',
      '  --json                 Print the raw content JSON document instead of the markdown body',
      '  --password-stdin       Read the password from stdin instead of prompting',
      '  -h, --help             Show this message',
      '',
      'The archive format is documented in FORMAT.md.',
      '',
    ].join('\n')
  );
}

function parseArgs(argv) {
  const options = {
    archive: null,
    list: false,
    version: null,
    all: false,
    trustee: null,
    json: false,
    passwordStdin: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '-h':
      case '--help':
        usage();
        process.exit(EXIT_OK);
        break;
      case '--list':
        options.list = true;
        break;
      case '--all':
        options.all = true;
        break;
      case '--json':
        options.json = true;
        break;
      case '--password-stdin':
        options.passwordStdin = true;
        break;
      case '--version':
        options.version = Number(argv[++i]);
        if (!Number.isInteger(options.version)) {
          fail('--version expects an integer version number', EXIT_USAGE);
        }
        break;
      case '--trustee':
        options.trustee = argv[++i];
        if (!options.trustee) {
          fail('--trustee expects a trustee ULID', EXIT_USAGE);
        }
        break;
      default:
        if (arg.startsWith('-')) {
          fail(`unknown option '${arg}'`, EXIT_USAGE);
        }
        if (options.archive) {
          fail('only one archive may be given', EXIT_USAGE);
        }
        options.archive = arg;
    }
  }

  return options;
}

/** Read a line from the terminal without echoing it. */
function promptPassword(prompt) {
  return new Promise((resolve) => {
    const stdin = process.stdin;

    if (!stdin.isTTY) {
      fail('no terminal available to prompt for a password; use --password-stdin', EXIT_USAGE);
    }

    process.stderr.write(prompt);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');

    let value = '';

    const onData = (chunk) => {
      for (const char of chunk) {
        // Enter, or EOT (Ctrl-D): submit what has been typed.
        if (char === '\r' || char === '\n' || char === '\u0004') {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.removeListener('data', onData);
          process.stderr.write('\n');
          resolve(value);
          return;
        }
        // ETX (Ctrl-C): abort with the conventional shell exit code.
        if (char === '\u0003') {
          stdin.setRawMode(false);
          process.stderr.write('\n');
          process.exit(130);
        }
        // DEL or backspace: erase the last character.
        if (char === '\u007f' || char === '\b') {
          value = value.slice(0, -1);
        } else {
          value += char;
        }
      }
    };

    stdin.on('data', onData);
  });
}

function readPasswordFromStdin() {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data.replace(/\r?\n$/, '')));
  });
}

function loadArchive(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (error) {
    fail(`cannot read '${file}': ${error.message}`, EXIT_USAGE);
  }

  let archive;
  try {
    archive = JSON.parse(raw);
  } catch (error) {
    fail(`'${file}' is not valid JSON: ${error.message}`);
  }

  const manifest = archive.manifest;
  if (!manifest || manifest.format !== 'icod-vault-archive') {
    fail(`'${path.basename(file)}' does not look like an ICOD vault archive`);
  }
  if (manifest.format_version !== 1) {
    fail(
      `archive format version ${manifest.format_version} is newer than this tool understands (1). ` +
        'Update icod-js, or follow the procedure in FORMAT.md by hand.'
    );
  }

  return archive;
}

/** Translate the library's error taxonomy into copy a grieving human can act on. */
function explain(error, role) {
  if (error instanceof InvalidPassphraseError) {
    return {
      message: `That password didn't unlock this vault${role ? ` as ${role}` : ''}. Nothing is wrong with the archive.`,
      code: EXIT_PASSWORD,
    };
  }
  if (error instanceof InvalidKeyError) {
    return {
      message: 'The recovered key does not match this payload. The archive may be inconsistent.',
      code: EXIT_DATA,
    };
  }
  if (error instanceof CorruptedDataError) {
    return {
      message:
        'The key was correct but the data failed its integrity check. This archive is damaged or has been altered.',
      code: EXIT_DATA,
    };
  }
  if (error instanceof IcodError) {
    return { message: error.message, code: EXIT_DATA };
  }
  return { message: error.message || String(error), code: EXIT_DATA };
}

async function recoverDekAsOwner(archive, password) {
  const ownerKey = archive.owner_key;
  if (!ownerKey || !ownerKey.payload) {
    fail('this archive contains no owner key; recover as a trustee with --trustee <ulid>');
  }

  try {
    return await decrypt(ownerKey.payload, password, { additionalData: ownerKey.aad });
  } catch (error) {
    const { message, code } = explain(error, 'the owner');
    fail(message, code);
  }
}

async function recoverDekAsTrustee(archive, trusteeUlid, password) {
  const trustee = (archive.trustees || []).find((candidate) => candidate.ulid === trusteeUlid);

  if (!trustee) {
    const known = (archive.trustees || []).map((t) => `  ${t.ulid}  ${t.name || ''}`).join('\n');
    fail(
      `no trustee '${trusteeUlid}' in this archive.` + (known ? `\n\nTrustees present:\n${known}` : ''),
      EXIT_USAGE
    );
  }
  if (!trustee.wrapped_private_key || !trustee.wrapped_dek) {
    fail(
      `trustee '${trusteeUlid}' has no key material in this archive — they were never armed, ` +
        'so this vault was never recoverable through them.'
    );
  }

  let privateKeyB64;
  try {
    privateKeyB64 = await decrypt(trustee.wrapped_private_key.payload, password, {
      additionalData: trustee.wrapped_private_key.aad,
    });
  } catch (error) {
    const { message, code } = explain(error, `trustee ${trustee.name || trusteeUlid}`);
    fail(message, code);
  }

  try {
    return await unwrapKey(trustee.wrapped_dek.wrapped, privateKeyB64);
  } catch (error) {
    fail(`could not unwrap the vault key with this trustee's private key: ${error.message}`);
  }
}

function listArchive(archive) {
  const { manifest } = archive;
  const versions = archive.versions || [];
  const trustees = archive.trustees || [];

  const lines = [
    `Vault      ${manifest.vault.ulid}`,
    `Label      ${manifest.vault.label}`,
    `Exported   ${manifest.generated_at}`,
    `Generator  ${manifest.generator}`,
    '',
    `Versions (${versions.length}):`,
  ];

  for (const version of versions) {
    lines.push(`  #${String(version.version_number).padStart(4)}  ${version.created_at}  schema ${version.content_schema_version}`);
  }

  lines.push('', `Trustees (${trustees.length}):`);
  for (const trustee of trustees) {
    const armed = trustee.wrapped_dek ? 'armed' : 'not armed';
    lines.push(`  ${trustee.ulid}  ${trustee.name || '(unnamed)'}  ${armed}`);
    if (trustee.public_key_fingerprint) {
      lines.push(`      fingerprint ${trustee.public_key_fingerprint}`);
    }
  }

  lines.push('', 'No content was decrypted. Re-run without --list to decrypt.');
  process.stdout.write(lines.join('\n') + '\n');
}

function renderVersion(version, plaintext, options, total) {
  if (options.json) {
    return plaintext;
  }

  let document;
  try {
    document = JSON.parse(plaintext);
  } catch (error) {
    // Not a JSON envelope. Print what we recovered rather than failing — recovering
    // something unexpected is still better than recovering nothing.
    return plaintext;
  }

  const body =
    typeof document.body_markdown === 'string'
      ? document.body_markdown
      : JSON.stringify(document, null, 2);

  if (total === 1) {
    return body;
  }

  return [
    `${'='.repeat(72)}`,
    `Version ${version.version_number}  ·  ${version.created_at}`,
    `${'='.repeat(72)}`,
    '',
    body,
    '',
  ].join('\n');
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  if (!options.archive) {
    usage();
    process.exit(EXIT_USAGE);
  }

  const archive = loadArchive(options.archive);

  if (options.list) {
    listArchive(archive);
    return;
  }

  const versions = (archive.versions || [])
    .slice()
    .sort((a, b) => a.version_number - b.version_number);

  if (versions.length === 0) {
    fail('this archive contains no versions');
  }

  let selected;
  if (options.all) {
    selected = versions;
  } else if (options.version !== null) {
    const match = versions.find((v) => v.version_number === options.version);
    if (!match) {
      fail(
        `no version ${options.version} in this archive (it has ${versions[0].version_number}–` +
          `${versions[versions.length - 1].version_number})`,
        EXIT_USAGE
      );
    }
    selected = [match];
  } else {
    selected = [versions[versions.length - 1]];
  }

  const password = options.passwordStdin
    ? await readPasswordFromStdin()
    : await promptPassword(
        options.trustee ? "Trustee's vault password: " : "Owner's vault password: "
      );

  if (!password) {
    fail('no password supplied', EXIT_USAGE);
  }

  const dek = options.trustee
    ? await recoverDekAsTrustee(archive, options.trustee, password)
    : await recoverDekAsOwner(archive, password);

  // Confirm the recovered key is the one this vault's history was written under,
  // before blaming any individual version for failing to decrypt.
  const expectedKeyHash = archive.manifest.vault.key_hash;
  if (expectedKeyHash && (await keyHashOf(dek)) !== expectedKeyHash) {
    fail(
      'the recovered key does not match this vault. The archive may be inconsistent, ' +
        'or assembled from more than one vault.'
    );
  }

  const rendered = [];
  for (const version of selected) {
    let plaintext;
    try {
      plaintext = await decryptWithKey(version.payload, dek, { additionalData: version.aad });
    } catch (error) {
      const { message } = explain(error);
      process.stderr.write(`icod-restore: version ${version.version_number}: ${message}\n`);
      continue;
    }
    rendered.push(renderVersion(version, plaintext, options, selected.length));
  }

  if (rendered.length === 0) {
    fail('no version could be decrypted');
  }

  process.stdout.write(rendered.join('\n') + '\n');
}

main().catch((error) => {
  const { message, code } = explain(error);
  fail(message, code);
});
