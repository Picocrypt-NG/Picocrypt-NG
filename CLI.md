# Picocrypt NG Command-Line Interface

This document provides comprehensive usage instructions for the Picocrypt NG command-line interface.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Build Modes](#build-modes)
- [Commands](#commands)
  - [Encrypt Command](#encrypt-command)
  - [Decrypt Command](#decrypt-command)
- [Usage Examples](#usage-examples)
- [Stdin/Stdout Streaming](#stdinstdout-streaming)
- [Scripting Guide](#scripting-guide)
- [Exit Codes](#exit-codes)
- [Troubleshooting](#troubleshooting)

## Overview

Picocrypt NG provides a full-featured command-line interface for encrypting and decrypting files. The CLI offers the same security features as the graphical interface:

- **XChaCha20** symmetric encryption with 256-bit security
- **Argon2id** memory-hard key derivation (GPU-resistant)
- **BLAKE2b-512** message authentication
- **Optional Serpent-CTR** cascade cipher (paranoid mode)
- **Reed-Solomon** error correction for data recovery
- **Plausible deniability** through nested encryption

## Installation

### Pre-built Binaries

Download the appropriate binary for your platform from the [releases page](https://github.com/Picocrypt-NG/Picocrypt-NG/releases).

### Building from Source

```bash
cd src/

# GUI + CLI build (requires graphics libraries)
CGO_ENABLED=1 go build -tags migrated_fynedo -ldflags="-s -w" -o Picocrypt-NG ./cmd/picocrypt

# CLI-only build (no graphics dependencies)
CGO_ENABLED=1 go build -tags cli -ldflags="-s -w" -o Picocrypt-NG-cli ./cmd/picocrypt
```

## Build Modes

Picocrypt NG offers two build configurations:

| Build Mode | Command | Graphics Required | Use Case |
|------------|---------|-------------------|----------|
| GUI + CLI | `go build -tags migrated_fynedo ./cmd/picocrypt` | Yes | Desktop systems |
| CLI-only | `go build -tags cli ./cmd/picocrypt` | No | Servers, containers, automation |

The **CLI-only build** has zero graphics dependencies, making it suitable for:
- Headless servers
- Docker containers
- CI/CD pipelines
- Systems without OpenGL support
- Scripted automation workflows

## Commands

### Encrypt Command

Encrypts one or more files into a Picocrypt volume (`.pcv`).

```
picocrypt encrypt [PATH...]
```

#### Input/Output Flags

| Flag | Short | Type | Required | Description |
|------|-------|------|----------|-------------|
| Positional `PATH...` | | path | Conditional | Literal input files or directories |
| `--glob` | `-g` | string | No | Add paths matching a quoted pattern (can be specified multiple times) |
| `--output` | `-o` | string | No | Output `.pcv` file path (auto-generated if omitted) |

`PATH` operands are literal: a name such as `report[1].txt` is not treated as a pattern. At least one literal `PATH` operand or one `--glob` pattern is required. Use quoted `--glob`/`-g` only when pattern matching is intended, for example `--glob "*.jpg" --glob "*.png"`. The option is repeatable; malformed patterns and patterns with no matches fail rather than silently selecting nothing. Use `--` before a literal path that begins with `-`. The removed `-i`/`--input` flag now errors with migration guidance; pass paths as operands instead.

#### Credential Flags

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--password` | `-p` | string | Encryption password |
| `--password-stdin` | `-P` | bool | Read password from stdin (for scripting) |
| `--password-fd` | | int | Unix: read one password line from an inherited descriptor `3` or higher |
| `--keyfile` | `-k` | string | PCV3 keyfile path (repeatable) |
| `--keyfile-ordered` | | bool | Require the selected keyfile order for PCV3 |

New encryption uses PCV3 with a password, keyfiles, or both. `--pcv3` remains an explicit
selection; `--pcv3=false` is rejected. Pass `-p ""` explicitly for keyfile-only PCV3, including D1.
Legacy v1/v2 volumes remain readable.

Do not pass real passwords with `-p` in routine use: the value can remain in shell history and process listings. Prefer an interactive prompt, `--password-stdin` when fd 0 is free, or `--password-fd` when stdin carries payload data.

#### Security Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--pcv3` | bool | true | Create PCV3; disabling is unsupported |
| `--comments` | string | | Comments to store in header (NOT encrypted) |
| `--paranoid` | bool | false | Enable Serpent-CTR + XChaCha20 cascade |
| `--reed-solomon` | bool | false | Enable Reed-Solomon error correction |
| `--deniability` | bool | false | Create PCV3 D1; requires `--paranoid` |
| `--compress` | bool | false | Compress files before encryption |

Normal PCV3 supports regular files, folders/ZIP payloads, Reed-Solomon, splitting, and
stdin/stdout. `--pcv3 --deniability --paranoid` creates random-looking PCV3 D1. D1 accepts files,
folders/multiple inputs, compression, splitting, raw stdin/stdout, and the same password-only,
keyfile-only, or combined credential policies as Normal PCV3. Normal archive payloads use the explicit `--pcv3-archive=extract` action.
D1 archive payloads decrypt to a durable `.zip` in the CLI. Optional automatic extraction
for Normal and D1 is available in the desktop GUI.

#### Split Output Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--split` | bool | false | Split output into multiple chunks |
| `--split-size` | int | | Size of each chunk (required with `--split`) |
| `--split-unit` | string | MiB | Unit: `KiB`, `MiB`, `GiB`, `TiB`, or `Total` |

When using `--split-unit=Total`, `--split-size` specifies the total number of chunks.
PCV3 publishes every chunk durably before removing the complete encrypted container.
If all chunks are complete and verified but their final directory durability cannot be
confirmed, Picocrypt NG keeps the chunks, the complete encrypted container, and the source
files, reports the uncertainty, and exits with code `3`. This result does not authorize
source deletion. Decrypting any `.pcv.N` chunk automatically uses numeric chunk order and
recombines an operation-owned copy.

#### General Flags

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--quiet` | `-q` | bool | Suppress progress output |
| `--yes` | `-y` | bool | Skip the prompt before replacing an existing output |
| `--follow-symlinks` | | bool | Follow symlinks to regular files |

### Global Flags (all commands)

| Flag | Type | Description |
|------|------|-------------|
| `--temp-dir` | string | Directory for temp files (overrides automatic selection) |

### Decrypt Command

Decrypts a Picocrypt volume back to its original files.

```
picocrypt decrypt VOLUME
```

#### Input/Output Flags

| Flag | Short | Type | Required | Description |
|------|-------|------|----------|-------------|
| Positional `VOLUME` | | path | Yes | Literal input `.pcv` file to decrypt |
| `--output` | `-o` | string | No | Output file path (auto-detected if omitted) |

`VOLUME` is a literal operand. Use `--` before a volume name that begins with `-`. The removed `-i`/`--input` flag now errors with migration guidance; pass the volume path as the operand.

#### Credential Flags

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--password` | `-p` | string | Decryption password |
| `--password-stdin` | `-P` | bool | Read password from stdin |
| `--password-fd` | | int | Unix: read one password line from an inherited descriptor `3` or higher |
| `--keyfile` | `-k` | string | Keyfile path (can be specified multiple times) |

#### Decryption Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--force` | bool | false | Continue despite MAC verification failure |
| `--verify-first` | bool | false | Two-pass verification (slower but more secure) |
| `--auto-unzip` | bool | false | Automatically extract if output is a zip archive |
| `--same-level` | bool | false | Extract to same directory instead of subdirectory |

#### Volume State Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--recombine` | bool | false | Recombine split chunks first (auto-detected) |
| `--deniability` | bool | false | Remove deniability wrapper before decryption |

Keyfiles remain available for decryption of supported legacy v1/v2 volumes. To decrypt a legacy
keyfile-only deniable v2 volume made with an empty outer password, pass `--deniability` and the
original `--keyfile` arguments, then press Enter at the password prompt (or provide an empty line
through `--password-stdin`). After recovery, create a new PCV3 volume. Merely adding a new outer wrapper does not fix the inner v2 keyfile
authentication schedule. If a keyfile factor is mandatory for a new volume, use explicit PCV3
creation on a supported desktop/CLI build; do not create another legacy v2 keyfile volume.

#### General Flags

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--quiet` | `-q` | bool | Suppress progress output |
| `--yes` | `-y` | bool | Skip the prompt before replacing an existing output |

#### PCV3 Flags

Normal PCV3 is detected by content. D1 is random-looking and therefore requires
`--pcv3-format=d1`. Every PCV3 decrypt requires the expected credential policy explicitly.
After a successful authenticated PCV3 read, the CLI prints its plaintext comment
as quoted UTF-8 on stderr; failed authentication never releases the comment.

| Flag | Description |
|------|-------------|
| `--pcv3-format=d1` | Select random-looking D1 input |
| `--pcv3-factors=password\|keyfiles\|combined` | Pin the expected credential policy |
| `--pcv3-keyfile-order=ordered\|unordered` | Pin keyfile ordering when keyfiles are used |
| `--pcv3-action=recovery\|force` | Select authenticated recovery or Force recovery |
| `--pcv3-role=primary\|backup\|front\|tail` | Select an explicit physical role for unverified Force |
| `--pcv3-archive=extract\|close` | Extract or discard an authenticated archive payload |
| `--pcv3-extract-to=DIR` | Existing extraction directory used with `extract` |

`--yes` never authorizes an output path that is the same file as an input,
encrypted volume, split chunk, or keyfile. Picocrypt NG rejects those conflicts
even when `--yes` is present. For `--auto-unzip` without `--same-level`, the
extraction root must not already exist: it is the requested output path for a
suffixless output, or the output path with the final `.zip` removed.
PCV3 creation, decryption, and recovery use no-replace publication. An occupied
PCV3 destination is rejected before KDF work, and `--yes` does not replace it.

Explicit Normal/D1 recovery uses a compact evidence map with an 8 MiB working
budget; there is no fixed 64 GiB plaintext limit. Missing tails do not allocate
one object per record. Before output, recovery checks the exact result size and
available disk space with a 64 MiB reserve. Unverified Force additionally limits
its evidence table to the larger of 64 MiB or the input's readable file length.
Ordinary encryption and decryption do not use the recovery-map budget.

## Usage Examples

### Basic Encryption

```bash
# Encrypt a single file
picocrypt encrypt document.pdf -o document.pcv -p "MySecurePassword123"

# Create Normal PCV3 explicitly
picocrypt encrypt document.pdf -o document.pcv --pcv3 -p "MySecurePassword123"

# Encrypt with auto-generated output name (creates document.pdf.pcv)
picocrypt encrypt document.pdf -p "MySecurePassword123"

# Encrypt multiple files (creates a zip archive internally)
picocrypt encrypt file1.txt file2.txt file3.txt -o archive.pcv -p "password"

# Encrypt an entire directory
picocrypt encrypt ./my-folder -o backup.pcv -p "password"

# Use glob patterns
picocrypt encrypt --glob "*.jpg" --glob "*.png" -o images.pcv -p "password"
```

### Security Options

```bash
# Paranoid mode with Reed-Solomon error correction
picocrypt encrypt sensitive.db -o sensitive.pcv -p "password" \
    --paranoid --reed-solomon

# Deniability wrapper for plausible deniability
picocrypt encrypt hidden.txt -o innocent.pcv -p "password" --deniability --paranoid

# Add comments (visible in header, NOT encrypted)
picocrypt encrypt report.docx -o report.pcv -p "password" \
    -c "Q4 Financial Report - Confidential"
```

### Split Output

```bash
# Split into 100 MiB chunks
picocrypt encrypt large-file.iso -o backup.pcv -p "password" \
    --split --split-size 100 --split-unit MiB

# Split into 5 equal parts
picocrypt encrypt archive.tar -o archive.pcv -p "password" \
    --split --split-size 5 --split-unit Total

# Split into 4.7 GiB chunks (DVD-size)
picocrypt encrypt video.mkv -o video.pcv -p "password" \
    --split --split-size 4700 --split-unit MiB
```

### Basic Decryption

```bash
# Decrypt a file
picocrypt decrypt document.pcv -o document.pdf --pcv3-factors=password -p "password"

# Auto-detect output name (removes .pcv extension)
picocrypt decrypt document.pcv --pcv3-factors=password -p "password"

# Decrypt with keyfile
picocrypt decrypt secret.pcv --pcv3-factors=combined --pcv3-keyfile-order=unordered -p "password" -k keyfile.key
```

### Advanced Decryption

The following legacy v1/v2 options remain available for existing volumes. For PCV3,
use the explicit format, factor and archive flags listed above.

```bash
# Authenticate before writing plaintext (two-pass)
picocrypt decrypt important.pcv -p "password" --verify-first

# Auto-extract zip archives after decryption
picocrypt decrypt archive.pcv -p "password" --auto-unzip

# Extract to same directory (not subdirectory)
picocrypt decrypt files.pcv -p "password" --auto-unzip --same-level

# Recombine split volume (usually auto-detected)
picocrypt decrypt backup.pcv.0 -p "password" --recombine

# Force decryption despite corruption (may produce partial output)
picocrypt decrypt damaged.pcv -p "password" --force

# Remove deniability wrapper
picocrypt decrypt innocent.pcv -p "real-password" --deniability
```

If `--force` keeps output after MAC verification failed, Picocrypt NG writes `Warning: Force decrypt kept output...` to stderr and exits with exit code 2. The recovered file or stdout bytes are not fully verified; scripts must not treat exit code 2 as clean success.

## Stdin/Stdout Streaming

Use `-` as the filename for stdin/stdout to enable pipeline automation. Because the volume formats require known sizes and safe publication, the CLI uses mode-`0600` temporary staging; failure to remove a staging file is an operation error.

### Basic Streaming

The examples below use Bash process substitution. `secret-command` must write exactly one password line; the password never enters Picocrypt NG's argv.

```bash
# Encrypt from stdin to file
cat document.txt | picocrypt encrypt - -o document.pcv --password-fd=3 3< <(secret-command)

# Encrypt file to stdout
picocrypt encrypt document.txt -o - --password-fd=3 3< <(secret-command) > document.pcv

# Full pipeline: stdin to stdout
cat secret.txt | picocrypt encrypt - -o - --password-fd=3 3< <(secret-command) > secret.pcv

# Decrypt from stdin
curl https://example.com/file.pcv | picocrypt decrypt - -o file.txt --password-fd=3 3< <(secret-command)

# Decrypt to stdout
picocrypt decrypt secret.pcv -o - --pcv3-factors=password --password-fd=3 3< <(secret-command) | less

# Round-trip pipeline
echo "secret data" | picocrypt encrypt - -o - --password-fd=3 3< <(secret-command) | \
    picocrypt decrypt - -o - --pcv3-factors=password --password-fd=3 3< <(secret-command)
```

### Pipeline Examples

```bash
# Encrypt and upload in one pipeline
tar czf - /home/user/documents | picocrypt encrypt - -o - --password-fd=3 3< <(secret-command) | \
    curl -X PUT -T - https://storage.example.com/backup.pcv

# Download, decrypt, and extract
curl -s https://storage.example.com/backup.pcv | \
    picocrypt decrypt - -o - --pcv3-factors=password --password-fd=3 3< <(secret-command) | tar xzf -

# Encrypt database dump directly
pg_dump mydb | picocrypt encrypt - -o - --password-fd=3 3< <(secret-command) > mydb.pcv

# Stream decrypt to database restore
picocrypt decrypt mydb.pcv -o - --pcv3-factors=password --password-fd=3 3< <(secret-command) | psql mydb
```

### Constraints

Stdin/stdout streaming has the following limitations:

| Constraint | Reason |
|------------|--------|
| `-` input operand cannot combine with `-P` | Both use stdin |
| `--password-fd` requires descriptor `3` or higher and cannot combine with `-p`/`-P` | Keeps credentials separate from payload and standard output/error |
| `-` input operand cannot combine with other operands or `--glob` | Stdin is single input |
| `-o -` cannot combine with `--split` | Cannot split stdout |
| `-` input operand / `-o -` cannot combine with legacy `--deniability` | The legacy wrapper requires file manipulation; PCV3 D1 supports raw stdin/stdout |
| `-o -` cannot combine with `--auto-unzip` (decrypt) | Cannot extract to stdout |

**Note:** When using `-o -`, progress output is automatically suppressed (quiet mode) to avoid mixing progress with encrypted data.

If `picocrypt decrypt VOLUME -o - --force` keeps recovered output after MAC verification failed, recovered bytes are written to stdout before the process returns exit code 2. The kept-output warning is written to stderr, so stdout remains parseable by scripts.

## Scripting Guide

### Reading Password from Stdin

For automated scripts, use `--password-stdin` (`-P`) to read the password from standard input:

```bash
# From echo (less secure - password visible in process list)
echo "password" | picocrypt encrypt file.txt -o file.pcv -P

# From file (more secure)
cat /path/to/password-file | picocrypt encrypt file.txt -o file.pcv -P

# From environment variable
echo "$ENCRYPTION_PASSWORD" | picocrypt encrypt file.txt -o file.pcv -P

# From secret manager (example with HashiCorp Vault)
vault kv get -field=password secret/encryption | picocrypt encrypt file.txt -o file.pcv -P
```

When fd 0 carries plaintext or a volume, pass the password on a separate inherited descriptor:

```bash
producer | picocrypt encrypt - -o - --pcv3 --password-fd=3 3< <(secret-command)
```

### Quiet Mode for Scripts

Use `--quiet` (`-q`) to suppress progress output:

```bash
picocrypt encrypt data.db -o data.pcv -p "password" -q
```

### Non-interactive Mode

PCV3 always requires a vacant destination. `--yes` (`-y`) remains accepted for
script compatibility but does not replace existing PCV3 outputs:

```bash
picocrypt encrypt file.txt -o file.pcv -p "password" -y
```

For legacy decryption, `--yes` authorizes replacement of the requested output file only. It never
authorizes replacing an input, keyfile, split chunk, an auto-unzip extraction
root, or an existing archive entry. Picocrypt NG rejects an occupied
non-`--same-level` extraction root before requesting credentials. If extraction
later collides with an existing entry, decryption fails without replacing it.
Picocrypt NG publishes the decrypted ZIP when its operation-owned extraction
root can be rolled back safely; if a suffixless root was replaced or made
nonempty concurrently, the foreign data and original encrypted volume are
preserved instead.

### Batch Processing

```bash
# Encrypt all PDFs in a directory
for file in *.pdf; do
    picocrypt encrypt "$file" -p "password" -q -y
done

# Decrypt multiple volumes
for pcv in *.pcv; do
    picocrypt decrypt "$pcv" -p "password" -q -y
done

# Parallel encryption with GNU Parallel
find . -name "*.docx" | parallel picocrypt encrypt {} -p "password" -q -y
```

### Error Handling in Scripts

```bash
#!/bin/bash
set -e

if picocrypt encrypt secret.txt -o secret.pcv -p "$PASSWORD" -q; then
    echo "Encryption successful"
    rm secret.txt  # Remove original after successful encryption
else
    echo "Encryption failed" >&2
    exit 1
fi
```

### Backup Script Example

```bash
#!/bin/bash

BACKUP_DIR="/backup"
PASSWORD_FILE="/root/.backup-password"
DATE=$(date +%Y%m%d)

# Create encrypted backup with Reed-Solomon protection
tar czf - /home/user/documents | \
    picocrypt encrypt - -o "$BACKUP_DIR/backup-$DATE.pcv" \
    --password-fd=3 3< "$PASSWORD_FILE" --reed-solomon --paranoid -q

echo "Backup completed: backup-$DATE.pcv"
```

### Streaming Backup Example

```bash
#!/bin/bash
# Encrypt and stream directly to remote storage

DATE=$(date +%Y%m%d)

# Backup to stdout, pipe to remote storage
tar czf - /home/user/documents | \
    picocrypt encrypt - -o - --password-fd=3 3< <(secret-command) --reed-solomon -q | \
    aws s3 cp - "s3://my-bucket/backups/backup-$DATE.pcv"
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error (invalid arguments, file not found, encryption/decryption failure) |
| 2 | PCV3 completed with a warning (including degraded recovery or incomplete cleanup), or legacy force-decrypt kept unverified output |
| 3 | PCV3 output was published, but durability could not be confirmed |
| 4 | PCV3 publication state is indeterminate |

Exit `3` also covers verified complete split output whose directory durability could
not be confirmed. In that case, both the chunks and the complete encrypted file remain
available, and source deletion is not allowed.

## Troubleshooting

### Common Issues

**"at least one input path or --glob pattern is required"**
Pass one or more literal input operands, or add a quoted `--glob` pattern.

**"password input: password cannot be empty"**
PCV3 requires a password, keyfiles, or both.

**"new encryption requires PCV3; --pcv3=false is unsupported"**
Remove `--pcv3=false`. New native encryption uses PCV3; legacy volumes remain readable.

**"PCV3 D1 requires --paranoid"**
Add `--paranoid` when creating a deniable volume with `--deniability`.

**"invalid glob pattern"**
Ensure explicit glob patterns are quoted to prevent shell expansion: `--glob "*.txt"`

**"keyfile not found"**
Verify the keyfile path exists and is accessible.

**"This volume requires keyfiles"**
The encrypted volume was created with keyfiles. Provide the same keyfiles with `-k`.

**"MAC verification failed"**
The password is incorrect, or the file is corrupted. Use `--force` to attempt recovery (may produce corrupted output).

### Split Volume Issues

Split volumes are automatically detected when the filename contains `.pcv.N` pattern (e.g., `file.pcv.0`, `file.pcv.1`). The CLI will automatically enable `--recombine`.

Ensure all chunk files are in the same directory before decryption.

### Performance Tips

- Use `--quiet` mode for faster operation (no terminal output overhead)
- Reed-Solomon adds recovery data and increases output size
- Paranoid mode doubles encryption time due to cascade cipher
- `--verify-first` authenticates before writing output at roughly twice the I/O cost; it does not
  repair corruption or add keyfile binding to a legacy v2 volume

## Version

This documentation applies to Picocrypt NG v3.0 (unreleased development version).

## See Also

- [Changelog.md](Changelog.md) - Version history and release notes
