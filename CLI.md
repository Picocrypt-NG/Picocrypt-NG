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
| Positional `PATH...` | | path | Yes | Literal input files or directories |
| `--glob` | `-g` | string | No | Add paths matching a quoted pattern (can be specified multiple times) |
| `--output` | `-o` | string | No | Output `.pcv` file path (auto-generated if omitted) |

`PATH` operands are literal: a name such as `report[1].txt` is not treated as a pattern. Use quoted `--glob`/`-g` only when pattern matching is intended, for example `--glob "*.jpg" --glob "*.png"`. The option is repeatable; malformed patterns and patterns with no matches fail rather than silently selecting nothing. Use `--` before a literal path that begins with `-`. The removed `-i`/`--input` flag now errors with migration guidance; pass paths as operands instead.

#### Credential Flags

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--password` | `-p` | string | Encryption password |
| `--password-stdin` | `-P` | bool | Read password from stdin (for scripting) |
| `--keyfile` | `-k` | string | Keyfile path (can be specified multiple times) |
| `--keyfile-ordered` | | bool | Keyfile order matters (sequential hashing) |

At least one of `--password` or `--keyfile` must be provided.

Do not pass real passwords with `-p` in routine use: the value can remain in shell history and process listings. Prefer an interactive prompt or `--password-stdin` when appropriate.

#### Security Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--comments` | string | | Comments to store in header (NOT encrypted) |
| `--paranoid` | bool | false | Enable Serpent-CTR + XChaCha20 cascade with HMAC-SHA3 |
| `--reed-solomon` | bool | false | Enable Reed-Solomon error correction (6% size overhead) |
| `--deniability` | bool | false | Add deniability wrapper for plausible deniability |
| `--compress` | bool | false | Compress files before encryption |

#### Split Output Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--split` | bool | false | Split output into multiple chunks |
| `--split-size` | int | | Size of each chunk (required with `--split`) |
| `--split-unit` | string | MiB | Unit: `KiB`, `MiB`, `GiB`, `TiB`, or `Total` |

When using `--split-unit=Total`, `--split-size` specifies the total number of chunks.

#### General Flags

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--quiet` | `-q` | bool | Suppress progress output |
| `--yes` | `-y` | bool | Overwrite output file without prompting |
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

#### General Flags

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--quiet` | `-q` | bool | Suppress progress output |
| `--yes` | `-y` | bool | Overwrite output file without prompting |

## Usage Examples

### Basic Encryption

```bash
# Encrypt a single file
picocrypt encrypt document.pdf -o document.pcv -p "MySecurePassword123"

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

# Add keyfile as an additional decryption factor
picocrypt encrypt data.zip -o data.pcv -p "password" -k keyfile.key

# Multiple keyfiles with ordered hashing
picocrypt encrypt secret.txt -o secret.pcv -p "password" \
    -k key1.key -k key2.key --keyfile-ordered

# Keyfile-only encryption (no password)
picocrypt encrypt document.pdf -o document.pcv -k master.key

# Deniability wrapper for plausible deniability
picocrypt encrypt hidden.txt -o innocent.pcv -p "password" --deniability

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
picocrypt decrypt document.pcv -o document.pdf -p "password"

# Auto-detect output name (removes .pcv extension)
picocrypt decrypt document.pcv -p "password"

# Decrypt with keyfile
picocrypt decrypt secret.pcv -p "password" -k keyfile.key
```

### Advanced Decryption

```bash
# Verify integrity before decryption (two-pass, recommended for critical data)
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

Use `-` as the filename for stdin/stdout to enable full pipeline automation. This allows encrypting data from pipes and streaming encrypted output without intermediate files.

### Basic Streaming

```bash
# Encrypt from stdin to file
cat document.txt | picocrypt encrypt - -o document.pcv -p "password"

# Encrypt file to stdout
picocrypt encrypt document.txt -o - -p "password" > document.pcv

# Full pipeline: stdin to stdout
cat secret.txt | picocrypt encrypt - -o - -p "password" > secret.pcv

# Decrypt from stdin
curl https://example.com/file.pcv | picocrypt decrypt - -o file.txt -p "password"

# Decrypt to stdout
picocrypt decrypt secret.pcv -o - -p "password" | less

# Round-trip pipeline
echo "secret data" | picocrypt encrypt - -o - -p "pw" | picocrypt decrypt - -o - -p "pw"
```

### Pipeline Examples

```bash
# Encrypt and upload in one pipeline
tar czf - /home/user/documents | picocrypt encrypt - -o - -p "password" | \
    curl -X PUT -T - https://storage.example.com/backup.pcv

# Download, decrypt, and extract
curl -s https://storage.example.com/backup.pcv | \
    picocrypt decrypt - -o - -p "password" | tar xzf -

# Encrypt database dump directly
pg_dump mydb | picocrypt encrypt - -o - -p "password" > mydb.pcv

# Stream decrypt to database restore
picocrypt decrypt mydb.pcv -o - -p "password" | psql mydb
```

### Constraints

Stdin/stdout streaming has the following limitations:

| Constraint | Reason |
|------------|--------|
| `-` input operand cannot combine with `-P` | Both use stdin |
| `-` input operand cannot combine with other operands or `--glob` | Stdin is single input |
| `-o -` cannot combine with `--split` | Cannot split stdout |
| `-` input operand / `-o -` cannot combine with `--deniability` | Requires file manipulation |
| `-o -` cannot combine with `--auto-unzip` (decrypt) | Cannot extract to stdout |
| `-o -` cannot combine with `--recombine` (decrypt) | Requires file access |

**Note:** When using `-o -`, progress output is automatically suppressed (quiet mode) to avoid mixing progress with encrypted data.

If `picocrypt decrypt -o - --force` keeps recovered output after MAC verification failed, recovered bytes are written to stdout before the process returns exit code 2. The kept-output warning is written to stderr, so stdout remains parseable by scripts.

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

### Quiet Mode for Scripts

Use `--quiet` (`-q`) to suppress progress output:

```bash
picocrypt encrypt data.db -o data.pcv -p "password" -q
```

### Non-interactive Mode

Use `--yes` (`-y`) to skip overwrite prompts:

```bash
picocrypt encrypt file.txt -o file.pcv -p "password" -y
```

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

# Read password from secure file
PASSWORD=$(cat "$PASSWORD_FILE")

# Create encrypted backup with Reed-Solomon protection
tar czf - /home/user/documents | \
    picocrypt encrypt - -o "$BACKUP_DIR/backup-$DATE.pcv" \
    -p "$PASSWORD" --reed-solomon --paranoid -q

echo "Backup completed: backup-$DATE.pcv"
```

### Streaming Backup Example

```bash
#!/bin/bash
# Encrypt and stream directly to remote storage

PASSWORD="$BACKUP_PASSWORD"
DATE=$(date +%Y%m%d)

# Backup to stdout, pipe to remote storage
tar czf - /home/user/documents | \
    picocrypt encrypt - -o - -p "$PASSWORD" --reed-solomon -q | \
    aws s3 cp - "s3://my-bucket/backups/backup-$DATE.pcv"
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error (invalid arguments, file not found, encryption/decryption failure) |
| 2 | Force-decrypt kept recovered output after MAC verification failed; output was delivered but is not fully verified |

## Troubleshooting

### Common Issues

**"at least one input path or --glob pattern is required"**
Pass one or more literal input operands, or add a quoted `--glob` pattern.

**"password (-p) or keyfile (-k) is required"**
Provide either a password, keyfile, or both.

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
- For large files, Reed-Solomon adds 6% size overhead but enables error recovery
- Paranoid mode doubles encryption time due to cascade cipher
- `--verify-first` doubles decryption time but ensures integrity before writing output

## Version

This documentation applies to Picocrypt NG v2.15 and later.

## See Also

- [Changelog.md](Changelog.md) - Version history and release notes
