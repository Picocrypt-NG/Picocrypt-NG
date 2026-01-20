# Picocrypt NG Command-Line Interface

This document provides comprehensive usage instructions for the Picocrypt NG command-line interface.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Build Modes](#build-modes)
- [Commands](#commands)
  - [Encrypt](#encrypt-command)
  - [Decrypt](#decrypt-command)
- [Usage Examples](#usage-examples)
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
CGO_ENABLED=1 go build -ldflags="-s -w" -o Picocrypt-NG ./cmd/picocrypt

# CLI-only build (no graphics dependencies)
CGO_ENABLED=1 go build -tags cli -ldflags="-s -w" -o Picocrypt-NG-cli ./cmd/picocrypt
```

## Build Modes

Picocrypt NG offers two build configurations:

| Build Mode | Command | Graphics Required | Use Case |
|------------|---------|-------------------|----------|
| GUI + CLI | `go build ./cmd/picocrypt` | Yes | Desktop systems |
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
picocrypt encrypt [flags]
```

#### Input/Output Flags

| Flag | Short | Type | Required | Description |
|------|-------|------|----------|-------------|
| `--input` | `-i` | string | Yes | Input file or directory (can be specified multiple times) |
| `--output` | `-o` | string | No | Output `.pcv` file path (auto-generated if omitted) |

#### Credential Flags

| Flag | Short | Type | Description |
|------|-------|------|-------------|
| `--password` | `-p` | string | Encryption password |
| `--password-stdin` | `-P` | bool | Read password from stdin (for scripting) |
| `--keyfile` | `-k` | string | Keyfile path (can be specified multiple times) |
| `--keyfile-ordered` | | bool | Keyfile order matters (sequential hashing) |

At least one of `--password` or `--keyfile` must be provided.

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

### Decrypt Command

Decrypts a Picocrypt volume back to its original files.

```
picocrypt decrypt [flags]
```

#### Input/Output Flags

| Flag | Short | Type | Required | Description |
|------|-------|------|----------|-------------|
| `--input` | `-i` | string | Yes | Input `.pcv` file to decrypt |
| `--output` | `-o` | string | No | Output file path (auto-detected if omitted) |

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
picocrypt encrypt -i document.pdf -o document.pcv -p "MySecurePassword123"

# Encrypt with auto-generated output name (creates document.pdf.pcv)
picocrypt encrypt -i document.pdf -p "MySecurePassword123"

# Encrypt multiple files (creates a zip archive internally)
picocrypt encrypt -i file1.txt -i file2.txt -i file3.txt -o archive.pcv -p "password"

# Encrypt an entire directory
picocrypt encrypt -i ./my-folder -o backup.pcv -p "password"

# Use glob patterns
picocrypt encrypt -i "*.jpg" -i "*.png" -o images.pcv -p "password"
```

### Security Options

```bash
# Paranoid mode with Reed-Solomon error correction
picocrypt encrypt -i sensitive.db -o sensitive.pcv -p "password" \
    --paranoid --reed-solomon

# Add keyfile for two-factor authentication
picocrypt encrypt -i data.zip -o data.pcv -p "password" -k keyfile.key

# Multiple keyfiles with ordered hashing
picocrypt encrypt -i secret.txt -o secret.pcv -p "password" \
    -k key1.key -k key2.key --keyfile-ordered

# Keyfile-only encryption (no password)
picocrypt encrypt -i document.pdf -o document.pcv -k master.key

# Deniability wrapper for plausible deniability
picocrypt encrypt -i hidden.txt -o innocent.pcv -p "password" --deniability

# Add comments (visible in header, NOT encrypted)
picocrypt encrypt -i report.docx -o report.pcv -p "password" \
    -c "Q4 Financial Report - Confidential"
```

### Split Output

```bash
# Split into 100 MiB chunks
picocrypt encrypt -i large-file.iso -o backup.pcv -p "password" \
    --split --split-size 100 --split-unit MiB

# Split into 5 equal parts
picocrypt encrypt -i archive.tar -o archive.pcv -p "password" \
    --split --split-size 5 --split-unit Total

# Split into 4.7 GiB chunks (DVD-size)
picocrypt encrypt -i video.mkv -o video.pcv -p "password" \
    --split --split-size 4700 --split-unit MiB
```

### Basic Decryption

```bash
# Decrypt a file
picocrypt decrypt -i document.pcv -o document.pdf -p "password"

# Auto-detect output name (removes .pcv extension)
picocrypt decrypt -i document.pcv -p "password"

# Decrypt with keyfile
picocrypt decrypt -i secret.pcv -p "password" -k keyfile.key
```

### Advanced Decryption

```bash
# Verify integrity before decryption (two-pass, recommended for critical data)
picocrypt decrypt -i important.pcv -p "password" --verify-first

# Auto-extract zip archives after decryption
picocrypt decrypt -i archive.pcv -p "password" --auto-unzip

# Extract to same directory (not subdirectory)
picocrypt decrypt -i files.pcv -p "password" --auto-unzip --same-level

# Recombine split volume (usually auto-detected)
picocrypt decrypt -i backup.pcv.0 -p "password" --recombine

# Force decryption despite corruption (may produce partial output)
picocrypt decrypt -i damaged.pcv -p "password" --force

# Remove deniability wrapper
picocrypt decrypt -i innocent.pcv -p "real-password" --deniability
```

## Scripting Guide

### Reading Password from Stdin

For automated scripts, use `--password-stdin` (`-P`) to read the password from standard input:

```bash
# From echo (less secure - password visible in process list)
echo "password" | picocrypt encrypt -i file.txt -o file.pcv -P

# From file (more secure)
cat /path/to/password-file | picocrypt encrypt -i file.txt -o file.pcv -P

# From environment variable
echo "$ENCRYPTION_PASSWORD" | picocrypt encrypt -i file.txt -o file.pcv -P

# From secret manager (example with HashiCorp Vault)
vault kv get -field=password secret/encryption | picocrypt encrypt -i file.txt -o file.pcv -P
```

### Quiet Mode for Scripts

Use `--quiet` (`-q`) to suppress progress output:

```bash
picocrypt encrypt -i data.db -o data.pcv -p "password" -q
```

### Non-interactive Mode

Use `--yes` (`-y`) to skip overwrite prompts:

```bash
picocrypt encrypt -i file.txt -o file.pcv -p "password" -y
```

### Batch Processing

```bash
# Encrypt all PDFs in a directory
for file in *.pdf; do
    picocrypt encrypt -i "$file" -p "password" -q -y
done

# Decrypt multiple volumes
for pcv in *.pcv; do
    picocrypt decrypt -i "$pcv" -p "password" -q -y
done

# Parallel encryption with GNU Parallel
find . -name "*.docx" | parallel picocrypt encrypt -i {} -p "password" -q -y
```

### Error Handling in Scripts

```bash
#!/bin/bash
set -e

if picocrypt encrypt -i secret.txt -o secret.pcv -p "$PASSWORD" -q; then
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
    picocrypt encrypt -i /dev/stdin -o "$BACKUP_DIR/backup-$DATE.pcv" \
    -P --reed-solomon --paranoid -q <<< "$PASSWORD"

echo "Backup completed: backup-$DATE.pcv"
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error (invalid arguments, file not found, encryption/decryption failure) |

## Troubleshooting

### Common Issues

**"input file is required (-i)"**
Specify at least one input file with the `-i` flag.

**"password (-p) or keyfile (-k) is required"**
Provide either a password, keyfile, or both.

**"invalid glob pattern"**
Ensure glob patterns are quoted to prevent shell expansion: `-i "*.txt"`

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

This documentation applies to Picocrypt NG v2.04 and later.

## See Also

- [Changelog.md](Changelog.md) - Version history and release notes
