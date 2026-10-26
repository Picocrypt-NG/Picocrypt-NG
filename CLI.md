# Picocrypt NG Command-Line Interface

Commands, options and scripting examples for Picocrypt NG.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Build Modes](#build-modes)
- [Commands](#commands)
  - [Encrypt Command](#encrypt-command)
  - [Decrypt Command](#decrypt-command)
  - [Verify Command](#verify-command)
- [Usage Examples](#usage-examples)
- [Stdin/Stdout Streaming](#stdinstdout-streaming)
- [Scripting Guide](#scripting-guide)
- [Exit Codes](#exit-codes)
- [Troubleshooting](#troubleshooting)

## Overview

The CLI encrypts files and folders, reads supported volumes and supports these
cryptographic options:

- **XChaCha20** symmetric encryption with a 256-bit key
- **Argon2id** memory-hard key derivation
- **BLAKE2b-512** message authentication
- **Optional Serpent-CTR** cascade cipher (paranoid mode)
- **Reed-Solomon** error correction for data recovery
- **Optional D1** encryption that hides the recognizable format header

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

Direct Linux executables disable kernel core dumps and ordinary peer debugger attachment before reading application input. If this startup protection fails, operations are refused; help and version remain available. Flatpak and the packaged Snap executable retain their existing process policy to preserve desktop portal access. This protection does not erase argv, swap, hibernation images, or existing dumps, and does not prevent privileged or in-process access.

#### Security Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--pcv3` | bool | true | Create PCV3; disabling is unsupported |
| `--comments` | string | | Header comment: plaintext in Normal, encrypted inside D1 |
| `--paranoid` | bool | false | Enable Serpent-CTR + XChaCha20 cascade |
| `--reed-solomon` | bool | false | Enable Reed-Solomon error correction |
| `--deniability` | bool | false | Create PCV3 D1; `--paranoid` is optional |
| `--compress` | bool | false | Compress files before encryption |

Normal PCV3 supports regular files, folders/ZIP payloads, Reed-Solomon, splitting, and
stdin/stdout. `--deniability` creates random-looking PCV3 D1; add `--paranoid` for the
Serpent cascade. The [fixed D1C KDF](Internals.md#pcv3-d1c) is independent of
that cipher choice. D1 accepts files,
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
| `--force` | bool | false | Legacy only: retain output despite integrity/authentication failure |
| `--verify-first` | bool | false | Legacy only: authenticate the payload before decryption; adds a read and KDF |
| `--auto-unzip` | bool | false | Legacy only: automatically extract ZIP output |
| `--same-level` | bool | false | Legacy only: extract to the output directory instead of a subdirectory |

#### Volume State Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--recombine` | bool | false | Recombine split chunks first (auto-detected) |
| `--deniability` | bool | false | Remove a legacy deniability wrapper before decryption |

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
After a successful authenticated PCV3 read, the CLI prints its comment as
quoted UTF-8 on stderr; failed authentication never releases the comment.
D1 hides the recognizable header; container name and size remain visible.
PCV3 uses the [frozen Unicode-18 password profile](Internals.md#pcv3-password-profile).

| Flag | Description |
|------|-------------|
| `--pcv3-format=d1` | Select random-looking D1 input |
| `--pcv3-factors=password\|keyfiles\|combined` | Pin the expected credential policy |
| `--pcv3-keyfile-order=ordered\|unordered` | Pin keyfile ordering when keyfiles are used |
| `--pcv3-action=recovery\|force` | Select authenticated recovery or Force recovery |
| `--pcv3-role=primary\|backup\|front\|tail` | Select an explicit physical role for unverified Force |
| `--pcv3-d1-suite=standard\|paranoid` | Hint the cipher suite only for explicitly selected unverified D1 Force |
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

If corruption prevents authenticating D1's hidden cipher suite, unverified Force
requires an explicit `--pcv3-d1-suite` choice together with `--pcv3-role=front|tail`.
This choice does not authenticate recovered data or reduce D1's fixed KDF cost.
A hint that contradicts an authenticated suite is refused. Ordinary reads and
authenticated recovery select the suite from authenticated metadata.

### Verify Command

`verify --deniability VOLUME` fully verifies PCV3 D1 without creating an output
file or modifying the source. It requires a regular file path and an explicit
`--pcv3-factors=password|keyfiles|combined` policy. Password input (`-p`, `-P`,
`--password-fd`) and keyfile/order flags follow the decrypt credential contract.

```bash
Picocrypt-NG verify --deniability hidden.pcv --pcv3-factors=password -P < /path/to/password-file
```

Both physical bootstraps must authenticate and agree on roots, profile and body
length, with independent bootstrap parameters and canonical geometry. Verification
then authenticates the complete outer and inner payload through the final record.
Strict verification checks the tail that an ordinary healthy D1 open can leave
unchecked. Its [D1C KDF cost](Internals.md#pcv3-d1c) is two sequential derivations;
there is no inner Argon2id call. Verification does not scrub every physical RS
parity byte.

The report on stderr shows front, tail, pair and payload checks. Exit 0 means a
complete clean verification; any incomplete, degraded, cancelled or failed run
returns exit 1. Wrong credentials and unauthenticatable damage are not distinguished.
Resource refusal, cancellation and I/O failures are operational failures.
There are no output, Force, suite-hint, extraction or source-deletion options.

## Usage Examples

### Basic Encryption

```bash
# Encrypt a single file
picocrypt encrypt document.pdf -o document.pcv

# Create Normal PCV3 explicitly
picocrypt encrypt document.pdf -o document.pcv --pcv3

# Encrypt with auto-generated output name (creates document.pdf.pcv)
picocrypt encrypt document.pdf

# Encrypt multiple files (creates a zip archive internally)
picocrypt encrypt file1.txt file2.txt file3.txt -o archive.pcv

# Encrypt an entire directory
picocrypt encrypt ./my-folder -o backup.pcv

# Use glob patterns
picocrypt encrypt --glob "*.jpg" --glob "*.png" -o images.pcv
```

### Security Options

```bash
# Paranoid mode with Reed-Solomon error correction
picocrypt encrypt sensitive.db -o sensitive.pcv \
    --paranoid --reed-solomon

# D1 hides the format header; name and size remain visible
picocrypt encrypt hidden.txt -o innocent.pcv --deniability --paranoid

# Add comments (visible in header, NOT encrypted)
picocrypt encrypt report.docx -o report.pcv \
    -c "Q4 Financial Report - Confidential"
```

### Split Output

```bash
# Split into 100 MiB chunks
picocrypt encrypt large-file.iso -o backup.pcv \
    --split --split-size 100 --split-unit MiB

# Split into 5 equal parts
picocrypt encrypt archive.tar -o archive.pcv \
    --split --split-size 5 --split-unit Total

# Split into 4.7 GiB chunks (DVD-size)
picocrypt encrypt video.mkv -o video.pcv \
    --split --split-size 4700 --split-unit MiB
```

### Basic Decryption

```bash
# Decrypt a file
picocrypt decrypt document.pcv -o document.decrypted.pdf --pcv3-factors=password

# Auto-detect output name (removes .pcv extension)
picocrypt decrypt document.pcv --pcv3-factors=password

# Decrypt with keyfile
picocrypt decrypt secret.pcv --pcv3-factors=combined --pcv3-keyfile-order=unordered -k keyfile.key

# Open explicitly selected D1 with its original credential policy
picocrypt decrypt innocent.pcv --pcv3-format=d1 --pcv3-factors=password
```

### Advanced Decryption

The following legacy v1/v2 options remain available for existing volumes. For PCV3,
use the explicit format, factor and archive flags listed above.

```bash
# Authenticate a legacy payload before decryption (two-pass)
picocrypt decrypt legacy-important.pcv --verify-first

# Auto-extract zip archives after decryption
picocrypt decrypt legacy-archive.pcv --auto-unzip

# Extract to same directory (not subdirectory)
picocrypt decrypt legacy-files.pcv --auto-unzip --same-level

# Recombine split volume (usually auto-detected)
picocrypt decrypt legacy-backup.pcv.0 --recombine

# Legacy Force decryption despite corruption (may produce partial output)
picocrypt decrypt legacy-damaged.pcv --force
```

If `--force` keeps output after an integrity or authentication check failed, Picocrypt NG writes `Warning: Force decrypt kept output...` to stderr and exits with exit code 2. The recovered file or stdout bytes are not fully verified; scripts must not treat exit code 2 as clean success.

## Stdin/Stdout Streaming

Use `-` as the filename for stdin/stdout to enable pipeline automation. The formats
require known sizes, so plaintext stdin and decrypted stdout use private encrypted
temporary staging with a fresh per-operation key. Ordinary decryption authenticates
the volume and the complete temporary stream before writing stdout. A hard crash
can leave ciphertext, and cleanup uncertainty is reported. A successful plaintext
stdout transfer reports `Publication: not-attempted`: no destination file was published.

### Basic Streaming

The examples below use Unix Bash process substitution. `secret-command` must write exactly one password line without putting it in its own arguments; each invocation gets a fresh descriptor 3. Enable `pipefail` so an upstream command failure makes the pipeline fail.

```bash
set -o pipefail

# Encrypt from stdin to file
cat document.txt | picocrypt encrypt - -o document.pcv --password-fd=3 3< <(secret-command)

# Encrypt file to stdout
picocrypt encrypt document.txt -o - --password-fd=3 3< <(secret-command) > document.pcv

# Full pipeline: stdin to stdout
cat secret.txt | picocrypt encrypt - -o - --password-fd=3 3< <(secret-command) > secret.pcv

# Decrypt from stdin
curl --fail --show-error https://example.com/file.pcv | \
    picocrypt decrypt - -o file.txt --pcv3-factors=password --password-fd=3 3< <(secret-command)

# Decrypt to stdout
picocrypt decrypt secret.pcv -o - --pcv3-factors=password --password-fd=3 3< <(secret-command) | less

# Round-trip pipeline
cat secret.txt | picocrypt encrypt - -o - --password-fd=3 3< <(secret-command) | \
    picocrypt decrypt - -o - --pcv3-factors=password --password-fd=3 3< <(secret-command)
```

### Pipeline Examples

```bash
set -o pipefail

# Encrypt and upload in one pipeline
tar czf - /home/user/documents | picocrypt encrypt - -o - --password-fd=3 3< <(secret-command) | \
    curl --fail --show-error -X PUT -T - https://storage.example.com/backup.pcv

# Download, decrypt, and extract
curl --fail --silent --show-error https://storage.example.com/backup.pcv | \
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

For legacy input, if `picocrypt decrypt VOLUME -o - --force` keeps recovered output after an integrity or authentication check failed, recovered bytes are written to stdout before the process returns exit code 2. The kept-output warning is written to stderr. Scripts must still check the exit code before treating those bytes as verified.

## Scripting Guide

### Reading Password from Stdin

For automated scripts, use `--password-stdin` (`-P`) when stdin is free. Password files must contain one password line and be readable only by their owner.

```bash
set -o pipefail

# From a secret provider
secret-command | picocrypt encrypt file.txt -o file.pcv -P

# From a protected password file
picocrypt encrypt file.txt -o file.pcv -P < /path/to/password-file
```

When fd 0 carries plaintext or a volume, use a separate inherited Unix descriptor. Open it afresh for each invocation:

```bash
set -o pipefail

producer | picocrypt encrypt - -o - --pcv3 --password-fd=3 3< <(secret-command)
```

### Quiet Mode for Scripts

Use `--quiet` (`-q`) to suppress progress output:

```bash
picocrypt encrypt data.db -o data.pcv -P -q < /path/to/password-file
```

### Non-interactive Mode

PCV3 always requires a vacant destination. `--yes` (`-y`) remains accepted for
script compatibility but does not replace existing PCV3 outputs:

```bash
picocrypt encrypt file.txt -o file.pcv -P -y < /path/to/password-file
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

These Unix Bash examples reopen the protected password file for every command.

```bash
set -euo pipefail

PASSWORD_FILE="/path/to/password-file"

# Encrypt all PDFs in a directory
for file in *.pdf; do
    picocrypt encrypt "$file" --password-fd=3 3< "$PASSWORD_FILE" -q -y
done

# Decrypt password-only PCV3 volumes
for pcv in *.pcv; do
    picocrypt decrypt "$pcv" --pcv3-factors=password --password-fd=3 3< "$PASSWORD_FILE" -q -y
done
```

### Error Handling in Scripts

```bash
#!/bin/bash
set -euo pipefail

if picocrypt encrypt secret.txt -o secret.pcv -P -q < /path/to/password-file; then
    echo "Encryption completed"
else
    picocrypt_status=$?
    echo "Encryption did not complete cleanly (exit $picocrypt_status); inspect stderr" >&2
    exit "$picocrypt_status"
fi
```

### Backup Script Example

```bash
#!/bin/bash
set -euo pipefail

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
set -euo pipefail

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

**"invalid glob pattern"**
Ensure explicit glob patterns are quoted to prevent shell expansion: `--glob "*.txt"`

**"keyfile not found"**
Verify the keyfile path exists and is accessible.

**"This volume requires keyfiles"**
The encrypted volume was created with keyfiles. Provide the same keyfiles with `-k`.

**"MAC verification failed"**
Authentication did not confirm the result. For legacy recovery, `--force` can
retain damaged or untrusted output. It does not select an alternative normalized
password. PCV3 rejects legacy `--force`; use the explicit
[`--pcv3-action` recovery options](#pcv3-flags), including separate consent and a
physical role when unverified Force requires them.

### Split Volume Issues

Split volumes are automatically detected when the filename contains `.pcv.N` pattern (e.g., `file.pcv.0`, `file.pcv.1`). The CLI will automatically enable `--recombine`.

Ensure all chunk files are in the same directory before decryption.

### Performance Tips

- `--quiet` suppresses progress output; its effect on runtime depends on the workload
- Reed-Solomon adds recovery data and increases output size
- Paranoid adds a Serpent cascade. Normal PCV3 also changes the KDF from four
  passes to eight; D1 keeps its fixed KDF. Measure the cost on the target hardware.
- Legacy `--verify-first` adds a payload read and key derivation before decryption;
  it does not add keyfile binding to a legacy v2 volume

## Version

This documentation applies to Picocrypt NG v3.0 (unreleased development version).

## See Also

- [Changelog.md](Changelog.md) - Version history and release notes
