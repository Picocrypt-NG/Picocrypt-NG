# Contributing to Picocrypt NG

## Setup

### Prerequisites

- Go 1.26+
- GCC (for CGO)
- Platform dependencies:
  - Linux: `libgtk-3-dev`, `libgl1-mesa-dev`, `xorg-dev`
  - macOS: Xcode CLI tools
  - Windows: TDM-GCC or MinGW-w64

### Build

```bash
git clone https://github.com/Picocrypt-NG/Picocrypt-NG.git
cd Picocrypt-NG/src
go build -tags migrated_fynedo -o picocrypt ./cmd/picocrypt
```

## Testing

```bash
go test -tags migrated_fynedo ./...                  # All tests
go test -tags migrated_fynedo -cover ./...           # With coverage
go test -tags migrated_fynedo -race ./...            # Race detector
go test -count=1 -run '^TestGolden' ./internal/volume # Backward compatibility
go test -tags migrated_fynedo -bench=. ./...         # Benchmarks
```

Golden tests verify v1/v2 volume compatibility.

## Code Style

- Run `gofmt -w .` before committing
- Use `golangci-lint run --build-tags migrated_fynedo` for linting
- Doc comments on all exported symbols
- Handle all errors
- Use `defer` for cleanup

```go
// DeriveKey derives an encryption key from password using Argon2id.
func DeriveKey(password, salt []byte, paranoid bool) ([]byte, error)
```

## Security

### Audit-Critical Packages

`crypto/`, `header/`, `keyfile/`, `volume/` contain audited code.

```go
// Zero key material
key := make([]byte, 32)
defer crypto.SecureZero(key)

// Constant-time MAC comparison
if subtle.ConstantTimeCompare(mac1, mac2) != 1 {
    return errors.New("MAC verification failed")
}

// Crypto-secure RNG only
nonce, err := crypto.RandomBytes(24)
```

## AI Assistance

AI tools (LLMs) are used in this project to assist with development — writing boilerplate, drafting tests, exploring refactoring options, and reviewing documentation.

All crypto-critical code (`crypto/`, `header/`, `keyfile/`, `volume/`) is reviewed and approved by a human before merging. AI-generated suggestions in these packages are treated with the same skepticism as any untrusted diff: they are read carefully, tested against golden vectors, and never merged on AI confidence alone.

The cryptographic design and on-disk volume format derive from Picocrypt, which completed a [Radically Open Security](https://www.radicallyopensecurity.com/) audit in 2024 with no major findings. Picocrypt NG refactored that audited single-file implementation into the modular `crypto/`, `header/`, `keyfile/`, and `volume/` packages; the original audited build is archived (`src/testdata/legacy/`) and the refactored code is regression-pinned against it and against frozen golden/interop vectors — so neither a refactor nor an AI-assisted change can silently alter the audited cryptographic behavior or the volume format. The v2 format additions (HMAC-SHA3-512 header authentication and verify-first decryption) implement the audit's own recommendations (PCC-001, PCC-004).

AI assistance does not replace human judgment on security decisions.

## Pull Requests

### Before Submitting

- [ ] Tests pass (`go test -tags migrated_fynedo ./...`)
- [ ] Code formatted (`gofmt -w .`)
- [ ] Linter clean (`golangci-lint run --build-tags migrated_fynedo`)
- [ ] Golden tests pass
- [ ] Documentation updated

### PR Guidelines

- One focused change per PR
- Include tests for new code
- Keep PRs small
- Reference related issues

## License

Contributions are licensed under GPL-3.0-only.
