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

All crypto-critical code — including the legacy `crypto/`, `header/`, `keyfile/`, and `volume/` paths and every PCV3 format, credential, operation, publication, and recovery path — is reviewed and approved by a human before merging. AI-generated suggestions in these packages are treated with the same skepticism as any untrusted diff: they are read carefully, tested against applicable compatibility evidence, and never merged on AI confidence alone.

The legacy v1/v2 lineage derives from Picocrypt, whose commit `7e403a2` was audited by [Radically Open Security](https://www.radicallyopensecurity.com/) in 2024. The archived build and golden/interop vectors protect compatibility with that lineage. PCV3 is a separate new format and is not covered by the 2024 audit; automated tests and vectors do not establish its cryptographic security. The v2 header MAC and optional verify-first mode were added in response to recommendations PCC-001 and PCC-004; they have not received an independent retest.

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
