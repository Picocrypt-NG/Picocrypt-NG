# Contributing to Picocrypt NG

## Setup

### Prerequisites

- Go 1.27.1, matching `src/go.mod`
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
# Default suite; serialize packages that use the fixed 1 GiB KDF.
go test -p 1 -tags migrated_fynedo ./...

# Separate PCV3 production-KDF vectors and operation checks.
go test -count=1 -p 1 -tags pcv3_production_kdf ./internal/pcv3operation/...

go test -count=1 -run '^TestGolden' ./internal/volume # Backward compatibility
```

Golden tests verify v1/v2 volume compatibility. Run race, fuzz and benchmark
checks for the affected paths separately. Record platform and opt-in skips;
the default suite does not execute every integration or large-resource test.
See [source test instructions](src/README.md#test) and
[Android validation](android/README.md) for the other execution lanes.

## Code Style

- Format changed Go files with `gofmt` before committing
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

The legacy `crypto/`, `header/`, `keyfile/`, and `volume/` paths, the PCV3
`pcv3operation/` boundary and its private implementation, `pcv3publication/`,
`pcv3result/`, and shared `secret/` code are audit-critical. The upstream audit
does not cover subsequent v2 additions or PCV3; see [AI Assistance](#ai-assistance).

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

Changes to crypto-critical code require human review and approval before merge.
This includes the legacy paths and every PCV3 format, credential, operation,
publication and recovery path. AI-generated changes require the same review and
compatibility evidence as other changes; model confidence is not approval.

The legacy v1/v2 lineage derives from Picocrypt, whose commit `7e403a2` was audited by [Radically Open Security](https://www.radicallyopensecurity.com/) in 2024. The archived build and golden/interop vectors protect compatibility with that lineage. PCV3 is a separate new format and is not covered by the 2024 audit; automated tests and vectors do not establish its cryptographic security. The v2 header MAC and optional verify-first mode were added in response to recommendations PCC-001 and PCC-004; they have not received an independent retest.

AI assistance does not replace human judgment on security decisions.

## Pull Requests

### Before Submitting

- [ ] Default tests pass (`go test -p 1 -tags migrated_fynedo ./...`); relevant separate lanes and skips reported
- [ ] Changed Go files formatted
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
