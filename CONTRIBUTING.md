# Contributing to Picocrypt NG

## Setup

### Prerequisites

- Go 1.24+
- GCC (for CGO)
- Platform dependencies:
  - Linux: `libgtk-3-dev`, `libgl1-mesa-dev`, `xorg-dev`
  - macOS: Xcode CLI tools
  - Windows: TDM-GCC or MinGW-w64

### Build

```bash
git clone https://github.com/Picocrypt-NG/Picocrypt-NG.git
cd Picocrypt-NG/src
go build -o picocrypt cmd/picocrypt/main.go
```

## Testing

```bash
go test ./...                                        # All tests
go test -cover ./...                                 # With coverage
go test -race ./...                                  # Race detector
go test -v ./internal/volume -run TestGoldenVectors  # Backward compatibility
go test -bench=. ./...                               # Benchmarks
```

Golden tests verify v1/v2 volume compatibility.

## Code Style

- Run `gofmt -w .` before committing
- Use `golangci-lint run` for linting
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

## Pull Requests

### Before Submitting

- [ ] Tests pass (`go test ./...`)
- [ ] Code formatted (`gofmt -w .`)
- [ ] Linter clean (`golangci-lint run`)
- [ ] Golden tests pass
- [ ] Documentation updated

### PR Guidelines

- One focused change per PR
- Include tests for new code
- Keep PRs small
- Reference related issues

## License

Contributions are licensed under GPL-3.0-only.
