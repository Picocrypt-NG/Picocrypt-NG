# Legacy Implementation Archive

This directory contains archived versions of the original audited monolithic implementation.

## Files

### `Picocrypt-NG.go.archive`

The original single-file implementation that was refactored into the modular
`internal/` package structure. This file is preserved for:

1. **Reference**: Comparing behavior during audits
2. **Regression Testing**: Ensuring the refactored code matches original behavior
3. **Historical Documentation**: Understanding the original design decisions

##  DO NOT USE

These files are **not compiled** and **not maintained**. The active codebase is:

- Entry point: `cmd/picocrypt/main.go`
- Core logic: `internal/` packages

## Related Files

- `original_audited_picocrypt.go`: The externally audited v1.49 implementation
- Golden test vectors in `testdata/golden/`: Used to verify backward compatibility
