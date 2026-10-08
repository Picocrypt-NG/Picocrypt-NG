package fileops

import "fmt"

const cleanupPanicMessage = "operation panic with incomplete cleanup [REDACTED]"

// cleanupPanic retains the original panic and cleanup diagnostic for lifetime
// and ownership purposes only. Neither is an unwrap/formatting authority. Outer
// boundaries can observe only the cleanup-warning predicate below.
type cleanupPanic struct {
	original any
	cleanup  error
}

func (cleanupPanic) Error() string                  { return cleanupPanicMessage }
func (cleanupPanic) String() string                 { return cleanupPanicMessage }
func (cleanupPanic) GoString() string               { return cleanupPanicMessage }
func (cleanupPanic) Format(state fmt.State, _ rune) { _, _ = state.Write([]byte(cleanupPanicMessage)) }

// PanicCleanupIncomplete reports only whether cleanup failed while an existing
// panic was propagating. It exposes no original panic value or cleanup path.
func PanicCleanupIncomplete(value any) bool {
	switch carrier := value.(type) {
	case *cleanupPanic:
		return carrier != nil && carrier.cleanup != nil
	case cleanupPanic:
		return carrier.cleanup != nil
	default:
		return false
	}
}

// RepanicWithCleanup never converts a panic into a normal result. Successful
// cleanup preserves the original panic identity. Failed cleanup propagates an
// opaque redacted carrier; use PanicCleanupIncomplete at the outer boundary.
func RepanicWithCleanup(value any, cleanupErr error) {
	if cleanupErr == nil {
		panic(value)
	}
	panic(&cleanupPanic{original: value, cleanup: cleanupErr})
}
