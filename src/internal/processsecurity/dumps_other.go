//go:build !linux || android

package processsecurity

// RestrictDumps has no process-wide policy on these platforms. In particular,
// Android's embedding application owns its process policy.
func RestrictDumps() error { return nil }
