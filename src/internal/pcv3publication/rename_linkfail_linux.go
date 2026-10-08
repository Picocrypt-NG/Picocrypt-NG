//go:build linux && !android

package pcv3publication

// linkFallbackFailed keeps desktop and non-Android Linux fail-closed: when the
// ENOSYS fallback's link(2) fails, no atomic no-replace primitive remains, so
// the original link error propagates through the caller's identity-based
// classification. A plain rename(2) would silently replace a concurrently
// created destination and is never substituted here.
func linkFallbackFailed(_ int, _, _ string, linkErr error) error {
	return linkErr
}
