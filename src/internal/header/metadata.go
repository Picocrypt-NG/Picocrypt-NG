package header

// CommentAuthenticity describes metadata trust independently of plaintext visibility.
type CommentAuthenticity string

const (
	CommentUnavailable   CommentAuthenticity = "unavailable"
	CommentUnverified    CommentAuthenticity = "unverified"
	CommentAuthenticated CommentAuthenticity = "authenticated"
)

type LegacySecurityWarning string

const (
	LegacyUnauthenticatedHeader      LegacySecurityWarning = "LEGACY_V1_UNAUTHENTICATED_HEADER"
	LegacyPasswordOnlyAuthentication LegacySecurityWarning = "LEGACY_V2_PASSWORD_ONLY_AUTHENTICATION" //nolint:gosec // G101: public warning discriminator, not a credential.
)

// LegacyMetadata reports only properties established by the legacy reader.
// Its zero value carries no authentication assertion.
type LegacyMetadata struct {
	Version             string                `json:"version"`
	CommentAuthenticity CommentAuthenticity   `json:"commentAuthenticity"`
	SecurityWarning     LegacySecurityWarning `json:"securityWarning"`
}

// LegacyMetadata requires an actual successful header MAC check to confirm v2
// comments. A v1 password-key hash cannot authenticate comment bytes.
func (h *VolumeHeader) LegacyMetadata(headerAuthenticated bool) LegacyMetadata {
	m := LegacyMetadata{CommentAuthenticity: CommentUnavailable}
	if h == nil {
		return m
	}
	m.Version = h.Version
	if h.Comments != "" {
		m.CommentAuthenticity = CommentUnverified
	}
	if !IsSupportedVersion([]byte(h.Version)) {
		return m
	}
	if h.IsLegacyV1() {
		m.SecurityWarning = LegacyUnauthenticatedHeader
		return m
	}
	if h.Flags.UseKeyfiles {
		m.SecurityWarning = LegacyPasswordOnlyAuthentication
	}
	if headerAuthenticated && h.Comments != "" {
		m.CommentAuthenticity = CommentAuthenticated
	}
	return m
}
