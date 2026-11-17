package header

import "testing"

func TestLegacyMetadataSeparatesCommentTrustFromFormatLimitations(t *testing.T) {
	for _, test := range []struct {
		name, version, comment, trust, warning string
		keyfiles, authenticated                bool
	}{
		{"v1 preview", "v1.33", "text", "unverified", "LEGACY_V1_UNAUTHENTICATED_HEADER", false, false},
		{"v1 successful read", "v1.33", "text", "unverified", "LEGACY_V1_UNAUTHENTICATED_HEADER", false, true},
		{"v2 preview", "v2.00", "text", "unverified", "", false, false},
		{"v2 authenticated", "v2.00", "text", "authenticated", "", false, true},
		{"v2 keyfile authentication", "v2.19", "text", "authenticated", "LEGACY_V2_PASSWORD_ONLY_AUTHENTICATION", true, true},
		{"v2 empty comment", "v2.19", "", "unavailable", "", false, true},
		{"unknown format", "v4.00", "text", "unverified", "", false, true},
		{"malformed format", "v2", "text", "unverified", "", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := &VolumeHeader{Version: test.version, Comments: test.comment, Flags: Flags{UseKeyfiles: test.keyfiles}}
			got := h.LegacyMetadata(test.authenticated)
			if string(got.CommentAuthenticity) != test.trust || string(got.SecurityWarning) != test.warning {
				t.Fatalf("metadata trust=%q warning=%q; want %q %q", got.CommentAuthenticity, got.SecurityWarning, test.trust, test.warning)
			}
		})
	}
}
