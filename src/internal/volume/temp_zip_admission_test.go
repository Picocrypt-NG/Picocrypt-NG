package volume

import "testing"

// Literal one-byte geometry catches omitted simultaneous temporary/final space,
// missing split overlap, and the legacy inner+deniability wrapper overlap.
func TestTemporaryZIPAdmissionCountsSimultaneousStorage(t *testing.T) {
	for _, tc := range []struct {
		name       string
		req        EncryptRequest
		free, want uint64
	}{
		{"normal", EncryptRequest{PCV3: true}, 2362, 17},
		{"normal split", EncryptRequest{PCV3: true, Split: true}, 4707, 17},
		{"d1", EncryptRequest{PCV3: true, Deniability: true, Paranoid: true}, 2890, 17},
		{"legacy", EncryptRequest{}, 807, 17},
		{"legacy wrapper", EncryptRequest{Deniability: true}, 1677, 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, e := admittedTemporaryZIPExtent(&tc.req, tc.free)
			if e != nil || got != tc.want {
				t.Fatalf("admission=%d/%v want %d", got, e, tc.want)
			}
			below, e := admittedTemporaryZIPExtent(&tc.req, tc.free-1)
			if e == nil && below >= tc.want {
				t.Fatalf("one byte beyond budget admitted: %d", below)
			}
		})
	}
}
