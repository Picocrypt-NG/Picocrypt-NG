package pcv3artifact

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"bytes"
	"context"
	"io"
	"testing"
)

// Overall raw D1 authority must coexist with honest verified inner evidence.
// Normal capsule roles still cannot encode that unverified/verified pairing.
func TestD1UnverifiedArtifactRetainsVerifiedInnerEvidence(t *testing.T) {
	for _, role := range []Role{RoleNone, RolePrimary, RoleBackup, RoleD1Front, RoleD1Tail} {
		t.Run(string(rune('0'+role)), func(t *testing.T) {
			literal := readLiteralArtifact(t, "partial")
			literal[18], literal[19], literal[20] = 2, byte(role), 1
			artifact, err := Parse(context.Background(), bytes.NewReader(literal), int64(len(literal)))
			builder, buildErr := pcv3ranges.NewBuilder(5, nil)
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			defer builder.Close()
			if err := builder.Append(pcv3ranges.Verified); err != nil {
				t.Fatal(err)
			}
			ranges, errMap := builder.Seal()
			if errMap != nil {
				t.Fatal(errMap)
			}
			plan, prepareErr := Prepare(Descriptor{State: StateUnverifiedForensic, Role: role, Final: FinalVerified, PlaintextLength: 5, Ranges: ranges})
			if role != RoleD1Front && role != RoleD1Tail {
				if err == nil || artifact != nil || prepareErr == nil || plan != nil {
					t.Fatal("normal artifact accepted unverified overall authority with verified records")
				}
				return
			}
			if err != nil || prepareErr != nil {
				t.Fatalf("D1 provenance rejected actual verified evidence: parse=%v prepare=%v", err, prepareErr)
			}
			var encoded bytes.Buffer
			if err := Encode(context.Background(), &encoded, plan, func(yield func(uint64, io.Reader) error) error {
				return yield(0, bytes.NewReader([]byte("VFY!\n")))
			}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(encoded.Bytes(), literal) {
				t.Fatal("artifact changed frozen header/table layout or evidence bytes")
			}
			if err := artifact.VisitRanges(context.Background(), func(entry Entry, segment io.Reader) error {
				if entry.Status != RangeVerified {
					t.Fatal("inner MAC relabeled")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
