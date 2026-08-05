package pcv3

import "testing"

func FuzzInspectRecoveryFixedSlots(f *testing.F) {
	fixtures := loadNormalFixtureManifest(f).FixturesByID()
	for _, name := range []string{
		"normal-standard-password-only-small",
		"normal-standard-combined-ordered-empty",
	} {
		f.Add(readNormalFixtureArtifact(f, fixtures[name].Volume))
	}
	f.Fuzz(func(t *testing.T, source []byte) {
		observer := &observingRecoveryReader{data: source}
		_, _ = InspectRecovery(observer, int64(len(source)))
		if len(observer.reads) > 51 {
			t.Fatalf("InspectRecovery issued %d reads; fixed bound is 51", len(observer.reads))
		}
		for _, read := range observer.reads {
			if read.length != 16 && read.length != 960 {
				t.Fatalf("InspectRecovery read %d bytes at %d; want raw 16 or fixed capsule 960", read.length, read.offset)
			}
			if read.offset < 0 {
				t.Fatalf("InspectRecovery issued negative-offset read %+v for size %d", read, len(source))
			}
		}
	})
}
