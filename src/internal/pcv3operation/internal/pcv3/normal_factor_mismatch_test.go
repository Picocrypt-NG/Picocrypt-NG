package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

type mismatchUnreadKeyfile struct{ closes int }

func (*mismatchUnreadKeyfile) Read([]byte) (int, error) {
	panic("tuple mismatch read credential content")
}
func (r *mismatchUnreadKeyfile) Close() error { r.closes++; return nil }

func mismatchFactors(mode pcv3credential.CredentialMode, policy pcv3credential.FactorPolicy, order pcv3credential.KeyfileMode, count int) *pcv3credential.FactorRequest {
	f := &pcv3credential.FactorRequest{Mode: mode, ExpectedPolicy: policy, KeyfileMode: order}
	if mode != pcv3credential.CredentialModeKeyfilesOnly {
		f.Password = []byte("mix")
	}
	for range count {
		f.Keyfiles = append(f.Keyfiles, pcv3credential.OwnKeyfileReader(&mismatchUnreadKeyfile{}))
	}
	return f
}

func TestNativeFactorMismatchRetainsOnlyDeclaredTuple(t *testing.T) {
	for _, test := range []struct {
		name     string
		factors  func() *pcv3credential.FactorRequest
		want     bool
		supplied uint16
	}{
		{"missing keyfiles", func() *pcv3credential.FactorRequest { return mismatchFactors(1, 1, 0, 0) }, true, 0},
		{"wrong factor policy", func() *pcv3credential.FactorRequest { return mismatchFactors(2, 2, 1, 2) }, true, 2},
		{"wrong order", func() *pcv3credential.FactorRequest { return mismatchFactors(3, 3, 2, 2) }, true, 2},
		{"wrong count", func() *pcv3credential.FactorRequest { return mismatchFactors(3, 3, 1, 1) }, true, 1},
		{"unsupported mode", func() *pcv3credential.FactorRequest { return mismatchFactors(99, 3, 1, 1) }, false, 0},
		{"unsupported order", func() *pcv3credential.FactorRequest { return mismatchFactors(3, 3, 99, 1) }, false, 0},
		{"contradictory policy", func() *pcv3credential.FactorRequest { return mismatchFactors(3, 1, 1, 1) }, false, 0},
		{"contradictory password mode", func() *pcv3credential.FactorRequest { return mismatchFactors(1, 1, 1, 1) }, false, 0},
		{"empty password", func() *pcv3credential.FactorRequest { f := mismatchFactors(3, 3, 1, 1); f.Password = nil; return f }, false, 0},
		{"overlong password", func() *pcv3credential.FactorRequest {
			f := mismatchFactors(3, 3, 1, 1)
			f.Password = make([]byte, (1<<20)+1)
			return f
		}, false, 0},
		{"over count", func() *pcv3credential.FactorRequest { return mismatchFactors(3, 3, 1, 65) }, false, 0},
		{"count must not truncate", func() *pcv3credential.FactorRequest {
			f := mismatchFactors(3, 3, 1, 0)
			f.Keyfiles = make([]*pcv3credential.KeyfileReader, 65536)
			return f
		}, false, 0},
		{"nil handle", func() *pcv3credential.FactorRequest {
			f := mismatchFactors(3, 3, 1, 0)
			f.Keyfiles = []*pcv3credential.KeyfileReader{nil}
			return f
		}, false, 0},
		{"opaque nil provider still mismatched declared tuple", func() *pcv3credential.FactorRequest {
			f := mismatchFactors(3, 3, 1, 0)
			f.Keyfiles = []*pcv3credential.KeyfileReader{pcv3credential.OwnKeyfileReader(nil)}
			return f
		}, true, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := previewFixture(t)
			dir := t.TempDir()
			admitter := &memoryDenyAdmitter{}
			result := RunNativeRead(context.Background(), &NativeReadRequest{Source: bytes.NewReader(data), SourceSize: int64(len(data)), Factors: test.factors(), Admitter: admitter, Target: filepath.Join(dir, "plain")}, func(*NativeReadOutput) error { t.Fatal("mismatch granted output callback"); return nil })
			requirements, supplied, ok := result.FactorPolicyMismatch()
			if ok != test.want || supplied != test.supplied {
				t.Fatalf("mismatch availability=%v supplied=%d want %v/%d", ok, supplied, test.want, test.supplied)
			}
			if ok && (requirements.Policy() != pcv3credential.FactorPolicyPasswordAndKeyfiles || requirements.KeyfileMode() != pcv3credential.KeyfileModeOrdered || requirements.KeyfileCount() != 2) {
				t.Fatal("wrong required tuple")
			}
			if admitter.calls != 0 || result.PublicationAttempted() || result.AuthenticatedComment() != "" {
				t.Fatal("mismatch or invalid shape granted admission/output/comment")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("mismatch created filesystem output: %v %v", entries, err)
			}
		})
	}
}
