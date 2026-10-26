package pcv3credential

import (
	"bytes"
	"context"
	"testing"
)

func TestPipelineRejectsImplicitCGJBeforeEntropyAdmissionAndKDF(t *testing.T) {
	for _, test := range []struct {
		name     string
		password []byte
		reject   bool
	}{
		{"bounded combining sequence", bytes.Repeat([]byte("\u0300"), 30), false},
		{"31 combining marks", bytes.Repeat([]byte("\u0300"), 31), true},
		{"31 backward-combining Jamo", bytes.Repeat([]byte("\u1161"), 31), true},
		{"explicit CGJ remains data", append(bytes.Repeat([]byte("\u0300"), 30), []byte("\u034f\u0300")...), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := pipelineRequest(t, SuiteStandard1)
			request.Factors.Password = test.password
			passwordAlias := request.Factors.Password
			probe := newPipelineProbe()
			owner, err := newCredential(context.Background(), request, probe.admit, probe.seams())
			if owner != nil {
				defer owner.Close()
			}
			if test.reject {
				requirePipelineCode(t, err, PipelineErrorTranscript, PipelineStageTranscript)
				if owner != nil || probe.entropy.calls != 0 || probe.admit.calls != 0 || probe.kdfCalls != 0 || probe.materialCalls != 0 || probe.published != 0 {
					t.Fatalf("combining-profile rejection crossed a protected boundary: owner=%v entropy=%d admission=%d KDF=%d material=%d published=%d", owner != nil, probe.entropy.calls, probe.admit.calls, probe.kdfCalls, probe.materialCalls, probe.published)
				}
			} else if err != nil || owner == nil || probe.entropy.calls == 0 || probe.admit.calls == 0 || probe.kdfCalls == 0 {
				t.Fatalf("accepted-profile positive control did not reach credential derivation: owner=%v entropy=%d admission=%d KDF=%d error=%v", owner != nil, probe.entropy.calls, probe.admit.calls, probe.kdfCalls, err)
			}
			if !allZero(passwordAlias) {
				t.Fatal("credential pipeline retained the transferred password after profile processing")
			}
		})
	}
}
