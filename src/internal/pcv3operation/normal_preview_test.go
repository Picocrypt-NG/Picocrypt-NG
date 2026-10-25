package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalFactorMismatchRefusesBeforeAdmissionOrOutput(t *testing.T) {
	source := openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
	directory := t.TempDir()
	admitter := &operationTestAdmitter{}
	result := runWithSeams(context.Background(), &Request{
		Mode: ModeReadNormal, Source: source, Target: filepath.Join(directory, "plaintext"),
		Factors: &FactorRequest{Mode: CredentialModePasswordOnly, ExpectedPolicy: FactorPolicyPasswordOnly, Password: []byte("mix")},
	}, operationSeams{admitter: admitter})
	if result.Outcome() != pcv3.OutcomeOperationFailed || result.Stage() != pcv3.StageCredentialPolicy ||
		result.Diagnostic() != DiagnosticCredentialPolicy {
		t.Fatalf("tuple refusal = %v/%v diagnostic %v; want credential policy diagnostic", result.Outcome(), result.Stage(), result.Diagnostic())
	}
	requirements, supplied, available := result.CredentialPolicyMismatch()
	if !available || requirements.Policy() != FactorPolicyPasswordAndKeyfiles || requirements.KeyfileMode() != KeyfileModeOrdered || requirements.KeyfileCount() != 2 || supplied != 0 {
		t.Fatalf("retained mismatch = %v supplied=%d available=%v", requirements, supplied, available)
	}
	if len(result.Args()) != 0 || len(result.Presentation().Args()) != 0 {
		t.Fatal("mismatch expanded wire presentation arguments")
	}
	if admitter.calls != 0 || result.PublicationAttempted() || result.AuthenticatedComment() != "" || result.SourceDeletionAllowed() {
		t.Fatal("factor tuple refusal admitted credentials or granted output/comment/deletion")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("factor tuple refusal created output: %v, %v", entries, err)
	}
}

func TestNormalPreviewFacadeBorrowsSelectedSource(t *testing.T) {
	source := openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
	defer func() { _ = source.Close() }()
	if _, err := source.Seek(23, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	info, err := source.Stat()
	if err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewNormal(context.Background(), source, info.Size())
	if comment, ok := preview.Comment(); err != nil || !ok || comment != "TEST ONLY comment" {
		t.Fatalf("facade preview err=%v available=%v comment=%q", err, ok, comment)
	}
	if position, err := source.Seek(0, io.SeekCurrent); err != nil || position != 23 {
		t.Fatalf("source position=%d err=%v", position, err)
	}
	if factors, ok := preview.Factors(); !ok || factors.Policy() != FactorPolicyPasswordAndKeyfiles || factors.KeyfileCount() != 2 {
		t.Fatal("facade lost factor hints")
	}
}

func TestNormalFactorContentAndOtherFailuresHideMismatch(t *testing.T) {
	for _, test := range []struct {
		name      string
		duplicate bool
		reporter  func(context.CancelFunc) Reporter
		want      Diagnostic
	}{
		{"matching duplicate contents", true, nil, DiagnosticNone},
		{"resource refusal", false, nil, DiagnosticResourceInsufficient},
		{"callback refusal", false, func(context.CancelFunc) Reporter {
			return func(s Status) error {
				if s.Code() == StatusCheckingResources {
					return errors.New("private callback error")
				}
				return nil
			}
		}, DiagnosticCallbackFailure},
		{"cancellation", false, func(cancel context.CancelFunc) Reporter {
			return func(s Status) error {
				if s.Code() == StatusCheckingResources {
					cancel()
				}
				return nil
			}
		}, DiagnosticCancellation},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			first, second := "one", "two!"
			if test.duplicate {
				second = first
			}
			factors := &FactorRequest{Mode: CredentialModePasswordAndKeyfiles, ExpectedPolicy: FactorPolicyPasswordAndKeyfiles, KeyfileMode: KeyfileModeOrdered, Password: []byte("mix"), Keyfiles: []*KeyfileReader{
				OwnKeyfileReader(io.NopCloser(strings.NewReader(first))), OwnKeyfileReader(io.NopCloser(strings.NewReader(second))),
			}}
			dir := t.TempDir()
			request := &Request{Mode: ModeReadNormal, Source: openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv"), Factors: factors, Target: filepath.Join(dir, "plain")}
			if test.reporter != nil {
				request.Reporter = test.reporter(cancel)
			}
			admitter := &operationTestAdmitter{admission: pcv3credential.KDFAdmissionDeniedInsufficient}
			result := runWithSeams(ctx, request, operationSeams{admitter: admitter})
			if result.Diagnostic() != test.want {
				t.Fatalf("diagnostic=%v want %v", result.Diagnostic(), test.want)
			}
			if _, _, ok := result.CredentialPolicyMismatch(); ok {
				t.Fatal("matching tuple content/resource/callback failure mislabeled mismatch")
			}
			if result.PublicationAttempted() || result.AuthenticatedComment() != "" || result.SourceDeletionAllowed() {
				t.Fatal("failure granted output/comment/deletion")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failure created output: %v %v", entries, err)
			}
		})
	}
}

func TestNormalMismatchGetterRejectsDiagnosticOverrides(t *testing.T) {
	source := openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
	result := runWithSeams(context.Background(), &Request{Mode: ModeReadNormal, Source: source, Target: filepath.Join(t.TempDir(), "plain"), Factors: &FactorRequest{Mode: CredentialModePasswordOnly, ExpectedPolicy: FactorPolicyPasswordOnly, Password: []byte("mix")}}, operationSeams{admitter: &operationTestAdmitter{}})
	for _, diagnostic := range []Diagnostic{DiagnosticNone, DiagnosticResourceBusy, DiagnosticResourceInsufficient, DiagnosticResourceUnknown, DiagnosticCallbackFailure, DiagnosticCallbackPanic, DiagnosticCancellation} {
		changed := *result
		changed.diagnostic = diagnostic
		if requirements, count, ok := changed.CredentialPolicyMismatch(); ok || requirements.Policy() != 0 || count != 0 {
			t.Fatalf("diagnostic override %v retained mismatch", diagnostic)
		}
	}
	if _, _, ok := (*Result)(nil).CredentialPolicyMismatch(); ok {
		t.Fatal("nil result carries mismatch")
	}
}
