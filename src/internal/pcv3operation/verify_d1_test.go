package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A verifier must consume request resources even before authentication, and
// resource refusal must not be reported as a damaged credential copy.
func TestVerifyD1OwnsAndCleansRejectedRequestsWithoutOutput(t *testing.T) {
	for _, failure := range []string{"cancelled", "resource denied", "reporter panic", "missing source"} {
		t.Run(failure, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "source.pcv")
			ciphertext := bytes.Repeat([]byte{0x93}, 1024)
			if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			password := []byte("TEST ONLY verify factor")
			request := &D1VerifyRequest{Source: source, Factors: &FactorRequest{Mode: CredentialModePasswordOnly, KeyfileMode: KeyfileModeNone, ExpectedPolicy: FactorPolicyPasswordOnly, Password: password}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			diagnostic := DiagnosticResourceInsufficient
			switch failure {
			case "cancelled":
				cancel()
				diagnostic = DiagnosticCancellation
			case "reporter panic":
				request.Reporter = func(Status) error { panic("TEST ONLY private callback text") }
				diagnostic = DiagnosticCallbackPanic
			case "missing source":
				request.Source = nil
				defer source.Close()
				diagnostic = DiagnosticInvalidRequest
			}
			report := verifyD1WithAdmitter(ctx, request, &operationTestAdmitter{admission: pcv3credential.KDFAdmissionDeniedInsufficient})
			if report.Outcome() != OutcomeOperationFailed || report.Diagnostic() != diagnostic || report.Verified() {
				t.Fatalf("incorrect refusal: outcome=%v diagnostic=%v", report.Outcome(), report.Diagnostic())
			}
			if request.Source != nil || request.Factors != nil || request.Reporter != nil {
				t.Fatal("request retained transferred resources")
			}
			if !bytes.Equal(password, make([]byte, len(password))) {
				t.Fatal("owned password was not wiped")
			}
			if failure != "missing source" {
				if _, err := source.Stat(); err == nil {
					t.Fatal("owned source still open")
				}
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, ciphertext) {
				t.Fatal("verification altered source")
			}
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatal("verification created an output/staging file")
			}
		})
	}
}

type d1VerifyCloseFailure struct{ bytes.Reader }

func (*d1VerifyCloseFailure) Close() error { return errors.New("TEST ONLY private cleanup failure") }

func TestVerifyD1ReportsCleanupFailureAndRedactsOwnedFactors(t *testing.T) {
	password := []byte("TEST ONLY nonzero private factor")
	request := &D1VerifyRequest{Factors: &FactorRequest{Password: password, Keyfiles: []*KeyfileReader{OwnKeyfileReader(&d1VerifyCloseFailure{})}}}
	before := fmt.Sprintf("%v %+v %#v", request, request, request)
	if strings.Contains(before, string(password)) || strings.Contains(before, "Password:") {
		t.Fatal("request formatting exposed owned factors")
	}
	report := VerifyD1(context.Background(), request)
	if !report.CleanupIncomplete() || report.Verified() || report.Outcome() != OutcomeOperationFailed {
		t.Fatal("cleanup failure was lost or promoted to verified")
	}
	if !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("refused factors retained password")
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", report, report), "private") {
		t.Fatal("report retained private cleanup text")
	}
}

type d1VerifyCancelAdmission struct{ cancel context.CancelFunc }

func (a d1VerifyCancelAdmission) AdmitKDF(ctx context.Context, _ pcv3credential.KDFProfile) (pcv3credential.KDFAdmission, error) {
	a.cancel()
	return pcv3credential.KDFAdmissionDenied, ctx.Err()
}

func TestVerifyD1ResourceObservationCancellationRemainsCancellation(t *testing.T) {
	source, err := os.CreateTemp(t.TempDir(), "volume")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Write(bytes.Repeat([]byte{0x91}, 1024)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := &D1VerifyRequest{Source: source, Factors: &FactorRequest{Mode: CredentialModePasswordOnly, KeyfileMode: KeyfileModeNone, ExpectedPolicy: FactorPolicyPasswordOnly, Password: []byte("TEST ONLY factor")}}
	report := verifyD1WithAdmitter(ctx, request, d1VerifyCancelAdmission{cancel: cancel})
	if report.Outcome() != OutcomeOperationFailed || report.Stage() != StageCancellation || report.Diagnostic() != DiagnosticCancellation {
		t.Fatalf("cancelled resource observation misclassified: outcome=%v stage=%v diagnostic=%v", report.Outcome(), report.Stage(), report.Diagnostic())
	}
}
