package pcv3credential

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyfileBorrowFileExpiresWhenOwnershipCloses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "factor")
	if err := os.WriteFile(path, []byte("original factor"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	reader := OwnKeyfileReader(file)
	if reader.BorrowFile() != file {
		t.Fatal("direct keyfile identity unavailable before consumption")
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if reader.BorrowFile() != nil {
		t.Fatal("closed keyfile still lends its descriptor")
	}
	if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("file ownership not closed: %v", err)
	}
	wrapped := OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("factor"))))
	defer wrapped.Close()
	if wrapped.BorrowFile() != nil {
		t.Fatal("opaque provider acquired file authority")
	}
}

// Early credential rejection consumes and closes factors before returning its
// normative error. The operation owner still needs the independent cleanup fact.
func TestCredentialEarlyRejectionPreservesCleanupObservation(t *testing.T) {
	tests := []struct {
		name string
		run  func(*FactorRequest) error
		code PipelineErrorCode
	}{
		{name: "writer-invalid-admitter", code: PipelineErrorInvalidRequest, run: func(factors *FactorRequest) error {
			_, err := NewCredential(context.Background(), &CredentialRequest{Suite: SuiteStandard1, Factors: factors}, nil)
			return err
		}},
		{name: "reader-invalid-callback", code: PipelineErrorInvalidRequest, run: func(factors *FactorRequest) error {
			_, err := WithReaderCredential(context.Background(), &ReaderCredentialRequest{Suite: SuiteStandard1, Factors: factors}, &pipelineAdmission{}, nil)
			return err
		}},
		{name: "recovery-invalid-tuples", code: PipelineErrorSchedule, run: func(factors *FactorRequest) error {
			_, err := WithRecoveryCredentialSession(context.Background(), &RecoveryCredentialRequest{Factors: factors}, nil, nil)
			return err
		}},
	}
	for _, test := range tests {
		for _, fail := range []bool{false, true} {
			name := "successful-close"
			if fail {
				name = "failed-close"
			}
			t.Run(test.name+"/"+name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "keyfile")
				if err := os.WriteFile(path, []byte("original factor"), 0o600); err != nil {
					t.Fatal(err)
				}
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				reader := &trackedReadCloser{readFn: file.Read, closeFn: func() error {
					err := file.Close()
					if fail {
						return errors.Join(err, errors.New("private provider /keyfile failure"))
					}
					return err
				}}
				password := []byte("owned password")
				factors := &FactorRequest{Mode: CredentialModePasswordAndKeyfiles, KeyfileMode: KeyfileModeOrdered, ExpectedPolicy: FactorPolicyPasswordAndKeyfiles, Password: password, Keyfiles: []*KeyfileReader{OwnKeyfileReader(reader)}}
				err = test.run(factors)
				var pipelineErr *PipelineError
				if !errors.As(err, &pipelineErr) || pipelineErr.Code != test.code {
					t.Fatalf("early rejection changed: %v", err)
				}
				if factors.CleanupIncomplete() != fail {
					t.Errorf("cleanup observation = %v; want %v", factors.CleanupIncomplete(), fail)
				}
				if closeErr := factors.Close(); closeErr != nil || reader.closeCalls != 1 || factors.CleanupIncomplete() != fail {
					t.Errorf("idempotent Close lost cleanup truth or reclosed provider: err=%v calls=%d cleanup=%v", closeErr, reader.closeCalls, factors.CleanupIncomplete())
				}
				var probe [1]byte
				if _, err := file.ReadAt(probe[:], 0); !errors.Is(err, os.ErrClosed) {
					t.Errorf("real descriptor remains open: %v", err)
				}
				got, err := os.ReadFile(path)
				if err != nil || string(got) != "original factor" {
					t.Error("original keyfile changed")
				}
				if !allZero(password) || factors.Password != nil || factors.Keyfiles != nil {
					t.Error("rejection retained owned factor material")
				}
				if formatted := fmt.Sprintf("%v %#v", pipelineErr, pipelineErr); strings.Contains(formatted, "private provider") || strings.Contains(formatted, "/keyfile") {
					t.Errorf("public error exposes provider details: %q", formatted)
				}
			})
		}
	}
}
