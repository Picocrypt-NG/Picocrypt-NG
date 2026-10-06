package pcv3operation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type cleanupErrorFile struct {
	*os.File
	fail  bool
	calls int
}

func (file *cleanupErrorFile) Close() error {
	file.calls++
	err := file.File.Close()
	if file.fail {
		return errors.Join(err, errors.New("private provider /keyfile close failure"))
	}
	return err
}

// The real descriptor closes even when its provider reports failure. The
// operation must retain that cleanup uncertainty after consuming the factors.
func TestOperationsRetainKeyfileCleanupTruthWithoutOutput(t *testing.T) {
	tests := []struct {
		name           string
		write          WriteMode
		read           Mode
		early          bool
		cancelled      bool
		policyMismatch bool
	}{
		{name: "write-normal", write: WriteModeNormal},
		{name: "write-d1", write: WriteModeD1},
		{name: "read-normal", read: ModeReadNormal},
		{name: "recover-normal", read: ModeRecoverNormal},
		{name: "read-d1", read: ModeReadD1},
		{name: "recover-d1", read: ModeRecoverD1},
		{name: "read-policy-rejection", read: ModeReadNormal, policyMismatch: true},
		{name: "read-routing-rejection", read: ModeReadNormal, early: true},
		{name: "d1-bootstrap-rejection", read: ModeReadD1, early: true},
		{name: "cancelled-read", read: ModeReadNormal, cancelled: true},
	}
	for _, test := range tests {
		for _, fail := range []bool{false, true} {
			name := "successful-close"
			if fail {
				name = "failed-close"
			}
			t.Run(test.name+"/"+name, func(t *testing.T) {
				directory := t.TempDir()
				sourcePath := filepath.Join(directory, "source")
				sourceBytes := []byte("original source")
				d1 := test.read == ModeReadD1 || test.read == ModeRecoverD1
				if test.read != 0 && !test.early {
					fixture := "internal/pcv3/testdata/normal/volumes/normal-standard-keyfiles-only-small.pcv"
					if d1 {
						fixture = "internal/pcv3/testdata/d1/independent/d1.pcv"
					}
					var err error
					sourceBytes, err = os.ReadFile(fixture)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err := os.WriteFile(sourcePath, sourceBytes, 0o600); err != nil {
					t.Fatal(err)
				}
				source, err := os.Open(sourcePath)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				keyPath := filepath.Join(directory, "factor")
				if err := os.WriteFile(keyPath, []byte("owned keyfile bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
				key, err := os.Open(keyPath)
				if err != nil {
					t.Fatal(err)
				}
				wrapped := &cleanupErrorFile{File: key, fail: fail}
				factors := &FactorRequest{Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeUnordered, ExpectedPolicy: FactorPolicyKeyfilesOnly, Keyfiles: []*KeyfileReader{OwnKeyfileReader(wrapped)}}
				var password []byte
				if d1 {
					password = []byte("owned password")
					factors.Mode, factors.KeyfileMode, factors.ExpectedPolicy = CredentialModePasswordAndKeyfiles, KeyfileModeOrdered, FactorPolicyPasswordAndKeyfiles
					factors.Password = password
				}
				if test.read != 0 && !test.early {
					factors.KeyfileMode = KeyfileModeOrdered
					// Frozen read fixtures pin two factors. The control stops before KDF.
					secondPath := filepath.Join(directory, "second-factor")
					if err := os.WriteFile(secondPath, []byte("second factor"), 0o600); err != nil {
						t.Fatal(err)
					}
					second, err := os.Open(secondPath)
					if err != nil {
						t.Fatal(err)
					}
					factors.Keyfiles = append(factors.Keyfiles, OwnKeyfileReader(second))
					defer func() {
						if _, err := second.Stat(); !errors.Is(err, os.ErrClosed) {
							t.Errorf("second real keyfile remains open: %v", err)
						}
					}()
				}
				if test.policyMismatch {
					factors.ExpectedPolicy = FactorPolicyPasswordOnly
				}
				target := filepath.Join(directory, "output")
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				reachedResourceCheck := false
				reporter := func(status Status) error {
					// Cancellation after facade validation exercises native early Close.
					if test.cancelled && status.Code() == StatusAuthenticating {
						cancel()
					}
					if status.Code() == StatusCheckingResources {
						reachedResourceCheck = true
						return errors.New("stop before admission and KDF")
					}
					return nil
				}
				var result *Result
				if test.write != 0 {
					suite := SuiteStandard
					if test.write == WriteModeD1 {
						suite = SuiteParanoid
					}
					result = RunWrite(ctx, &WriteRequest{Mode: test.write, Suite: suite, PayloadKind: PayloadKindRaw, PlaintextLength: uint64(len(sourceBytes)), Source: source, SourceFile: source, SourcePath: sourcePath, Target: target, Factors: factors, Reporter: reporter})
					if _, err := source.Stat(); err != nil {
						t.Errorf("borrowed write source closed: %v", err)
					}
				} else {
					result = Run(ctx, &Request{Mode: test.read, Source: source, Factors: factors, Target: target, Reporter: reporter})
					if _, err := source.Stat(); !errors.Is(err, os.ErrClosed) {
						t.Errorf("owned read source not closed: %v", err)
					}
				}
				if wrapped.calls != 1 {
					t.Errorf("keyfile close calls = %d; want one", wrapped.calls)
				}
				if _, err := key.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Errorf("real keyfile descriptor remains open: %v", err)
				}
				wantResourceCheck := !fail && !test.early && !test.cancelled && !test.policyMismatch
				if reachedResourceCheck != wantResourceCheck {
					t.Errorf("resource checkpoint = %v; want %v", reachedResourceCheck, wantResourceCheck)
				}
				if got := slices.Contains(result.Warnings(), WarningCleanupIncomplete); got != fail {
					t.Errorf("cleanup warning = %v; want %v; result=%v stage=%v warnings=%v", got, fail, result, result.Stage(), result.Warnings())
				}
				if result.SourceDeletionAllowed() || result.PublicationAttempted() || result.OutputFollowUp() != nil || result.ArchiveFollowUp() != nil {
					t.Error("failed operation granted output/deletion authority")
				}
				if test.cancelled && (result.Stage() != StageCancellation || !errors.Is(result, context.Canceled)) {
					t.Errorf("lost cancellation semantics: %v", result)
				}
				if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("unexpected output: %v", err)
				}
				got, err := os.ReadFile(sourcePath)
				if err != nil || !slices.Equal(got, sourceBytes) {
					t.Error("original source changed")
				}
				got, err = os.ReadFile(keyPath)
				if err != nil || string(got) != "owned keyfile bytes" {
					t.Error("original keyfile changed")
				}
				for _, value := range password {
					if value != 0 {
						t.Error("owned password retained")
						break
					}
				}
				formatted := fmt.Sprintf("%v %#v", result, result)
				if strings.Contains(formatted, "private provider") || strings.Contains(formatted, "/keyfile") {
					t.Errorf("public formatting exposed provider error: %q", formatted)
				}
				entries, err := os.ReadDir(directory)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if entry.Name() != "source" && entry.Name() != "factor" && entry.Name() != "second-factor" {
						t.Errorf("left private output/stage: %s", entry.Name())
					}
				}
			})
		}
	}
}
