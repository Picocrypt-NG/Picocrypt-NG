//go:build pcv3_production_kdf

package pcv3recovery

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The admission seam grants the fixed production profile. Encryption, both D1
// credential domains, authentication, stage custody, and extraction are real.
func TestD1ArchiveProductionKDFRawZIPRequiresExplicitPreparation(t *testing.T) {
	directory := t.TempDir()
	plaintext := recoveryArchiveBytes(t)
	sourcePath := filepath.Join(directory, "zip-source")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	factors := func() *pcv3credential.FactorRequest {
		return &pcv3credential.FactorRequest{
			Mode:           pcv3credential.CredentialModePasswordOnly,
			KeyfileMode:    pcv3credential.KeyfileModeNone,
			ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly,
			Password:       []byte("D1 archive custody production regression"),
		}
	}
	ciphertext := filepath.Join(directory, "d1-ciphertext")
	publication, retained, err := pcv3.RunNativeD1WriteWithPublication(context.Background(), &pcv3.NativeD1WriteRequest{
		Suite: pcv3.SuiteParanoid, PayloadKind: pcv3.PayloadKindRaw,
		PlaintextLength: uint64(len(plaintext)), SourcePath: sourcePath, Source: source,
		Plaintext: source, DestinationPath: ciphertext, Protected: []string{sourcePath},
		Factors: factors(), Admitter: recoveryOperationAdmitter{},
	}, false)
	if err != nil || publication == nil || publication.State() != pcv3publication.StatePublishedDurable || retained != nil {
		if retained != nil {
			_ = retained.Close()
		}
		t.Fatalf("D1 archive creation publication=%v retained=%v err=%v", publication, retained, err)
	}
	for _, prepare := range []bool{false, true} {
		t.Run(map[bool]string{false: "default durable ZIP", true: "explicit extraction"}[prepare], func(t *testing.T) {
			encrypted, err := os.Open(ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			defer encrypted.Close()
			info, err := encrypted.Stat()
			if err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "manual-name-without-zip-extension")
			result := RunD1WithOptions(context.Background(), &Request{
				Source: encrypted, SourceSize: info.Size(), Factors: factors(),
				Admitter: recoveryOperationAdmitter{}, Mode: pcv3.RecoveryModeNormalV3,
				Target: target, Protected: []string{ciphertext},
			}, ExecutionOptions{PrepareArchive: prepare})
			if result.Outcome() != pcv3.OutcomeSuccess || result.Stage() != pcv3.StageNone || result.Code() != pcv3.CodeSuccess {
				t.Fatalf("D1 archive authentication = %v/%v/%v", result.Outcome(), result.Stage(), result.Code())
			}
			handoff := result.TakeArchiveHandoff()
			if !prepare {
				if handoff != nil || result.PublicationState() != pcv3publication.StatePublishedDurable {
					t.Fatal("default D1 ZIP behavior changed")
				}
				assertFileBytesAndMode(t, target, plaintext, 0o600)
				return
			}
			if handoff == nil || result.PublicationAttempted() {
				t.Fatal("explicit preparation did not retain unpublished archive")
			}
			defer handoff.Close()
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("D1 ZIP published before extraction: %v", err)
			}
			extractDir := t.TempDir()
			root, err := os.OpenRoot(extractDir)
			if err != nil {
				t.Fatal(err)
			}
			extraction := handoff.Extract(context.Background(), root)
			if extraction == nil || extraction.State() != fileops.UnpackStatePublishedDurable || extraction.CleanupIncomplete() {
				t.Fatalf("production D1 extraction=%v", extraction)
			}
			assertFileBytesAndMode(t, filepath.Join(extractDir, "payload.txt"), []byte("authenticated archive contents\n"), 0o600)
			assertNoRecoveryStageResidue(t, filepath.Dir(target))
		})
	}
	assertFileBytesAndMode(t, sourcePath, plaintext, 0o600)
}
