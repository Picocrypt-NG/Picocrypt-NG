//go:build linux || android

package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const operationPrivateStageJournalName = ".picocrypt-pcv3-stage.journal"

type operationJournalSentinel struct {
	path  string
	info  os.FileInfo
	bytes []byte
}

func TestJournalPrivateStageOptionReachesOrdinaryReadRoute(t *testing.T) {
	directory := t.TempDir()
	journal := seedOperationJournalSentinel(t, directory, "ordinary route foreign journal")
	target := filepath.Join(directory, "must-not-publish.bin")
	source := openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
	factors, password, keyfiles := newOperationJournalCombinedFactors(t)
	admitter := &operationTestAdmitter{grant: true}
	request := &Request{
		Mode:    ModeReadNormal,
		Source:  source,
		Factors: factors,
		Target:  target,
	}

	result := runWithSeamsAndOptions(
		context.Background(),
		request,
		operationSeams{admitter: admitter},
		ExecutionOptions{RetainDurableOutput: true, JournalPrivateStage: true},
	)
	defer discardUnexpectedJournalRouteOutput(result)

	if result == nil || !errors.Is(result, pcv3publication.ErrCleanupIncomplete) ||
		result.OutputFollowUp() != nil {
		entries, _ := os.ReadDir(directory)
		t.Fatalf(
			"ordinary journal route = %#v outcome=%v stage=%v attempted=%v state=%v warnings=%v cleanup=%v follow-up-live=%v entries=%v; want fail-closed cleanup uncertainty",
			result, result.Outcome(), result.Stage(), result.PublicationAttempted(),
			result.PublicationState(), result.Warnings(),
			errors.Is(result, pcv3publication.ErrCleanupIncomplete),
			result.OutputFollowUp() != nil, entries,
		)
	}
	if admitter.calls != 1 {
		t.Fatalf("ordinary journal route KDF admissions = %d; want one authenticated route", admitter.calls)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ordinary journal route published plaintext: %v", err)
	}
	assertOperationJournalSentinel(t, journal)
	requireNoOperationJournalStageResidue(t, directory)
	assertOperationRequestTransferred(t, request)
	assertOperationPasswordZero(t, password)
	assertOperationKeyfilesClosedOnce(t, keyfiles)
	assertOperationFileClosed(t, source)
}

func TestJournalPrivateStageOptionReachesSharedRecoveryRoute(t *testing.T) {
	directory := t.TempDir()
	journal := seedOperationJournalSentinel(t, directory, "shared recovery foreign journal")
	target := filepath.Join(directory, "must-not-publish.pcv3-recovery")
	source := openOperationNormalFixture(t, "normal-negative-record.pcv")
	factors, password, keyfiles := newOperationJournalCombinedFactors(t)
	admitter := &operationTestAdmitter{grant: true}
	request := &Request{
		Mode:    ModeForceNormal,
		Source:  source,
		Factors: factors,
		Target:  target,
	}

	result := runWithSeamsAndOptions(
		context.Background(),
		request,
		operationSeams{admitter: admitter},
		ExecutionOptions{RetainDurableOutput: true, JournalPrivateStage: true},
	)
	defer discardUnexpectedJournalRouteOutput(result)

	if result == nil {
		t.Fatal("shared recovery journal route returned no closed result")
	}
	if !result.PublicationAttempted() ||
		result.PublicationState() != pcv3publication.StateNotPublished ||
		!errors.Is(result, pcv3publication.ErrCleanupIncomplete) ||
		result.OutputFollowUp() != nil {
		t.Fatalf(
			"shared recovery journal route = %#v attempted=%v state=%v cleanup=%v follow-up=%v; want fail-closed not-published cleanup uncertainty",
			result, result.PublicationAttempted(), result.PublicationState(),
			errors.Is(result, pcv3publication.ErrCleanupIncomplete), result.OutputFollowUp(),
		)
	}
	if admitter.calls != 1 {
		t.Fatalf("shared recovery journal route KDF admissions = %d; want one authenticated route", admitter.calls)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("shared recovery journal route published an artifact: %v", err)
	}
	assertOperationJournalSentinel(t, journal)
	requireNoOperationJournalStageResidue(t, directory)
	assertOperationRequestTransferred(t, request)
	assertOperationPasswordZero(t, password)
	assertOperationKeyfilesClosedOnce(t, keyfiles)
	assertOperationFileClosed(t, source)
}

func TestJournalPrivateStageOptionReachesUnverifiedRecoveryRoute(t *testing.T) {
	directory := t.TempDir()
	journal := seedOperationJournalSentinel(t, directory, "unverified route foreign journal")
	target := filepath.Join(directory, "must-not-publish.pcv3-recovery")
	source := openOperationNormalFixture(t, "normal-negative-record.pcv")
	factors, password, keyfiles := newOperationJournalCombinedFactors(t)
	admitter := &operationTestAdmitter{grant: true}
	consentCalls := 0
	request := &Request{
		Mode:    ModeForceUnverifiedNormal,
		Source:  source,
		Factors: factors,
		Target:  target,
		Consent: func(_ ConsentRequest, action ConsentAction) error {
			consentCalls++
			return action(RolePrimary)
		},
	}

	result := runWithSeamsAndOptions(
		context.Background(),
		request,
		operationSeams{admitter: admitter},
		ExecutionOptions{RetainDurableOutput: true, JournalPrivateStage: true},
	)
	defer discardUnexpectedJournalRouteOutput(result)

	if result == nil || !result.PublicationAttempted() ||
		result.PublicationState() != pcv3publication.StateNotPublished ||
		!errors.Is(result, pcv3publication.ErrCleanupIncomplete) ||
		result.OutputFollowUp() != nil {
		t.Fatalf(
			"unverified journal route = %#v attempted=%v state=%v cleanup=%v follow-up=%v; want fail-closed not-published cleanup uncertainty",
			result, result.PublicationAttempted(), result.PublicationState(),
			errors.Is(result, pcv3publication.ErrCleanupIncomplete), result.OutputFollowUp(),
		)
	}
	if consentCalls != 1 || admitter.calls != 1 {
		t.Fatalf("unverified journal route calls = consent %d KDF %d; want one selected authenticated route", consentCalls, admitter.calls)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unverified journal route published plaintext: %v", err)
	}
	assertOperationJournalSentinel(t, journal)
	requireNoOperationJournalStageResidue(t, directory)
	assertOperationRequestTransferred(t, request)
	assertOperationPasswordZero(t, password)
	assertOperationKeyfilesClosedOnce(t, keyfiles)
	assertOperationFileClosed(t, source)
}

func newOperationJournalCombinedFactors(
	t *testing.T,
) (*pcv3credential.FactorRequest, []byte, []*operationObservedReadCloser) {
	t.Helper()
	password := []byte("mix")
	keyfiles := []*operationObservedReadCloser{
		newOperationObservedKeyfile(t, []byte("red")),
		newOperationObservedKeyfile(t, []byte("blue")),
	}
	return &pcv3credential.FactorRequest{
		Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
		KeyfileMode:    pcv3credential.KeyfileModeOrdered,
		ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
		Password:       password,
		Keyfiles:       operationKeyfileHandles(keyfiles),
	}, password, keyfiles
}

func seedOperationJournalSentinel(t *testing.T, directory, contents string) operationJournalSentinel {
	t.Helper()
	path := filepath.Join(directory, operationPrivateStageJournalName)
	data := []byte(contents)
	if err := os.WriteFile(path, data, 0o640); err != nil {
		t.Fatalf("seed operation foreign journal: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("stat operation foreign journal: %v", err)
	}
	return operationJournalSentinel{path: path, info: info, bytes: data}
}

func assertOperationJournalSentinel(t *testing.T, sentinel operationJournalSentinel) {
	t.Helper()
	info, err := os.Lstat(sentinel.path)
	if err != nil {
		t.Fatalf("stat preserved operation foreign journal: %v", err)
	}
	data, err := os.ReadFile(sentinel.path)
	if err != nil || !bytes.Equal(data, sentinel.bytes) || !os.SameFile(sentinel.info, info) ||
		info.Mode().Perm() != sentinel.info.Mode().Perm() {
		t.Fatalf(
			"operation foreign journal changed: bytes=%q error=%v same-inode=%v mode=%o",
			data, err, os.SameFile(sentinel.info, info), info.Mode().Perm(),
		)
	}
}

func requireNoOperationJournalStageResidue(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read operation journal directory: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != operationPrivateStageJournalName &&
			strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
			t.Fatalf("operation route left private stage residue: %q", entry.Name())
		}
	}
}

func discardUnexpectedJournalRouteOutput(result *Result) {
	if result == nil {
		return
	}
	if followUp := result.OutputFollowUp(); followUp != nil {
		_ = followUp.Discard()
	}
}
