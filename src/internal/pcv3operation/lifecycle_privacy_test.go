package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/pcv3resource"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"
)

// phase9PrivacyAdmitter records every admission call with the exact profile,
// the caller context cancellation state, and the returned decision. An
// optional delegate supplies the production platform decision; otherwise the
// scripted admission is returned. It never alters the fixed profile.
type phase9PrivacyAdmitter struct {
	calls     int
	profiles  []pcv3credential.KDFProfile
	cancelled []bool
	decisions []pcv3credential.KDFAdmission
	admission pcv3credential.KDFAdmission
	delegate  pcv3credential.Admitter
}

func (admitter *phase9PrivacyAdmitter) AdmitKDF(
	ctx context.Context,
	profile pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	admitter.calls++
	admitter.profiles = append(admitter.profiles, profile)
	admitter.cancelled = append(admitter.cancelled, ctx != nil && ctx.Err() != nil)
	var decision pcv3credential.KDFAdmission
	var err error
	if admitter.delegate != nil {
		decision, err = admitter.delegate.AdmitKDF(ctx, profile)
	} else {
		decision = admitter.admission
	}
	admitter.decisions = append(admitter.decisions, decision)
	return decision, err
}

// phase9PrivacyWant is the exact closed terminal tuple plus publication axes
// one operation case must produce.
type phase9PrivacyWant struct {
	outcome              pcv3.Outcome
	stage                pcv3.Stage
	code                 pcv3.Code
	diagnostic           Diagnostic
	class                CompletionClass
	warnings             []Warning
	publicationAttempted bool
	publicationState     pcv3publication.State
	publicationStage     pcv3.Stage
	publicationCode      pcv3publication.Code
}

func phase9PrivacyRequireResult(t *testing.T, result *Result, want phase9PrivacyWant) {
	t.Helper()
	if result == nil {
		t.Fatal("operation returned no closed result")
	}
	if result.Outcome() != want.outcome || result.Stage() != want.stage ||
		result.Code() != want.code || result.Diagnostic() != want.diagnostic ||
		result.CompletionClass() != want.class {
		t.Fatalf(
			"terminal tuple = %v/%v/%v diagnostic=%v class=%v; want %v/%v/%v diagnostic=%v class=%v",
			result.Outcome(), result.Stage(), result.Code(), result.Diagnostic(), result.CompletionClass(),
			want.outcome, want.stage, want.code, want.diagnostic, want.class,
		)
	}
	if !slices.Equal(result.Warnings(), want.warnings) {
		t.Fatalf("warnings = %v; want %v", result.Warnings(), want.warnings)
	}
	if result.PublicationAttempted() != want.publicationAttempted ||
		result.PublicationState() != want.publicationState ||
		result.PublicationStage() != want.publicationStage ||
		result.PublicationCode() != want.publicationCode {
		t.Fatalf(
			"publication = %v/%v/%v/%v; want %v/%v/%v/%v",
			result.PublicationAttempted(), result.PublicationState(),
			result.PublicationStage(), result.PublicationCode(),
			want.publicationAttempted, want.publicationState,
			want.publicationStage, want.publicationCode,
		)
	}
}

func phase9PrivacyRequireNoCapability(t *testing.T, result *Result) {
	t.Helper()
	if result.ArchiveFollowUp() != nil || result.OutputFollowUp() != nil ||
		result.ArtifactInspection() != nil {
		t.Fatal("terminal result retained a live output capability")
	}
}

// phase9PrivacyRun executes one operation through the same-package production
// seam with log/stdout/stderr capture for the privacy scan.
func phase9PrivacyRun(
	t *testing.T,
	run *phase9LifecycleRun,
	admitter pcv3credential.Admitter,
) (result *Result, stdout, stderr, logBytes []byte) {
	t.Helper()
	var logBuffer bytes.Buffer
	originalLogOutput := log.Writer()
	originalLogFlags := log.Flags()
	log.SetOutput(&logBuffer)
	defer func() {
		log.SetOutput(originalLogOutput)
		log.SetFlags(originalLogFlags)
	}()
	stdout, stderr = phase9CaptureProcess(t, func() {
		result = runWithSeams(run.ctx, run.request, operationSeams{admitter: admitter})
	})
	return result, stdout, stderr, logBuffer.Bytes()
}

// phase9PrivacyFinish proves ownership transfer, post-close zeroing, and the
// absence of every registered sentinel from every captured channel.
func phase9PrivacyFinish(
	t *testing.T,
	run *phase9LifecycleRun,
	result *Result,
	stdout, stderr, logBytes []byte,
) {
	t.Helper()
	assertOperationRequestTransferred(t, run.request)
	if run.request.Migration != nil {
		t.Fatal("operation request retained the transferred migration owner")
	}
	phase9AssertZeroed(t, run)
	phase9ScanChannels(t, run, result, stdout, stderr, logBytes)
}

// phase9PrivacyRequireLive proves the retained password aliases hold non-zero
// content before ownership transfers (the zeroing oracle is not vacuous).
func phase9PrivacyRequireLive(t *testing.T, run *phase9LifecycleRun) {
	t.Helper()
	for _, sentinel := range run.passwords {
		live := false
		for _, value := range sentinel.value {
			if value != 0 {
				live = true
				break
			}
		}
		if !live {
			t.Fatalf("password alias %s was not live before transfer", sentinel.id)
		}
	}
}

// phase9PrivacyCombinedFactors builds the frozen combined credential shape
// (password plus ordered "red"/"blue" public fixture keyfiles) with observed
// keyfile descriptors for exact close counting.
func phase9PrivacyCombinedFactors(
	t *testing.T,
	run *phase9LifecycleRun,
	password []byte,
	passwordID string,
) *pcv3credential.FactorRequest {
	t.Helper()
	run.passwords = append(run.passwords, phase9Sentinel{id: passwordID, value: password})
	run.keyfiles = []*operationObservedReadCloser{
		newOperationObservedKeyfile(t, []byte("red")),
		newOperationObservedKeyfile(t, []byte("blue")),
	}
	return &pcv3credential.FactorRequest{
		Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
		KeyfileMode:    pcv3credential.KeyfileModeOrdered,
		ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
		Password:       password,
		Keyfiles:       operationKeyfileHandles(run.keyfiles),
	}
}

// phase9FrozenPlaintext returns one frozen public plaintext, bound to the
// independently frozen manifest SHA-256 literal.
func phase9FrozenPlaintext(t *testing.T, name, wantSHA256 string) []byte {
	t.Helper()
	plaintext, err := os.ReadFile(filepath.Join(
		"..", "pcv3", "testdata", "normal", "plaintext", name,
	))
	if err != nil {
		t.Fatalf("read frozen plaintext %s: %v", name, err)
	}
	digest := sha256.Sum256(plaintext)
	if hex.EncodeToString(digest[:]) != wantSHA256 {
		t.Fatalf("frozen plaintext %s drifted from the manifest literal", name)
	}
	return plaintext
}

func phase9PrivacyRequireDirNames(t *testing.T, directory string, want []string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("inspect operation directory: %v", err)
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	slices.Sort(names)
	if !slices.Equal(names, want) {
		t.Fatalf("operation directory entries = %v; want exactly %v", names, want)
	}
}

func phase9PrivacyRequireTargetBytes(t *testing.T, target string, want []byte) {
	t.Helper()
	contents, err := os.ReadFile(target) // #nosec G304 -- test-owned output path
	if err != nil {
		t.Fatalf("read published output: %v", err)
	}
	if !bytes.Equal(contents, want) {
		t.Fatalf("published bytes = %x; want exact frozen plaintext", contents)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("inspect published output: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("published output mode = %v; want regular 0600", info.Mode())
	}
}

func phase9PrivacyWaitResult(t *testing.T, channel <-chan *Result, name string) *Result {
	t.Helper()
	select {
	case result := <-channel:
		return result
	case <-time.After(120 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return nil
	}
}

func phase9PrivacyWaitError(t *testing.T, channel <-chan error, name string) error {
	t.Helper()
	select {
	case err := <-channel:
		return err
	case <-time.After(120 * time.Second):
		t.Fatalf("timed out waiting for %s", name)
		return nil
	}
}

func phase9PrivacyRequireRootClosed(t *testing.T, root *os.Root, name string) {
	t.Helper()
	if _, err := root.Stat("."); err == nil {
		t.Fatalf("%s extraction root remained open", name)
	}
}

// phase9PrivacyRequireCleanSuccess pins the complete battery for one actual
// completed normal read over the frozen one-byte production-vector volume. The
// target path must be captured before ownership transfer clears the request.
func phase9PrivacyRequireCleanSuccess(
	t *testing.T,
	run *phase9LifecycleRun,
	result *Result,
	admitter *phase9PrivacyAdmitter,
	plaintext []byte,
	target string,
) {
	t.Helper()
	phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
		outcome:              pcv3.OutcomeSuccess,
		stage:                pcv3.StageNone,
		code:                 pcv3.CodeSuccess,
		diagnostic:           DiagnosticNone,
		class:                CompletionClean,
		publicationAttempted: true,
		publicationState:     pcv3publication.StatePublishedDurable,
		publicationStage:     pcv3.StageNone,
		publicationCode:      pcv3publication.CodePublishedDurable,
	})
	phase9PrivacyRequireNoCapability(t, result)
	if !slices.Equal(run.statuses, []StatusCode{
		StatusCheckingRequest,
		StatusCheckingFactors,
		StatusAuthenticating,
		StatusCheckingResources,
		StatusDerivingKey,
	}) {
		t.Fatalf("clean success status sequence = %v; want exact reached boundaries", run.statuses)
	}
	if admitter.calls != 1 || len(admitter.profiles) != 1 ||
		admitter.profiles[0] != phase9Standard1Profile {
		t.Fatalf(
			"clean success admissions = %d profiles %+v; want exactly one fixed-profile admission",
			admitter.calls, admitter.profiles,
		)
	}
	if len(admitter.decisions) != 1 || admitter.decisions[0] != pcv3credential.KDFAdmissionGranted {
		t.Fatalf("clean success admission decisions = %v; want one grant", admitter.decisions)
	}
	phase9PrivacyRequireTargetBytes(t, target, plaintext)
	phase9PrivacyRequireDirNames(t, run.outputDir, []string{filepath.Base(target)})
}

// TestPhase9OperationLifecyclePrivacyMatrix runs actual completed operations
// through the production operation/resource/credential/publication composition
// and pins, per case, the exact closed tuple, status sequence, fixed-profile
// admission behavior, ownership transfer, post-close zeroing, capability
// absence, and the absence of every sentinel from every captured channel.
// Injected observers only record effects; they never replace the production
// owner, KDF schedule, codec, publisher, or frontend adapter.
func TestPhase9OperationLifecyclePrivacyMatrix(t *testing.T) {
	oneBytePlaintext := phase9FrozenPlaintext(
		t,
		"normal-standard-combined-ordered-one.bin",
		"dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986",
	)
	degradedPlaintext := phase9FrozenPlaintext(
		t,
		"normal-degraded-capsule.bin",
		"abe4ee7a105042f73b12b1f1a28788522d2f253445a475a94ab4d6e1f7b0ec52",
	)

	t.Run("normal read publishes exact plaintext through one fixed-profile derivation", func(t *testing.T) {
		run := phase9BaseRun(t, "normal")
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		run.source = openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
		run.request.Mode = ModeReadNormal
		run.request.Source = run.source
		run.request.Factors = phase9PrivacyCombinedFactors(t, run, []byte("mix"), "password-normal")
		phase9WireReporter(run)
		phase9PrivacyRequireLive(t, run)
		target := run.request.Target

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		phase9PrivacyRequireCleanSuccess(t, run, result, admitter, oneBytePlaintext, target)
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})

	t.Run("recovery publishes exact degraded plaintext with the exact warning", func(t *testing.T) {
		run := phase9BaseRun(t, "recovery")
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		run.source = openOperationNormalFixture(t, "normal-degraded-capsule.pcv")
		run.request.Mode = ModeRecoverNormal
		run.request.Source = run.source
		run.request.Factors = phase9PrivacyCombinedFactors(t, run, []byte("mix"), "password-recovery")
		phase9WireReporter(run)
		phase9PrivacyRequireLive(t, run)
		target := run.request.Target

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:              pcv3.OutcomeAuthenticatedDegraded,
			stage:                pcv3.StageCapsuleRS,
			code:                 pcv3.CodeAuthenticatedDegraded,
			diagnostic:           DiagnosticNone,
			class:                CompletionWarning,
			warnings:             []Warning{WarningAuthenticatedDegraded},
			publicationAttempted: true,
			publicationState:     pcv3publication.StatePublishedDurable,
			publicationStage:     pcv3.StageNone,
			publicationCode:      pcv3publication.CodePublishedDurable,
		})
		phase9PrivacyRequireNoCapability(t, result)
		if !slices.Equal(run.statuses, []StatusCode{
			StatusCheckingRequest,
			StatusCheckingFactors,
			StatusRecovering,
			StatusCheckingResources,
			StatusDerivingKey,
		}) {
			t.Fatalf("degraded recovery status sequence = %v; want exact reached boundaries", run.statuses)
		}
		if admitter.calls != 1 || admitter.profiles[0] != phase9Standard1Profile {
			t.Fatalf("degraded recovery admissions = %d; want one fixed-profile admission", admitter.calls)
		}
		phase9PrivacyRequireTargetBytes(t, target, degradedPlaintext)
		phase9PrivacyRequireDirNames(t, run.outputDir, []string{filepath.Base(target)})
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})

	t.Run("force recovery publishes the partial artifact with exact ranges authority", func(t *testing.T) {
		run := phase9BaseRun(t, "force")
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		run.source = openOperationNormalFixture(t, "normal-negative-record.pcv")
		run.request.Mode = ModeForceNormal
		run.request.Source = run.source
		run.request.Factors = phase9PrivacyCombinedFactors(t, run, []byte("mix"), "password-force")
		phase9WireReporter(run)
		phase9PrivacyRequireLive(t, run)
		target := run.request.Target

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:              pcv3.OutcomeForcePartial,
			stage:                pcv3.StageRecordAuth,
			code:                 pcv3.CodeForcePartial,
			diagnostic:           DiagnosticNone,
			class:                CompletionWarning,
			warnings:             []Warning{WarningForcePartial},
			publicationAttempted: true,
			publicationState:     pcv3publication.StatePublishedDurable,
			publicationStage:     pcv3.StageNone,
			publicationCode:      pcv3publication.CodePublishedDurable,
		})
		if result.ForceProvenance() != pcv3.ForceProvenancePartial {
			t.Fatalf("force provenance = %v; want partial", result.ForceProvenance())
		}
		if result.ArtifactInspection() == nil {
			t.Fatal("verified Force recovery granted no artifact inspection authority")
		}
		if result.ArchiveFollowUp() != nil || result.OutputFollowUp() != nil {
			t.Fatal("verified Force recovery retained archive or output authority")
		}
		if !slices.Equal(run.statuses, []StatusCode{
			StatusCheckingRequest,
			StatusCheckingFactors,
			StatusRecovering,
			StatusCheckingResources,
			StatusDerivingKey,
		}) {
			t.Fatalf("force status sequence = %v; want exact reached boundaries", run.statuses)
		}
		if admitter.calls != 1 || admitter.profiles[0] != phase9Standard1Profile {
			t.Fatalf("force admissions = %d; want one fixed-profile admission", admitter.calls)
		}
		info, err := os.Lstat(target)
		if err != nil || info.Size() != 120 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("force artifact = %v size %d mode %v; want 120-byte regular 0600 artifact", err, info.Size(), info.Mode())
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, []string{filepath.Base(target)})
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})

	t.Run("unverified D1 consent selects the front role and fails closed at bootstrap without admission", func(t *testing.T) {
		run := phase9BaseRun(t, "d1")
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		run.source = newOperationEmptySource(t)
		run.request.Mode = ModeForceUnverifiedD1
		run.request.Source = run.source
		run.request.Factors = phase9PasswordFactors(run, "password-d1")
		phase9WireReporter(run)
		run.request.Consent = func(request ConsentRequest, action ConsentAction) error {
			run.consentCalls++
			if request.Mode() != ModeForceUnverifiedD1 {
				return errors.New("consent mode mismatch")
			}
			if !slices.Equal(request.AllowedRoles(), []PhysicalRole{RoleD1Front, RoleD1Tail}) {
				return errors.New("consent role set mismatch")
			}
			run.retainedAction = action
			return action(RoleD1Front)
		}
		phase9PrivacyRequireLive(t, run)

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:    pcv3.OutcomeCredentialsOrDamage,
			stage:      pcv3.StageD1Bootstrap,
			code:       pcv3.CodeCredentialsOrDamage,
			diagnostic: DiagnosticNone,
			class:      CompletionNoOutput,
		})
		phase9PrivacyRequireNoCapability(t, result)
		if !slices.Equal(run.statuses, []StatusCode{
			StatusCheckingRequest,
			StatusCheckingFactors,
			StatusRecovering,
		}) {
			t.Fatalf("D1 consent status sequence = %v; want exact reached boundaries", run.statuses)
		}
		if admitter.calls != 0 || run.consentCalls != 1 {
			t.Fatalf("D1 bootstrap admissions = %d consent calls = %d; want 0/1", admitter.calls, run.consentCalls)
		}
		if !errors.Is(run.retainedAction(RoleD1Front), ErrConsentExpired) {
			t.Fatal("used D1 consent action did not expire")
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, nil)
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})

	t.Run("migration governance refusal keeps the frozen legacy KDF outside the PCV3 lease", func(t *testing.T) {
		run := phase9BaseRun(t, "migration")
		run.migrationActive = true
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		run.source = newOperationEmptySource(t)
		run.request.Mode = ModeMigrate
		run.request.Source = run.source
		run.request.Factors = phase9PasswordFactors(run, "password-migration-outer")
		phase9WireReporter(run)
		comment := phase9SentinelBytes("migration-comment")
		legacyPassword := phase9SentinelBytes("legacy-password")
		legacyKeyfilePath := "p9-life-legacy-keyfile-2c48aa"
		run.comment = comment
		run.legacyPassword = legacyPassword
		run.legacyKeyfiles = []string{legacyKeyfilePath}
		run.legacyRequest = &volume.DecryptRequest{
			InputFile: "p9-life-legacy-input-60f1bb",
			Password:  legacyPassword,
			Keyfiles:  run.legacyKeyfiles,
		}
		run.request.Migration = &MigrationRequest{
			Legacy:     run.legacyRequest,
			NewFactors: operationPasswordFactors(phase9SentinelBytes("password-migration-new")),
			Comment:    comment,
		}
		run.passwords = append(run.passwords, phase9Sentinel{
			id:    "password-migration-new",
			value: run.request.Migration.NewFactors.Password,
		})
		run.sentinels = append(run.sentinels,
			phase9Sentinel{id: "migration-comment", value: comment},
			phase9Sentinel{id: "legacy-password", value: legacyPassword},
			phase9Sentinel{id: "legacy-keyfile-path", value: []byte(legacyKeyfilePath)},
			phase9Sentinel{id: "legacy-input-path", value: []byte("p9-life-legacy-input-60f1bb")},
			phase9Sentinel{id: "password-migration-new", value: run.request.Migration.NewFactors.Password},
		)
		phase9PrivacyRequireLive(t, run)
		if !bytes.Equal(run.comment, phase9SentinelBytes("migration-comment")) ||
			!bytes.Equal(run.legacyPassword, phase9SentinelBytes("legacy-password")) {
			t.Fatal("migration sentinels were not live before transfer")
		}

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:    pcv3.OutcomeUnsupportedRoutingPreKDF,
			stage:      pcv3.StageRouting,
			code:       pcv3.CodeUnsupported,
			diagnostic: DiagnosticGovernanceRefusal,
			class:      CompletionRefused,
		})
		phase9PrivacyRequireNoCapability(t, result)
		if len(run.statuses) != 0 {
			t.Fatalf("migration refusal reported statuses %v; want none before effects", run.statuses)
		}
		if admitter.calls != 0 {
			t.Fatalf("migration admitted %d KDF derivations; the frozen legacy KDF must stay outside the PCV3 lease", admitter.calls)
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, nil)
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})

	t.Run("wrong credentials refuse after exactly one fixed-profile derivation with no output", func(t *testing.T) {
		run := phase9BaseRun(t, "wrong")
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		secret := phase9SentinelBytes("wrong-password")
		run.sentinels = append(run.sentinels, phase9Sentinel{id: "wrong-password", value: secret})
		run.source = openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
		run.request.Mode = ModeReadNormal
		run.request.Source = run.source
		run.request.Factors = phase9PrivacyCombinedFactors(t, run, secret, "wrong-password")
		phase9WireReporter(run)
		phase9PrivacyRequireLive(t, run)

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:    pcv3.OutcomeCredentialsOrDamage,
			stage:      pcv3.StageWrapAuth,
			code:       pcv3.CodeCredentialsOrDamage,
			diagnostic: DiagnosticNone,
			class:      CompletionNoOutput,
		})
		phase9PrivacyRequireNoCapability(t, result)
		if !slices.Equal(run.statuses, []StatusCode{
			StatusCheckingRequest,
			StatusCheckingFactors,
			StatusAuthenticating,
			StatusCheckingResources,
			StatusDerivingKey,
		}) {
			t.Fatalf("wrong-credential status sequence = %v; want exact reached boundaries", run.statuses)
		}
		if admitter.calls != 1 || admitter.profiles[0] != phase9Standard1Profile ||
			admitter.decisions[0] != pcv3credential.KDFAdmissionGranted {
			t.Fatalf("wrong-credential admissions = %d decisions %v; want one granted fixed-profile derivation", admitter.calls, admitter.decisions)
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, nil)
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})

	t.Run("cancellation at the resource boundary admits a cancelled context and derives nothing", func(t *testing.T) {
		run := phase9BaseRun(t, "cancel")
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		run.ctx = ctx
		run.source = openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
		run.request.Mode = ModeReadNormal
		run.request.Source = run.source
		run.request.Factors = phase9PrivacyCombinedFactors(t, run, []byte("mix"), "password-cancel")
		phase9WireReporter(run)
		wiredReporter := run.request.Reporter
		run.request.Reporter = func(status Status) error {
			if err := wiredReporter(status); err != nil {
				return err
			}
			if status.Code() == StatusCheckingResources {
				cancel()
			}
			return nil
		}
		phase9PrivacyRequireLive(t, run)

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:    pcv3.OutcomeOperationFailed,
			stage:      pcv3.StageCancellation,
			code:       pcv3.CodeOperationFailed,
			diagnostic: DiagnosticNone,
			class:      CompletionRefused,
		})
		phase9PrivacyRequireNoCapability(t, result)
		if !slices.Equal(run.statuses, []StatusCode{
			StatusCheckingRequest,
			StatusCheckingFactors,
			StatusAuthenticating,
			StatusCheckingResources,
			StatusDerivingKey,
		}) {
			t.Fatalf("resource-boundary cancellation status sequence = %v; want exact reached boundaries", run.statuses)
		}
		if admitter.calls != 1 || len(admitter.cancelled) != 1 || !admitter.cancelled[0] {
			t.Fatalf(
				"resource-boundary admissions = %d cancelled %v; want one admission that observed the cancelled context",
				admitter.calls, admitter.cancelled,
			)
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, nil)
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})

	t.Run("reporter panic at the authentication boundary is contained without disclosure", func(t *testing.T) {
		run := phase9BaseRun(t, "panic")
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		panicSentinel := phase9SentinelBytes("reporter-panic")
		run.sentinels = append(run.sentinels, phase9Sentinel{id: "reporter-panic", value: panicSentinel})
		run.source = openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
		run.request.Mode = ModeReadNormal
		run.request.Source = run.source
		run.request.Factors = phase9PrivacyCombinedFactors(t, run, []byte("mix"), "password-panic")
		phase9WireReporter(run)
		wiredReporter := run.request.Reporter
		run.request.Reporter = func(status Status) error {
			if err := wiredReporter(status); err != nil {
				return err
			}
			if status.Code() == StatusAuthenticating {
				panic(string(panicSentinel))
			}
			return nil
		}
		phase9PrivacyRequireLive(t, run)

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:    pcv3.OutcomeOperationFailed,
			stage:      pcv3.StageCredentialPolicy,
			code:       pcv3.CodeOperationFailed,
			diagnostic: DiagnosticCallbackPanic,
			class:      CompletionRefused,
			warnings:   []Warning{WarningCallbackFailure},
		})
		phase9PrivacyRequireNoCapability(t, result)
		if !slices.Equal(run.statuses, []StatusCode{
			StatusCheckingRequest,
			StatusCheckingFactors,
			StatusAuthenticating,
		}) {
			t.Fatalf("reporter panic status sequence = %v; want exact reached boundaries", run.statuses)
		}
		if admitter.calls != 0 {
			t.Fatalf("reporter panic reached %d admissions; want zero before the KDF boundary", admitter.calls)
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, nil)
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})

	t.Run("retry after resource refusal republishes the same target", func(t *testing.T) {
		run := phase9BaseRun(t, "retry")
		denying := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionDeniedInsufficient}
		run.source = openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
		run.request.Mode = ModeReadNormal
		run.request.Source = run.source
		run.request.Factors = phase9PrivacyCombinedFactors(t, run, []byte("mix"), "password-retry-first")
		phase9WireReporter(run)
		phase9PrivacyRequireLive(t, run)
		target := run.request.Target

		first, firstStdout, firstStderr, firstLog := phase9PrivacyRun(t, run, denying)
		phase9PrivacyRequireResult(t, first, phase9PrivacyWant{
			outcome:    pcv3.OutcomeOperationFailed,
			stage:      pcv3.StageCredentialPolicy,
			code:       pcv3.CodeOperationFailed,
			diagnostic: DiagnosticResourceInsufficient,
			class:      CompletionRefused,
		})
		phase9PrivacyRequireNoCapability(t, first)
		if denying.calls != 1 || denying.decisions[0] != pcv3credential.KDFAdmissionDeniedInsufficient {
			t.Fatalf("refused attempt admissions = %d decisions %v; want one insufficiency refusal", denying.calls, denying.decisions)
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, nil)
		phase9PrivacyFinish(t, run, first, firstStdout, firstStderr, firstLog)

		retry := phase9BaseRun(t, "retry-second")
		granting := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		retry.outputDir = run.outputDir
		retry.request.Target = target
		retry.source = openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
		retry.request.Mode = ModeReadNormal
		retry.request.Source = retry.source
		retry.request.Factors = phase9PrivacyCombinedFactors(t, retry, []byte("mix"), "password-retry-second")
		phase9WireReporter(retry)
		phase9PrivacyRequireLive(t, retry)

		second, secondStdout, secondStderr, secondLog := phase9PrivacyRun(t, retry, granting)
		phase9PrivacyRequireCleanSuccess(t, retry, second, granting, oneBytePlaintext, target)
		phase9PrivacyFinish(t, retry, second, secondStdout, secondStderr, secondLog)
	})

	t.Run("production platform admission records one fail-closed fixed-profile decision without derivation", func(t *testing.T) {
		run := phase9BaseRun(t, "production")
		admitter := &phase9PrivacyAdmitter{delegate: pcv3resource.NewPlatformAdmitter()}
		run.source = openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
		run.request.Mode = ModeReadNormal
		run.request.Source = run.source
		run.request.Factors = phase9PrivacyCombinedFactors(t, run, []byte("mix"), "password-production")
		phase9WireReporter(run)
		phase9PrivacyRequireLive(t, run)

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		// The real desktop provider reads /proc meminfo, the address-space
		// limit, the cgroup memory headroom, and the same-snapshot process
		// footprint. On this host the cgroup v2 root exposes no memory
		// controller files, so conservative native facts cannot establish a
		// safe admission and the provider must fail closed with exactly one
		// denied-unknown decision for the frozen fixed profile — never a
		// guess, never a derivation, never output.
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:    pcv3.OutcomeOperationFailed,
			stage:      pcv3.StageCredentialPolicy,
			code:       pcv3.CodeOperationFailed,
			diagnostic: DiagnosticResourceUnknown,
			class:      CompletionRefused,
		})
		phase9PrivacyRequireNoCapability(t, result)
		if !slices.Equal(run.statuses, []StatusCode{
			StatusCheckingRequest,
			StatusCheckingFactors,
			StatusAuthenticating,
			StatusCheckingResources,
		}) {
			t.Fatalf("production refusal status sequence = %v; want exact reached boundaries without DerivingKey", run.statuses)
		}
		if admitter.calls != 1 || len(admitter.profiles) != 1 ||
			admitter.profiles[0] != phase9Standard1Profile ||
			len(admitter.decisions) != 1 ||
			admitter.decisions[0] != pcv3credential.KDFAdmissionDeniedUnknown {
			t.Fatalf(
				"production admission = calls %d profiles %+v decisions %v; want one fail-closed denied-unknown decision on the frozen profile",
				admitter.calls, admitter.profiles, admitter.decisions,
			)
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, nil)
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})

	t.Run("expired consent action stays refused after the operation completes", func(t *testing.T) {
		run := phase9BaseRun(t, "expired-consent")
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		returned := make(chan struct{})
		actionErr := make(chan error, 1)
		run.source = newOperationEmptySource(t)
		run.request.Mode = ModeForceUnverifiedD1
		run.request.Source = run.source
		run.request.Factors = phase9PasswordFactors(run, "password-expired-consent")
		phase9WireReporter(run)
		run.request.Consent = func(_ ConsentRequest, action ConsentAction) error {
			run.consentCalls++
			run.retainedAction = action
			go func() {
				<-returned
				actionErr <- action(RoleD1Front)
			}()
			return nil
		}
		phase9PrivacyRequireLive(t, run)

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:    pcv3.OutcomeOperationFailed,
			stage:      pcv3.StageCredentialPolicy,
			code:       pcv3.CodeOperationFailed,
			diagnostic: DiagnosticCredentialPolicy,
			class:      CompletionRefused,
		})
		phase9PrivacyRequireNoCapability(t, result)
		if run.consentCalls != 1 || admitter.calls != 0 {
			t.Fatalf("expired-consent calls = %d admissions = %d; want 1/0", run.consentCalls, admitter.calls)
		}
		close(returned)
		if err := phase9PrivacyWaitError(t, actionErr, "expired consent action"); !errors.Is(err, ErrConsentExpired) {
			t.Fatalf("post-completion consent action = %v; want ErrConsentExpired", err)
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, nil)
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})

	t.Run("live consent action raced with cancellation returns one terminal result", func(t *testing.T) {
		run := phase9BaseRun(t, "raced-consent")
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		run.ctx = ctx
		entered := make(chan struct{})
		release := make(chan struct{})
		actionErr := make(chan error, 1)
		run.source = newOperationEmptySource(t)
		run.request.Mode = ModeForceUnverifiedNormal
		run.request.Source = run.source
		run.request.Factors = phase9PasswordFactors(run, "password-raced-consent")
		phase9WireReporter(run)
		wiredReporter := run.request.Reporter
		run.request.Reporter = func(status Status) error {
			if err := wiredReporter(status); err != nil {
				return err
			}
			if status.Code() == StatusRecovering {
				close(entered)
				<-release
			}
			return nil
		}
		run.request.Consent = func(request ConsentRequest, action ConsentAction) error {
			run.consentCalls++
			if !slices.Equal(request.AllowedRoles(), []PhysicalRole{RolePrimary, RoleBackup}) {
				return errors.New("consent role set mismatch")
			}
			run.retainedAction = action
			go func() { actionErr <- action(RolePrimary) }()
			<-entered
			return nil
		}
		phase9PrivacyRequireLive(t, run)

		var result *Result
		var stdout, stderr []byte
		var logBuffer bytes.Buffer
		originalLogOutput := log.Writer()
		originalLogFlags := log.Flags()
		log.SetOutput(&logBuffer)
		defer func() {
			log.SetOutput(originalLogOutput)
			log.SetFlags(originalLogFlags)
		}()
		stdout, stderr = phase9CaptureProcess(t, func() {
			operationDone := make(chan *Result, 1)
			go func() {
				operationDone <- runWithSeams(run.ctx, run.request, operationSeams{admitter: admitter})
			}()
			select {
			case <-entered:
			case <-time.After(120 * time.Second):
				t.Fatal("live consent action never reached the recovery boundary")
			}
			cancel()
			close(release)
			result = phase9PrivacyWaitResult(t, operationDone, "raced consent operation")
		})
		if err := phase9PrivacyWaitError(t, actionErr, "raced consent action"); err != nil {
			t.Fatalf("live consent action = %v; want nil after one completed selection", err)
		}
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:    pcv3.OutcomeOperationFailed,
			stage:      pcv3.StageCancellation,
			code:       pcv3.CodeOperationFailed,
			diagnostic: DiagnosticNone,
			class:      CompletionRefused,
		})
		phase9PrivacyRequireNoCapability(t, result)
		if !slices.Equal(run.statuses, []StatusCode{
			StatusCheckingRequest,
			StatusCheckingFactors,
			StatusRecovering,
		}) {
			t.Fatalf("raced consent status sequence = %v; want exact reached boundaries", run.statuses)
		}
		if run.consentCalls != 1 || admitter.calls != 0 {
			t.Fatalf("raced consent calls = %d admissions = %d; want 1/0", run.consentCalls, admitter.calls)
		}
		if !errors.Is(run.retainedAction(RoleBackup), ErrConsentExpired) {
			t.Fatal("used raced consent action did not expire")
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, nil)
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBuffer.Bytes())
	})

	t.Run("concurrent fixed-profile derivations serialize on the one-flight lease", func(t *testing.T) {
		runs := make([]*phase9LifecycleRun, 2)
		admitters := make([]*phase9PrivacyAdmitter, 2)
		results := make([]*Result, 2)
		targets := make([]string, 2)
		var wait sync.WaitGroup
		for index := range runs {
			run := phase9BaseRun(t, []string{"concurrent-a", "concurrent-b"}[index])
			admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
			run.source = openOperationNormalFixture(t, "normal-standard-combined-ordered-one.pcv")
			run.request.Mode = ModeReadNormal
			run.request.Source = run.source
			run.request.Factors = phase9PrivacyCombinedFactors(t, run, []byte("mix"), "password-concurrent")
			phase9WireReporter(run)
			phase9PrivacyRequireLive(t, run)
			runs[index] = run
			admitters[index] = admitter
			targets[index] = run.request.Target
		}
		start := make(chan struct{})
		for index := range runs {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				results[index] = runWithSeams(runs[index].ctx, runs[index].request, operationSeams{admitter: admitters[index]})
			}()
		}
		close(start)
		wait.Wait()
		for index := range runs {
			phase9PrivacyRequireCleanSuccess(t, runs[index], results[index], admitters[index], oneBytePlaintext, targets[index])
			assertOperationRequestTransferred(t, runs[index].request)
			phase9AssertZeroed(t, runs[index])
		}
	})

	t.Run("concurrent one-shot archive consumers race exactly once", func(t *testing.T) {
		run := phase9BaseRun(t, "archive-race")
		admitter := &phase9PrivacyAdmitter{admission: pcv3credential.KDFAdmissionGranted}
		run.source = openOperationNormalFixture(t, "normal-standard-combined-ordered-archive-small.pcv")
		run.request.Mode = ModeReadNormal
		run.request.Source = run.source
		run.request.Factors = phase9PrivacyCombinedFactors(t, run, []byte("mix"), "password-archive-race")
		phase9WireReporter(run)
		phase9PrivacyRequireLive(t, run)

		result, stdout, stderr, logBytes := phase9PrivacyRun(t, run, admitter)
		phase9PrivacyRequireResult(t, result, phase9PrivacyWant{
			outcome:    pcv3.OutcomeSuccess,
			stage:      pcv3.StageNone,
			code:       pcv3.CodeSuccess,
			diagnostic: DiagnosticNone,
			class:      CompletionArchivePending,
		})
		if result.PublicationAttempted() || result.ArtifactInspection() != nil ||
			result.OutputFollowUp() != nil {
			t.Fatal("archive operation attempted publication or retained non-archive authority")
		}
		followUp := result.ArchiveFollowUp()
		if followUp == nil {
			t.Fatal("authenticated archive result exposed no extraction authority")
		}
		if !slices.Equal(run.statuses, []StatusCode{
			StatusCheckingRequest,
			StatusCheckingFactors,
			StatusAuthenticating,
			StatusCheckingResources,
			StatusDerivingKey,
		}) {
			t.Fatalf("archive status sequence = %v; want exact reached boundaries", run.statuses)
		}
		if admitter.calls != 1 || admitter.profiles[0] != phase9Standard1Profile {
			t.Fatalf("archive admissions = %d; want one fixed-profile derivation", admitter.calls)
		}

		extractRootA := t.TempDir()
		extractRootB := t.TempDir()
		rootA, err := os.OpenRoot(extractRootA)
		if err != nil {
			t.Fatalf("open extraction root A: %v", err)
		}
		rootB, err := os.OpenRoot(extractRootB)
		if err != nil {
			t.Fatalf("open extraction root B: %v", err)
		}
		consumerResults := make([]*Result, 3)
		start := make(chan struct{})
		var wait sync.WaitGroup
		consumers := []func(){
			func() { consumerResults[0] = followUp.Extract(context.Background(), rootA) },
			func() { consumerResults[1] = followUp.Close() },
			func() { consumerResults[2] = followUp.Extract(context.Background(), rootB) },
		}
		for _, consumer := range consumers {
			wait.Add(1)
			go func(consume func()) {
				defer wait.Done()
				<-start
				consume()
			}(consumer)
		}
		close(start)
		wait.Wait()

		winners := 0
		losers := 0
		extractionWon := false
		for index, consumerResult := range consumerResults {
			if consumerResult == nil {
				t.Fatalf("consumer %d returned no closed result", index)
			}
			isExtract := index != 1
			switch {
			case isExtract && consumerResult.Outcome() == pcv3.OutcomeSuccess:
				winners++
				extractionWon = true
				phase9PrivacyRequireResult(t, consumerResult, phase9PrivacyWant{
					outcome:              pcv3.OutcomeSuccess,
					stage:                pcv3.StageNone,
					code:                 pcv3.CodeSuccess,
					diagnostic:           DiagnosticNone,
					class:                CompletionClean,
					publicationAttempted: true,
					publicationState:     pcv3publication.StatePublishedDurable,
					publicationStage:     pcv3.StageNone,
					publicationCode:      pcv3publication.CodePublishedDurable,
				})
			case !isExtract && consumerResult.Diagnostic() == DiagnosticNone:
				winners++
				phase9PrivacyRequireResult(t, consumerResult, phase9PrivacyWant{
					outcome:    pcv3.OutcomeOperationFailed,
					stage:      pcv3.StageOutputPublication,
					code:       pcv3.CodeOperationFailed,
					diagnostic: DiagnosticNone,
					class:      CompletionNoOutput,
				})
			default:
				losers++
				phase9PrivacyRequireResult(t, consumerResult, phase9PrivacyWant{
					outcome:    pcv3.OutcomeOperationFailed,
					stage:      pcv3.StageOutputPublication,
					code:       pcv3.CodeOperationFailed,
					diagnostic: DiagnosticInvalidRequest,
					class:      CompletionNoOutput,
				})
			}
		}
		if winners != 1 || losers != 2 {
			t.Fatalf("archive consumer race winners = %d losers = %d; want exactly 1/2", winners, losers)
		}
		phase9PrivacyRequireRootClosed(t, rootA, "A")
		phase9PrivacyRequireRootClosed(t, rootB, "B")
		if extractionWon {
			winnerDir := extractRootA
			loserDir := extractRootB
			if consumerResults[2] != nil && consumerResults[2].Outcome() == pcv3.OutcomeSuccess {
				winnerDir = extractRootB
				loserDir = extractRootA
			}
			phase9PrivacyRequireDirNames(t, winnerDir, []string{"docs", "root.txt"})
			phase9PrivacyRequireTargetBytes(t,
				filepath.Join(winnerDir, "root.txt"),
				[]byte("PCV3 authenticated archive fixture\n"),
			)
			phase9PrivacyRequireTargetBytes(t,
				filepath.Join(winnerDir, "docs", "readme.txt"),
				[]byte("Extraction is admitted only after whole-volume authentication.\n"),
			)
			phase9PrivacyRequireDirNames(t, loserDir, nil)
		} else {
			phase9PrivacyRequireDirNames(t, extractRootA, nil)
			phase9PrivacyRequireDirNames(t, extractRootB, nil)
		}
		if again := followUp.Close(); again == nil || again.Diagnostic() != DiagnosticInvalidRequest {
			t.Fatal("consumed archive authority accepted a late consumer")
		}
		phase9PrivacyRequireDirNames(t, run.outputDir, nil)
		phase9PrivacyFinish(t, run, result, stdout, stderr, logBytes)
	})
}
