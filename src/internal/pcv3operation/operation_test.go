package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/synctest"
)

type operationTestAdmitter struct {
	calls     int
	grant     bool
	admission pcv3credential.KDFAdmission
}

func (admitter *operationTestAdmitter) AdmitKDF(
	_ context.Context,
	_ pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	admitter.calls++
	if admitter.grant {
		return pcv3credential.KDFAdmissionGranted, nil
	}
	if admitter.admission != pcv3credential.KDFAdmissionUnknown {
		return admitter.admission, nil
	}
	return pcv3credential.KDFAdmissionDenied, nil
}

type operationObservedReadCloser struct {
	file       *os.File
	closeCalls int
}

func (reader *operationObservedReadCloser) Read(destination []byte) (int, error) {
	return reader.file.Read(destination)
}

func (reader *operationObservedReadCloser) Close() error {
	reader.closeCalls++
	return reader.file.Close()
}

func TestOperationRejectsFactorIntentBeforeEffects(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		factors func(*testing.T) (*pcv3credential.FactorRequest, []*operationObservedReadCloser, []byte)
	}{
		{
			name:    "wrong factor shape",
			fixture: "normal-standard-password-only-small.pcv",
			factors: func(*testing.T) (*pcv3credential.FactorRequest, []*operationObservedReadCloser, []byte) {
				password := []byte{}
				return &pcv3credential.FactorRequest{
					Mode:           pcv3credential.CredentialModePasswordOnly,
					KeyfileMode:    pcv3credential.KeyfileModeNone,
					ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly,
					Password:       password,
				}, nil, password
			},
		},
		{
			name:    "wrong keyfile order policy",
			fixture: "normal-standard-keyfiles-only-small.pcv",
			factors: func(t *testing.T) (*pcv3credential.FactorRequest, []*operationObservedReadCloser, []byte) {
				readers := []*operationObservedReadCloser{
					newOperationObservedKeyfile(t, []byte("one")),
					newOperationObservedKeyfile(t, []byte("two!")),
				}
				return &pcv3credential.FactorRequest{
					Mode:           pcv3credential.CredentialModeKeyfilesOnly,
					KeyfileMode:    pcv3credential.KeyfileModeUnordered,
					ExpectedPolicy: pcv3credential.FactorPolicyKeyfilesOnly,
					Keyfiles:       operationKeyfileHandles(readers),
				}, readers, nil
			},
		},
		{
			name:    "too many keyfiles",
			fixture: "normal-standard-keyfiles-only-small.pcv",
			factors: func(t *testing.T) (*pcv3credential.FactorRequest, []*operationObservedReadCloser, []byte) {
				readers := make([]*operationObservedReadCloser, 65)
				for index := range readers {
					readers[index] = newOperationObservedKeyfile(t, []byte{byte(index)})
				}
				return &pcv3credential.FactorRequest{
					Mode:           pcv3credential.CredentialModeKeyfilesOnly,
					KeyfileMode:    pcv3credential.KeyfileModeOrdered,
					ExpectedPolicy: pcv3credential.FactorPolicyKeyfilesOnly,
					Keyfiles:       operationKeyfileHandles(readers),
				}, readers, nil
			},
		},
		{
			name:    "duplicate keyfile digest",
			fixture: "normal-standard-keyfiles-only-small.pcv",
			factors: func(t *testing.T) (*pcv3credential.FactorRequest, []*operationObservedReadCloser, []byte) {
				readers := []*operationObservedReadCloser{
					newOperationObservedKeyfile(t, []byte("same keyfile")),
					newOperationObservedKeyfile(t, []byte("same keyfile")),
				}
				return &pcv3credential.FactorRequest{
					Mode:           pcv3credential.CredentialModeKeyfilesOnly,
					KeyfileMode:    pcv3credential.KeyfileModeOrdered,
					ExpectedPolicy: pcv3credential.FactorPolicyKeyfilesOnly,
					Keyfiles:       operationKeyfileHandles(readers),
				}, readers, nil
			},
		},
		{
			name:    "caller policy mismatch",
			fixture: "normal-standard-keyfiles-only-small.pcv",
			factors: func(t *testing.T) (*pcv3credential.FactorRequest, []*operationObservedReadCloser, []byte) {
				readers := []*operationObservedReadCloser{
					newOperationObservedKeyfile(t, []byte("one")),
					newOperationObservedKeyfile(t, []byte("two!")),
				}
				return &pcv3credential.FactorRequest{
					Mode:           pcv3credential.CredentialModeKeyfilesOnly,
					KeyfileMode:    pcv3credential.KeyfileModeOrdered,
					ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly,
					Keyfiles:       operationKeyfileHandles(readers),
				}, readers, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := openOperationNormalFixture(t, test.fixture)
			factors, readers, password := test.factors(t)
			outputRoot := t.TempDir()
			admitter := &operationTestAdmitter{}
			var statuses []StatusCode
			request := &Request{
				Mode:    ModeReadNormal,
				Source:  source,
				Factors: factors,
				Target:  filepath.Join(outputRoot, "plaintext.bin"),
				Reporter: func(status Status) error {
					statuses = append(statuses, status.Code())
					return nil
				},
			}

			result := runWithSeams(context.Background(), request, operationSeams{admitter: admitter})

			if result.Outcome() != pcv3.OutcomeOperationFailed ||
				result.Stage() != pcv3.StageCredentialPolicy ||
				result.Code() != pcv3.CodeOperationFailed || result.PublicationAttempted() {
				t.Fatalf(
					"invalid factor result = %v/%v/%v attempted=%v; want credential-policy before publication",
					result.Outcome(), result.Stage(), result.Code(), result.PublicationAttempted(),
				)
			}
			if admitter.calls != 0 {
				t.Fatalf("pre-KDF admission calls = %d; want zero", admitter.calls)
			}
			wantStatuses := []StatusCode{
				StatusCheckingRequest,
				StatusCheckingFactors,
				StatusAuthenticating,
			}
			if !reflect.DeepEqual(statuses, wantStatuses) {
				t.Fatalf("pre-KDF status sequence = %v; want %v", statuses, wantStatuses)
			}
			entries, err := os.ReadDir(outputRoot)
			if err != nil {
				t.Fatalf("inspect output root: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf("invalid factors created %d output/stage entries; want none", len(entries))
			}
			assertOperationRequestTransferred(t, request)
			assertOperationFileClosed(t, source)
			assertOperationPasswordZero(t, password)
			assertOperationKeyfilesClosedOnce(t, readers)
		})
	}
}

func TestOperationReporterUsesRealBoundariesAndStopsBeforeKDF(t *testing.T) {
	t.Run("resource refusal reports only reached production boundaries", func(t *testing.T) {
		source := openOperationNormalFixture(t, "normal-standard-password-only-small.pcv")
		password := []byte("mix")
		admitter := &operationTestAdmitter{}
		var statuses []StatusCode
		request := &Request{
			Mode:    ModeReadNormal,
			Source:  source,
			Factors: operationPasswordFactors(password),
			Target:  filepath.Join(t.TempDir(), "output.bin"),
			Reporter: func(status Status) error {
				if len(status.Args()) != 0 {
					t.Fatalf("status %v carried unexpected arguments", status.Code())
				}
				statuses = append(statuses, status.Code())
				return nil
			},
		}

		result := runWithSeams(
			context.Background(),
			request,
			operationSeams{admitter: admitter},
		)
		want := []StatusCode{
			StatusCheckingRequest,
			StatusCheckingFactors,
			StatusAuthenticating,
			StatusCheckingResources,
		}
		if !reflect.DeepEqual(statuses, want) {
			t.Fatalf("status sequence = %v; want exact reached boundaries %v", statuses, want)
		}
		if admitter.calls != 1 || result.Stage() != pcv3.StageCredentialPolicy ||
			result.PublicationAttempted() {
			t.Fatalf("refusal = calls %d stage %v attempted %v; want one admission and no output", admitter.calls, result.Stage(), result.PublicationAttempted())
		}
	})

	t.Run("reporter failure after admission prevents derivation", func(t *testing.T) {
		var statuses []StatusCode
		owner := &operationOwner{reporter: func(status Status) error {
			statuses = append(statuses, status.Code())
			if status.Code() == StatusDerivingKey {
				return errors.New("TEST ONLY reporter failure")
			}
			return nil
		}}
		admitter := &operationTestAdmitter{grant: true}
		wrapped := reportingAdmitter{owner: owner, next: admitter}

		admission, err := wrapped.AdmitKDF(
			context.Background(),
			pcv3credential.KDFProfile{},
		)
		if err == nil || admission == pcv3credential.KDFAdmissionGranted {
			t.Fatalf("reporter failure admission = %v, %v; want refusal before caller can derive", admission, err)
		}
		if !reflect.DeepEqual(statuses, []StatusCode{StatusCheckingResources, StatusDerivingKey}) ||
			admitter.calls != 1 {
			t.Fatalf("reporter boundary = statuses %v admission calls %d", statuses, admitter.calls)
		}
		failure := owner.reportFailure()
		if failure == nil || failure.Diagnostic() != DiagnosticCallbackFailure ||
			failure.PublicationAttempted() {
			t.Fatalf("reporter failure result = %#v; want closed callback refusal", failure)
		}
	})

	t.Run("reporter panic is contained before resource admission", func(t *testing.T) {
		owner := &operationOwner{reporter: func(Status) error {
			panic("TEST ONLY reporter panic with /private/path")
		}}
		admitter := &operationTestAdmitter{grant: true}
		wrapped := reportingAdmitter{owner: owner, next: admitter}

		admission, err := wrapped.AdmitKDF(context.Background(), pcv3credential.KDFProfile{})
		if err == nil || admission == pcv3credential.KDFAdmissionGranted || admitter.calls != 0 {
			t.Fatalf("reporter panic admission=%v err=%v calls=%d; want contained pre-admission refusal", admission, err, admitter.calls)
		}
		failure := owner.reportFailure()
		if failure.Diagnostic() != DiagnosticCallbackPanic ||
			strings.Contains(fmt.Sprintf("%v %#v", failure, failure), "/private/") {
			t.Fatalf("reporter panic result = %v/%#v; want redacted panic diagnostic", failure, failure)
		}
	})
}

type operationTestArchiveState struct {
	active bool
}

func (state *operationTestArchiveState) live() bool {
	return state != nil && state.active
}

func (state *operationTestArchiveState) extract(root *os.Root) *Result {
	if state == nil || !state.active {
		return archiveNoOutput(DiagnosticInvalidRequest, closeExtractionRoot(root))
	}
	state.active = false
	return archiveNoOutput(DiagnosticNone, closeExtractionRoot(root))
}

func (state *operationTestArchiveState) close() *Result {
	if state == nil || !state.active {
		return archiveNoOutput(DiagnosticInvalidRequest, false)
	}
	state.active = false
	return archiveNoOutput(DiagnosticNone, false)
}

func TestPCV3OperationPreservesResultAxes(t *testing.T) {
	tests := []struct {
		name                 string
		data                 resultData
		archive              *ArchiveFollowUp
		wantCompletion       CompletionClass
		wantOutcome          pcv3.Outcome
		wantPublicationState pcv3publication.State
	}{
		{
			name: "authenticated degraded remains warning after durable publication",
			data: resultData{
				outcome: pcv3.OutcomeAuthenticatedDegraded, stage: pcv3.StageMetadata,
				code: pcv3.CodeAuthenticatedDegraded, publicationAttempted: true,
				publicationState: pcv3publication.StatePublishedDurable,
				publicationCode:  pcv3publication.CodePublishedDurable,
			},
			wantCompletion:       CompletionWarning,
			wantOutcome:          pcv3.OutcomeAuthenticatedDegraded,
			wantPublicationState: pcv3publication.StatePublishedDurable,
		},
		{
			name: "Force partial remains warning after durable publication",
			data: resultData{
				outcome: pcv3.OutcomeForcePartial, stage: pcv3.StageRecordAuth,
				code: pcv3.CodeForcePartial, publicationAttempted: true,
				publicationState: pcv3publication.StatePublishedDurable,
				publicationCode:  pcv3publication.CodePublishedDurable,
			},
			wantCompletion:       CompletionWarning,
			wantOutcome:          pcv3.OutcomeForcePartial,
			wantPublicationState: pcv3publication.StatePublishedDurable,
		},
		{
			name: "semantic success remains separate from uncertain durability",
			data: resultData{
				outcome: pcv3.OutcomeSuccess, stage: pcv3.StageNone,
				code: pcv3.CodeSuccess, publicationAttempted: true,
				publicationState: pcv3publication.StatePublishedDurabilityUncertain,
				publicationStage: pcv3.StageDirectorySync,
				publicationCode:  pcv3publication.CodeDurabilityUncertain,
			},
			wantCompletion:       CompletionDurabilityUncertain,
			wantOutcome:          pcv3.OutcomeSuccess,
			wantPublicationState: pcv3publication.StatePublishedDurabilityUncertain,
		},
		{
			name: "semantic success remains separate from indeterminate publication",
			data: resultData{
				outcome: pcv3.OutcomeSuccess, stage: pcv3.StageNone,
				code: pcv3.CodeSuccess, publicationAttempted: true,
				publicationState: pcv3publication.StatePublicationIndeterminate,
				publicationStage: pcv3.StageOutputPublication,
				publicationCode:  pcv3publication.CodePublicationIndeterminate,
			},
			wantCompletion:       CompletionPublicationIndeterminate,
			wantOutcome:          pcv3.OutcomeSuccess,
			wantPublicationState: pcv3publication.StatePublicationIndeterminate,
		},
		{
			name: "live exact-success archive tuple is pending rather than terminal",
			data: resultData{
				outcome: pcv3.OutcomeSuccess, stage: pcv3.StageNone,
				code: pcv3.CodeSuccess,
			},
			archive:        &ArchiveFollowUp{state: &operationTestArchiveState{active: true}},
			wantCompletion: CompletionArchivePending,
			wantOutcome:    pcv3.OutcomeSuccess,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := newResult(test.data)
			result.archiveFollowUp = test.archive
			if result.Outcome() != test.wantOutcome ||
				result.PublicationState() != test.wantPublicationState ||
				result.CompletionClass() != test.wantCompletion {
				t.Fatalf(
					"closed tuple = %v/%v/%v; want %v/%v/%v",
					result.Outcome(), result.PublicationState(), result.CompletionClass(),
					test.wantOutcome, test.wantPublicationState, test.wantCompletion,
				)
			}
			if test.wantCompletion == CompletionArchivePending && result.ArchiveFollowUp() == nil {
				t.Fatal("valid archive-pending tuple lost its sole live follow-up")
			}
			if test.wantCompletion != CompletionArchivePending && result.ArchiveFollowUp() != nil {
				t.Fatal("terminal tuple granted archive authority")
			}
		})
	}
}

func TestPCV3OperationRequiresExplicitModeAndLiveConsent(t *testing.T) {
	t.Run("zero mode never infers D1 or recovery", func(t *testing.T) {
		source := newOperationEmptySource(t)
		password := []byte("mode must be explicit")
		consentCalls := 0
		request := &Request{
			Source:  source,
			Factors: operationPasswordFactors(password),
			Target:  filepath.Join(t.TempDir(), "output.bin"),
			Consent: func(ConsentRequest, ConsentAction) error {
				consentCalls++
				return nil
			},
		}

		result := Run(context.Background(), request)
		if result.Outcome() != pcv3.OutcomeUnsupportedRoutingPreKDF ||
			result.Stage() != pcv3.StageRouting || consentCalls != 0 {
			t.Fatalf("implicit mode result = %v/%v consent=%d; want routing refusal with no callback", result.Outcome(), result.Stage(), consentCalls)
		}
		assertOperationPasswordZero(t, password)
		assertOperationFileClosed(t, source)
	})

	t.Run("explicit D1 read traverses the recovery wrapper", func(t *testing.T) {
		source := newOperationEmptySource(t)
		password := []byte("d1 wrapper")
		request := &Request{
			Mode: ModeReadD1, Source: source,
			Factors: operationPasswordFactors(password),
			Target:  filepath.Join(t.TempDir(), "output.bin"),
		}

		result := runWithSeams(context.Background(), request, operationSeams{admitter: &operationTestAdmitter{}})
		if result.Outcome() != pcv3.OutcomeCredentialsOrDamage ||
			result.Stage() != pcv3.StageD1Bootstrap || result.PublicationAttempted() ||
			result.CompletionClass() != CompletionNoOutput {
			t.Fatalf(
				"D1 wrapper result = %v/%v attempted=%v class=%v; want closed bootstrap/no-output tuple",
				result.Outcome(), result.Stage(), result.PublicationAttempted(), result.CompletionClass(),
			)
		}
		assertOperationPasswordZero(t, password)
		assertOperationFileClosed(t, source)
	})

	t.Run("D1 unverified authority is exact-role live and one-shot", func(t *testing.T) {
		source := newOperationEmptySource(t)
		password := []byte("d1 consent")
		var retained ConsentAction
		callbackCalls := 0
		request := &Request{
			Mode: ModeForceUnverifiedD1, Source: source,
			Factors: operationPasswordFactors(password),
			Target:  filepath.Join(t.TempDir(), "output.bin"),
			Consent: func(consent ConsentRequest, action ConsentAction) error {
				callbackCalls++
				roles := consent.AllowedRoles()
				if consent.Mode() != ModeForceUnverifiedD1 ||
					!reflect.DeepEqual(roles, []PhysicalRole{RoleD1Front, RoleD1Tail}) {
					return errors.New("wrong physical consent role set")
				}
				roles[0] = RolePrimary
				if !reflect.DeepEqual(
					consent.AllowedRoles(),
					[]PhysicalRole{RoleD1Front, RoleD1Tail},
				) {
					return errors.New("caller mutated the core role set")
				}
				retained = action
				return action(RoleD1Tail)
			},
		}

		result := runWithSeams(context.Background(), request, operationSeams{admitter: &operationTestAdmitter{}})
		if callbackCalls != 1 || result.Outcome() != pcv3.OutcomeCredentialsOrDamage ||
			result.Stage() != pcv3.StageD1Bootstrap || result.PublicationAttempted() {
			t.Fatalf(
				"D1 consent result = %v/%v attempted=%v callbacks=%d; want one exact-role wrapper call",
				result.Outcome(), result.Stage(), result.PublicationAttempted(), callbackCalls,
			)
		}
		if retained == nil || !errors.Is(retained(RoleD1Front), ErrConsentExpired) {
			t.Fatal("retained D1 consent action survived callback return")
		}
		assertOperationPasswordZero(t, password)
		assertOperationFileClosed(t, source)
	})

	t.Run("D1 consent rejects a capsule role and consumes live authority", func(t *testing.T) {
		source := newOperationEmptySource(t)
		password := []byte("wrong role")
		callbackCalls := 0
		request := &Request{
			Mode: ModeForceUnverifiedD1, Source: source,
			Factors: operationPasswordFactors(password),
			Target:  filepath.Join(t.TempDir(), "output.bin"),
			Consent: func(_ ConsentRequest, action ConsentAction) error {
				callbackCalls++
				if !errors.Is(action(RolePrimary), ErrConsentRole) {
					return errors.New("capsule role was not rejected")
				}
				if !errors.Is(action(RoleD1Front), ErrConsentExpired) {
					return errors.New("invalid first selection did not consume consent")
				}
				return nil
			},
		}

		result := runWithSeams(
			context.Background(),
			request,
			operationSeams{admitter: &operationTestAdmitter{}},
		)
		if result.Stage() != pcv3.StageCredentialPolicy || result.PublicationAttempted() || callbackCalls != 1 {
			t.Fatalf("role-selection result stage=%v attempted=%v callbacks=%d; want one refused live selection", result.Stage(), result.PublicationAttempted(), callbackCalls)
		}
		assertOperationPasswordZero(t, password)
		assertOperationFileClosed(t, source)
	})

	t.Run("cancellation while consent is pending remains cancellation", func(t *testing.T) {
		source := newOperationEmptySource(t)
		password := []byte("cancel pending consent")
		ctx, cancel := context.WithCancel(context.Background())
		request := &Request{
			Mode: ModeForceUnverifiedD1, Source: source,
			Factors: operationPasswordFactors(password),
			Target:  filepath.Join(t.TempDir(), "output.bin"),
			Consent: func(ConsentRequest, ConsentAction) error {
				cancel()
				return nil
			},
		}

		result := runWithSeams(ctx, request, operationSeams{admitter: &operationTestAdmitter{}})
		if result.Stage() != pcv3.StageCancellation ||
			result.Diagnostic() != DiagnosticCancellation || result.PublicationAttempted() {
			t.Fatalf(
				"pending-consent cancellation = %v/%v attempted=%v; want cancellation/no output",
				result.Stage(), result.Diagnostic(), result.PublicationAttempted(),
			)
		}
		assertOperationPasswordZero(t, password)
		assertOperationFileClosed(t, source)
	})

	t.Run("normal unverified consent receives the complete capsule role set", func(t *testing.T) {
		source := newOperationEmptySource(t)
		password := []byte("normal consent")
		callbackCalls := 0
		request := &Request{
			Mode:    ModeForceUnverifiedNormal,
			Source:  source,
			Factors: operationPasswordFactors(password),
			Target:  filepath.Join(t.TempDir(), "output.bin"),
			Consent: func(consent ConsentRequest, action ConsentAction) error {
				callbackCalls++
				if !reflect.DeepEqual(
					consent.AllowedRoles(),
					[]PhysicalRole{RolePrimary, RoleBackup},
				) {
					return errors.New("normal consent did not receive the capsule role set")
				}
				return action(RoleBackup)
			},
		}

		result := runWithSeams(
			context.Background(),
			request,
			operationSeams{admitter: &operationTestAdmitter{}},
		)
		if callbackCalls != 1 || result.PublicationAttempted() {
			t.Fatalf("normal consent callbacks=%d attempted=%v; want one live selection and no output", callbackCalls, result.PublicationAttempted())
		}
		assertOperationPasswordZero(t, password)
		assertOperationFileClosed(t, source)
	})
}

func TestOperationConsentDoesNotOutliveTransferredResources(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		source := newOperationEmptySource(t)
		password := []byte("asynchronous consent")
		recoveryEntered := make(chan struct{})
		releaseRecovery := make(chan struct{})
		actionDone := make(chan error, 1)
		operationDone := make(chan *Result, 1)
		request := &Request{
			Mode:    ModeForceUnverifiedD1,
			Source:  source,
			Factors: operationPasswordFactors(password),
			Target:  filepath.Join(t.TempDir(), "output.bin"),
			Reporter: func(status Status) error {
				if status.Code() == StatusRecovering {
					close(recoveryEntered)
					<-releaseRecovery
				}
				return nil
			},
			Consent: func(_ ConsentRequest, action ConsentAction) error {
				go func() { actionDone <- action(RoleD1Front) }()
				<-recoveryEntered
				return nil
			},
		}

		go func() {
			operationDone <- runWithSeams(
				context.Background(),
				request,
				operationSeams{admitter: &operationTestAdmitter{}},
			)
		}()

		<-recoveryEntered
		synctest.Wait()
		select {
		case <-operationDone:
			t.Fatal("operation returned and released transferred resources while consent action was active")
		default:
		}
		close(releaseRecovery)
		if err := <-actionDone; err != nil {
			t.Fatalf("live consent action failed: %v", err)
		}
		result := <-operationDone
		if result == nil || result.Stage() != pcv3.StageD1Bootstrap {
			t.Fatalf("terminal result stage = %v; want D1 bootstrap after active action completed", result.Stage())
		}
		assertOperationPasswordZero(t, password)
		assertOperationFileClosed(t, source)
	})
}

func TestOperationOwnerClosesAndZerosEveryExit(t *testing.T) {
	callbackFailure := errors.New("TEST ONLY callback failure with /private/attacker/path")
	tests := []struct {
		name      string
		ctx       func() context.Context
		mode      Mode
		consent   func() Consent
		wantStage pcv3.Stage
	}{
		{
			name: "ordinary terminal return",
			ctx:  context.Background,
			mode: ModeReadD1, wantStage: pcv3.StageD1Bootstrap,
		},
		{
			name: "admission refusal",
			ctx:  context.Background,
			mode: ModeReadNormal, wantStage: pcv3.StageCredentialPolicy,
		},
		{
			name: "cancellation",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			mode: ModeReadD1, wantStage: pcv3.StageCancellation,
		},
		{
			name: "consent refusal",
			ctx:  context.Background,
			mode: ModeForceUnverifiedD1,
			consent: func() Consent {
				return func(ConsentRequest, ConsentAction) error { return nil }
			},
			wantStage: pcv3.StageCredentialPolicy,
		},
		{
			name: "callback failure",
			ctx:  context.Background,
			mode: ModeForceUnverifiedD1,
			consent: func() Consent {
				return func(ConsentRequest, ConsentAction) error { return callbackFailure }
			},
			wantStage: pcv3.StageCredentialPolicy,
		},
		{
			name: "contained callback panic",
			ctx:  context.Background,
			mode: ModeForceUnverifiedD1,
			consent: func() Consent {
				return func(ConsentRequest, ConsentAction) error {
					panic("TEST ONLY panic with /private/attacker/path")
				}
			},
			wantStage: pcv3.StageCredentialPolicy,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var source *os.File
			if test.mode == ModeReadNormal {
				source = openOperationNormalFixture(t, "normal-standard-password-only-small.pcv")
			} else {
				source = newOperationEmptySource(t)
			}
			password := []byte("owner secret")
			keyfile := newOperationObservedKeyfile(t, []byte("owned keyfile"))
			factors := &pcv3credential.FactorRequest{
				Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
				KeyfileMode:    pcv3credential.KeyfileModeOrdered,
				ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
				Password:       password,
				Keyfiles:       operationKeyfileHandles([]*operationObservedReadCloser{keyfile}),
			}
			if test.mode == ModeReadNormal {
				factors.Mode = pcv3credential.CredentialModePasswordOnly
				factors.KeyfileMode = pcv3credential.KeyfileModeNone
				factors.ExpectedPolicy = pcv3credential.FactorPolicyPasswordOnly
				_ = factors.Keyfiles[0].Close()
				factors.Keyfiles = nil
			}
			reporter := Reporter(func(Status) error { return nil })
			request := &Request{
				Mode: test.mode, Source: source, Factors: factors,
				Target:    filepath.Join(t.TempDir(), "output.bin"),
				Protected: []string{filepath.Join(t.TempDir(), "protected.bin")},
				Reporter:  reporter,
			}
			if test.consent != nil {
				request.Consent = test.consent()
			}

			result := runWithSeams(test.ctx(), request, operationSeams{admitter: &operationTestAdmitter{}})
			if result == nil || result.Stage() != test.wantStage {
				t.Fatalf("terminal stage = %v; want %v", result.Stage(), test.wantStage)
			}
			formatted := fmt.Sprintf("%v %#v", result, result)
			if strings.Contains(formatted, "/private/") || strings.Contains(formatted, "owner secret") {
				t.Fatalf("result formatting disclosed callback/path/secret material: %q", formatted)
			}
			assertOperationRequestTransferred(t, request)
			assertOperationPasswordZero(t, password)
			assertOperationFileClosed(t, source)
			if test.mode != ModeReadNormal {
				assertOperationKeyfilesClosedOnce(t, []*operationObservedReadCloser{keyfile})
			}
		})
	}
}

func TestOperationRequestCannotInjectResourceAuthority(t *testing.T) {
	// This public-shape assertion is a policy/API guard. Product behavior is
	// covered independently by TestOperationResourceRefusalHasNoOutput.
	requestType := reflect.TypeOf(Request{})
	admitterType := reflect.TypeOf((*pcv3credential.Admitter)(nil)).Elem()
	for index := range requestType.NumField() {
		field := requestType.Field(index)
		lowerName := strings.ToLower(field.Name)
		lowerType := strings.ToLower(field.Type.String())
		unexpectedCallback := field.Type.Kind() == reflect.Func &&
			field.Type != reflect.TypeOf(Reporter(nil)) && field.Type != reflect.TypeOf(Consent(nil))
		if field.Type == admitterType || field.Type.Implements(admitterType) ||
			field.Type.Kind() == reflect.Interface || unexpectedCallback ||
			strings.Contains(lowerName, "admitter") || strings.Contains(lowerName, "provider") ||
			strings.Contains(lowerName, "snapshot") || strings.Contains(lowerName, "resource") ||
			strings.Contains(lowerName, "policy") || strings.Contains(lowerName, "digest") ||
			strings.Contains(lowerName, "identity") || strings.Contains(lowerType, "provider") ||
			strings.Contains(lowerType, "snapshot") || strings.Contains(lowerType, "resource") ||
			strings.Contains(lowerType, "policy") {
			t.Fatalf("public Request exposes forbidden authority/identity field %s %v", field.Name, field.Type)
		}
	}
}

func TestOperationResourceRefusalHasNoOutput(t *testing.T) {
	tests := []struct {
		name       string
		admission  pcv3credential.KDFAdmission
		diagnostic Diagnostic
	}{
		{
			name:       "insufficient resources",
			admission:  pcv3credential.KDFAdmissionDeniedInsufficient,
			diagnostic: DiagnosticResourceInsufficient,
		},
		{
			name:       "unknown resource state",
			admission:  pcv3credential.KDFAdmissionDeniedUnknown,
			diagnostic: DiagnosticResourceUnknown,
		},
		{
			name:       "generic refusal fails closed as unknown",
			admission:  pcv3credential.KDFAdmissionDenied,
			diagnostic: DiagnosticResourceUnknown,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			privateSource := openOperationNormalFixture(t, "normal-standard-combined-ordered-archive-small.pcv")
			privatePassword := []byte("mix")
			keyfiles := []*operationObservedReadCloser{
				newOperationObservedKeyfile(t, []byte("one")),
				newOperationObservedKeyfile(t, []byte("two!")),
			}
			privateAdmitter := &operationTestAdmitter{admission: test.admission}
			outputRoot := t.TempDir()
			privateRequest := &Request{
				Mode: ModeReadNormal, Source: privateSource,
				Factors: &pcv3credential.FactorRequest{
					Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
					KeyfileMode:    pcv3credential.KeyfileModeOrdered,
					ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
					Password:       privatePassword,
					Keyfiles:       operationKeyfileHandles(keyfiles),
				},
				Target: filepath.Join(outputRoot, "output.bin"),
			}
			privateResult := runWithSeams(
				context.Background(),
				privateRequest,
				operationSeams{admitter: privateAdmitter},
			)
			if privateResult.Stage() != pcv3.StageCredentialPolicy ||
				privateResult.Diagnostic() != test.diagnostic || privateAdmitter.calls != 1 {
				t.Fatalf(
					"resource refusal = stage %v diagnostic %v calls %d; want credential-policy/%v/1",
					privateResult.Stage(), privateResult.Diagnostic(), privateAdmitter.calls,
					test.diagnostic,
				)
			}
			entries, err := os.ReadDir(outputRoot)
			if err != nil || len(entries) != 0 {
				t.Fatalf("resource refusal output entries = %v, error %v; want none", entries, err)
			}
			assertOperationPasswordZero(t, privatePassword)
			assertOperationFileClosed(t, privateSource)
			assertOperationKeyfilesClosedOnce(t, keyfiles)
		})
	}
}

func operationPasswordFactors(password []byte) *pcv3credential.FactorRequest {
	return &pcv3credential.FactorRequest{
		Mode:           pcv3credential.CredentialModePasswordOnly,
		KeyfileMode:    pcv3credential.KeyfileModeNone,
		ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly,
		Password:       password,
	}
}

func operationKeyfileHandles(readers []*operationObservedReadCloser) []*pcv3credential.KeyfileReader {
	handles := make([]*pcv3credential.KeyfileReader, len(readers))
	for index := range readers {
		handles[index] = pcv3credential.OwnKeyfileReader(readers[index])
	}
	return handles
}

func newOperationObservedKeyfile(t *testing.T, content []byte) *operationObservedReadCloser {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "keyfile-")
	if err != nil {
		t.Fatalf("create real keyfile descriptor: %v", err)
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		t.Fatalf("seed real keyfile descriptor: %v", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		t.Fatalf("rewind real keyfile descriptor: %v", err)
	}
	return &operationObservedReadCloser{file: file}
}

func openOperationNormalFixture(t *testing.T, name string) *os.File {
	t.Helper()
	path := filepath.Join("..", "pcv3", "testdata", "normal", "volumes", name)
	file, err := os.Open(path) // #nosec G304 -- frozen in-repository test fixture
	if err != nil {
		t.Fatalf("open frozen normal fixture %s: %v", name, err)
	}
	return file
}

func newOperationEmptySource(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "empty-source-")
	if err != nil {
		t.Fatalf("create real empty source: %v", err)
	}
	return file
}

func assertOperationRequestTransferred(t *testing.T, request *Request) {
	t.Helper()
	if request == nil || request.Mode != 0 || request.Source != nil || request.Factors != nil ||
		request.Target != "" || request.Protected != nil ||
		request.Reporter != nil || request.Consent != nil {
		t.Fatalf("operation request retained transferred input: %#v", request)
	}
}

func assertOperationPasswordZero(t *testing.T, password []byte) {
	t.Helper()
	for index, value := range password {
		if value != 0 {
			t.Fatalf("password byte %d survived ownership close: 0x%02x", index, value)
		}
	}
}

func assertOperationFileClosed(t *testing.T, file *os.File) {
	t.Helper()
	if file == nil {
		t.Fatal("test lost the original descriptor observer")
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("operation returned with its transferred source descriptor open")
	}
}

func assertOperationKeyfilesClosedOnce(t *testing.T, readers []*operationObservedReadCloser) {
	t.Helper()
	for index, reader := range readers {
		if reader.closeCalls != 1 {
			t.Fatalf("keyfile %d close calls = %d; want exactly one", index, reader.closeCalls)
		}
		if _, err := reader.file.Stat(); err == nil {
			t.Fatalf("keyfile %d underlying descriptor remains open", index)
		}
	}
}
