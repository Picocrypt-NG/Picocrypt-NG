package pcv3credential

import (
	pcsecret "Picocrypt-NG/internal/secret"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
)

type credentialLifecycleCounts struct {
	entropyCalls         int
	kdfCalls             int
	expandCalls          int
	ownerPublications    int
	activeBorrows        int
	unclearedOwnedBuffer int
}

type credentialLifecycleProbe struct {
	entropy *pipelineEntropy
	admit   *pipelineAdmission

	kdfCalls          int
	expandCalls       int
	ownerPublications int
	kdfErr            error
	extractErrAt      int
	expandErrAt       int
	invalidateOwner   bool
	cancelDuringKDF   context.CancelFunc
	cancelAfterDerive context.CancelFunc
	kdfSaltSnapshots  [][]byte
	aliases           map[string][]byte
}

func newCredentialLifecycleProbe() *credentialLifecycleProbe {
	return &credentialLifecycleProbe{
		entropy: &pipelineEntropy{},
		admit: &pipelineAdmission{
			result: KDFAdmissionGranted,
		},
		aliases: make(map[string][]byte),
	}
}

func (probe *credentialLifecycleProbe) observe(
	name string,
	alias []byte,
) {
	if alias != nil {
		probe.aliases[name] = alias
	}
}

func (probe *credentialLifecycleProbe) observeMaterial(material *keyMaterial) {
	if material == nil {
		return
	}
	if material.credentialRoot != nil && material.credentialRoot.secret != nil {
		probe.observe(
			"material/CredentialRoot",
			material.credentialRoot.secret.Bytes(),
		)
	}
	if material.volumeKey != nil && material.volumeKey.secret != nil {
		probe.observe("material/VolumeKey", material.volumeKey.secret.Bytes())
	}
	if material.credentialPRK != nil && material.credentialPRK.secret != nil {
		probe.observe(
			"material/CredentialPRK",
			material.credentialPRK.secret.Bytes(),
		)
	}
	if material.volumePRK != nil && material.volumePRK.secret != nil {
		probe.observe("material/VolumePRK", material.volumePRK.secret.Bytes())
	}
	for i := range material.keys {
		if material.keys[i].secret != nil {
			probe.observe(
				fmt.Sprintf("material/DerivedKey[%d]", i),
				material.keys[i].secret.Bytes(),
			)
		}
	}
}

func (probe *credentialLifecycleProbe) seams() pipelineSeams {
	return pipelineSeams{
		entropy: probe.entropy,
		derive: func(
			_ []byte,
			salt []byte,
			_ KDFProfile,
		) ([]byte, error) {
			probe.kdfCalls++
			probe.kdfSaltSnapshots = append(
				probe.kdfSaltSnapshots,
				append([]byte(nil), salt...),
			)
			returned := bytes.Repeat(
				[]byte{byte(0x90 + probe.kdfCalls)},
				credentialRootBytes,
			)
			probe.observe(
				fmt.Sprintf("kdf/return[%d]", probe.kdfCalls),
				returned,
			)
			if probe.cancelDuringKDF != nil {
				probe.cancelDuringKDF()
			}
			return returned, probe.kdfErr
		},
		deriveMaterial: func(
			schedule *validatedSchedule,
			root *credentialRoot,
			key *volumeKey,
			volumeID []byte,
		) (*keyMaterial, error) {
			if root != nil && root.secret != nil {
				probe.observe("derive/CredentialRoot", root.secret.Bytes())
			}
			if key != nil && key.secret != nil {
				probe.observe("derive/VolumeKey", key.secret.Bytes())
			}
			extractCalls := 0
			material, err := deriveKeyMaterialWith(
				schedule,
				root,
				key,
				volumeID,
				func([]byte, []byte) ([]byte, error) {
					extractCalls++
					returned := bytes.Repeat(
						[]byte{byte(0xa0 + extractCalls)},
						derivedKeyBytes,
					)
					probe.observe(
						fmt.Sprintf("extract/return[%d]", extractCalls),
						returned,
					)
					if probe.extractErrAt == extractCalls {
						return returned, errors.New("injected extract failure")
					}
					return returned, nil
				},
				func([]byte, string, int) ([]byte, error) {
					probe.expandCalls++
					returned := bytes.Repeat(
						[]byte{byte(0xc0 + probe.expandCalls)},
						derivedKeyBytes,
					)
					probe.observe(
						fmt.Sprintf("expand/return[%d]", probe.expandCalls),
						returned,
					)
					if probe.expandErrAt == probe.expandCalls {
						return returned, errors.New("injected expand failure")
					}
					return returned, nil
				},
			)
			probe.observeMaterial(material)
			if err == nil && probe.invalidateOwner {
				material.keys[0].row.suite = Suite(0xffff)
			}
			if err == nil && probe.cancelAfterDerive != nil {
				probe.cancelAfterDerive()
			}
			return material, err
		},
		observeNormalInput: func(input []byte) {
			probe.observe("transcript/CredentialInputNormal", input)
		},
		observeOwner: func(*Owner) {
			probe.ownerPublications++
		},
	}
}

func (probe *credentialLifecycleProbe) counts(
	activeBorrows int,
) credentialLifecycleCounts {
	uncleared := 0
	for _, alias := range probe.aliases {
		if !allZero(alias) {
			uncleared++
		}
	}
	for _, alias := range probe.entropy.destinations {
		if !allZero(alias) {
			uncleared++
		}
	}
	return credentialLifecycleCounts{
		entropyCalls:         probe.entropy.calls,
		kdfCalls:             probe.kdfCalls,
		expandCalls:          probe.expandCalls,
		ownerPublications:    probe.ownerPublications,
		activeBorrows:        activeBorrows,
		unclearedOwnedBuffer: uncleared,
	}
}

func requireCredentialLifecycleCounts(
	t *testing.T,
	got credentialLifecycleCounts,
	want credentialLifecycleCounts,
) {
	t.Helper()
	if got != want {
		t.Fatalf("lifecycle counts = %+v; want %+v", got, want)
	}
}

func requireCredentialPipelineFailure(
	t *testing.T,
	err error,
	code PipelineErrorCode,
	stage PipelineStage,
) {
	t.Helper()
	requirePipelineCode(t, err, code, stage)
}

func requirePipelinePreExpandScheduleValidation(t *testing.T) {
	t.Helper()
	request := pipelineRequest(t, SuiteStandard1)
	allRequests := request.KeyRequests
	request.KeyRequests = []KeyRequest{
		allRequests[0],
		allRequests[1],
		allRequests[0],
	}
	passwordAlias := request.Factors.Password
	probe := newCredentialLifecycleProbe()
	owner, err := newCredential(
		context.Background(),
		request,
		probe.admit,
		probe.seams(),
	)
	if owner != nil {
		owner.Close()
		t.Fatal("schedule rejection published an owner")
	}
	requireCredentialPipelineFailure(
		t,
		err,
		PipelineErrorSchedule,
		PipelineStageSchedule,
	)
	if !allZero(passwordAlias) {
		t.Fatal("schedule rejection retained the password")
	}
	requireCredentialLifecycleCounts(
		t,
		probe.counts(0),
		credentialLifecycleCounts{},
	)
}

func TestCredentialLifecycleExitMatrix(t *testing.T) {
	const standardExpands = 9
	required := map[string]bool{
		"success":                   false,
		"factor-validation":         false,
		"reader-failure":            false,
		"reader-close-failure":      false,
		"schedule-validation":       false,
		"transcript-validation":     false,
		"admission-failure":         false,
		"entropy-argon-salt":        false,
		"entropy-volume-id":         false,
		"entropy-volume-key":        false,
		"initial-cancellation":      false,
		"pre-kdf-cancellation":      false,
		"kdf-failure":               false,
		"post-kdf-cancellation":     false,
		"owner-stage-cancellation":  false,
		"derivation-extract":        false,
		"derivation-expand":         false,
		"owner-publication-failure": false,
		"callback-return":           false,
		"callback-error":            false,
		"callback-cancellation":     false,
		"explicit-close":            false,
	}
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "success",
			run: func(t *testing.T) {
				request := pipelineRequest(t, SuiteStandard1)
				passwordAlias := request.Factors.Password
				probe := newCredentialLifecycleProbe()
				owner, err := newCredential(
					context.Background(),
					request,
					probe.admit,
					probe.seams(),
				)
				if err != nil {
					t.Fatalf("newCredential: %v", err)
				}
				owner.Close()
				if !allZero(passwordAlias) {
					t.Fatal("success retained the transferred password")
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{
						entropyCalls:      3,
						kdfCalls:          1,
						expandCalls:       standardExpands,
						ownerPublications: 1,
					},
				)
			},
		},
		{
			name: "factor-validation",
			run: func(t *testing.T) {
				request := pipelineRequest(t, SuiteStandard1)
				passwordAlias := request.Factors.Password
				request.Factors.Mode = CredentialModeKeyfilesOnly
				probe := newCredentialLifecycleProbe()
				owner, err := newCredential(
					context.Background(),
					request,
					probe.admit,
					probe.seams(),
				)
				if owner != nil {
					owner.Close()
					t.Fatal("factor rejection published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorFactors,
					PipelineStageFactors,
				)
				if !allZero(passwordAlias) {
					t.Fatal("factor rejection retained the transferred password")
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{},
				)
			},
		},
		{
			name: "reader-failure",
			run: func(t *testing.T) {
				readErr := errors.New("injected keyfile read failure")
				reader := newImmediateErrorReadCloser(readErr)
				request := pipelineRequest(t, SuiteStandard1)
				request.Factors = &FactorRequest{
					Mode:           CredentialModeKeyfilesOnly,
					KeyfileMode:    KeyfileModeOrdered,
					ExpectedPolicy: FactorPolicyKeyfilesOnly,
					Keyfiles:       ownKeyfileReaders(reader),
				}
				probe := newCredentialLifecycleProbe()
				owner, err := newCredential(
					context.Background(),
					request,
					probe.admit,
					probe.seams(),
				)
				if owner != nil {
					owner.Close()
					t.Fatal("reader failure published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorFactors,
					PipelineStageFactors,
				)
				if reader.readCalls != 1 || reader.closeCalls != 1 {
					t.Fatalf(
						"reader calls read/close = %d/%d; want 1/1",
						reader.readCalls,
						reader.closeCalls,
					)
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{},
				)
			},
		},
		{
			name: "reader-close-failure",
			run: func(t *testing.T) {
				reader := newChunkedReadCloser([]byte("keyfile secret"), 4)
				reader.closeErr = errors.New("injected keyfile close failure")
				request := pipelineRequest(t, SuiteStandard1)
				request.Factors = &FactorRequest{
					Mode:           CredentialModeKeyfilesOnly,
					KeyfileMode:    KeyfileModeOrdered,
					ExpectedPolicy: FactorPolicyKeyfilesOnly,
					Keyfiles:       ownKeyfileReaders(reader),
				}
				probe := newCredentialLifecycleProbe()
				owner, err := newCredential(
					context.Background(),
					request,
					probe.admit,
					probe.seams(),
				)
				if owner != nil {
					owner.Close()
					t.Fatal("close failure published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorFactors,
					PipelineStageFactors,
				)
				if reader.closeCalls != 1 {
					t.Fatalf("reader close calls = %d; want 1", reader.closeCalls)
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{},
				)
			},
		},
		{
			name: "schedule-validation",
			run: func(t *testing.T) {
				requirePipelinePreExpandScheduleValidation(t)
			},
		},
		{
			name: "transcript-validation",
			run: func(t *testing.T) {
				request := pipelineRequest(t, SuiteStandard1)
				request.Factors.Password = []byte{0xff}
				passwordAlias := request.Factors.Password
				probe := newCredentialLifecycleProbe()
				owner, err := newCredential(
					context.Background(),
					request,
					probe.admit,
					probe.seams(),
				)
				if owner != nil {
					owner.Close()
					t.Fatal("transcript rejection published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorTranscript,
					PipelineStageTranscript,
				)
				if !allZero(passwordAlias) {
					t.Fatal("transcript rejection retained the password")
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{},
				)
			},
		},
		{
			name: "admission-failure",
			run: func(t *testing.T) {
				request := pipelineRequest(t, SuiteStandard1)
				passwordAlias := request.Factors.Password
				probe := newCredentialLifecycleProbe()
				probe.admit.result = KDFAdmissionDenied
				owner, err := newCredential(
					context.Background(),
					request,
					probe.admit,
					probe.seams(),
				)
				if owner != nil {
					owner.Close()
					t.Fatal("admission failure published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorAdmission,
					PipelineStageAdmission,
				)
				if !allZero(passwordAlias) {
					t.Fatal("admission failure retained the password")
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{entropyCalls: 3},
				)
			},
		},
		{
			name: "entropy-argon-salt",
			run: func(t *testing.T) {
				testCredentialEntropyFailure(
					t,
					1,
					PipelineStageArgonSalt,
				)
			},
		},
		{
			name: "entropy-volume-id",
			run: func(t *testing.T) {
				testCredentialEntropyFailure(t, 2, PipelineStageVolumeID)
			},
		},
		{
			name: "entropy-volume-key",
			run: func(t *testing.T) {
				testCredentialEntropyFailure(t, 3, PipelineStageVolumeKey)
			},
		},
		{
			name: "initial-cancellation",
			run: func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				request := pipelineRequest(t, SuiteStandard1)
				passwordAlias := request.Factors.Password
				probe := newCredentialLifecycleProbe()
				owner, err := newCredential(
					ctx,
					request,
					probe.admit,
					probe.seams(),
				)
				if owner != nil {
					owner.Close()
					t.Fatal("initial cancellation published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorCancelled,
					PipelineStageFactors,
				)
				if !allZero(passwordAlias) {
					t.Fatal("initial cancellation retained the password")
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{},
				)
			},
		},
		{
			name: "pre-kdf-cancellation",
			run: func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				request := pipelineRequest(t, SuiteStandard1)
				passwordAlias := request.Factors.Password
				probe := newCredentialLifecycleProbe()
				seams := probe.seams()
				seams.beforeKDF = cancel
				owner, err := newCredential(
					ctx,
					request,
					probe.admit,
					seams,
				)
				if owner != nil {
					owner.Close()
					t.Fatal("pre-KDF cancellation published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorCancelled,
					PipelineStageKDF,
				)
				if !allZero(passwordAlias) {
					t.Fatal("pre-KDF cancellation retained the password")
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{entropyCalls: 3},
				)
			},
		},
		{
			name: "kdf-failure",
			run: func(t *testing.T) {
				request := pipelineRequest(t, SuiteStandard1)
				passwordAlias := request.Factors.Password
				probe := newCredentialLifecycleProbe()
				probe.kdfErr = errors.New("injected KDF failure")
				owner, err := newCredential(
					context.Background(),
					request,
					probe.admit,
					probe.seams(),
				)
				if owner != nil {
					owner.Close()
					t.Fatal("KDF failure published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorKDF,
					PipelineStageKDF,
				)
				if !allZero(passwordAlias) {
					t.Fatal("KDF failure retained the password")
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{
						entropyCalls: 3,
						kdfCalls:     1,
					},
				)
			},
		},
		{
			name: "post-kdf-cancellation",
			run: func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				request := pipelineRequest(t, SuiteStandard1)
				passwordAlias := request.Factors.Password
				probe := newCredentialLifecycleProbe()
				probe.cancelDuringKDF = cancel
				owner, err := newCredential(
					ctx,
					request,
					probe.admit,
					probe.seams(),
				)
				if owner != nil {
					owner.Close()
					t.Fatal("post-KDF cancellation published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorCancelled,
					PipelineStageKDF,
				)
				if !allZero(passwordAlias) {
					t.Fatal("post-KDF cancellation retained the password")
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{
						entropyCalls: 3,
						kdfCalls:     1,
					},
				)
			},
		},
		{
			name: "derivation-extract",
			run: func(t *testing.T) {
				testCredentialDerivationFailure(
					t,
					1,
					0,
					0,
				)
			},
		},
		{
			name: "owner-stage-cancellation",
			run: func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				request := pipelineRequest(t, SuiteStandard1)
				passwordAlias := request.Factors.Password
				probe := newCredentialLifecycleProbe()
				probe.cancelAfterDerive = cancel
				owner, err := newCredential(
					ctx,
					request,
					probe.admit,
					probe.seams(),
				)
				if owner != nil {
					owner.Close()
					t.Fatal("owner-stage cancellation published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorCancelled,
					PipelineStageOwner,
				)
				if !allZero(passwordAlias) {
					t.Fatal("owner-stage cancellation retained the password")
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{
						entropyCalls: 3,
						kdfCalls:     1,
						expandCalls:  standardExpands,
					},
				)
			},
		},
		{
			name: "derivation-expand",
			run: func(t *testing.T) {
				testCredentialDerivationFailure(
					t,
					0,
					4,
					4,
				)
			},
		},
		{
			name: "owner-publication-failure",
			run: func(t *testing.T) {
				request := pipelineRequest(t, SuiteStandard1)
				passwordAlias := request.Factors.Password
				probe := newCredentialLifecycleProbe()
				probe.invalidateOwner = true
				owner, err := newCredential(
					context.Background(),
					request,
					probe.admit,
					probe.seams(),
				)
				if owner != nil {
					owner.Close()
					t.Fatal("owner validation failure published an owner")
				}
				requireCredentialPipelineFailure(
					t,
					err,
					PipelineErrorOwner,
					PipelineStageOwner,
				)
				if !allZero(passwordAlias) {
					t.Fatal("owner validation failure retained the password")
				}
				requireCredentialLifecycleCounts(
					t,
					probe.counts(0),
					credentialLifecycleCounts{
						entropyCalls: 3,
						kdfCalls:     1,
						expandCalls:  standardExpands,
					},
				)
			},
		},
		{
			name: "callback-return",
			run: func(t *testing.T) {
				testCredentialOwnerCallback(
					t,
					func(*BorrowedKeys) error { return nil },
					nil,
				)
			},
		},
		{
			name: "callback-error",
			run: func(t *testing.T) {
				testCredentialOwnerCallback(
					t,
					func(*BorrowedKeys) error {
						return errors.New("injected callback failure")
					},
					newOwnerError(OwnerErrorCallback),
				)
			},
		},
		{
			name: "callback-cancellation",
			run: func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				testCredentialOwnerCallbackWithContext(
					t,
					ctx,
					func(*BorrowedKeys) error {
						cancel()
						return nil
					},
					newOwnerError(OwnerErrorCancelled),
				)
			},
		},
		{
			name: "explicit-close",
			run: func(t *testing.T) {
				fixture := newOwnerFixture(t)
				fixture.owner.Close()
				fixture.owner.Close()
				requireOwnerAliasesZero(t, fixture.aliases)
				requireCredentialLifecycleCounts(
					t,
					credentialLifecycleCounts{},
					credentialLifecycleCounts{},
				)
			},
		},
	}

	for _, test := range tests {
		if _, ok := required[test.name]; !ok {
			t.Fatalf("unregistered lifecycle case %q", test.name)
		}
		if required[test.name] {
			t.Fatalf("duplicate lifecycle case %q", test.name)
		}
		required[test.name] = true
		requireNoCredentialProcessOutput(t, test.name, func() {
			t.Run(test.name, test.run)
		})
	}
	for name, covered := range required {
		if !covered {
			t.Errorf("missing deterministic lifecycle proof for %q", name)
		}
	}
}

func TestPipelinePreExpandScheduleValidationMutation(t *testing.T) {
	requirePipelinePreExpandScheduleValidation(t)
}

func requireNoCredentialProcessOutput(
	t *testing.T,
	name string,
	callback func(),
) {
	t.Helper()
	stdout, stderr, logs := captureCredentialProcessOutput(t, callback)
	if stdout != "" || stderr != "" || logs != "" {
		t.Fatalf(
			"lifecycle case %q wrote package output: stdout=%q stderr=%q logs=%q",
			name,
			stdout,
			stderr,
			logs,
		)
	}
}

func testCredentialEntropyFailure(
	t *testing.T,
	failAt int,
	stage PipelineStage,
) {
	t.Helper()
	request := pipelineRequest(t, SuiteStandard1)
	passwordAlias := request.Factors.Password
	probe := newCredentialLifecycleProbe()
	probe.entropy.failAt = failAt
	owner, err := newCredential(
		context.Background(),
		request,
		probe.admit,
		probe.seams(),
	)
	if owner != nil {
		owner.Close()
		t.Fatal("entropy failure published an owner")
	}
	requireCredentialPipelineFailure(
		t,
		err,
		PipelineErrorEntropy,
		stage,
	)
	if !allZero(passwordAlias) {
		t.Fatal("entropy failure retained the password")
	}
	requireCredentialLifecycleCounts(
		t,
		probe.counts(0),
		credentialLifecycleCounts{entropyCalls: failAt},
	)
}

func testCredentialDerivationFailure(
	t *testing.T,
	extractErrAt int,
	expandErrAt int,
	wantExpands int,
) {
	t.Helper()
	request := pipelineRequest(t, SuiteStandard1)
	passwordAlias := request.Factors.Password
	probe := newCredentialLifecycleProbe()
	probe.extractErrAt = extractErrAt
	probe.expandErrAt = expandErrAt
	owner, err := newCredential(
		context.Background(),
		request,
		probe.admit,
		probe.seams(),
	)
	if owner != nil {
		owner.Close()
		t.Fatal("derivation failure published an owner")
	}
	requireCredentialPipelineFailure(
		t,
		err,
		PipelineErrorKeyDerivation,
		PipelineStageKeyDerivation,
	)
	if !allZero(passwordAlias) {
		t.Fatal("derivation failure retained the password")
	}
	requireCredentialLifecycleCounts(
		t,
		probe.counts(0),
		credentialLifecycleCounts{
			entropyCalls: 3,
			kdfCalls:     1,
			expandCalls:  wantExpands,
		},
	)
}

func testCredentialOwnerCallback(
	t *testing.T,
	callback func(*BorrowedKeys) error,
	wantErr error,
) {
	t.Helper()
	testCredentialOwnerCallbackWithContext(
		t,
		context.Background(),
		callback,
		wantErr,
	)
}

func testCredentialOwnerCallbackWithContext(
	t *testing.T,
	ctx context.Context,
	callback func(*BorrowedKeys) error,
	wantErr error,
) {
	t.Helper()
	fixture := newOwnerFixture(t)
	activeBorrows := 0
	var retained *BorrowedKeys
	err := fixture.owner.WithKeys(ctx, func(keys *BorrowedKeys) error {
		activeBorrows++
		retained = keys
		defer func() {
			activeBorrows--
		}()
		return callback(keys)
	})
	if wantErr == nil {
		if err != nil {
			fixture.owner.Close()
			t.Fatalf("WithKeys: %v", err)
		}
	} else {
		var got *OwnerError
		var want *OwnerError
		if !errors.As(err, &got) ||
			!errors.As(wantErr, &want) ||
			got.Code != want.Code {
			fixture.owner.Close()
			t.Fatalf("WithKeys error = %T %v; want code %d", err, err, want.Code)
		}
	}
	if retained == nil {
		fixture.owner.Close()
		t.Fatal("callback did not receive its scoped borrow")
	}
	destination := make([]byte, derivedKeyBytes)
	if err := retained.CopyVolumeKey(destination); err == nil {
		fixture.owner.Close()
		t.Fatal("borrow survived callback return")
	}
	fixture.owner.Close()
	requireOwnerAliasesZero(t, fixture.aliases)
	requireCredentialLifecycleCounts(
		t,
		credentialLifecycleCounts{activeBorrows: activeBorrows},
		credentialLifecycleCounts{},
	)
}

func TestCredentialActiveBorrowCloseBarrier(t *testing.T) {
	requireNoCredentialProcessOutput(t, "active-borrow-close-barrier", func() {
		testCredentialActiveBorrowCloseBarrier(t)
	})
}

func testCredentialActiveBorrowCloseBarrier(t *testing.T) {
	t.Helper()
	fixture := newOwnerFixture(t)
	borrowStarted := make(chan *BorrowedKeys, 1)
	releaseBorrow := make(chan struct{})
	callbackDone := make(chan error, 1)
	go func() {
		callbackDone <- fixture.owner.WithKeys(
			context.Background(),
			func(keys *BorrowedKeys) error {
				borrowStarted <- keys
				<-releaseBorrow
				return nil
			},
		)
	}()

	borrow := <-borrowStarted
	live := make([]byte, derivedKeyBytes)
	if err := borrow.CopyVolumeKey(live); err != nil {
		close(releaseBorrow)
		<-callbackDone
		fixture.owner.Close()
		t.Fatalf("live borrow: %v", err)
	}
	if allZero(live) {
		close(releaseBorrow)
		<-callbackDone
		fixture.owner.Close()
		t.Fatal("live borrow observed cleared VolumeKey")
	}
	pcsecret.SecureZero(live)

	closeDone := make(chan struct{})
	go func() {
		fixture.owner.Close()
		close(closeDone)
	}()
	<-fixture.owner.state.closing

	select {
	case <-closeDone:
		close(releaseBorrow)
		<-callbackDone
		t.Fatal("Close returned while a borrow remained active")
	default:
	}
	for name, alias := range fixture.aliases {
		if allZero(alias) {
			close(releaseBorrow)
			<-callbackDone
			<-closeDone
			t.Fatalf("Close cleared %s while it remained borrowed", name)
		}
	}

	close(releaseBorrow)
	if err := <-callbackDone; err != nil {
		<-closeDone
		t.Fatalf("WithKeys: %v", err)
	}
	<-closeDone
	requireOwnerAliasesZero(t, fixture.aliases)
	destination := make([]byte, derivedKeyBytes)
	if err := borrow.CopyVolumeKey(destination); err == nil {
		t.Fatal("borrow survived release")
	}
}

func TestCredentialCallbackPanicCleanup(t *testing.T) {
	requireNoCredentialProcessOutput(t, "callback-panic-cleanup", func() {
		testCredentialCallbackPanicCleanup(t)
	})
}

func testCredentialCallbackPanicCleanup(t *testing.T) {
	t.Helper()
	fixture := newOwnerFixture(t)
	var retained *BorrowedKeys
	panicValue := func() (recovered any) {
		defer func() {
			recovered = recover()
		}()
		_ = fixture.owner.WithKeys(
			context.Background(),
			func(keys *BorrowedKeys) error {
				retained = keys
				panic("credential callback panic marker")
			},
		)
		return nil
	}()
	if panicValue != "credential callback panic marker" {
		fixture.owner.Close()
		t.Fatalf("recovered panic = %#v", panicValue)
	}
	destination := make([]byte, derivedKeyBytes)
	if retained == nil || retained.CopyVolumeKey(destination) == nil {
		fixture.owner.Close()
		t.Fatal("panic left the scoped borrow live")
	}
	fixture.owner.Close()
	requireOwnerAliasesZero(t, fixture.aliases)
}

func TestCredentialRetryFreshnessAndCleanup(t *testing.T) {
	requireNoCredentialProcessOutput(t, "retry-freshness-and-cleanup", func() {
		testCredentialRetryFreshnessAndCleanup(t)
	})
}

func testCredentialRetryFreshnessAndCleanup(t *testing.T) {
	t.Helper()
	probe := newCredentialLifecycleProbe()
	probe.kdfErr = errors.New("injected first-attempt KDF failure")
	first, err := newCredential(
		context.Background(),
		pipelineRequest(t, SuiteStandard1),
		probe.admit,
		probe.seams(),
	)
	requireCredentialPipelineFailure(
		t,
		err,
		PipelineErrorKDF,
		PipelineStageKDF,
	)
	if first != nil {
		first.Close()
		t.Fatal("failed attempt published an owner")
	}
	if len(probe.kdfSaltSnapshots) != 1 {
		t.Fatalf(
			"failed attempt KDF salt snapshots = %d; want 1",
			len(probe.kdfSaltSnapshots),
		)
	}
	firstSalt := append([]byte(nil), probe.kdfSaltSnapshots[0]...)
	firstAliases := make(map[string][]byte, len(probe.aliases))
	for name, alias := range probe.aliases {
		firstAliases[name] = alias
	}
	for name, alias := range firstAliases {
		if !allZero(alias) {
			t.Fatalf("failed retry attempt retained %s", name)
		}
	}

	probe.kdfErr = nil
	second, err := newCredential(
		context.Background(),
		pipelineRequest(t, SuiteStandard1),
		probe.admit,
		probe.seams(),
	)
	if err != nil {
		t.Fatalf("retry newCredential: %v", err)
	}
	metadata := second.Metadata()
	second.Close()
	if len(probe.kdfSaltSnapshots) != 2 {
		t.Fatalf(
			"retry KDF salt snapshots = %d; want 2",
			len(probe.kdfSaltSnapshots),
		)
	}
	if !bytes.Equal(metadata.ArgonSalt[:], probe.kdfSaltSnapshots[1]) {
		t.Fatal("published retry metadata did not preserve its KDF salt")
	}
	if bytes.Equal(probe.kdfSaltSnapshots[1], firstSalt) {
		t.Fatal("retry reused the failed attempt's Argon salt")
	}
	pcsecret.SecureZero(firstSalt)
	for _, snapshot := range probe.kdfSaltSnapshots {
		pcsecret.SecureZero(snapshot)
	}
	requireCredentialLifecycleCounts(
		t,
		probe.counts(0),
		credentialLifecycleCounts{
			entropyCalls:      6,
			kdfCalls:          2,
			expandCalls:       9,
			ownerPublications: 1,
		},
	)
}

var _ io.Reader = (*pipelineEntropy)(nil)
