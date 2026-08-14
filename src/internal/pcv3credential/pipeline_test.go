package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

const pipelineSecretSentinel = "pcv3-pipeline-secret-sentinel"

type pipelineEntropy struct {
	calls        int
	failAt       int
	destinations [][]byte
}

func (entropy *pipelineEntropy) Read(destination []byte) (int, error) {
	entropy.calls++
	entropy.destinations = append(entropy.destinations, destination)
	for i := range destination {
		destination[i] = byte(entropy.calls*31 + i)
	}
	if entropy.calls == entropy.failAt {
		return len(destination) / 2, errors.New(pipelineSecretSentinel)
	}
	return len(destination), nil
}

type pipelineAdmission struct {
	calls    int
	result   KDFAdmission
	err      error
	profiles []KDFProfile
	onCall   func()
}

func (admission *pipelineAdmission) AdmitKDF(
	_ context.Context,
	profile KDFProfile,
) (KDFAdmission, error) {
	admission.calls++
	admission.profiles = append(admission.profiles, profile)
	if admission.onCall != nil {
		admission.onCall()
	}
	return admission.result, admission.err
}

type pipelineProbe struct {
	entropy *pipelineEntropy
	admit   *pipelineAdmission

	kdfCalls       int
	kdfInputs      [][]byte
	kdfSalts       [][]byte
	kdfReturns     [][]byte
	materialCalls  int
	published      int
	normalObserved int
	normalAliases  [][]byte

	cancelDuringKDF  context.CancelFunc
	kdfError         error
	materialError    error
	rootAliases      [][]byte
	volumeKeyAliases [][]byte
	extractRoots     [][]byte
	extractSalts     [][]byte
}

func newPipelineProbe() *pipelineProbe {
	return &pipelineProbe{
		entropy: &pipelineEntropy{},
		admit: &pipelineAdmission{
			result: KDFAdmissionGranted,
		},
	}
}

func (probe *pipelineProbe) seams() pipelineSeams {
	return pipelineSeams{
		entropy: probe.entropy,
		derive: func(
			input []byte,
			salt []byte,
			_ KDFProfile,
		) ([]byte, error) {
			probe.kdfCalls++
			probe.kdfInputs = append(probe.kdfInputs, input)
			probe.kdfSalts = append(probe.kdfSalts, salt)
			returned := bytes.Repeat(
				[]byte{byte(0x90 + probe.kdfCalls)},
				credentialRootBytes,
			)
			probe.kdfReturns = append(probe.kdfReturns, returned)
			if probe.cancelDuringKDF != nil {
				probe.cancelDuringKDF()
			}
			return returned, probe.kdfError
		},
		deriveMaterial: func(
			schedule *validatedSchedule,
			root *credentialRoot,
			key *volumeKey,
			volumeID []byte,
		) (*keyMaterial, error) {
			probe.materialCalls++
			if root != nil && root.secret != nil {
				probe.rootAliases = append(
					probe.rootAliases,
					root.secret.Bytes(),
				)
			}
			if key != nil && key.secret != nil {
				probe.volumeKeyAliases = append(
					probe.volumeKeyAliases,
					key.secret.Bytes(),
				)
			}
			if probe.materialError != nil {
				return nil, probe.materialError
			}
			return deriveKeyMaterialWith(
				schedule,
				root,
				key,
				volumeID,
				func(secret, salt []byte) ([]byte, error) {
					probe.extractRoots = append(
						probe.extractRoots,
						append([]byte(nil), secret...),
					)
					probe.extractSalts = append(
						probe.extractSalts,
						append([]byte(nil), salt...),
					)
					return bytes.Repeat(
						[]byte{byte(0xa0 + len(probe.extractRoots))},
						derivedKeyBytes,
					), nil
				},
				func(_ []byte, _ string, length int) ([]byte, error) {
					return bytes.Repeat([]byte{0xc1}, length), nil
				},
			)
		},
		observeNormalInput: func(input []byte) {
			probe.normalObserved++
			probe.normalAliases = append(probe.normalAliases, input)
		},
		observeOwner: func(*Owner) {
			probe.published++
		},
	}
}

func pipelineRequest(t *testing.T, suite Suite) *CredentialRequest {
	t.Helper()
	rows, err := fixedScheduleForSuite(suite)
	if err != nil {
		t.Fatalf("fixedScheduleForSuite(%#04x): %v", suite, err)
	}
	requests := make([]KeyRequest, len(rows))
	for i := range rows {
		requests[i] = rows[i].request
	}
	return &CredentialRequest{
		Suite: suite,
		Factors: &FactorRequest{
			Mode:           CredentialModePasswordOnly,
			KeyfileMode:    KeyfileModeNone,
			ExpectedPolicy: FactorPolicyPasswordOnly,
			Password:       []byte("correct horse battery staple"),
		},
		KeyRequests: requests,
	}
}

type ownerMetadataFactorCase struct {
	name        string
	mode        CredentialMode
	keyfileMode KeyfileMode
	policy      FactorPolicy
	password    []byte
	keyfiles    [][]byte
}

func ownerMetadataFactorCases() []ownerMetadataFactorCase {
	return []ownerMetadataFactorCase{
		{
			name: "password only", mode: CredentialModePasswordOnly,
			keyfileMode: KeyfileModeNone, policy: FactorPolicyPasswordOnly,
			password: []byte("metadata password"),
		},
		{
			name: "keyfiles only ordered", mode: CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeOrdered, policy: FactorPolicyKeyfilesOnly,
			keyfiles: [][]byte{[]byte("keyfile one"), []byte("keyfile two")},
		},
		{
			name: "keyfiles only unordered", mode: CredentialModeKeyfilesOnly,
			keyfileMode: KeyfileModeUnordered, policy: FactorPolicyKeyfilesOnly,
			keyfiles: [][]byte{[]byte("keyfile two"), []byte("keyfile one")},
		},
		{
			name: "combined ordered", mode: CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeOrdered, policy: FactorPolicyPasswordAndKeyfiles,
			password: []byte("metadata password"),
			keyfiles: [][]byte{[]byte("keyfile one"), []byte("keyfile two")},
		},
		{
			name: "combined unordered", mode: CredentialModePasswordAndKeyfiles,
			keyfileMode: KeyfileModeUnordered, policy: FactorPolicyPasswordAndKeyfiles,
			password: []byte("metadata password"),
			keyfiles: [][]byte{[]byte("keyfile two"), []byte("keyfile one")},
		},
	}
}

func factorRequestForOwnerMetadata(test ownerMetadataFactorCase) *FactorRequest {
	keyfiles := make([]*KeyfileReader, len(test.keyfiles))
	for i := range test.keyfiles {
		keyfiles[i] = OwnKeyfileReader(io.NopCloser(bytes.NewReader(test.keyfiles[i])))
	}
	return &FactorRequest{
		Mode:           test.mode,
		KeyfileMode:    test.keyfileMode,
		ExpectedPolicy: test.policy,
		Password:       append([]byte(nil), test.password...),
		Keyfiles:       keyfiles,
	}
}

func requirePipelineCode(
	t *testing.T,
	err error,
	code PipelineErrorCode,
	stage PipelineStage,
) *PipelineError {
	t.Helper()
	var pipelineErr *PipelineError
	if !errors.As(err, &pipelineErr) {
		t.Fatalf("error = %T %v; want *PipelineError", err, err)
	}
	if pipelineErr.Code != code || pipelineErr.Stage != stage {
		t.Fatalf(
			"pipeline error = code %d stage %d; want code %d stage %d",
			pipelineErr.Code,
			pipelineErr.Stage,
			code,
			stage,
		)
	}
	return pipelineErr
}

func requirePipelineBuffersZero(t *testing.T, buffers [][]byte) {
	t.Helper()
	for i, buffer := range buffers {
		if !allZero(buffer) {
			t.Fatalf("pipeline-controlled buffer %d was not cleared", i)
		}
	}
}

func TestPipelineRejectsBeforeEntropyAndKDF(t *testing.T) {
	tests := []struct {
		name          string
		edit          func(*CredentialRequest, *pipelineProbe)
		code          PipelineErrorCode
		stage         PipelineStage
		wantAdmission int
	}{
		{
			name: "invalid factors",
			edit: func(request *CredentialRequest, _ *pipelineProbe) {
				request.Factors.Mode = CredentialModeKeyfilesOnly
			},
			code:  PipelineErrorFactors,
			stage: PipelineStageFactors,
		},
		{
			name: "invalid transcript",
			edit: func(request *CredentialRequest, _ *pipelineProbe) {
				request.Factors.Password = []byte{0xff}
			},
			code:  PipelineErrorTranscript,
			stage: PipelineStageTranscript,
		},
		{
			name: "invalid suite",
			edit: func(request *CredentialRequest, _ *pipelineProbe) {
				request.Suite = Suite(0xffff)
			},
			code:  PipelineErrorSchedule,
			stage: PipelineStageSchedule,
		},
		{
			name: "invalid schedule",
			edit: func(request *CredentialRequest, _ *pipelineProbe) {
				request.KeyRequests = append(
					request.KeyRequests,
					request.KeyRequests[0],
				)
			},
			code:  PipelineErrorSchedule,
			stage: PipelineStageSchedule,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := pipelineRequest(t, SuiteStandard1)
			probe := newPipelineProbe()
			test.edit(request, probe)
			passwordAlias := request.Factors.Password

			owner, err := newCredential(
				context.Background(),
				request,
				probe.admit,
				probe.seams(),
			)
			requirePipelineCode(t, err, test.code, test.stage)
			if owner != nil ||
				probe.entropy.calls != 0 ||
				probe.kdfCalls != 0 ||
				probe.materialCalls != 0 ||
				probe.published != 0 ||
				probe.admit.calls != test.wantAdmission {
				if owner != nil {
					owner.Close()
				}
				t.Fatalf(
					"rejection owner/admission/entropy/KDF/material/publication = %v/%d/%d/%d/%d/%d; want nil/%d/0/0/0/0",
					owner,
					probe.admit.calls,
					probe.entropy.calls,
					probe.kdfCalls,
					probe.materialCalls,
					probe.published,
					test.wantAdmission,
				)
			}
			if !allZero(passwordAlias) {
				t.Fatal("rejected request retained transferred password")
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), pipelineSecretSentinel) {
				t.Fatal("pipeline diagnostics disclosed admission sentinel")
			}
		})
	}
}

func TestPipelineAdmissionOccursAtKDFBoundary(t *testing.T) {
	tests := []struct {
		name      string
		admission KDFAdmission
		wantOwner bool
		wantKDF   int
	}{
		{name: "granted", admission: KDFAdmissionGranted, wantOwner: true, wantKDF: 1},
		{name: "refused", admission: KDFAdmissionDenied},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe := newPipelineProbe()
			probe.admit.result = test.admission
			entropyAtAdmission := -1
			kdfAtAdmission := -1
			probe.admit.onCall = func() {
				entropyAtAdmission = probe.entropy.calls
				kdfAtAdmission = probe.kdfCalls
			}

			owner, err := newCredential(
				context.Background(),
				pipelineRequest(t, SuiteStandard1),
				probe.admit,
				probe.seams(),
			)
			if test.wantOwner {
				if err != nil || owner == nil {
					t.Fatalf("admitted pipeline = owner %v, error %v; want owner", owner, err)
				}
				owner.Close()
			} else {
				requirePipelineCode(t, err, PipelineErrorAdmission, PipelineStageAdmission)
				if owner != nil {
					owner.Close()
					t.Fatal("resource-refused pipeline published an owner")
				}
			}
			if entropyAtAdmission != 3 || kdfAtAdmission != 0 ||
				probe.entropy.calls != 3 || probe.admit.calls != 1 ||
				probe.kdfCalls != test.wantKDF {
				t.Fatalf(
					"boundary entropy/admission-KDF/final admission/KDF = %d/%d/%d/%d; want 3/0/1/%d",
					entropyAtAdmission, kdfAtAdmission, probe.admit.calls,
					probe.kdfCalls, test.wantKDF,
				)
			}
			if !test.wantOwner {
				if probe.materialCalls != 0 || probe.published != 0 {
					t.Fatalf(
						"resource refusal material/publication = %d/%d; want zero",
						probe.materialCalls, probe.published,
					)
				}
				requirePipelineBuffersZero(t, probe.entropy.destinations)
			}
		})
	}
}

func TestPipelineNormalCredentialInputOnly(t *testing.T) {
	request := pipelineRequest(t, SuiteStandard1)
	passwordAlias := request.Factors.Password
	probe := newPipelineProbe()
	if strings.Contains(
		fmt.Sprintf("%v %+v %#v", request, request, request),
		string(passwordAlias),
	) {
		t.Fatal("credential request diagnostics disclosed its password")
	}

	owner, err := newCredential(
		context.Background(),
		request,
		probe.admit,
		probe.seams(),
	)
	if err != nil {
		t.Fatalf("newCredential: %v", err)
	}
	defer owner.Close()

	if probe.normalObserved != 1 ||
		probe.kdfCalls != 1 ||
		len(probe.kdfInputs) != 1 ||
		len(probe.kdfInputs[0]) != credentialInputNormalBytes {
		t.Fatalf(
			"normal/KDF observations = %d/%d input widths %v; want 1/1/[64]",
			probe.normalObserved,
			probe.kdfCalls,
			func() []int {
				widths := make([]int, len(probe.kdfInputs))
				for i := range probe.kdfInputs {
					widths[i] = len(probe.kdfInputs[i])
				}
				return widths
			}(),
		)
	}
	if !allZero(passwordAlias) ||
		!allZero(probe.normalAliases[0]) ||
		!allZero(probe.kdfInputs[0]) {
		t.Fatal("normal-input path retained a factor or consumed input alias")
	}
}

func TestPipelineFreshEntropy(t *testing.T) {
	probe := newPipelineProbe()
	first, err := newCredential(
		context.Background(),
		pipelineRequest(t, SuiteStandard1),
		probe.admit,
		probe.seams(),
	)
	if err != nil {
		t.Fatalf("first newCredential: %v", err)
	}
	defer first.Close()
	firstMetadata := first.Metadata()

	second, err := newCredential(
		context.Background(),
		pipelineRequest(t, SuiteStandard1),
		probe.admit,
		probe.seams(),
	)
	if err != nil {
		t.Fatalf("second newCredential: %v", err)
	}
	defer second.Close()
	secondMetadata := second.Metadata()

	if probe.entropy.calls != 6 {
		t.Fatalf("entropy calls = %d; want 6", probe.entropy.calls)
	}
	wantWidths := []int{16, 32, 32, 16, 32, 32}
	for i, destination := range probe.entropy.destinations {
		if len(destination) != wantWidths[i] {
			t.Fatalf(
				"entropy destination %d width = %d; want %d",
				i,
				len(destination),
				wantWidths[i],
			)
		}
	}
	if firstMetadata.ArgonSalt == secondMetadata.ArgonSalt ||
		firstMetadata.VolumeID == secondMetadata.VolumeID {
		t.Fatal("successful calls reused public entropy")
	}
	requirePipelineBuffersZero(t, probe.entropy.destinations)
}

func TestPipelineSeparateRootsSharedVolumeID(t *testing.T) {
	probe := newPipelineProbe()
	owner, err := newCredential(
		context.Background(),
		pipelineRequest(t, SuiteStandard1),
		probe.admit,
		probe.seams(),
	)
	if err != nil {
		t.Fatalf("newCredential: %v", err)
	}
	metadata := owner.Metadata()
	defer owner.Close()
	defer func() {
		for _, value := range probe.extractRoots {
			crypto.SecureZero(value)
		}
		for _, value := range probe.extractSalts {
			crypto.SecureZero(value)
		}
	}()

	if len(probe.extractRoots) != 2 || len(probe.extractSalts) != 2 {
		t.Fatalf(
			"Extract observations = roots %d salts %d; want 2/2",
			len(probe.extractRoots),
			len(probe.extractSalts),
		)
	}
	if bytes.Equal(probe.extractRoots[0], probe.extractRoots[1]) {
		t.Fatal("CredentialPRK and VolumePRK reused the same IKM root")
	}
	if !bytes.Equal(probe.extractSalts[0], metadata.VolumeID[:]) ||
		!bytes.Equal(probe.extractSalts[1], metadata.VolumeID[:]) {
		t.Fatal("the two Extracts did not share the generated volume_id")
	}
}

func TestPipelineExactlyOneKDF(t *testing.T) {
	probe := newPipelineProbe()
	owner, err := newCredential(
		context.Background(),
		pipelineRequest(t, SuiteParanoid1),
		probe.admit,
		probe.seams(),
	)
	if err != nil {
		t.Fatalf("newCredential: %v", err)
	}
	defer owner.Close()

	if probe.admit.calls != 1 ||
		probe.kdfCalls != 1 ||
		probe.materialCalls != 1 ||
		probe.published != 1 {
		t.Fatalf(
			"calls admission/KDF/material/publication = %d/%d/%d/%d; want 1/1/1/1",
			probe.admit.calls,
			probe.kdfCalls,
			probe.materialCalls,
			probe.published,
		)
	}
	profile, err := fixedProfileForSuite(SuiteParanoid1)
	if err != nil {
		t.Fatalf("fixedProfileForSuite: %v", err)
	}
	if len(probe.admit.profiles) != 1 ||
		probe.admit.profiles[0] != profile {
		t.Fatal("pipeline adapted or repeated the suite-selected profile")
	}

}

func TestPipelinePreKDFCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	probe := newPipelineProbe()
	seams := probe.seams()
	seams.beforeKDF = cancel

	owner, err := newCredential(
		ctx,
		pipelineRequest(t, SuiteStandard1),
		probe.admit,
		seams,
	)
	requirePipelineCode(
		t,
		err,
		PipelineErrorCancelled,
		PipelineStageKDF,
	)
	if owner != nil ||
		probe.admit.calls != 0 ||
		probe.entropy.calls != 3 ||
		probe.kdfCalls != 0 ||
		probe.materialCalls != 0 ||
		probe.published != 0 {
		if owner != nil {
			owner.Close()
		}
		t.Fatalf(
			"pre-KDF cancel owner/admission/entropy/KDF/material/publication = %v/%d/%d/%d/%d/%d",
			owner,
			probe.admit.calls,
			probe.entropy.calls,
			probe.kdfCalls,
			probe.materialCalls,
			probe.published,
		)
	}
	requirePipelineBuffersZero(t, probe.entropy.destinations)
	requirePipelineBuffersZero(t, probe.normalAliases)
}

func TestPipelinePostKDFCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	probe := newPipelineProbe()
	probe.cancelDuringKDF = cancel

	owner, err := newCredential(
		ctx,
		pipelineRequest(t, SuiteStandard1),
		probe.admit,
		probe.seams(),
	)
	requirePipelineCode(
		t,
		err,
		PipelineErrorCancelled,
		PipelineStageKDF,
	)
	if owner != nil ||
		probe.admit.calls != 1 ||
		probe.entropy.calls != 3 ||
		probe.kdfCalls != 1 ||
		probe.materialCalls != 0 ||
		probe.published != 0 {
		if owner != nil {
			owner.Close()
		}
		t.Fatalf(
			"post-KDF cancel owner/admission/entropy/KDF/material/publication = %v/%d/%d/%d/%d/%d",
			owner,
			probe.admit.calls,
			probe.entropy.calls,
			probe.kdfCalls,
			probe.materialCalls,
			probe.published,
		)
	}
	requirePipelineBuffersZero(t, probe.kdfReturns)
	requirePipelineBuffersZero(t, probe.entropy.destinations)
	requirePipelineBuffersZero(t, probe.normalAliases)
}

func TestPipelineFailureCleanup(t *testing.T) {
	t.Run("entropy failure", func(t *testing.T) {
		probe := newPipelineProbe()
		probe.entropy.failAt = 3
		owner, err := newCredential(
			context.Background(),
			pipelineRequest(t, SuiteStandard1),
			probe.admit,
			probe.seams(),
		)
		requirePipelineCode(
			t,
			err,
			PipelineErrorEntropy,
			PipelineStageVolumeKey,
		)
		if owner != nil || probe.kdfCalls != 0 || probe.published != 0 {
			if owner != nil {
				owner.Close()
			}
			t.Fatal("entropy failure published work")
		}
		requirePipelineBuffersZero(t, probe.entropy.destinations)
		if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), pipelineSecretSentinel) {
			t.Fatal("entropy failure disclosed provider sentinel")
		}
	})

	t.Run("key derivation failure", func(t *testing.T) {
		probe := newPipelineProbe()
		probe.materialError = errors.New(pipelineSecretSentinel)
		owner, err := newCredential(
			context.Background(),
			pipelineRequest(t, SuiteStandard1),
			probe.admit,
			probe.seams(),
		)
		requirePipelineCode(
			t,
			err,
			PipelineErrorKeyDerivation,
			PipelineStageKeyDerivation,
		)
		if owner != nil ||
			probe.kdfCalls != 1 ||
			probe.materialCalls != 1 ||
			probe.published != 0 {
			if owner != nil {
				owner.Close()
			}
			t.Fatal("key-derivation failure call counts were not bounded")
		}
		requirePipelineBuffersZero(t, probe.kdfReturns)
		requirePipelineBuffersZero(t, probe.rootAliases)
		requirePipelineBuffersZero(t, probe.volumeKeyAliases)
		requirePipelineBuffersZero(t, probe.entropy.destinations)
		if strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), pipelineSecretSentinel) {
			t.Fatal("key-derivation failure disclosed provider sentinel")
		}
	})
}

func TestPipelinePublishesOneOwner(t *testing.T) {
	request := pipelineRequest(t, SuiteStandard1)
	firstRequest := request.KeyRequests[0]
	probe := newPipelineProbe()
	seams := probe.seams()
	var observedOwner *Owner
	seams.observeOwner = func(owner *Owner) {
		observedOwner = owner
	}

	owner, err := newCredential(
		context.Background(),
		request,
		probe.admit,
		seams,
	)
	if err != nil {
		t.Fatalf("newCredential: %v", err)
	}
	if owner == nil {
		if observedOwner != nil {
			observeErr := observedOwner.WithKeys(
				context.Background(),
				func(*BorrowedKeys) error { return nil },
			)
			var ownerErr *OwnerError
			if !errors.As(observeErr, &ownerErr) ||
				ownerErr.Code != OwnerErrorClosed {
				t.Fatalf(
					"unpublished owner cleanup = %v; want closed",
					observeErr,
				)
			}
		}
		t.Fatal("published owner = nil")
	}
	defer owner.Close()

	metadata := owner.Metadata()
	if metadata.Suite != SuiteStandard1 ||
		metadata.ExpectedPolicy != FactorPolicyPasswordOnly ||
		metadata.CredentialMode != CredentialModePasswordOnly ||
		metadata.KeyfileMode != KeyfileModeNone ||
		metadata.KeyfileCount != 0 {
		t.Fatalf("owner metadata = %+v", metadata)
	}
	copied := make([]byte, derivedKeyBytes)
	if err := owner.WithKeys(
		context.Background(),
		func(keys *BorrowedKeys) error {
			return keys.CopyKey(firstRequest, copied)
		},
	); err != nil {
		t.Fatalf("published owner borrow: %v", err)
	}
	if allZero(copied) {
		t.Fatal("published owner did not contain the admitted schedule")
	}
	crypto.SecureZero(copied)
}

func TestNewCredentialOwnerMetadataBindsValidatedFactors(t *testing.T) {
	for _, test := range ownerMetadataFactorCases() {
		t.Run(test.name, func(t *testing.T) {
			request := pipelineRequest(t, SuiteStandard1)
			if err := request.Factors.Close(); err != nil {
				t.Fatalf("close default factors: %v", err)
			}
			request.Factors = factorRequestForOwnerMetadata(test)
			probe := newPipelineProbe()
			owner, err := newCredential(
				context.Background(),
				request,
				probe.admit,
				probe.seams(),
			)
			if err != nil {
				t.Fatalf("newCredential: %v", err)
			}
			defer owner.Close()

			metadata := owner.Metadata()
			if metadata.CredentialMode != test.mode ||
				metadata.KeyfileMode != test.keyfileMode ||
				metadata.KeyfileCount != uint16(len(test.keyfiles)) ||
				metadata.ExpectedPolicy != test.policy {
				t.Fatalf("owner metadata = %+v; want mode/order/count/policy %d/%d/%d/%d", metadata, test.mode, test.keyfileMode, len(test.keyfiles), test.policy)
			}
		})
	}
}

func TestPipelineRetryFreshness(t *testing.T) {
	probe := newPipelineProbe()
	probe.kdfError = errors.New(pipelineSecretSentinel)
	first, err := newCredential(
		context.Background(),
		pipelineRequest(t, SuiteStandard1),
		probe.admit,
		probe.seams(),
	)
	requirePipelineCode(t, err, PipelineErrorKDF, PipelineStageKDF)
	if first != nil {
		first.Close()
		t.Fatal("failed first attempt published an owner")
	}
	firstEntropy := append([][]byte(nil), probe.entropy.destinations...)

	probe.kdfError = nil
	second, err := newCredential(
		context.Background(),
		pipelineRequest(t, SuiteStandard1),
		probe.admit,
		probe.seams(),
	)
	if err != nil {
		t.Fatalf("retry newCredential: %v", err)
	}
	defer second.Close()

	if probe.entropy.calls != 6 ||
		probe.kdfCalls != 2 ||
		probe.admit.calls != 2 ||
		probe.published != 1 {
		t.Fatalf(
			"retry calls entropy/KDF/admission/publication = %d/%d/%d/%d; want 6/2/2/1",
			probe.entropy.calls,
			probe.kdfCalls,
			probe.admit.calls,
			probe.published,
		)
	}
	requirePipelineBuffersZero(t, firstEntropy)
	requirePipelineBuffersZero(t, probe.kdfReturns)
	metadata := second.Metadata()
	if bytes.Equal(metadata.ArgonSalt[:], probe.kdfSalts[0]) {
		t.Fatal("retry reused the first attempt's Argon salt")
	}
}

var _ io.Reader = (*pipelineEntropy)(nil)
