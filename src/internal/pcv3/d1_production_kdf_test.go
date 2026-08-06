//go:build pcv3_private_corpus && pcv3_production_kdf

package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3corpus"
	"Picocrypt-NG/internal/pcv3credential"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"testing"
)

var d1ProductionKDFFixtureIDs = []string{
	"d1-paranoid-password-only-healthy",
	"d1-paranoid-keyfiles-only-healthy",
	"d1-paranoid-combined-ordered-healthy",
	"d1-paranoid-combined-unordered-healthy",
	"d1-degraded-front-bootstrap-only",
	"d1-degraded-tail-bootstrap-only",
	"d1-negative-wrong-credential",
	"d1-negative-record-tamper",
	"d1-negative-record-reorder",
	"d1-negative-body-truncation",
	"d1-negative-final-loss",
	"d1-negative-bootstrap-splice",
	"d1-negative-anchored-ambiguity",
	"d1-negative-inner-volume",
}

type d1ProductionKDFAdmitter struct {
	calls          int
	active         atomic.Int32
	maximumActive  atomic.Int32
	profileInvalid bool
}

func (admitter *d1ProductionKDFAdmitter) AdmitKDF(
	ctx context.Context,
	profile pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	active := admitter.active.Add(1)
	defer admitter.active.Add(-1)
	for {
		maximum := admitter.maximumActive.Load()
		if active <= maximum || admitter.maximumActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	admitter.calls++
	if ctx == nil || ctx.Err() != nil {
		return pcv3credential.KDFAdmissionDenied, ctx.Err()
	}
	if profile.ID != 0x02 || profile.Argon2Version != 0x13 || profile.Time != 8 ||
		profile.MemoryKiB != 1_048_576 || profile.Parallelism != 8 ||
		profile.SaltBytes != 16 || profile.OutputBytes != 32 {
		admitter.profileInvalid = true
	}
	return pcv3credential.KDFAdmissionGranted, nil
}

type d1ProductionKDFKeyfile struct {
	reader     *bytes.Reader
	ownedBytes []byte
	readBytes  int
	closeCalls int
}

func (keyfile *d1ProductionKDFKeyfile) Read(destination []byte) (int, error) {
	count, err := keyfile.reader.Read(destination)
	keyfile.readBytes += count
	return count, err
}

func (keyfile *d1ProductionKDFKeyfile) Close() error {
	keyfile.closeCalls++
	pcv3crypto.SecureZero(keyfile.ownedBytes)
	return nil
}

var _ io.ReadCloser = (*d1ProductionKDFKeyfile)(nil)

func TestD1ProductionKDF(t *testing.T) {
	root, rootPresent := os.LookupEnv(productionKDFPrivateRootEnv)
	if !rootPresent || root == "" {
		t.Fatalf("%s must be set for the private D1 production-KDF test", productionKDFPrivateRootEnv)
	}
	custodyID, custodyPresent := os.LookupEnv(productionKDFPrivateCustodyEnv)
	if !custodyPresent || custodyID == "" {
		t.Fatalf("%s must be set for the private D1 production-KDF test", productionKDFPrivateCustodyEnv)
	}

	err := pcv3corpus.WithD1VolumeFixtures(
		root,
		custodyID,
		d1ProductionKDFFixtureIDs,
		func(fixtures []*pcv3corpus.D1VolumeFixture) error {
			if len(fixtures) != len(d1ProductionKDFFixtureIDs) {
				return errors.New("private D1 fixture inventory was incomplete")
			}
			for fixtureIndex, fixture := range fixtures {
				if fixture == nil || fixture.ID() != d1ProductionKDFFixtureIDs[fixtureIndex] {
					return errors.New("private D1 fixture order did not match the closed inventory")
				}
				operations := fixture.Operations()
				if len(operations) < 2 {
					return errors.New("private D1 fixture omitted required normal or Force evidence")
				}
				for _, operation := range operations {
					operation := operation
					t.Run(fixture.ID()+"/"+operation.Name(), func(t *testing.T) {
						if err := runD1ProductionKDFOperation(fixture, operation); err != nil {
							t.Fatal(err)
						}
					})
				}
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("load private D1 production-KDF fixtures: %v", err)
	}
}

func runD1ProductionKDFOperation(
	fixture *pcv3corpus.D1VolumeFixture,
	operation pcv3corpus.D1OperationExpectation,
) (resultErr error) {
	factors, passwordAlias, keyfiles, err := newD1ProductionKDFFactors(fixture, operation)
	if err != nil {
		return err
	}
	defer func() {
		recovered := recover()
		_ = factors.Close()
		if cleanupErr := verifyD1ProductionKDFFactorCleanup(factors, passwordAlias, keyfiles); cleanupErr != nil && resultErr == nil {
			resultErr = cleanupErr
		}
		if recovered != nil {
			panic(recovered)
		}
	}()

	admitter := &d1ProductionKDFAdmitter{}
	callbackCalls := 0
	var callbackErr error
	output := func(result *RecoveryResult, _ D1BootstrapRole, emit RecoveryEmitter) error {
		callbackCalls++
		if !operation.ExpectedCompletion() || operation.ExpectedOutput() == "none" {
			return errors.New("D1 recovery published output for a no-output schedule")
		}
		callbackErr = verifyD1ProductionKDFEmission(fixture, operation, result, emit)
		return callbackErr
	}

	volume := fixture.Volume()
	var result *RecoveryResult
	switch operation.Mode() {
	case "normal":
		result, err = RecoverD1(
			context.Background(), bytes.NewReader(volume), int64(len(volume)), factors, admitter,
			RecoveryModeNormalV3, output,
		)
	case "force":
		result, err = RecoverD1(
			context.Background(), bytes.NewReader(volume), int64(len(volume)), factors, admitter,
			RecoveryModeForce, output,
		)
	case "force-unverified":
		role, roleOK := d1ProductionKDFUnverifiedRole(operation.UnverifiedRole())
		if !roleOK {
			return errors.New("private D1 schedule selected an invalid unverified role")
		}
		result, err = RecoverD1Unverified(
			context.Background(), bytes.NewReader(volume), int64(len(volume)), factors, admitter,
			role, output,
		)
	default:
		return errors.New("private D1 schedule selected an unknown recovery mode")
	}
	if result != nil {
		defer result.Close()
	}
	if callbackErr != nil {
		return callbackErr
	}
	if err != nil {
		if result != nil {
			return fmt.Errorf(
				"private D1 production recovery returned an operational error at closed stage %s",
				result.Stage().String(),
			)
		}
		return errors.New("private D1 production recovery returned an operational error without a semantic result")
	}
	if result == nil {
		return errors.New("private D1 production recovery returned no semantic result")
	}
	if err := verifyD1ProductionKDFResult(result, operation); err != nil {
		return err
	}
	wantCallbacks := 0
	if operation.ExpectedCompletion() {
		wantCallbacks = 1
	}
	if callbackCalls != wantCallbacks {
		return fmt.Errorf("D1 output callbacks = %d; want %d", callbackCalls, wantCallbacks)
	}
	if admitter.profileInvalid {
		return errors.New("D1 production KDF did not use the fixed Paranoid-1 profile")
	}
	if admitter.calls != operation.ExpectedKDFCalls() {
		return fmt.Errorf("D1 production KDF admissions = %d; want %d", admitter.calls, operation.ExpectedKDFCalls())
	}
	if admitter.maximumActive.Load() != 1 || admitter.active.Load() != 0 {
		return errors.New("D1 production KDF admissions overlapped or remained active")
	}
	return nil
}

func newD1ProductionKDFFactors(
	fixture *pcv3corpus.D1VolumeFixture,
	operation pcv3corpus.D1OperationExpectation,
) (*pcv3credential.FactorRequest, []byte, []*d1ProductionKDFKeyfile, error) {
	var borrowedPassword []byte
	var borrowedKeyfiles [][]byte
	switch operation.Factors() {
	case "correct":
		borrowedPassword = fixture.Password()
		borrowedKeyfiles = fixture.Keyfiles()
	case "wrong":
		borrowedPassword = fixture.WrongPassword()
		borrowedKeyfiles = fixture.WrongKeyfiles()
	default:
		return nil, nil, nil, errors.New("private D1 schedule selected an unknown factor set")
	}
	if operation.KeyfileOrder() == "reversed" {
		for left, right := 0, len(borrowedKeyfiles)-1; left < right; left, right = left+1, right-1 {
			borrowedKeyfiles[left], borrowedKeyfiles[right] = borrowedKeyfiles[right], borrowedKeyfiles[left]
		}
	} else if operation.KeyfileOrder() != "manifest" {
		return nil, nil, nil, errors.New("private D1 schedule selected an unknown keyfile order")
	}

	passwordAlias := append([]byte(nil), borrowedPassword...)
	readers := make([]*pcv3credential.KeyfileReader, len(borrowedKeyfiles))
	owned := make([]*d1ProductionKDFKeyfile, len(borrowedKeyfiles))
	for index, keyfile := range borrowedKeyfiles {
		ownedBytes := append([]byte(nil), keyfile...)
		tracked := &d1ProductionKDFKeyfile{reader: bytes.NewReader(ownedBytes), ownedBytes: ownedBytes}
		owned[index] = tracked
		readers[index] = pcv3credential.OwnKeyfileReader(tracked)
	}
	request := &pcv3credential.FactorRequest{Password: passwordAlias, Keyfiles: readers}
	switch fixture.CredentialMode() {
	case "password-only":
		request.Mode = pcv3credential.CredentialModePasswordOnly
		request.KeyfileMode = pcv3credential.KeyfileModeNone
		request.ExpectedPolicy = pcv3credential.FactorPolicyPasswordOnly
	case "keyfiles-only":
		request.Mode = pcv3credential.CredentialModeKeyfilesOnly
		request.ExpectedPolicy = pcv3credential.FactorPolicyKeyfilesOnly
	case "combined":
		request.Mode = pcv3credential.CredentialModePasswordAndKeyfiles
		request.ExpectedPolicy = pcv3credential.FactorPolicyPasswordAndKeyfiles
	default:
		_ = request.Close()
		return nil, passwordAlias, owned, errors.New("private D1 fixture selected an unknown credential mode")
	}
	if fixture.CredentialMode() != "password-only" {
		switch fixture.KeyfileMode() {
		case "ordered":
			request.KeyfileMode = pcv3credential.KeyfileModeOrdered
		case "unordered":
			request.KeyfileMode = pcv3credential.KeyfileModeUnordered
		default:
			_ = request.Close()
			return nil, passwordAlias, owned, errors.New("private D1 fixture selected an unknown keyfile mode")
		}
	}
	return request, passwordAlias, owned, nil
}

func verifyD1ProductionKDFFactorCleanup(
	factors *pcv3credential.FactorRequest,
	passwordAlias []byte,
	keyfiles []*d1ProductionKDFKeyfile,
) error {
	if factors == nil || factors.Password != nil || factors.Keyfiles != nil || !allZero(passwordAlias) {
		return errors.New("D1 factor ownership was not consumed and zeroed")
	}
	for _, keyfile := range keyfiles {
		if keyfile == nil || keyfile.closeCalls != 1 || keyfile.readBytes != len(keyfile.ownedBytes) ||
			!allZero(keyfile.ownedBytes) {
			return errors.New("D1 keyfile was not consumed once, closed once, and zeroed")
		}
	}
	return nil
}

func verifyD1ProductionKDFResult(
	result *RecoveryResult,
	operation pcv3corpus.D1OperationExpectation,
) error {
	closedFields := []struct {
		name string
		got  string
		want string
	}{
		{"outcome", result.Outcome().String(), operation.ExpectedOutcome()},
		{"stage", result.Stage().String(), operation.ExpectedStage()},
		{"detail stage", result.DetailStage().String(), operation.ExpectedDetailStage()},
		{"code", result.Code().String(), operation.ExpectedCode()},
		{"D1 provenance", d1ProductionKDFBootstrapProvenance(result.D1BootstrapProvenance()), operation.ExpectedD1Provenance()},
		{"Force provenance", d1ProductionKDFForceProvenance(result.ForceProvenance()), operation.ExpectedForceProvenance()},
		{"plaintext length", fmt.Sprint(result.PlaintextLength()), fmt.Sprint(operation.ExpectedPlaintextLength())},
		{"final state", d1ProductionKDFFinalState(result.FinalRecordState()), operation.ExpectedFinalState()},
	}
	for _, field := range closedFields {
		if field.got != field.want {
			return fmt.Errorf("D1 production %s = %s; want %s", field.name, field.got, field.want)
		}
	}
	wantRanges := operation.ExpectedRanges()
	gotRanges := result.Ranges()
	if len(gotRanges) != len(wantRanges) {
		return errors.New("D1 production result did not preserve the independent range count")
	}
	for index := range gotRanges {
		if gotRanges[index].RecordIndex() != wantRanges[index].RecordIndex() ||
			gotRanges[index].Start() != wantRanges[index].Start() ||
			gotRanges[index].End() != wantRanges[index].End() ||
			d1ProductionKDFRangeState(gotRanges[index].State()) != wantRanges[index].State() {
			return errors.New("D1 production result did not preserve the independent range evidence")
		}
	}
	return nil
}

func verifyD1ProductionKDFEmission(
	fixture *pcv3corpus.D1VolumeFixture,
	operation pcv3corpus.D1OperationExpectation,
	result *RecoveryResult,
	emit RecoveryEmitter,
) error {
	if result == nil || emit == nil {
		return errors.New("D1 production output omitted result or emitter capability")
	}
	expected, err := d1ProductionKDFExpectedOutput(fixture, operation.ExpectedOutput())
	if err != nil {
		return err
	}
	defer pcv3crypto.SecureZero(expected)
	wantRanges := operation.ExpectedRanges()
	hasScheduledRanges := len(wantRanges) != 0
	wantEmittedRanges := make([]pcv3corpus.D1ExpectedRange, 0, len(wantRanges))
	for _, recoveryRange := range wantRanges {
		if recoveryRange.State() != "missing" {
			wantEmittedRanges = append(wantEmittedRanges, recoveryRange)
		}
	}
	nextOffset := uint64(0)
	emittedRanges := 0
	emittedBytes := 0
	err = emit(func(recoveryRange RecoveryRange, plaintext []byte) error {
		start, end := recoveryRange.Start(), recoveryRange.End()
		if end < start || end > uint64(len(expected)) || uint64(len(plaintext)) != end-start {
			return errors.New("D1 emitter produced an out-of-bounds plaintext range")
		}
		if !bytes.Equal(plaintext, expected[start:end]) {
			return errors.New("D1 emitter bytes differed from the independent fixture")
		}
		if !hasScheduledRanges {
			if start != nextOffset {
				return errors.New("D1 emitter produced non-canonical complete output ranges")
			}
			nextOffset = end
		} else {
			if emittedRanges >= len(wantEmittedRanges) {
				return errors.New("D1 emitter produced an unexpected extra range")
			}
			want := wantEmittedRanges[emittedRanges]
			if recoveryRange.RecordIndex() != want.RecordIndex() || start != want.Start() || end != want.End() ||
				d1ProductionKDFRangeState(recoveryRange.State()) != want.State() {
				return errors.New("D1 emitter range differed from the independent schedule")
			}
		}
		emittedRanges++
		emittedBytes += len(plaintext)
		return nil
	})
	if err != nil {
		return err
	}
	if !hasScheduledRanges {
		if nextOffset != uint64(len(expected)) || emittedBytes != len(expected) {
			return errors.New("D1 emitter did not publish the complete authenticated fixture")
		}
	} else if emittedRanges != len(wantEmittedRanges) {
		return errors.New("D1 emitter omitted an independently scheduled recoverable range")
	}
	return nil
}

func d1ProductionKDFExpectedOutput(
	fixture *pcv3corpus.D1VolumeFixture,
	kind string,
) ([]byte, error) {
	switch kind {
	case "plaintext":
		return append([]byte(nil), fixture.Plaintext()...), nil
	case "outer-inner":
		inner := fixture.InnerVolume()
		output := make([]byte, 16+len(inner))
		copy(output, []byte("PCVOUT3\x00"))
		binary.BigEndian.PutUint64(output[8:16], uint64(len(inner)))
		copy(output[16:], inner)
		return output, nil
	default:
		return nil, errors.New("private D1 schedule selected an unknown output artifact")
	}
}

func d1ProductionKDFUnverifiedRole(value string) (D1BootstrapRole, bool) {
	switch value {
	case "front":
		return D1BootstrapFront, true
	case "tail":
		return D1BootstrapTail, true
	default:
		return 0, false
	}
}

func d1ProductionKDFBootstrapProvenance(value D1BootstrapProvenance) string {
	switch value {
	case D1BootstrapProvenanceNone:
		return "none"
	case D1BootstrapProvenanceFront:
		return "front"
	case D1BootstrapProvenanceTail:
		return "tail"
	case D1BootstrapProvenanceMatching:
		return "matching"
	default:
		return "unknown"
	}
}

func d1ProductionKDFForceProvenance(value ForceProvenance) string {
	switch value {
	case ForceProvenanceNone:
		return "none"
	case ForceProvenanceVerified:
		return "verified"
	case ForceProvenancePartial:
		return "partial"
	case ForceProvenanceUnverified:
		return "unverified"
	default:
		return "unknown"
	}
}

func d1ProductionKDFRangeState(value RecoveryRangeState) string {
	switch value {
	case RecoveryRangeVerified:
		return "verified"
	case RecoveryRangeUnverified:
		return "unverified"
	case RecoveryRangeMissing:
		return "missing"
	default:
		return "unknown"
	}
}

func d1ProductionKDFFinalState(value RecoveryFinalState) string {
	switch value {
	case 0:
		return "none"
	case RecoveryFinalVerified:
		return "verified"
	case RecoveryFinalUnverified:
		return "unverified"
	case RecoveryFinalMissing:
		return "missing"
	default:
		return "unknown"
	}
}
