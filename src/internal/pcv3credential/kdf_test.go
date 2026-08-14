package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"testing/synctest"
	"time"
)

const (
	normalInputKATHex           = "47156ab898a6329d3388ca7d762b35af622897e7ce3e7da960aa55f9b1051073afeb902632ea30ddef7d6da4fc6f12c34493bb5abda4ee9a3ac191cba09dd011"
	literalCredentialInputBytes = 64
	literalKDFSaltBytes         = 16
	literalCredentialRootBytes  = 32
)

// These compile-only bindings keep the real adapter on the same typed runner
// while exact-profile execution remains isolated to the later production gate.
var (
	_ kdfDeriver = deriveArgon2ID
	_ func(
		context.Context,
		*CredentialInputNormal,
		[]byte,
		Suite,
		Admitter,
	) (*credentialRoot, error) = deriveCredentialRoot
)

type testAdmitter func(
	context.Context,
	KDFProfile,
) (KDFAdmission, error)

func (admitter testAdmitter) AdmitKDF(
	ctx context.Context,
	profile KDFProfile,
) (KDFAdmission, error) {
	return admitter(ctx, profile)
}

func grantKDFAdmission() Admitter {
	return testAdmitter(func(
		context.Context,
		KDFProfile,
	) (KDFAdmission, error) {
		return KDFAdmissionGranted, nil
	})
}

func requireKDFCode(t *testing.T, err error, want KDFErrorCode) *KDFError {
	t.Helper()
	var kdfErr *KDFError
	if !errors.As(err, &kdfErr) {
		t.Fatalf("error = %T %v; want *KDFError code %d", err, err, want)
	}
	if kdfErr.Code != want {
		t.Fatalf(
			"KDF error code = %d; want %d (error %v)",
			kdfErr.Code,
			want,
			err,
		)
	}
	return kdfErr
}

func testNormalInput(
	t *testing.T,
) (*CredentialInputNormal, *crypto.Secret, []byte) {
	t.Helper()
	input := newPasswordNormalInput(t)
	owner := input.secret
	alias := owner.Bytes()
	return input, owner, alias
}

func literalNormalInputBytes(t *testing.T) []byte {
	t.Helper()
	value, err := hex.DecodeString(normalInputKATHex)
	if err != nil {
		t.Fatalf("invalid normal-input literal: %v", err)
	}
	return value
}

func fakeKDFResult(value byte, size int) []byte {
	return bytes.Repeat([]byte{value}, size)
}

func TestFixedProfileTable(t *testing.T) {
	tests := []struct {
		name  string
		suite Suite
		want  KDFProfile
	}{
		{
			name:  "Standard-1 selects Normal-1",
			suite: SuiteStandard1,
			want: KDFProfile{
				ID:            0x01,
				Argon2Version: 0x13,
				Time:          4,
				MemoryKiB:     1048576,
				Parallelism:   4,
				SaltBytes:     16,
				OutputBytes:   32,
			},
		},
		{
			name:  "Paranoid-1 selects Paranoid-1",
			suite: SuiteParanoid1,
			want: KDFProfile{
				ID:            0x02,
				Argon2Version: 0x13,
				Time:          8,
				MemoryKiB:     1048576,
				Parallelism:   8,
				SaltBytes:     16,
				OutputBytes:   32,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := fixedProfileForSuite(test.suite)
			if err != nil {
				t.Fatalf("fixedProfileForSuite(%#04x) failed: %v", test.suite, err)
			}
			if got != test.want {
				t.Fatalf(
					"fixedProfileForSuite(%#04x) = %+v; want literal %+v",
					test.suite,
					got,
					test.want,
				)
			}
		})
	}

	for _, suite := range []Suite{0x0000, 0x0003, 0xffff} {
		profile, err := fixedProfileForSuite(suite)
		kdfErr := requireKDFCode(t, err, KDFErrorInvalidSuite)
		if kdfErr.Suite != suite {
			t.Fatalf(
				"unknown-suite error records suite %#04x; want %#04x",
				kdfErr.Suite,
				suite,
			)
		}
		if profile != (KDFProfile{}) {
			t.Fatalf("unknown suite %#04x published profile %+v", suite, profile)
		}
	}
}

func TestKDFConsumesNormalCredentialInput(t *testing.T) {
	t.Run("success consumes exact literal and clears every borrow", func(t *testing.T) {
		input, owner, inputAlias := testNormalInput(t)
		wantInput := literalNormalInputBytes(t)
		defer crypto.SecureZero(wantInput)
		var seamBorrow []byte
		var seenInput []byte
		var seenSalt []byte
		salt := []byte{
			0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff,
		}
		wantSalt := []byte{
			0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77,
			0x88, 0x99, 0xaa, 0xbb,
			0xcc, 0xdd, 0xee, 0xff,
		}
		calls := 0
		root, err := runCredentialKDF(
			context.Background(),
			input,
			salt,
			SuiteStandard1,
			testAdmitter(func(
				context.Context,
				KDFProfile,
			) (KDFAdmission, error) {
				salt[0] = 0xfe
				return KDFAdmissionGranted, nil
			}),
			func(
				normalInput []byte,
				fixedSalt []byte,
				_ KDFProfile,
			) ([]byte, error) {
				calls++
				seamBorrow = normalInput
				seenInput = append([]byte(nil), normalInput...)
				seenSalt = append([]byte(nil), fixedSalt...)
				return fakeKDFResult(0xa5, literalCredentialRootBytes), nil
			},
		)
		defer crypto.SecureZero(seenInput)
		if err != nil {
			t.Fatalf("runCredentialKDF failed: %v", err)
		}
		if calls != 1 {
			t.Fatalf("KDF calls = %d; want 1", calls)
		}
		if !bytes.Equal(seenInput, wantInput) {
			t.Fatalf(
				"KDF input = %x; want literal %x",
				seenInput,
				wantInput,
			)
		}
		if !bytes.Equal(seenSalt, wantSalt) {
			t.Fatalf("KDF salt = %x; want literal %x", seenSalt, wantSalt)
		}
		if input.secret != nil || owner.Len() != 0 ||
			!allZero(inputAlias) || !allZero(seamBorrow) {
			t.Fatal("KDF success did not consume and clear every input borrow")
		}
		if root == nil || root.secret == nil || !bytes.Equal(
			root.secret.Bytes(),
			fakeKDFResult(0xa5, literalCredentialRootBytes),
		) {
			t.Fatal("KDF success did not publish the seam result exactly")
		}
		rootOwner := root.secret
		rootAlias := rootOwner.Bytes()
		copiedRoot := *root
		root.close()
		if root.secret != nil || rootOwner.Len() != 0 ||
			copiedRoot.secret == nil || copiedRoot.secret.Len() != 0 ||
			!allZero(rootAlias) {
			t.Fatal("credential root close did not clear its retained alias")
		}

		admissionCalls := 0
		deriveCalls := 0
		secondRoot, secondErr := runCredentialKDF(
			context.Background(),
			input,
			make([]byte, literalKDFSaltBytes),
			SuiteStandard1,
			testAdmitter(func(
				context.Context,
				KDFProfile,
			) (KDFAdmission, error) {
				admissionCalls++
				return KDFAdmissionGranted, nil
			}),
			func([]byte, []byte, KDFProfile) ([]byte, error) {
				deriveCalls++
				return fakeKDFResult(0xa6, literalCredentialRootBytes), nil
			},
		)
		requireKDFCode(t, secondErr, KDFErrorInvalidInput)
		if secondRoot != nil || admissionCalls != 0 || deriveCalls != 0 {
			if secondRoot != nil {
				secondRoot.close()
			}
			t.Fatalf(
				"second consume = root %v, admission/KDF calls %d/%d; want nil, 0/0",
				secondRoot,
				admissionCalls,
				deriveCalls,
			)
		}
	})
}

func TestKDFRejectsBeforeCall(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name               string
		ctx                context.Context
		suite              Suite
		salt               []byte
		admission          KDFAdmission
		admissionErr       error
		nilInput           bool
		inputBytes         int
		nilAdmitter        bool
		nilDeriver         bool
		wantAdmissionCalls int
		want               KDFErrorCode
	}{
		{
			name:      "nil context",
			suite:     SuiteStandard1,
			salt:      make([]byte, literalKDFSaltBytes),
			admission: KDFAdmissionGranted,
			want:      KDFErrorInvalidRequest,
		},
		{
			name:      "unknown suite",
			ctx:       context.Background(),
			suite:     0x0003,
			salt:      make([]byte, literalKDFSaltBytes),
			admission: KDFAdmissionGranted,
			want:      KDFErrorInvalidSuite,
		},
		{
			name:      "short salt",
			ctx:       context.Background(),
			suite:     SuiteStandard1,
			salt:      make([]byte, literalKDFSaltBytes-1),
			admission: KDFAdmissionGranted,
			want:      KDFErrorInvalidSalt,
		},
		{
			name:      "long salt",
			ctx:       context.Background(),
			suite:     SuiteStandard1,
			salt:      make([]byte, literalKDFSaltBytes+1),
			admission: KDFAdmissionGranted,
			want:      KDFErrorInvalidSalt,
		},
		{
			name:               "unknown admission",
			ctx:                context.Background(),
			suite:              SuiteStandard1,
			salt:               make([]byte, literalKDFSaltBytes),
			admission:          KDFAdmissionUnknown,
			wantAdmissionCalls: 1,
			want:               KDFErrorAdmission,
		},
		{
			name:               "denied admission",
			ctx:                context.Background(),
			suite:              SuiteStandard1,
			salt:               make([]byte, literalKDFSaltBytes),
			admission:          KDFAdmissionDenied,
			wantAdmissionCalls: 1,
			want:               KDFErrorAdmission,
		},
		{
			name:               "admission error",
			ctx:                context.Background(),
			suite:              SuiteStandard1,
			salt:               make([]byte, literalKDFSaltBytes),
			admission:          KDFAdmissionGranted,
			admissionErr:       errors.New("private-admission-sentinel"),
			wantAdmissionCalls: 1,
			want:               KDFErrorAdmission,
		},
		{
			name:      "cancelled before call",
			ctx:       cancelled,
			suite:     SuiteStandard1,
			salt:      make([]byte, literalKDFSaltBytes),
			admission: KDFAdmissionGranted,
			want:      KDFErrorCancelled,
		},
		{
			name:       "nil input",
			ctx:        context.Background(),
			suite:      SuiteStandard1,
			salt:       make([]byte, literalKDFSaltBytes),
			admission:  KDFAdmissionGranted,
			nilInput:   true,
			inputBytes: literalCredentialInputBytes,
			want:       KDFErrorInvalidInput,
		},
		{
			name:       "wrong input width",
			ctx:        context.Background(),
			suite:      SuiteStandard1,
			salt:       make([]byte, literalKDFSaltBytes),
			admission:  KDFAdmissionGranted,
			inputBytes: literalCredentialInputBytes - 1,
			want:       KDFErrorInvalidInput,
		},
		{
			name:       "long input width",
			ctx:        context.Background(),
			suite:      SuiteStandard1,
			salt:       make([]byte, literalKDFSaltBytes),
			admission:  KDFAdmissionGranted,
			inputBytes: literalCredentialInputBytes + 1,
			want:       KDFErrorInvalidInput,
		},
		{
			name:               "unknown numeric admission",
			ctx:                context.Background(),
			suite:              SuiteStandard1,
			salt:               make([]byte, literalKDFSaltBytes),
			admission:          KDFAdmission(0xff),
			wantAdmissionCalls: 1,
			want:               KDFErrorAdmission,
		},
		{
			name:        "nil admitter",
			ctx:         context.Background(),
			suite:       SuiteStandard1,
			salt:        make([]byte, literalKDFSaltBytes),
			admission:   KDFAdmissionGranted,
			nilAdmitter: true,
			want:        KDFErrorInvalidRequest,
		},
		{
			name:       "nil deriver",
			ctx:        context.Background(),
			suite:      SuiteStandard1,
			salt:       make([]byte, literalKDFSaltBytes),
			admission:  KDFAdmissionGranted,
			nilDeriver: true,
			want:       KDFErrorInvalidRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var input *CredentialInputNormal
			var owner *crypto.Secret
			var alias []byte
			switch {
			case test.nilInput:
			case test.inputBytes > 0:
				alias = fakeKDFResult(0x41, test.inputBytes)
				owner = crypto.SecretFrom(alias)
				input = &CredentialInputNormal{secret: owner}
			default:
				input, owner, alias = testNormalInput(t)
			}

			admissionCalls := 0
			var admitter Admitter = testAdmitter(func(
				context.Context,
				KDFProfile,
			) (KDFAdmission, error) {
				admissionCalls++
				return test.admission, test.admissionErr
			})
			if test.nilAdmitter {
				admitter = nil
			}

			kdfCalls := 0
			var deriver kdfDeriver = func(
				_ []byte,
				_ []byte,
				_ KDFProfile,
			) ([]byte, error) {
				kdfCalls++
				return fakeKDFResult(0x42, literalCredentialRootBytes), nil
			}
			if test.nilDeriver {
				deriver = nil
			}

			root, err := runCredentialKDF(
				test.ctx,
				input,
				test.salt,
				test.suite,
				admitter,
				deriver,
			)
			kdfErr := requireKDFCode(t, err, test.want)
			if kdfErr.Suite != test.suite {
				t.Fatalf(
					"KDF error suite = %#04x; want %#04x",
					kdfErr.Suite,
					test.suite,
				)
			}
			if root != nil {
				root.close()
				t.Fatal("rejected KDF request published a credential root")
			}
			if admissionCalls != test.wantAdmissionCalls || kdfCalls != 0 {
				t.Fatalf(
					"rejected request admission/KDF calls = %d/%d; want %d/0",
					admissionCalls,
					kdfCalls,
					test.wantAdmissionCalls,
				)
			}
			if input != nil &&
				(input.secret != nil || owner.Len() != 0 || !allZero(alias)) {
				t.Fatal("rejected KDF request did not clear transferred input")
			}
		})
	}
}

func TestKDFCallsOnce(t *testing.T) {
	tests := []struct {
		name      string
		deriveErr error
		wantCode  KDFErrorCode
	}{
		{name: "success"},
		{
			name:      "adapter error is not retried",
			deriveErr: errors.New("private-adapter-sentinel"),
			wantCode:  KDFErrorDerivation,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := newPasswordNormalInput(t)
			events := make([]string, 0, 2)
			admissionCalls := 0
			kdfCalls := 0
			returned := fakeKDFResult(0x63, literalCredentialRootBytes)
			root, err := runCredentialKDF(
				context.Background(),
				input,
				make([]byte, literalKDFSaltBytes),
				SuiteStandard1,
				testAdmitter(func(
					context.Context,
					KDFProfile,
				) (KDFAdmission, error) {
					admissionCalls++
					events = append(events, "admit")
					return KDFAdmissionGranted, nil
				}),
				func(
					_ []byte,
					_ []byte,
					_ KDFProfile,
				) ([]byte, error) {
					kdfCalls++
					events = append(events, "derive")
					return returned, test.deriveErr
				},
			)
			if admissionCalls != 1 || kdfCalls != 1 ||
				len(events) != 2 ||
				events[0] != "admit" || events[1] != "derive" {
				t.Fatalf(
					"admission/KDF calls and order = %d/%d %v; want 1/1 [admit derive]",
					admissionCalls,
					kdfCalls,
					events,
				)
			}
			if test.wantCode == 0 {
				if err != nil || root == nil {
					t.Fatalf("KDF success = root %v, error %v; want root", root, err)
				}
				root.close()
			} else {
				requireKDFCode(t, err, test.wantCode)
				if root != nil {
					root.close()
					t.Fatal("adapter error published a credential root")
				}
			}
			if !allZero(returned) {
				t.Fatal("KDF runner retained the adapter result slice")
			}
		})
	}
}

type kdfFixedProfileCase struct {
	suite Suite
	want  KDFProfile
}

func kdfFixedProfileCases() []kdfFixedProfileCase {
	return []kdfFixedProfileCase{
		{
			suite: SuiteStandard1,
			want: KDFProfile{
				ID:            0x01,
				Argon2Version: 0x13,
				Time:          4,
				MemoryKiB:     1048576,
				Parallelism:   4,
				SaltBytes:     16,
				OutputBytes:   32,
			},
		},
		{
			suite: SuiteParanoid1,
			want: KDFProfile{
				ID:            0x02,
				Argon2Version: 0x13,
				Time:          8,
				MemoryKiB:     1048576,
				Parallelism:   8,
				SaltBytes:     16,
				OutputBytes:   32,
			},
		},
	}
}

func requireKDFFixedProfile(t *testing.T, test kdfFixedProfileCase) {
	t.Helper()
	input := newPasswordNormalInput(t)
	admissionCalls := 0
	kdfCalls := 0
	var admitted KDFProfile
	var derived KDFProfile
	root, err := runCredentialKDF(
		context.Background(),
		input,
		make([]byte, literalKDFSaltBytes),
		test.suite,
		testAdmitter(func(
			_ context.Context,
			profile KDFProfile,
		) (KDFAdmission, error) {
			admissionCalls++
			admitted = profile
			return KDFAdmissionGranted, nil
		}),
		func(
			_ []byte,
			_ []byte,
			profile KDFProfile,
		) ([]byte, error) {
			kdfCalls++
			derived = profile
			return nil, errors.New("stop after recording exact tuple")
		},
	)
	requireKDFCode(t, err, KDFErrorDerivation)
	if root != nil {
		root.close()
		t.Fatal("recording failure published a credential root")
	}
	if admissionCalls != 1 || kdfCalls != 1 ||
		admitted != test.want || derived != test.want {
		t.Fatalf(
			"admission/KDF calls/profiles = %d/%d %+v/%+v; want 1/1 %+v",
			admissionCalls,
			kdfCalls,
			admitted,
			derived,
			test.want,
		)
	}
}

func TestKDFNeverWeakens(t *testing.T) {
	for _, test := range kdfFixedProfileCases() {
		t.Run(fmt.Sprintf("suite-%04x", test.suite), func(t *testing.T) {
			requireKDFFixedProfile(t, test)
		})
	}
}

func TestKDFFixedProfileWeakeningMutation(t *testing.T) {
	for _, test := range kdfFixedProfileCases() {
		requireKDFFixedProfile(t, test)
	}
}

func TestKDFSequential(t *testing.T) {
	input := newPasswordNormalInput(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	type result struct {
		root *credentialRoot
		err  error
	}
	resultCh := make(chan result, 1)
	calls := 0
	go func() {
		root, err := runCredentialKDF(
			context.Background(),
			input,
			make([]byte, literalKDFSaltBytes),
			SuiteStandard1,
			grantKDFAdmission(),
			func(
				_ []byte,
				_ []byte,
				_ KDFProfile,
			) ([]byte, error) {
				calls++
				close(entered)
				<-release
				return fakeKDFResult(0x72, literalCredentialRootBytes), nil
			},
		)
		resultCh <- result{root: root, err: err}
	}()

	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("KDF seam was not invoked synchronously")
	}
	select {
	case got := <-resultCh:
		if got.root != nil {
			got.root.close()
		}
		close(release)
		t.Fatalf("runner returned before the sole KDF call completed: %v", got.err)
	default:
	}
	close(release)
	select {
	case got := <-resultCh:
		if got.err != nil || got.root == nil {
			t.Fatalf("runner completion = root %v, error %v; want root", got.root, got.err)
		}
		got.root.close()
	case <-time.After(2 * time.Second):
		t.Fatal("runner did not return after the sole KDF call completed")
	}
	if calls != 1 {
		t.Fatalf("KDF calls = %d; want exactly 1", calls)
	}
}

type kdfLeaseResult struct {
	secret *crypto.Secret
	err    error
}

func withKDFLeaseBubble(t *testing.T, test func(*testing.T)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		previous := fixedProfileKDFLease
		fixedProfileKDFLease = make(chan struct{}, 1)
		defer func() { fixedProfileKDFLease = previous }()
		test(t)
	})
}

func requireNoKDFLeaseEffect(t *testing.T, effect <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-effect:
		t.Error(failure)
	default:
	}
}

func closeKDFLeaseResult(t *testing.T, result kdfLeaseResult) {
	t.Helper()
	if result.secret != nil {
		result.secret.Close()
	}
}

func requireKDFLeaseAvailable(t *testing.T) {
	t.Helper()
	admitted := make(chan struct{}, 1)
	derived := make(chan struct{}, 1)
	result := make(chan kdfLeaseResult, 1)
	go func() {
		secret, err := runFixedProfileKDFBorrowed(
			context.Background(),
			make([]byte, literalCredentialInputBytes),
			make([]byte, literalKDFSaltBytes),
			SuiteStandard1,
			testAdmitter(func(
				context.Context,
				KDFProfile,
			) (KDFAdmission, error) {
				admitted <- struct{}{}
				return KDFAdmissionGranted, nil
			}),
			func(
				_ []byte,
				_ []byte,
				_ KDFProfile,
			) ([]byte, error) {
				derived <- struct{}{}
				return fakeKDFResult(0x75, literalCredentialRootBytes), nil
			},
		)
		result <- kdfLeaseResult{secret: secret, err: err}
	}()
	synctest.Wait()
	select {
	case got := <-result:
		admittedOK := len(admitted) == 1
		derivedOK := len(derived) == 1
		if got.err != nil || got.secret == nil || !admittedOK || !derivedOK {
			closeKDFLeaseResult(t, got)
			t.Fatalf(
				"follow-up KDF = secret %v, error %v, admitted/derived %t/%t; want successful derivation",
				got.secret,
				got.err,
				admittedOK,
				derivedOK,
			)
		}
		got.secret.Close()
		return
	default:
	}

	// The test owns this isolated lease. Drain a leaked token so the probe can
	// terminate before reporting the regression instead of hanging the suite.
	select {
	case <-fixedProfileKDFLease:
	default:
	}
	synctest.Wait()
	select {
	case got := <-result:
		closeKDFLeaseResult(t, got)
	default:
	}
	t.Fatal("follow-up KDF remained durably blocked; prior exit did not release the process lease")
}

func TestDerivationLeaseSerializesAndRechecksFixedProfile(t *testing.T) {
	withKDFLeaseBubble(t, func(t *testing.T) {
		firstAdmissionEntered := make(chan struct{})
		releaseFirstAdmission := make(chan struct{})
		firstDerivationEntered := make(chan struct{})
		releaseFirstDerivation := make(chan struct{})
		firstResult := make(chan kdfLeaseResult, 1)

		go func() {
			secret, err := runFixedProfileKDFBorrowed(
				context.Background(),
				make([]byte, literalCredentialInputBytes),
				make([]byte, literalKDFSaltBytes),
				SuiteStandard1,
				testAdmitter(func(
					context.Context,
					KDFProfile,
				) (KDFAdmission, error) {
					close(firstAdmissionEntered)
					<-releaseFirstAdmission
					return KDFAdmissionGranted, nil
				}),
				func(
					_ []byte,
					_ []byte,
					_ KDFProfile,
				) ([]byte, error) {
					close(firstDerivationEntered)
					<-releaseFirstDerivation
					return fakeKDFResult(0x76, literalCredentialRootBytes), nil
				},
			)
			firstResult <- kdfLeaseResult{secret: secret, err: err}
		}()
		<-firstAdmissionEntered

		secondAdmissionEntered := make(chan struct{}, 1)
		secondDecision := make(chan KDFAdmission, 1)
		secondDerivationEntered := make(chan struct{}, 1)
		secondResult := make(chan kdfLeaseResult, 1)

		go func() {
			secret, err := runFixedProfileKDFBorrowed(
				context.Background(),
				make([]byte, literalCredentialInputBytes),
				make([]byte, literalKDFSaltBytes),
				SuiteStandard1,
				testAdmitter(func(
					_ context.Context,
					profile KDFProfile,
				) (KDFAdmission, error) {
					if profile != (KDFProfile{
						ID:            0x01,
						Argon2Version: 0x13,
						Time:          4,
						MemoryKiB:     1048576,
						Parallelism:   4,
						SaltBytes:     16,
						OutputBytes:   32,
					}) {
						return KDFAdmissionUnknown, errors.New("unexpected fixed profile")
					}
					secondAdmissionEntered <- struct{}{}
					return <-secondDecision, nil
				}),
				func(
					_ []byte,
					_ []byte,
					_ KDFProfile,
				) ([]byte, error) {
					secondDerivationEntered <- struct{}{}
					return fakeKDFResult(0x77, literalCredentialRootBytes), nil
				},
			)
			secondResult <- kdfLeaseResult{secret: secret, err: err}
		}()

		synctest.Wait()
		requireNoKDFLeaseEffect(
			t,
			secondAdmissionEntered,
			"second caller overlapped the first admission",
		)

		close(releaseFirstAdmission)
		<-firstDerivationEntered
		synctest.Wait()
		requireNoKDFLeaseEffect(
			t,
			secondAdmissionEntered,
			"second caller reached admission while the first derivation was active",
		)

		// The resource state changes while caller two is queued. Its only decision
		// must therefore be the denial supplied after lease acquisition, not a
		// reusable preflight decision from before caller one finished.
		secondDecision <- KDFAdmissionDenied
		close(releaseFirstDerivation)

		gotFirst := <-firstResult
		defer closeKDFLeaseResult(t, gotFirst)
		gotSecond := <-secondResult
		defer closeKDFLeaseResult(t, gotSecond)
		if gotFirst.err != nil || gotFirst.secret == nil {
			t.Errorf(
				"first leased derivation = secret %v, error %v; want success",
				gotFirst.secret,
				gotFirst.err,
			)
		}
		requireKDFCode(t, gotSecond.err, KDFErrorAdmission)
		if gotSecond.secret != nil {
			t.Error("fresh post-queue resource refusal published a secret")
		}
		requireNoKDFLeaseEffect(
			t,
			secondDerivationEntered,
			"fresh post-queue resource refusal reached derivation",
		)
	})
}

func TestDerivationLeaseReleasesEveryExit(t *testing.T) {
	tests := []struct {
		name      string
		run       func() (error, any)
		want      KDFErrorCode
		wantPanic string
	}{
		{
			name: "resource denial",
			want: KDFErrorAdmission,
			run: func() (error, any) {
				_, err := runFixedProfileKDFBorrowed(
					context.Background(),
					make([]byte, literalCredentialInputBytes),
					make([]byte, literalKDFSaltBytes),
					SuiteStandard1,
					testAdmitter(func(
						context.Context,
						KDFProfile,
					) (KDFAdmission, error) {
						return KDFAdmissionDenied, nil
					}),
					func([]byte, []byte, KDFProfile) ([]byte, error) {
						return fakeKDFResult(0x78, literalCredentialRootBytes), nil
					},
				)
				return err, nil
			},
		},
		{
			name: "derivation error",
			want: KDFErrorDerivation,
			run: func() (error, any) {
				_, err := runFixedProfileKDFBorrowed(
					context.Background(),
					make([]byte, literalCredentialInputBytes),
					make([]byte, literalKDFSaltBytes),
					SuiteStandard1,
					grantKDFAdmission(),
					func([]byte, []byte, KDFProfile) ([]byte, error) {
						return nil, errors.New("derive failure")
					},
				)
				return err, nil
			},
		},
		{
			name: "cancellation after admission",
			want: KDFErrorCancelled,
			run: func() (error, any) {
				ctx, cancel := context.WithCancel(context.Background())
				_, err := runFixedProfileKDFBorrowed(
					ctx,
					make([]byte, literalCredentialInputBytes),
					make([]byte, literalKDFSaltBytes),
					SuiteStandard1,
					testAdmitter(func(
						context.Context,
						KDFProfile,
					) (KDFAdmission, error) {
						cancel()
						return KDFAdmissionGranted, nil
					}),
					func([]byte, []byte, KDFProfile) ([]byte, error) {
						return fakeKDFResult(0x79, literalCredentialRootBytes), nil
					},
				)
				return err, nil
			},
		},
		{
			name:      "admission panic",
			wantPanic: "admission panic",
			run: func() (err error, recovered any) {
				defer func() { recovered = recover() }()
				_, err = runFixedProfileKDFBorrowed(
					context.Background(),
					make([]byte, literalCredentialInputBytes),
					make([]byte, literalKDFSaltBytes),
					SuiteStandard1,
					testAdmitter(func(
						context.Context,
						KDFProfile,
					) (KDFAdmission, error) {
						panic("admission panic")
					}),
					func([]byte, []byte, KDFProfile) ([]byte, error) {
						return fakeKDFResult(0x7a, literalCredentialRootBytes), nil
					},
				)
				return err, nil
			},
		},
		{
			name:      "derivation panic",
			wantPanic: "derivation panic",
			run: func() (err error, recovered any) {
				defer func() { recovered = recover() }()
				_, err = runFixedProfileKDFBorrowed(
					context.Background(),
					make([]byte, literalCredentialInputBytes),
					make([]byte, literalKDFSaltBytes),
					SuiteStandard1,
					grantKDFAdmission(),
					func([]byte, []byte, KDFProfile) ([]byte, error) {
						panic("derivation panic")
					},
				)
				return err, nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			withKDFLeaseBubble(t, func(t *testing.T) {
				err, recovered := test.run()
				if test.want != 0 {
					requireKDFCode(t, err, test.want)
					if recovered != nil {
						t.Fatalf("unexpected panic after typed exit: %v", recovered)
					}
				} else if recovered != test.wantPanic {
					t.Fatalf("propagated panic = %v; want exact %q", recovered, test.wantPanic)
				}
				requireKDFLeaseAvailable(t)
			})
		})
	}
}

func TestCredentialKDFLeaseOrder(t *testing.T) {
	withKDFLeaseBubble(t, func(t *testing.T) {
		holderEntered := make(chan struct{})
		releaseHolder := make(chan struct{})
		holderResult := make(chan kdfLeaseResult, 1)
		holderReleased := false
		defer func() {
			if !holderReleased {
				close(releaseHolder)
			}
		}()

		go func() {
			secret, err := runFixedProfileKDFBorrowed(
				context.Background(),
				make([]byte, literalCredentialInputBytes),
				make([]byte, literalKDFSaltBytes),
				SuiteStandard1,
				grantKDFAdmission(),
				func([]byte, []byte, KDFProfile) ([]byte, error) {
					close(holderEntered)
					<-releaseHolder
					return fakeKDFResult(0x7b, literalCredentialRootBytes), nil
				},
			)
			holderResult <- kdfLeaseResult{secret: secret, err: err}
		}()
		<-holderEntered

		queuedContext, cancelQueued := context.WithCancelCause(context.Background())
		queuedAdmission := make(chan struct{}, 1)
		queuedDerivation := make(chan struct{}, 1)
		queuedResult := make(chan kdfLeaseResult, 1)
		go func() {
			secret, err := runFixedProfileKDFBorrowed(
				queuedContext,
				make([]byte, literalCredentialInputBytes),
				make([]byte, literalKDFSaltBytes),
				SuiteParanoid1,
				testAdmitter(func(
					context.Context,
					KDFProfile,
				) (KDFAdmission, error) {
					queuedAdmission <- struct{}{}
					return KDFAdmissionGranted, nil
				}),
				func([]byte, []byte, KDFProfile) ([]byte, error) {
					queuedDerivation <- struct{}{}
					return fakeKDFResult(0x7c, literalCredentialRootBytes), nil
				},
			)
			queuedResult <- kdfLeaseResult{secret: secret, err: err}
		}()

		synctest.Wait()
		requireNoKDFLeaseEffect(
			t,
			queuedAdmission,
			"queued caller reached admission before cancellation",
		)
		cancelQueued(errors.New("queued cancellation"))
		gotQueued := <-queuedResult
		defer closeKDFLeaseResult(t, gotQueued)
		requireKDFCode(t, gotQueued.err, KDFErrorCancelled)
		if gotQueued.secret != nil {
			t.Error("queued cancellation published a secret")
		}
		requireNoKDFLeaseEffect(
			t,
			queuedAdmission,
			"queued cancellation reached resource admission",
		)
		requireNoKDFLeaseEffect(
			t,
			queuedDerivation,
			"queued cancellation reached derivation",
		)

		close(releaseHolder)
		holderReleased = true
		gotHolder := <-holderResult
		defer closeKDFLeaseResult(t, gotHolder)
		if gotHolder.err != nil || gotHolder.secret == nil {
			t.Errorf(
				"lease holder completion = secret %v, error %v; want success",
				gotHolder.secret,
				gotHolder.err,
			)
		}
	})
}

func TestFixedProfileResourceRefusalHasZeroKDF(t *testing.T) {
	derivationEntered := make(chan struct{}, 1)
	secret, err := runFixedProfileKDFBorrowed(
		context.Background(),
		make([]byte, literalCredentialInputBytes),
		make([]byte, literalKDFSaltBytes),
		SuiteParanoid1,
		testAdmitter(func(
			context.Context,
			KDFProfile,
		) (KDFAdmission, error) {
			return KDFAdmissionDenied, nil
		}),
		func([]byte, []byte, KDFProfile) ([]byte, error) {
			derivationEntered <- struct{}{}
			return fakeKDFResult(0x7d, literalCredentialRootBytes), nil
		},
	)
	requireKDFCode(t, err, KDFErrorAdmission)
	if secret != nil {
		secret.Close()
		t.Fatal("resource refusal published a secret")
	}
	select {
	case <-derivationEntered:
		t.Fatal("resource refusal reached the KDF deriver")
	default:
	}
}

type kdfReturnedSliceCleanupCase struct {
	name      string
	size      int
	deriveErr error
	wantCode  KDFErrorCode
}

func kdfReturnedSliceCleanupCases() []kdfReturnedSliceCleanupCase {
	return []kdfReturnedSliceCleanupCase{
		{
			name: "success",
			size: literalCredentialRootBytes,
		},
		{
			name:      "adapter error with returned bytes",
			size:      literalCredentialRootBytes,
			deriveErr: errors.New("adapter failure"),
			wantCode:  KDFErrorDerivation,
		},
		{
			name:     "short output",
			size:     literalCredentialRootBytes - 1,
			wantCode: KDFErrorOutput,
		},
		{
			name:     "long output",
			size:     literalCredentialRootBytes + 1,
			wantCode: KDFErrorOutput,
		},
	}
}

func requireKDFReturnedSliceCleanup(
	t *testing.T,
	test kdfReturnedSliceCleanupCase,
) {
	t.Helper()
	input := newPasswordNormalInput(t)
	returned := fakeKDFResult(0x84, test.size)
	wantRoot := append([]byte(nil), returned...)
	defer crypto.SecureZero(wantRoot)
	root, err := runCredentialKDF(
		context.Background(),
		input,
		make([]byte, literalKDFSaltBytes),
		SuiteStandard1,
		grantKDFAdmission(),
		func(
			_ []byte,
			_ []byte,
			_ KDFProfile,
		) ([]byte, error) {
			return returned, test.deriveErr
		},
	)
	if !allZero(returned) {
		t.Fatal("KDF runner did not clear the exact returned slice")
	}
	if test.wantCode == 0 {
		if err != nil || root == nil {
			t.Fatalf("KDF success = root %v, error %v; want root", root, err)
		}
		if root.secret == nil ||
			!bytes.Equal(root.secret.Bytes(), wantRoot) {
			t.Fatalf(
				"credential root = %x; want seam bytes %x",
				root.secret.Bytes(),
				wantRoot,
			)
		}
		root.close()
		return
	}
	requireKDFCode(t, err, test.wantCode)
	if root != nil {
		root.close()
		t.Fatal("invalid returned slice published a credential root")
	}
}

func TestKDFReturnedSliceCleanup(t *testing.T) {
	for _, test := range kdfReturnedSliceCleanupCases() {
		t.Run(test.name, func(t *testing.T) {
			requireKDFReturnedSliceCleanup(t, test)
		})
	}
}

func TestKDFReturnedSliceCleanupMutation(t *testing.T) {
	for _, test := range kdfReturnedSliceCleanupCases() {
		requireKDFReturnedSliceCleanup(t, test)
	}
}

func requireKDFPostCallCancellation(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	input, owner, inputAlias := testNormalInput(t)
	returned := fakeKDFResult(0x94, literalCredentialRootBytes)
	admissionCalls := 0
	kdfCalls := 0
	root, err := runCredentialKDF(
		ctx,
		input,
		make([]byte, literalKDFSaltBytes),
		SuiteParanoid1,
		testAdmitter(func(
			context.Context,
			KDFProfile,
		) (KDFAdmission, error) {
			admissionCalls++
			return KDFAdmissionGranted, nil
		}),
		func(
			_ []byte,
			_ []byte,
			_ KDFProfile,
		) ([]byte, error) {
			kdfCalls++
			cancel(errors.New("private-post-cancel-sentinel"))
			return returned, nil
		},
	)
	if root != nil {
		root.close()
		t.Fatal("post-call cancellation published a credential root")
	}
	requireKDFCode(t, err, KDFErrorCancelled)
	if admissionCalls != 1 || kdfCalls != 1 ||
		input.secret != nil || owner.Len() != 0 ||
		!allZero(inputAlias) || !allZero(returned) {
		t.Fatal("post-call cancellation did not clear one-call material")
	}
}

func TestKDFCancellationBoundary(t *testing.T) {
	t.Run("pre-call cancellation makes zero calls", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		cancel(errors.New("private-pre-cancel-sentinel"))
		input, owner, inputAlias := testNormalInput(t)
		admissionCalls := 0
		kdfCalls := 0
		root, err := runCredentialKDF(
			ctx,
			input,
			make([]byte, literalKDFSaltBytes),
			SuiteStandard1,
			testAdmitter(func(
				context.Context,
				KDFProfile,
			) (KDFAdmission, error) {
				admissionCalls++
				return KDFAdmissionGranted, nil
			}),
			func(
				_ []byte,
				_ []byte,
				_ KDFProfile,
			) ([]byte, error) {
				kdfCalls++
				return fakeKDFResult(0x91, literalCredentialRootBytes), nil
			},
		)
		requireKDFCode(t, err, KDFErrorCancelled)
		if root != nil {
			root.close()
			t.Fatal("pre-call cancellation published a credential root")
		}
		if admissionCalls != 0 || kdfCalls != 0 ||
			input.secret != nil || owner.Len() != 0 ||
			!allZero(inputAlias) {
			t.Fatal("pre-call cancellation did not preserve zero-call cleanup")
		}
	})

	t.Run("cancellation during admission prevents KDF", func(t *testing.T) {
		ctx, cancel := context.WithCancelCause(context.Background())
		input, owner, inputAlias := testNormalInput(t)
		admissionCalls := 0
		kdfCalls := 0
		var seenAdmissionContext context.Context
		root, err := runCredentialKDF(
			ctx,
			input,
			make([]byte, literalKDFSaltBytes),
			SuiteStandard1,
			testAdmitter(func(
				admitCtx context.Context,
				_ KDFProfile,
			) (KDFAdmission, error) {
				admissionCalls++
				seenAdmissionContext = admitCtx
				cancel(errors.New("private-admission-cancel-sentinel"))
				return KDFAdmissionGranted, nil
			}),
			func(
				_ []byte,
				_ []byte,
				_ KDFProfile,
			) ([]byte, error) {
				kdfCalls++
				return fakeKDFResult(0x92, literalCredentialRootBytes), nil
			},
		)
		requireKDFCode(t, err, KDFErrorCancelled)
		if root != nil {
			root.close()
			t.Fatal("admission-time cancellation published a credential root")
		}
		if admissionCalls != 1 || kdfCalls != 0 ||
			seenAdmissionContext != ctx ||
			input.secret != nil || owner.Len() != 0 ||
			!allZero(inputAlias) {
			t.Fatal("admission-time cancellation did not preserve zero-KDF cleanup")
		}
	})

	t.Run("external cancellation waits for non-interruptible KDF", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithCancelCause(context.Background())
			input, owner, inputAlias := testNormalInput(t)
			returned := fakeKDFResult(0x93, literalCredentialRootBytes)
			entered := make(chan struct{})
			release := make(chan struct{})
			type result struct {
				root *credentialRoot
				err  error
			}
			resultCh := make(chan result, 1)
			go func() {
				root, err := runCredentialKDF(
					ctx,
					input,
					make([]byte, literalKDFSaltBytes),
					SuiteStandard1,
					grantKDFAdmission(),
					func(
						_ []byte,
						_ []byte,
						_ KDFProfile,
					) ([]byte, error) {
						close(entered)
						<-release
						return returned, nil
					},
				)
				resultCh <- result{root: root, err: err}
			}()

			<-entered
			cancel(errors.New("private-inflight-cancel-sentinel"))
			synctest.Wait()
			select {
			case got := <-resultCh:
				if got.root != nil {
					got.root.close()
				}
				close(release)
				t.Fatalf(
					"runner returned before non-interruptible KDF completed: %v",
					got.err,
				)
			default:
			}
			close(release)
			synctest.Wait()

			got := <-resultCh
			requireKDFCode(t, got.err, KDFErrorCancelled)
			if got.root != nil {
				got.root.close()
				t.Fatal("in-flight cancellation published a credential root")
			}
			if input.secret != nil || owner.Len() != 0 ||
				!allZero(inputAlias) || !allZero(returned) {
				t.Fatal("in-flight cancellation did not clear KDF and input material")
			}
		})
	})

	t.Run("post-call cancellation clears result and publishes nothing", func(t *testing.T) {
		requireKDFPostCallCancellation(t)
	})
}

func TestKDFPostCallCancellationMutation(t *testing.T) {
	requireKDFPostCallCancellation(t)
}

func TestKDFPanicCleanup(t *testing.T) {
	t.Run("admitter panic clears input before propagation", func(t *testing.T) {
		input, owner, inputAlias := testNormalInput(t)
		kdfCalls := 0
		var recovered any
		func() {
			defer func() {
				recovered = recover()
			}()
			_, _ = runCredentialKDF(
				context.Background(),
				input,
				make([]byte, literalKDFSaltBytes),
				SuiteStandard1,
				testAdmitter(func(
					context.Context,
					KDFProfile,
				) (KDFAdmission, error) {
					panic("admitter-panic-sentinel")
				}),
				func(
					_ []byte,
					_ []byte,
					_ KDFProfile,
				) ([]byte, error) {
					kdfCalls++
					return fakeKDFResult(0xa1, literalCredentialRootBytes), nil
				},
			)
		}()
		if recovered != "admitter-panic-sentinel" {
			t.Fatalf("admitter panic = %#v; want original panic", recovered)
		}
		if kdfCalls != 0 || input.secret != nil || owner.Len() != 0 ||
			!allZero(inputAlias) {
			t.Fatal("admitter panic did not preserve zero-KDF input cleanup")
		}
	})

	t.Run("deriver panic clears every reachable input borrow", func(t *testing.T) {
		input, owner, inputAlias := testNormalInput(t)
		admissionCalls := 0
		var seamBorrow []byte
		var recovered any
		func() {
			defer func() {
				recovered = recover()
			}()
			_, _ = runCredentialKDF(
				context.Background(),
				input,
				make([]byte, literalKDFSaltBytes),
				SuiteParanoid1,
				testAdmitter(func(
					context.Context,
					KDFProfile,
				) (KDFAdmission, error) {
					admissionCalls++
					return KDFAdmissionGranted, nil
				}),
				func(
					normalInput []byte,
					_ []byte,
					_ KDFProfile,
				) ([]byte, error) {
					seamBorrow = normalInput
					panic("deriver-panic-sentinel")
				},
			)
		}()
		if recovered != "deriver-panic-sentinel" {
			t.Fatalf("deriver panic = %#v; want original panic", recovered)
		}
		if admissionCalls != 1 || input.secret != nil || owner.Len() != 0 ||
			!allZero(inputAlias) || !allZero(seamBorrow) {
			t.Fatal("deriver panic did not clear every reachable input borrow")
		}
	})
}

func TestKDFDiagnosticsNoDisclosure(t *testing.T) {
	t.Run("live credential root formatting is exactly redacted", func(t *testing.T) {
		const (
			rootSentinel = "private-root-sentinel-0123456789"
			wantRendered = "pcv3credential.credentialRoot([REDACTED])"
		)
		if len(rootSentinel) != literalCredentialRootBytes {
			t.Fatalf(
				"root sentinel width = %d; want literal 32",
				len(rootSentinel),
			)
		}
		input := newPasswordNormalInput(t)
		returned := []byte(rootSentinel)
		root, err := runCredentialKDF(
			context.Background(),
			input,
			make([]byte, literalKDFSaltBytes),
			SuiteStandard1,
			grantKDFAdmission(),
			func(
				_ []byte,
				_ []byte,
				_ KDFProfile,
			) ([]byte, error) {
				return returned, nil
			},
		)
		if err != nil || root == nil || root.secret == nil {
			t.Fatalf("live-root setup = root %v, error %v; want root", root, err)
		}
		if !allZero(returned) ||
			!bytes.Equal(root.secret.Bytes(), []byte(rootSentinel)) {
			root.close()
			t.Fatal("live root did not own an independent exact result copy")
		}
		for _, rendered := range []string{
			fmt.Sprintf("%v", root),
			fmt.Sprintf("%+v", root),
			fmt.Sprintf("%#v", root),
		} {
			if rendered != wantRendered ||
				bytes.Contains([]byte(rendered), []byte(rootSentinel)) {
				root.close()
				t.Fatalf("live credential root formatted as %q", rendered)
			}
		}
		rootAlias := root.secret.Bytes()
		root.close()
		if !allZero(rootAlias) {
			t.Fatal("formatted credential root did not clear its retained alias")
		}
	})

	type diagnosticCase struct {
		name     string
		sentinel string
		wantCode KDFErrorCode
		build    func() (context.Context, Admitter, kdfDeriver)
	}
	tests := []diagnosticCase{
		{
			name:     "admission error",
			sentinel: "private-admission-error-sentinel",
			wantCode: KDFErrorAdmission,
			build: func() (context.Context, Admitter, kdfDeriver) {
				return context.Background(), testAdmitter(func(
						context.Context,
						KDFProfile,
					) (KDFAdmission, error) {
						return KDFAdmissionGranted,
							errors.New("private-admission-error-sentinel")
					}), func(
						_ []byte,
						_ []byte,
						_ KDFProfile,
					) ([]byte, error) {
						return fakeKDFResult(0xb1, literalCredentialRootBytes), nil
					}
			},
		},
		{
			name:     "deriver error",
			sentinel: "private-deriver-error-sentinel",
			wantCode: KDFErrorDerivation,
			build: func() (context.Context, Admitter, kdfDeriver) {
				return context.Background(), grantKDFAdmission(), func(
					_ []byte,
					_ []byte,
					_ KDFProfile,
				) ([]byte, error) {
					return fakeKDFResult(0xb2, literalCredentialRootBytes),
						errors.New("private-deriver-error-sentinel")
				}
			},
		},
		{
			name:     "cancellation cause",
			sentinel: "private-cancellation-cause-sentinel",
			wantCode: KDFErrorCancelled,
			build: func() (context.Context, Admitter, kdfDeriver) {
				ctx, cancel := context.WithCancelCause(context.Background())
				cancel(errors.New("private-cancellation-cause-sentinel"))
				return ctx, grantKDFAdmission(), func(
					_ []byte,
					_ []byte,
					_ KDFProfile,
				) ([]byte, error) {
					return fakeKDFResult(0xb3, literalCredentialRootBytes), nil
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, admitter, deriver := test.build()
			input, owner, inputAlias := testNormalInput(t)
			root, err := runCredentialKDF(
				ctx,
				input,
				make([]byte, literalKDFSaltBytes),
				SuiteStandard1,
				admitter,
				deriver,
			)
			requireKDFCode(t, err, test.wantCode)
			if root != nil {
				root.close()
				t.Fatal("diagnostic failure published a credential root")
			}
			if input.secret != nil || owner.Len() != 0 || !allZero(inputAlias) {
				t.Fatal("diagnostic failure did not clear transferred input")
			}
			for _, rendered := range []string{
				err.Error(),
				fmt.Sprintf("%v", err),
				fmt.Sprintf("%+v", err),
				fmt.Sprintf("%#v", err),
			} {
				if bytes.Contains([]byte(rendered), []byte(test.sentinel)) {
					t.Fatalf(
						"KDF diagnostics disclosed sentinel in %q",
						rendered,
					)
				}
			}
		})
	}
}
