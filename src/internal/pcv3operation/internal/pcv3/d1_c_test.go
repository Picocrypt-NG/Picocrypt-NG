package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"errors"
	"testing"
)

// This lane exercises the real bootstrap, body, inner credential schedule,
// capsule authentication, RS reader and plaintext emitter. Literal slot keys
// replace Argon only; independent production-KDF vectors cover that boundary.
func TestD1CIndependentCopiesRecoverBothPayloadSuites(t *testing.T) {
	for _, suite := range []Suite{SuiteStandard, SuiteParanoid} {
		t.Run(map[Suite]string{SuiteStandard: "standard", SuiteParanoid: "paranoid"}[suite], func(t *testing.T) {
			volume, front, tail, want := newD1CCodecFixture(t, suite)
			for _, loss := range []string{"none", "front", "tail"} {
				t.Run(loss, func(t *testing.T) {
					physical := volume
					role, access := D1BootstrapFront, front
					if loss == "front" {
						physical = volume[d1BootstrapLength:]
						role, access = D1BootstrapTail, tail
					}
					if loss == "tail" {
						physical = volume[:len(volume)-d1BootstrapLength]
					}
					got, result := readD1CCodecFixture(t, physical, role, access)
					defer result.Close()
					if !bytes.Equal(got, want) || (result.Outcome() != OutcomeSuccess && result.Outcome() != OutcomeAuthenticatedDegraded) {
						t.Fatalf("independent copy recovery: outcome=%v stage=%v plaintext=%q", result.Outcome(), result.Stage(), got)
					}
				})
			}
		})
	}
}

func TestD1CRequiresBothPurposeMACsAndBindsWholeCiphertextPrefix(t *testing.T) {
	for _, suite := range []Suite{SuiteStandard, SuiteParanoid} {
		volume, access, _, _ := newD1CCodecFixture(t, suite)
		for _, offset := range []int{56, 96, d1BootstrapWrapTagOffset, d1BootstrapInnerWrapTagOffset} {
			raw := append([]byte(nil), volume[:d1BootstrapLength]...)
			raw[offset] ^= 1
			candidate, err := parseD1Bootstrap(raw, D1BootstrapFront)
			if err != nil {
				t.Fatal(err)
			}
			attempt := authenticateD1BootstrapWithAccess(context.Background(), candidate, access, defaultD1BootstrapAuthSeams())
			if attempt.Outcome() != OutcomeCredentialsOrDamage || attempt.authenticated != nil || attempt.Stage() != StageWrapAuth {
				t.Fatalf("suite=%v mutation=%d admitted bootstrap: outcome=%v stage=%v", suite, offset, attempt.Outcome(), attempt.Stage())
			}
			attempt.Close()
		}
	}
}

func TestD1CBootstrapBranchesAndWholeSlotsCannotBeTransplantedAcrossRoles(t *testing.T) {
	for _, suite := range []Suite{SuiteStandard, SuiteParanoid} {
		volume, access, _, _ := newD1CCodecFixture(t, suite)
		tail := volume[len(volume)-d1BootstrapLength:]
		for _, branch := range [][2]int{{56, 96}, {96, 128}, {0, d1BootstrapLength}} {
			raw := append([]byte(nil), volume[:d1BootstrapLength]...)
			copy(raw[branch[0]:branch[1]], tail[branch[0]:branch[1]])
			bootstrap, err := parseD1Bootstrap(raw, D1BootstrapFront)
			if err != nil {
				t.Fatal(err)
			}
			attempt := authenticateD1BootstrapWithAccess(context.Background(), bootstrap, access, defaultD1BootstrapAuthSeams())
			if attempt.Outcome() != OutcomeCredentialsOrDamage || attempt.authenticated != nil {
				t.Fatalf("suite=%v transplanted branch=%v admitted plaintext authority", suite, branch)
			}
			attempt.Close()
		}
	}
}

func TestD1CCandidateIdentityIncludesInnerRootAndProfile(t *testing.T) {
	ctx := context.Background()
	for _, difference := range []string{"inner", "profile"} {
		left, err := pcv3credential.NewD1RootsOwner(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), pcv3credential.D1ProfileParanoid)
		if err != nil {
			t.Fatal(err)
		}
		inner, profile := byte(2), pcv3credential.D1ProfileParanoid
		if difference == "inner" {
			inner = 3
		} else {
			profile = pcv3credential.D1ProfileStandard
		}
		right, err := pcv3credential.NewD1RootsOwner(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{inner}, 32), profile)
		if err != nil {
			t.Fatal(err)
		}
		equal, err := sameD1OuterSecretAccess(ctx, 4096, &d1OuterOwnerAccess{owner: left}, 4096, &d1OuterOwnerAccess{owner: right})
		left.Close()
		right.Close()
		if err != nil || equal {
			t.Fatalf("different %s merged into one identity: equal=%v err=%v", difference, equal, err)
		}
	}
}

func TestD1CCreationRejectsMissingInnerCredentialRoot(t *testing.T) {
	outer := bytes.Repeat([]byte{0x31}, 32)
	owner, err := pcv3credential.NewD1RootsOwner(outer, nil, pcv3credential.D1ProfileParanoid)
	if owner != nil {
		owner.Close()
	}
	if err == nil || owner != nil || !allZero(outer) {
		t.Fatal("creation admitted an O-only owner without independently random I")
	}
}

func TestD1CAllUnwrapScratchIsClearedAfterAuthenticationAndPanic(t *testing.T) {
	volume, access, _, _ := newD1CCodecFixture(t, SuiteParanoid)
	candidate, err := parseD1Bootstrap(volume[:d1BootstrapLength], D1BootstrapFront)
	if err != nil {
		t.Fatal(err)
	}
	for _, panicAfter := range []int{0, 1, 2} {
		seams := defaultD1BootstrapAuthSeams()
		unwrap := seams.unwrapParanoid
		var aliases [][]byte
		panicMarker := errors.New("TEST ONLY D1C unwrap panic")
		seams.unwrapParanoid = func(dst, src, x, nonce, s, iv []byte) error {
			aliases = append(aliases, dst)
			if len(aliases) == panicAfter {
				panic(panicMarker)
			}
			return unwrap(dst, src, x, nonce, s, iv)
		}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil && recovered != panicMarker { //nolint:errorlint // Panic payload must retain exact identity; wrapping it is a regression.
					panic(recovered)
				}
			}()
			attempt := authenticateD1BootstrapWithAccess(context.Background(), candidate, access, seams)
			defer attempt.Close()
			if panicAfter != 0 {
				t.Fatal("unwrap panic was swallowed")
			}
			if attempt.Outcome() != OutcomeSuccess {
				t.Fatal(attempt)
			}
		}()
		for _, alias := range aliases {
			if !allZero(alias) {
				t.Fatal("D1C bootstrap retained O or I unwrap scratch")
			}
		}
	}
}

func TestD1CRawSuiteHintIsRequiredOnlyWithoutAuthenticationAndCannotPromoteOutput(t *testing.T) {
	for _, suite := range []Suite{SuiteStandard, SuiteParanoid} {
		volume, access, _, want := newD1CCodecFixture(t, suite)
		bootstrap, err := parseD1Bootstrap(volume[:d1BootstrapLength], D1BootstrapFront)
		if err != nil {
			t.Fatal(err)
		}
		wrong := SuiteStandard
		if suite == SuiteStandard {
			wrong = SuiteParanoid
		}
		if evaluation, _, err := evaluateD1BootstrapWithHint(context.Background(), bootstrap, access, defaultD1BootstrapAuthSeams(), d1BootstrapAllowRawUnwrap, wrong, true); !errors.Is(err, errD1ProfileMismatch) || evaluation != nil {
			t.Fatalf("authenticated profile accepted contradictory hint: eval=%v err=%v", evaluation, err)
		}
		bootstrap.wrapTag[0] ^= 1
		bootstrap.innerWrapTag[0] ^= 1
		// Both purpose tags can be lost while the independent replica tag
		// still authenticates the hidden profile without any user hint.
		evaluation, _, err := evaluateD1BootstrapWithHint(context.Background(), bootstrap, access, defaultD1BootstrapAuthSeams(), d1BootstrapAllowRawUnwrap, 0, true)
		if err != nil || evaluation == nil || evaluation.wrapVerified || !evaluation.replicaVerified || evaluation.profileHinted {
			t.Fatalf("surviving replica evidence lost: eval=%v err=%v", evaluation, err)
		}
		evaluation.Close()
		bootstrap.replicaTag[0] ^= 1
		if evaluation, _, err := evaluateD1BootstrapWithHint(context.Background(), bootstrap, access, defaultD1BootstrapAuthSeams(), d1BootstrapAllowRawUnwrap, 0, true); !errors.Is(err, ErrD1ProfileRequired) || evaluation != nil {
			t.Fatalf("ambiguous raw profile guessed without hint: eval=%v err=%v", evaluation, err)
		}
		err = withUnverifiedD1RecoveryRequestAndSuite(D1BootstrapFront, suite, func(request d1RecoveryRequest) error {
			return bindD1ForceCandidateWithHint(context.Background(), bootstrap, access, defaultD1BootstrapAuthSeams(), suite, true, func(candidate *d1ForceCandidate) error {
				if candidate == nil || !candidate.profileHinted || candidate.wrapVerified || candidate.replicaVerified {
					return errors.New("raw hint manufactured authentication")
				}
				selection, terminal, err := selectD1ForceCandidateWithPreanalysis(context.Background(), bytes.NewReader(volume), int64(len(volume)), request, []*d1ForceCandidate{candidate}, defaultD1ForceSeams(), nil)
				if err != nil || terminal != nil {
					return errors.New("hinted candidate did not reach real outer-body selection")
				}
				if selection.outerProvenance != D1OuterProvenanceRawSelected {
					return errors.New("hinted candidate lost raw provenance")
				}
				var plaintext []byte
				var result *RecoveryResult
				err = pcv3credential.WithValidatedFactors(context.Background(), d1CCodecFactors(), func(factors *pcv3credential.ValidatedFactors) error {
					var err error
					result, err = recoverD1Selection(context.Background(), bytes.NewReader(volume), int64(len(volume)), factors, request, selection, defaultD1ForceSeams(), func(_ *RecoveryResult, _ D1BootstrapRole, _ string, _ RecoveryOutputPlan, emitter RecoveryEmitter) error {
						return emitter(func(_ RecoveryRange, data []byte) error { plaintext = append(plaintext, data...); return nil })
					})
					return err
				})
				if result != nil {
					defer result.Close()
				}
				if err != nil || result == nil || result.Outcome() != OutcomeForceUnverified || result.D1OuterProvenance() != D1OuterProvenanceRawSelected || !bytes.Equal(plaintext, want) {
					return errors.New("authenticated inner promoted suite-hinted raw recovery")
				}
				return nil
			})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestD1CDeepProfileRefusalDoesNotRepeatCandidateCallbackOrTailKDF(t *testing.T) {
	volume, access, _, _ := newD1CCodecFixture(t, SuiteParanoid)
	bootstrap, err := parseD1Bootstrap(volume[:d1BootstrapLength], D1BootstrapFront)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = withUnverifiedD1RecoveryRequest(D1BootstrapFront, func(request d1RecoveryRequest) error {
		return withD1RecoveryCandidate(context.Background(), bootstrap, access, request, func(*d1ForceCandidate) error {
			calls++
			// This callback owns tail derivation in the production nesting. Its
			// refusal must propagate, rather than re-entering the tail path.
			return ErrD1ProfileRequired
		})
	})
	if !errors.Is(err, ErrD1ProfileRequired) || calls != 1 {
		t.Fatalf("deep profile refusal repeated tail work: calls=%d err=%v", calls, err)
	}
}

func TestD1CSuiteHintCannotContradictOtherSlotSinglePurposeAuthentication(t *testing.T) {
	volume, access, _, _ := newD1CCodecFixture(t, SuiteParanoid)
	raw := append([]byte(nil), volume[:d1BootstrapLength]...)
	raw[d1BootstrapReplicaTagOffset] ^= 1
	recomputeD1BootstrapWrapTag(t, raw, D1BootstrapFront, access.keys[1].mac[:], access.keys[1].innerMAC[:])
	raw[d1BootstrapWrapTagOffset] ^= 1
	bootstrap, err := parseD1Bootstrap(raw, D1BootstrapFront)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	err = withUnverifiedD1RecoveryRequestAndSuite(D1BootstrapTail, SuiteStandard, func(request d1RecoveryRequest) error {
		return withD1RecoveryCandidate(context.Background(), bootstrap, access, request, func(*d1ForceCandidate) error { calls++; return nil })
	})
	if err == nil || calls != 0 {
		t.Fatalf("hint contradicted surviving inner-purpose authentication on other slot: calls=%d err=%v", calls, err)
	}
}

type d1CProfileTestAccess struct {
	bootstrapRole D1BootstrapRole
	keys          [2]d1BootstrapWrapKeys
}

func (access *d1CProfileTestAccess) role() D1BootstrapRole { return access.bootstrapRole }
func (access *d1CProfileTestAccess) withWrapKeys(ctx context.Context, callback func(*d1BootstrapWrapKeys) error) error {
	return access.withProfileWrapKeys(ctx, pcv3credential.D1ProfileParanoid, callback)
}

func (access *d1CProfileTestAccess) withProfileWrapKeys(ctx context.Context, profile pcv3credential.D1Profile, callback func(*d1BootstrapWrapKeys) error) error {
	if ctx == nil || ctx.Err() != nil || callback == nil || profile.Suite() == 0 {
		return errInvalidD1Bootstrap
	}
	index := 0
	if profile == pcv3credential.D1ProfileParanoid {
		index = 1
	}
	keys := access.keys[index]
	defer keys.close()
	return callback(&keys)
}

func newD1CCodecFixture(t *testing.T, suite Suite) ([]byte, *d1CProfileTestAccess, *d1CProfileTestAccess, []byte) {
	t.Helper()
	ctx := context.Background()
	profile := pcv3credential.D1ProfileForSuite(credentialSuite(suite))
	outer, err := pcv3credential.NewD1RootsOwner(bytes.Repeat([]byte{0x31}, 32), bytes.Repeat([]byte{0x72}, 32), profile)
	if err != nil {
		t.Fatal(err)
	}
	defer outer.Close()
	outerAccess := &d1OuterOwnerAccess{owner: outer}
	accesses := [2]*d1CProfileTestAccess{}
	for role := range accesses {
		accesses[role] = &d1CProfileTestAccess{bootstrapRole: D1BootstrapRole(role)}
		for profileIndex := range accesses[role].keys {
			keys := &accesses[role].keys[profileIndex]
			for keyIndex, destination := range [][]byte{keys.xChaCha20[:], keys.serpent[:], keys.mac[:], keys.innerXChaCha20[:], keys.innerSerpent[:], keys.innerMAC[:]} {
				fillD1TestBytes(destination, byte(1+role*17+profileIndex*31+keyIndex*43))
			}
		}
	}
	plaintext := []byte("TEST ONLY D1C independently recoverable roots and optional Paranoid")
	request := normalWriteRequest{suite: suite, payloadKind: PayloadKindRaw, payloadBodyRS: true, plaintextLength: uint64(len(plaintext))}
	plan, err := planD1Write(request)
	if err != nil {
		t.Fatal(err)
	}
	var volume bytes.Buffer
	err = pcv3credential.WithValidatedFactors(ctx, d1CCodecFactors(), func(factors *pcv3credential.ValidatedFactors) error {
		return pcv3credential.WithD1InnerCredentialOwner(ctx, bytes.Repeat([]byte{0x72}, 32), profile, factors, [16]byte{0x41}, [32]byte{0x51}, bytes.Repeat([]byte{0xa3}, 32), func(owner *pcv3credential.Owner) error {
			parameters := [2]d1BootstrapWriteParameters{}
			for role := range parameters {
				fillD1TestBytes(parameters[role].argonSalt[:], byte(0x10+role))
				fillD1TestBytes(parameters[role].wrapNonce[:], byte(0x30+role))
				fillD1TestBytes(parameters[role].wrapSerpentIV[:], byte(0x50+role))
			}
			front, err := encodeD1Bootstrap(ctx, D1BootstrapFront, plan.outer.bodyLength, parameters[0], accesses[0], outerAccess)
			if err != nil {
				return err
			}
			volume.Write(front[:])
			codecs, err := pcencoding.NewRSCodecs()
			if err != nil {
				return err
			}
			if _, err := writeD1NormalBody(ctx, request, bytes.NewReader(plaintext), &volume, ownerNormalWriteMaterial{owner: owner}, normalWriteSeams{entropy: bytes.NewReader(bytes.Repeat([]byte{0x93}, 256)), codecs: codecs}, outerAccess); err != nil {
				return err
			}
			tail, err := encodeD1Bootstrap(ctx, D1BootstrapTail, plan.outer.bodyLength, parameters[1], accesses[1], outerAccess)
			if err != nil {
				return err
			}
			volume.Write(tail[:])
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return volume.Bytes(), accesses[0], accesses[1], plaintext
}

func d1CCodecFactors() *pcv3credential.FactorRequest {
	return &pcv3credential.FactorRequest{Mode: pcv3credential.CredentialModePasswordOnly, KeyfileMode: pcv3credential.KeyfileModeNone, ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly, Password: []byte("TEST ONLY D1C factor")}
}

func readD1CCodecFixture(t *testing.T, volume []byte, role D1BootstrapRole, access *d1CProfileTestAccess) ([]byte, *RecoveryResult) {
	t.Helper()
	ctx := context.Background()
	offset := 0
	if role == D1BootstrapTail {
		offset = len(volume) - d1BootstrapLength
	}
	bootstrap, err := parseD1Bootstrap(volume[offset:offset+d1BootstrapLength], role)
	if err != nil {
		t.Fatal(err)
	}
	attempt := authenticateD1BootstrapWithAccess(ctx, bootstrap, access, defaultD1BootstrapAuthSeams())
	defer attempt.Close()
	if attempt.Outcome() != OutcomeSuccess {
		t.Fatalf("authenticate D1C profile: %v", attempt)
	}
	secret := attempt.authenticated.takeSecret()
	candidate := &d1ForceCandidate{role: role, bootstrap: bootstrap, bootstrapKnown: true, bodyLength: secret.bodyLength, secret: secret, wrapVerified: true, replicaVerified: true}
	defer candidate.Close()
	window, err := deriveD1ForceBodyWindow(int64(len(volume)), secret.bodyLength, role)
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := analyzeD1ForceCandidate(ctx, bytes.NewReader(volume), window, candidate, defaultD1ForceSeams())
	if err != nil {
		t.Fatal(err)
	}
	request, err := newD1RecoveryRequest(RecoveryModeNormalV3)
	if err != nil {
		t.Fatal(err)
	}
	selection := d1ForceSelection{analysis: analysis, provenance: d1BootstrapProvenanceForRole(role), bootstrapHealthy: canonicalD1Geometry(int64(len(volume)), secret.bodyLength), outerHealthy: true}
	var plaintext []byte
	var result *RecoveryResult
	err = pcv3credential.WithValidatedFactors(ctx, d1CCodecFactors(), func(factors *pcv3credential.ValidatedFactors) error {
		var err error
		result, err = recoverD1Selection(ctx, bytes.NewReader(volume), int64(len(volume)), factors, request, selection, defaultD1ForceSeams(), func(_ *RecoveryResult, _ D1BootstrapRole, _ string, _ RecoveryOutputPlan, emitter RecoveryEmitter) error {
			return emitter(func(r RecoveryRange, data []byte) error {
				if r.State() != RecoveryRangeVerified {
					return errors.New("unverified D1C plaintext")
				}
				plaintext = append(plaintext, data...)
				return nil
			})
		})
		return err
	})
	if err != nil || result == nil {
		t.Fatalf("read real D1C inner path: result=%v err=%v", result, err)
	}
	return plaintext, result
}
