package pcv3

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3credential"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"testing"
)

func authenticateCapsulesWithProvider(
	ctx context.Context,
	structure Structure,
	provider capsuleCredentialProvider,
	seams capsuleAuthSeams,
) *normalAuthResult {
	return authenticateCapsulesWithProviderMode(ctx, structure, provider, seams, true, false)
}

func TestAuthenticateCapsulesCredentialPipelineClassification(t *testing.T) {
	claimed, ok := credentialFactorPolicy(CredentialModeCombined)
	if !ok || claimed != pcv3credential.FactorPolicyPasswordAndKeyfiles {
		t.Fatal("combined capsule mode did not map to its complete factor policy")
	}
	if _, ok := credentialFactorPolicy(CredentialMode(0xff)); ok {
		t.Fatal("unknown capsule credential mode mapped to a factor policy")
	}

	missingOwner := &pcv3credential.PipelineError{
		Code:  pcv3credential.PipelineErrorOwner,
		Stage: pcv3credential.PipelineStageOwner,
	}
	if !expectedMissingOwner(missingOwner) {
		t.Fatal("expected no-adoption Owner result was not recognized")
	}

	tests := []struct {
		name string
		err  error
		want Stage
	}{
		{
			name: "post-callback cancellation remains terminal",
			err: &pcv3credential.PipelineError{
				Code:  pcv3credential.PipelineErrorCancelled,
				Stage: pcv3credential.PipelineStageCallback,
			},
			want: StageCancellation,
		},
		{
			name: "factor rejection is credential policy",
			err: &pcv3credential.PipelineError{
				Code:  pcv3credential.PipelineErrorFactors,
				Stage: pcv3credential.PipelineStageFactors,
			},
			want: StageCredentialPolicy,
		},
		{
			name: "KDF failure is runtime",
			err: &pcv3credential.PipelineError{
				Code:  pcv3credential.PipelineErrorKDF,
				Stage: pcv3credential.PipelineStageKDF,
			},
			want: StageKDFRuntime,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if expectedMissingOwner(test.err) {
				t.Fatal("operational error was mistaken for expected no-adoption")
			}
			if got := credentialPipelineStage(test.err); got != test.want {
				t.Fatalf("stage = %v; want %v", got, test.want)
			}
		})
	}
}

// TEST ONLY: independently generated decoded capsule and derived-key literals.
// Expectations below never call the production serializer or MAC builder.
const (
	literalStandardPrimary = "5043560000030001000100000000045812131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30310101010000000000000000000000000000000000161718191a1b1c1d1e1f202122232425000000000000000000000000000100010000000032333435363738393a3b3c3d3e3f40417172737475767778797a7b7c7d7e7f80818283848586878800000000000000000000000000000000ec3f7d78243c472664abecdb50b6d0772c55fd8848a03ce145873ffa8a86c62fdd3ff0b811cfb14c8e2ed8a272ed529e745ecadda1f5d46f33143b96ccd06ef1795c2b5988992c6e96ebc6e70993a7661bf87722d81451eb023e100e87845d6659f00d55d5a520f6c73f049485fa931e12ae712eb5e385ab76f095c08acc81eccb52b2c688ec15f44f623cc8dd458197c6072cc5dcf257b66eb1b31876a8d6b1"
	literalStandardBackup  = "5043560000030001000100000000045812131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30310101010000000000000000000000000000000000161718191a1b1c1d1e1f202122232425000000000000000000000000010100010000000032333435363738393a3b3c3d3e3f40419192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a80000000000000000000000000000000049a1dd33712fea1a9babe26c6829aff9c5b042dbc2b5b31b04582585504e26bf419fb4a08276331a12c8e470504a4c6f6e76066bc3ca09d9c9ad60d8c2095dd7389d153df2e802a656e8615e2c44136cedce2114f5c4f0a087d02880b2b97dd7c680a1f5e559187f7e54bbfd3a7915319c36fb0e04b41ae18be31cfac34b8066fd8c96cb63f06c132cfc641264257d8042d503d89e3f4c1a6ab429a855f30e87"
	literalParanoidPrimary = "50435600000300010002000000000458131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313201010100000000000000000000000000000000001718191a1b1c1d1e1f2021222324252645464748494a4b4c000000000001000200000000333435363738393a3b3c3d3e3f4041427172737475767778797a7b7c7d7e7f8081828384858687889192939495969798999a9b9c9d9e9fa035334419859e7956da6f308ba3349abaad61c02342ecdf105242f705d1515daedbfcf543ba350b9f9047816e331a977c394968b5c7275d1c6162775ca28656c3e22f70d9720a953ac297b7bbacd2e91172192fe3615bf62b91092fbea248e0d4d68754da70fcc8379b13b5be0296d131f79e41c22bd5109ff167a9ecaf23113208f003947a466061d1f87cf30af0ee017e3aa90297c11bc442a71206c723b12d"
	literalParanoidBackup  = "50435600000300010002000000000458131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313201010100000000000000000000000000000000001718191a1b1c1d1e1f2021222324252645464748494a4b4c000000000101000200000000333435363738393a3b3c3d3e3f4041429192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8b9babbbcbdbebfc0177f75575d542c11817f5255e5ad4cc4a1380d38f940528e4e38122821909d1a899ced4970424f167ee052b594dbecc82b4ac98aaffeb68718f822dba82628dbb1399397c2e594bb4696fadcfb7a6e3039a4622cfacfd6dfeb28443697125b8e172fc94aff138a8a72ffdc8973ffed020802e1261e09a288fe883db64ec02071f6d1c8a33c7594bf13d3ca4e0eafbe6c6eed4089186d1ed2eaf0c6356c069895"
	literalDamagedWrap     = "5043560000030001000100000000045812131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30310101010000000000000000000000000000000000161718191a1b1c1d1e1f202122232425000000000000000000000000000100010000000032333435363738393a3b3c3d3e3f40417172737475767778797a7b7c7d7e7f80818283848586878800000000000000000000000000000000ec3f7d78243c472664abecdb50b6d0772c55fd8848a03ce145873ffa8a86c62fdd3ff0b811cfb14c8e2ed8a272ed529e745ecadda1f5d46f33143b96ccd06ef1795c2b5988992c6e96ebc6e70993a7661bf87722d81451eb023e100e87845d6658f00d55d5a520f6c73f049485fa931e12ae712eb5e385ab76f095c08acc81eccb52b2c688ec15f44f623cc8dd458197c6072cc5dcf257b66eb1b31876a8d6b1"
	literalDamagedReplica  = "5043560000030001000100000000045812131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30310101010000000000000000000000000000000000161718191a1b1c1d1e1f202122232425000000000000000000000000000100010000000032333435363738393a3b3c3d3e3f40417172737475767778797a7b7c7d7e7f80818283848586878800000000000000000000000000000000ec3f7d78243c472664abecdb50b6d0772c55fd8848a03ce145873ffa8a86c62fdc3ff0b811cfb14c8e2ed8a272ed529e745ecadda1f5d46f33143b96ccd06ef1795c2b5988992c6e96ebc6e70993a7661bf87722d81451eb023e100e87845d66ce01af7c3879ff97a2ff4640580cb01a0d052ed4f98a91fc8d1e8d418a19e5ef73fac4edab0c5a7a215c36132696e2ea8d99a9483d93da9fda190c33f4bac69a"
	literalDivergentBackup = "5043560000030001000100000000045842434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60610101010000000000000000000000000000000000161718191a1b1c1d1e1f202122232425000000000000000000000000010100010000000052535455565758595a5b5c5d5e5f60619192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8000000000000000000000000000000002d9fb31fe73ff2e0c1f3e2fabc78a513bcaeef06b94c5daf72fa6eec1ffdf4b80ea1f5fd3b7942e538dc10584c4e3eeb6295eeb0b1411d6fd3126fc4d85bf069f1d784b6900bd2fe5c4fd7a1c0150d0a19de6b954bd901f0e0f3cd78b082736f11235abe77146bd30157d8eccb4b157c77e8f15e1f84ae92f01c48fac6b79ad29e9ebb13d6d59a20646db22450c23846444ac204a5efd33181f05e9e261ae14b"
	literalSpliceBackup    = "5043560000030001000100000000045812131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30310101010000000000000000000000000000000000161718191a1b1c1d1e1f202122232425000000000000000000000000010100010000000032333435363738393a3b3c3d3e3f40419192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a80000000000000000000000000000000009e19d73316faa5adbeba22c2869efb985f0029b82f5f35b441865c5100e66ff298ced90cb499c7831d6272f5a81c62b15a98a124659ad97b04e894706b0a7de6929453578068800888525471fed28fcf15cd0c0f191cc50f2ee993489f4f92b78bd5870829d4cb36a5274bdf54fabea81b5e125575c923dfae09a5416486d59a612fa5e8be466f92e4ea2cd4af91aabb811cb88ea73233762dc97882b35c836"
)

type literalReplicaSelector struct {
	role      CapsuleRole
	volumeKey [32]byte
}

type literalCredentialAccess struct {
	wrap         [2]capsuleWrapKeys
	replica      map[literalReplicaSelector][32]byte
	replicaCalls int
	adoptCalls   int
	adopted      [32]byte
}

func (access *literalCredentialAccess) withWrapKeys(
	role CapsuleRole,
	callback func(*capsuleWrapKeys) error,
) error {
	if !isSupportedCapsuleRole(role) || callback == nil {
		return errors.New("invalid literal wrap-key request")
	}
	keys := access.wrap[role]
	defer keys.close()
	return callback(&keys)
}

func (access *literalCredentialAccess) withReplicaKey(
	role CapsuleRole,
	volumeKey []byte,
	callback func([]byte) error,
) error {
	if !isSupportedCapsuleRole(role) || len(volumeKey) != 32 || callback == nil {
		return errors.New("invalid literal replica-key request")
	}
	access.replicaCalls++
	var selector literalReplicaSelector
	selector.role = role
	copy(selector.volumeKey[:], volumeKey)
	key, ok := access.replica[selector]
	if !ok {
		return errors.New("unknown literal VolumeKey")
	}
	return callback(key[:])
}

func (access *literalCredentialAccess) adoptVolumeKey(transfer []byte) error {
	defer crypto.SecureZero(transfer)
	if len(transfer) != 32 || access.adoptCalls != 0 {
		return errors.New("invalid literal VolumeKey adoption")
	}
	access.adoptCalls++
	copy(access.adopted[:], transfer)
	return nil
}

func (access *literalCredentialAccess) close() {
	for i := range access.wrap {
		crypto.SecureZero(access.wrap[i].xChaCha20[:])
		crypto.SecureZero(access.wrap[i].serpent[:])
		crypto.SecureZero(access.wrap[i].mac[:])
	}
	for selector, key := range access.replica {
		crypto.SecureZero(selector.volumeKey[:])
		crypto.SecureZero(key[:])
		delete(access.replica, selector)
	}
	crypto.SecureZero(access.adopted[:])
}

type literalCredentialProvider struct {
	access *literalCredentialAccess
	calls  int
}

func (provider *literalCredentialProvider) withCredential(
	ctx context.Context,
	_ credentialTuple,
	callback func(capsuleCredentialAccess) error,
) error {
	if ctx == nil || ctx.Err() != nil || callback == nil {
		return errors.New("invalid literal credential request")
	}
	provider.calls++
	return callback(provider.access)
}

type literalKDFAdmitter struct {
	calls int
}

func (admitter *literalKDFAdmitter) AdmitKDF(
	context.Context,
	pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	admitter.calls++
	return pcv3credential.KDFAdmissionGranted, nil
}

func TestAuthenticateCapsulesReaderAdapterOwnershipCancellationAndZeroing(
	t *testing.T,
) {
	primary := literalCandidate(t, literalStandardPrimary, CapsuleRolePrimary)
	backup := literalCandidate(t, literalStandardBackup, CapsuleRoleBackup)
	structure := literalStructure(primary, backup)
	tuple, ok := credentialTupleForStructure(structure)
	if !ok {
		t.Fatal("TEST ONLY Standard-1 structure did not produce a credential tuple")
	}

	tests := []struct {
		name         string
		publishOwner bool
		runnerErr    error
		unwrapErr    bool
		wantOutcome  Outcome
		wantStage    Stage
		wantAuth     int
		wantReplica  int
		wantAdopt    int
		wantOwner    bool
	}{
		{
			name:         "transfers the only published Owner",
			publishOwner: true,
			wantOutcome:  OutcomeSuccess,
			wantStage:    StageNone,
			wantAuth:     2,
			wantReplica:  2,
			wantAdopt:    1,
			wantOwner:    true,
		},
		{
			name: "post-adoption cancellation remains terminal",
			runnerErr: &pcv3credential.PipelineError{
				Code:  pcv3credential.PipelineErrorCancelled,
				Stage: pcv3credential.PipelineStageCallback,
			},
			wantOutcome: OutcomeOperationFailed,
			wantStage:   StageCancellation,
			wantReplica: 2,
			wantAdopt:   1,
		},
		{
			name: "authenticated result without Owner fails closed",
			runnerErr: &pcv3credential.PipelineError{
				Code:  pcv3credential.PipelineErrorOwner,
				Stage: pcv3credential.PipelineStageOwner,
			},
			wantOutcome: OutcomeOperationFailed,
			wantStage:   StageUnwrap,
			wantReplica: 2,
			wantAdopt:   1,
		},
		{
			name:        "unwrap error clears the exact destination",
			unwrapErr:   true,
			wantOutcome: OutcomeOperationFailed,
			wantStage:   StageUnwrap,
			wantReplica: 0,
			wantAdopt:   0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			access := standardLiteralAccess(t)
			defer access.close()
			var publishedOwner *pcv3credential.Owner
			if test.publishOwner {
				publishedOwner = &pcv3credential.Owner{}
			}
			runnerCalls := 0
			admitter := &literalKDFAdmitter{}
			provider := &readerCredentialProvider{
				admitter: admitter,
				run: func(
					_ context.Context,
					request *pcv3credential.ReaderCredentialRequest,
					_ pcv3credential.Admitter,
					_ Suite,
					callback func(capsuleCredentialAccess) error,
				) (*pcv3credential.Owner, error) {
					runnerCalls++
					if request == nil ||
						request.Suite != credentialSuite(tuple.suite) ||
						request.ProfileID != uint8(tuple.kdfProfile) ||
						request.ClaimedPolicy != pcv3credential.FactorPolicyPasswordOnly ||
						!bytes.Equal(request.ArgonSalt, tuple.argonSalt[:]) ||
						!bytes.Equal(request.VolumeID, tuple.volumeID[:]) {
						t.Fatal("adapter did not build the credential request from the capsule tuple")
					}
					if err := callback(access); err != nil {
						return nil, err
					}
					return publishedOwner, test.runnerErr
				},
			}

			var unwrapAliases [][]byte
			seams := defaultCapsuleAuthSeams()
			standard := seams.unwrapStandard
			seams.unwrapStandard = func(
				destination, source, key, nonce []byte,
			) error {
				unwrapAliases = append(unwrapAliases, destination)
				if err := standard(destination, source, key, nonce); err != nil {
					return err
				}
				if test.unwrapErr {
					return errors.New("TEST ONLY injected unwrap failure")
				}
				return nil
			}

			result := authenticateCapsulesWithProvider(
				context.Background(),
				structure,
				provider,
				seams,
			)
			if result.Outcome() != test.wantOutcome ||
				result.Stage() != test.wantStage ||
				result.AuthenticatedCapsules() != test.wantAuth {
				t.Fatalf(
					"result = %v/%v/%d; want %v/%v/%d",
					result.Outcome(),
					result.Stage(),
					result.AuthenticatedCapsules(),
					test.wantOutcome,
					test.wantStage,
					test.wantAuth,
				)
			}
			if runnerCalls != 1 || access.replicaCalls != test.wantReplica ||
				access.adoptCalls != test.wantAdopt {
				t.Fatalf(
					"runner/replica/adopt calls = %d/%d/%d; want 1/%d/%d",
					runnerCalls,
					access.replicaCalls,
					access.adoptCalls,
					test.wantReplica,
					test.wantAdopt,
				)
			}
			if provider.owner != nil {
				t.Fatal("adapter retained the transferred Owner")
			}
			if test.wantOwner {
				if result.owner != publishedOwner {
					t.Fatal("authenticated result did not receive the exact Owner")
				}
			} else if result.owner != nil {
				t.Fatal("failed authentication published an Owner")
			}
			for i, alias := range unwrapAliases {
				if !allZero(alias) {
					t.Fatalf("unwrapped VolumeKey alias %d survived adapter exit", i)
				}
			}
			result.Close()
			if result.owner != nil {
				t.Fatal("result Close retained the published Owner")
			}
		})
	}
}

type literalKeyfileReadCloser struct {
	reader *bytes.Reader
	reads  int
	closes int
}

func (reader *literalKeyfileReadCloser) Read(destination []byte) (int, error) {
	reader.reads++
	return reader.reader.Read(destination)
}

func (reader *literalKeyfileReadCloser) Close() error {
	reader.closes++
	return nil
}

func TestAuthenticateCapsulesReaderAdapterClosesFactorsOnPreKDFExit(
	t *testing.T,
) {
	primary := literalCandidate(t, literalStandardPrimary, CapsuleRolePrimary)
	backup := literalCandidate(t, literalStandardBackup, CapsuleRoleBackup)
	healthy := literalStructure(primary, backup)
	tests := []struct {
		name        string
		ctx         func() context.Context
		structure   Structure
		wantOutcome Outcome
		wantStage   Stage
	}{
		{
			name:        "invalid structure",
			ctx:         context.Background,
			structure:   Structure{},
			wantOutcome: OutcomeInvalidStructurePreKDF,
			wantStage:   StageCapsuleStructure,
		},
		{
			name: "pre-cancelled context",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			structure:   healthy,
			wantOutcome: OutcomeOperationFailed,
			wantStage:   StageCancellation,
		},
		{
			name:        "caller policy contradicts capsule claim",
			ctx:         context.Background,
			structure:   healthy,
			wantOutcome: OutcomeOperationFailed,
			wantStage:   StageCredentialPolicy,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			passwordAlias := []byte("TEST ONLY transferred password")
			keyfile := &literalKeyfileReadCloser{
				reader: bytes.NewReader([]byte("TEST ONLY keyfile")),
			}
			factors := &pcv3credential.FactorRequest{
				Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
				KeyfileMode:    pcv3credential.KeyfileModeOrdered,
				ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
				Password:       passwordAlias,
				Keyfiles: []*pcv3credential.KeyfileReader{
					pcv3credential.OwnKeyfileReader(keyfile),
				},
			}
			admitter := &literalKDFAdmitter{}
			provider := &readerCredentialProvider{
				factors:  factors,
				admitter: admitter,
			}

			result := authenticateCapsulesWithProvider(
				test.ctx(),
				test.structure,
				provider,
				defaultCapsuleAuthSeams(),
			)
			defer result.Close()
			if result.Outcome() != test.wantOutcome ||
				result.Stage() != test.wantStage ||
				result.AuthenticatedCapsules() != 0 {
				t.Fatalf(
					"pre-KDF exit = %v/%v/%d; want %v/%v/0",
					result.Outcome(),
					result.Stage(),
					result.AuthenticatedCapsules(),
					test.wantOutcome,
					test.wantStage,
				)
			}
			if provider.factors != nil || factors.Password != nil || factors.Keyfiles != nil {
				t.Fatal("adapter retained transferred factors after pre-KDF exit")
			}
			if !allZero(passwordAlias) {
				t.Fatal("pre-KDF exit retained the transferred password alias")
			}
			if keyfile.reads != 0 || keyfile.closes != 1 {
				t.Fatalf(
					"pre-KDF exit keyfile reads/closes = %d/%d; want 0/1",
					keyfile.reads,
					keyfile.closes,
				)
			}
			if admitter.calls != 0 {
				t.Fatalf("pre-KDF exit reached KDF admission %d times", admitter.calls)
			}
		})
	}
}

func TestAuthenticateCapsulesFrozenCases(t *testing.T) {
	standardPrimary := literalCandidate(t, literalStandardPrimary, CapsuleRolePrimary)
	standardBackup := literalCandidate(t, literalStandardBackup, CapsuleRoleBackup)
	paranoidPrimary := literalCandidate(t, literalParanoidPrimary, CapsuleRolePrimary)
	paranoidBackup := literalCandidate(t, literalParanoidBackup, CapsuleRoleBackup)
	damagedWrap := literalCandidate(t, literalDamagedWrap, CapsuleRolePrimary)
	damagedReplica := literalCandidate(t, literalDamagedReplica, CapsuleRolePrimary)
	divergentBackup := literalCandidate(t, literalDivergentBackup, CapsuleRoleBackup)
	spliceBackup := literalCandidate(t, literalSpliceBackup, CapsuleRoleBackup)

	tests := []struct {
		name         string
		structure    Structure
		access       func(*testing.T) *literalCredentialAccess
		wantOutcome  Outcome
		wantStage    Stage
		wantAuth     int
		wantProvider int
		wantUnwrap   int
		wantReplica  int
		wantAdopt    int
		wantSelected int
	}{
		{
			name:         "healthy Standard-1",
			structure:    literalStructure(standardPrimary, standardBackup),
			access:       standardLiteralAccess,
			wantOutcome:  OutcomeSuccess,
			wantStage:    StageNone,
			wantAuth:     2,
			wantProvider: 1,
			wantUnwrap:   2,
			wantReplica:  2,
			wantAdopt:    1,
			wantSelected: 0,
		},
		{
			name:         "healthy Paranoid-1",
			structure:    literalStructure(paranoidPrimary, paranoidBackup),
			access:       paranoidLiteralAccess,
			wantOutcome:  OutcomeSuccess,
			wantStage:    StageNone,
			wantAuth:     2,
			wantProvider: 1,
			wantUnwrap:   2,
			wantReplica:  2,
			wantAdopt:    1,
			wantSelected: 0,
		},
		{
			name:         "wrap failure never unwraps",
			structure:    literalStructure(damagedWrap, standardBackup),
			access:       standardLiteralAccess,
			wantOutcome:  OutcomeAuthenticatedDegraded,
			wantStage:    StageWrapAuth,
			wantAuth:     1,
			wantProvider: 1,
			wantUnwrap:   1,
			wantReplica:  1,
			wantAdopt:    1,
			wantSelected: 1,
		},
		{
			name:         "replica failure after valid wrap",
			structure:    literalStructure(damagedReplica, standardBackup),
			access:       standardLiteralAccess,
			wantOutcome:  OutcomeAuthenticatedDegraded,
			wantStage:    StageReplicaAuth,
			wantAuth:     1,
			wantProvider: 1,
			wantUnwrap:   2,
			wantReplica:  2,
			wantAdopt:    1,
			wantSelected: 1,
		},
		{
			name:         "backup role survives compressed index zero",
			structure:    literalStructure(standardBackup),
			access:       standardLiteralAccess,
			wantOutcome:  OutcomeAuthenticatedDegraded,
			wantStage:    StageCapsuleStructure,
			wantAuth:     1,
			wantProvider: 1,
			wantUnwrap:   1,
			wantReplica:  1,
			wantAdopt:    1,
			wantSelected: 0,
		},
		{
			name: "authenticated semantics reject stale tags",
			structure: func() Structure {
				mutated := standardPrimary
				mutated.core.payloadKind = PayloadKindArchive
				return literalStructure(mutated, standardBackup)
			}(),
			access:       standardLiteralAccess,
			wantOutcome:  OutcomeAuthenticatedDegraded,
			wantStage:    StageWrapAuth,
			wantAuth:     1,
			wantProvider: 1,
			wantUnwrap:   1,
			wantReplica:  1,
			wantAdopt:    1,
			wantSelected: 1,
		},
		{
			name:         "wrong credential is generic",
			structure:    literalStructure(standardPrimary, standardBackup),
			access:       wrongCredentialLiteralAccess,
			wantOutcome:  OutcomeCredentialsOrDamage,
			wantStage:    StageWrapAuth,
			wantAuth:     0,
			wantProvider: 1,
			wantUnwrap:   0,
			wantReplica:  0,
			wantAdopt:    0,
			wantSelected: -1,
		},
		{
			name:         "divergent tuple stops before KDF",
			structure:    literalStructure(standardPrimary, divergentBackup),
			access:       standardLiteralAccess,
			wantOutcome:  OutcomeInvalidStructurePreKDF,
			wantStage:    StageCapsuleStructure,
			wantAuth:     0,
			wantProvider: 0,
			wantUnwrap:   0,
			wantReplica:  0,
			wantAdopt:    0,
			wantSelected: -1,
		},
		{
			name:         "authenticated splice is ambiguous",
			structure:    literalStructure(standardPrimary, spliceBackup),
			access:       spliceLiteralAccess,
			wantOutcome:  OutcomeAmbiguousVolume,
			wantStage:    StageCapsuleStructure,
			wantAuth:     2,
			wantProvider: 1,
			wantUnwrap:   2,
			wantReplica:  2,
			wantAdopt:    0,
			wantSelected: -1,
		},
		{
			name: "authenticated core mismatch degrades at preamble",
			structure: func() Structure {
				structure := literalStructure(standardPrimary, standardBackup)
				structure.preamble.featureFlags ^= payloadBodyRSFeatureMask
				return structure
			}(),
			access:       standardLiteralAccess,
			wantOutcome:  OutcomeAuthenticatedDegraded,
			wantStage:    StagePreamble,
			wantAuth:     2,
			wantProvider: 1,
			wantUnwrap:   2,
			wantReplica:  2,
			wantAdopt:    1,
			wantSelected: 0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			access := test.access(t)
			defer access.close()
			provider := &literalCredentialProvider{access: access}
			unwrapCalls := 0
			var unwrapAliases [][]byte
			seams := defaultCapsuleAuthSeams()
			standard := seams.unwrapStandard
			paranoid := seams.unwrapParanoid
			seams.unwrapStandard = func(destination, source, key, nonce []byte) error {
				unwrapCalls++
				unwrapAliases = append(unwrapAliases, destination)
				return standard(destination, source, key, nonce)
			}
			seams.unwrapParanoid = func(destination, source, xKey, nonce, serpentKey, iv []byte) error {
				unwrapCalls++
				unwrapAliases = append(unwrapAliases, destination)
				return paranoid(destination, source, xKey, nonce, serpentKey, iv)
			}

			result := authenticateCapsulesWithProvider(
				context.Background(),
				test.structure,
				provider,
				seams,
			)
			defer result.Close()
			if result.Outcome() != test.wantOutcome ||
				result.Stage() != test.wantStage ||
				result.AuthenticatedCapsules() != test.wantAuth {
				t.Fatalf(
					"result = %v/%v/%d; want %v/%v/%d",
					result.Outcome(),
					result.Stage(),
					result.AuthenticatedCapsules(),
					test.wantOutcome,
					test.wantStage,
					test.wantAuth,
				)
			}
			if provider.calls != test.wantProvider ||
				unwrapCalls != test.wantUnwrap ||
				access.replicaCalls != test.wantReplica ||
				access.adoptCalls != test.wantAdopt {
				t.Fatalf(
					"provider/unwrap/replica/adopt calls = %d/%d/%d/%d; want %d/%d/%d/%d",
					provider.calls,
					unwrapCalls,
					access.replicaCalls,
					access.adoptCalls,
					test.wantProvider,
					test.wantUnwrap,
					test.wantReplica,
					test.wantAdopt,
				)
			}
			// The adopted key identity, selected candidate identity, and
			// Owner/publication state are independent frozen observations:
			// no outcome may publish an Owner through the literal provider,
			// failure outcomes publish no candidate, and an adoption must
			// transfer exactly the independently frozen VolumeKey bytes.
			if test.wantSelected >= 0 {
				if result.candidate != test.structure.candidates[test.wantSelected] {
					t.Fatalf("selected candidate is not exactly frozen structure slot %d", test.wantSelected)
				}
			} else if result.candidate != (Candidate{}) {
				t.Fatal("unauthenticated or ambiguous result published candidate state")
			}
			if result.owner != nil {
				t.Fatal("literal-provider authentication published an Owner")
			}
			wantAdopted := [32]byte{}
			if test.wantAdopt == 1 {
				wantAdopted = literalVolumeKey(t, 0x20)
			}
			if access.adopted != wantAdopted {
				t.Fatal("adopted VolumeKey differs from the independently frozen literal")
			}
			for i, alias := range unwrapAliases {
				if !allZero(alias) {
					t.Fatalf("unwrapped VolumeKey alias %d survived authentication", i)
				}
			}
		})
	}
}

func literalCandidate(t *testing.T, encoded string, role CapsuleRole) Candidate {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode TEST ONLY capsule: %v", err)
	}
	candidate, err := ValidateDecodedCapsule(decoded, role)
	crypto.SecureZero(decoded)
	if err != nil {
		t.Fatalf("validate TEST ONLY capsule: %v", err)
	}
	return candidate
}

func literalStructure(candidates ...Candidate) Structure {
	structure := Structure{}
	if len(candidates) > len(structure.candidates) {
		panic("TEST ONLY too many literal candidates")
	}
	structure.candidateCount = uint8(len(candidates))
	copy(structure.candidates[:], candidates)
	if len(candidates) != 0 {
		core := candidates[0].core
		structure.preamble = Preamble{
			suite:             core.suite,
			featureFlags:      core.featureFlags,
			frontHeaderLength: core.frontHeaderLength,
		}
	}
	return structure
}

func literalKey(t *testing.T, encoded string) [32]byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		t.Fatalf("decode TEST ONLY key: length %d, error %v", len(decoded), err)
	}
	var key [32]byte
	copy(key[:], decoded)
	crypto.SecureZero(decoded)
	return key
}

func literalVolumeKey(t *testing.T, first byte) [32]byte {
	t.Helper()
	var key [32]byte
	for i := range key {
		key[i] = first + byte(i)
	}
	return key
}

func standardLiteralAccess(t *testing.T) *literalCredentialAccess {
	t.Helper()
	access := &literalCredentialAccess{replica: make(map[literalReplicaSelector][32]byte)}
	access.wrap[0] = capsuleWrapKeys{
		xChaCha20: literalKey(t, "65714c50f8ef37b8e0805f39de3414a92e94d41bcd4f6fc3c21f5a54007b457a"),
		mac:       literalKey(t, "15a8e09c3f9c40c3e7d89bf852d65a7f08973fe47682390d4e7f779243344e3f"),
	}
	access.wrap[1] = capsuleWrapKeys{
		xChaCha20: literalKey(t, "7a96753201cd7802b7cb5f878470daf43258c45c6640028e998ec53f7b3289da"),
		mac:       literalKey(t, "042b7640b96b9910eaaf7cd1a5be2874920566c69e5e2f72a6c2dd91fd0da93a"),
	}
	volumeKey := literalVolumeKey(t, 0x20)
	access.replica[literalReplicaSelector{CapsuleRolePrimary, volumeKey}] = literalKey(t, "4fefebc937f2b598086249296965147c35387959b607e417320e4f21e77cef8d")
	access.replica[literalReplicaSelector{CapsuleRoleBackup, volumeKey}] = literalKey(t, "b1278df59c77c4d9de3a756042d9b84ba45ebabf20442a5c6a3ec48d7c49f2dd")
	return access
}

func paranoidLiteralAccess(t *testing.T) *literalCredentialAccess {
	t.Helper()
	access := &literalCredentialAccess{replica: make(map[literalReplicaSelector][32]byte)}
	access.wrap[0] = capsuleWrapKeys{
		xChaCha20: literalKey(t, "1c320ea6213f6af2a50e6085bdd79d8c3f13d4090d603ae13ade7384c8ac0b1b"),
		serpent:   literalKey(t, "e57706112f15e9a03ea5eb46b8bd9c76c18394fd7e9f9e8d0068644c9d68fe1f"),
		mac:       literalKey(t, "34f70d323543f0dd3f05e38c47ebbaf7defa1513ad63291c0caf192d26070580"),
	}
	access.wrap[1] = capsuleWrapKeys{
		xChaCha20: literalKey(t, "4f2636327998b103d712a93a0f7d039090f8173aba8d3fc8d878cd5e79e9e775"),
		serpent:   literalKey(t, "9d9453293a51e324cb4290eac14dfff534db3c55b776ef703b4ca7a17d58cbb5"),
		mac:       literalKey(t, "7eb1861a6e7d0cf2f8a97c4d16213a1347054ef2eb19380a376a37cb7d2a7157"),
	}
	volumeKey := literalVolumeKey(t, 0x20)
	access.replica[literalReplicaSelector{CapsuleRolePrimary, volumeKey}] = literalKey(t, "3163643c425454b000c89291ef68a9c3c7586994ea64973b0a67c4fdee3b62fb")
	access.replica[literalReplicaSelector{CapsuleRoleBackup, volumeKey}] = literalKey(t, "710773304b35f8e8ec0e812589116258cc14ffb14ba94c98291c1f927d297cc5")
	return access
}

func wrongCredentialLiteralAccess(t *testing.T) *literalCredentialAccess {
	t.Helper()
	access := &literalCredentialAccess{replica: make(map[literalReplicaSelector][32]byte)}
	access.wrap[0] = capsuleWrapKeys{
		xChaCha20: literalKey(t, "2a63f1952d6650630764907d4f7a8ab9eda41801427ef8f22f1642d0d373a6bd"),
		mac:       literalKey(t, "23275fb6037ec9a7224d9373a5fb2b8f711446a9931b5a88e82aa08925b03286"),
	}
	access.wrap[1] = capsuleWrapKeys{
		xChaCha20: literalKey(t, "05c3e30f9abe59e679722399b0e2dd83d8e3369902302eb92480b024f1d1bc87"),
		mac:       literalKey(t, "12da28b1ba05801e61745de80dd2f710149277fd89dfcf4aa882055ae2ff55cf"),
	}
	return access
}

func spliceLiteralAccess(t *testing.T) *literalCredentialAccess {
	t.Helper()
	access := standardLiteralAccess(t)
	volumeKey := literalVolumeKey(t, 0x60)
	access.replica[literalReplicaSelector{CapsuleRoleBackup, volumeKey}] = literalKey(t, "a81b2742bd103f979b929cfb98cfe22b607e22e6269c52631b89d598fad0f7d3")
	return access
}
