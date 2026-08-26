package pcv3_test

import (
	"Picocrypt-NG/internal/pcv3"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"testing"
)

func TestParsePreamble(t *testing.T) {
	admitted := [4]byte{'P', 'C', 'V', 0}
	for _, test := range []struct {
		name        string
		suite       uint16
		flags       uint16
		frontHeader uint32
	}{
		{name: "minimum Standard header", suite: 1, frontHeader: 1112},
		{name: "aligned two-block Standard header", suite: 1, frontHeader: 1248},
		{name: "maximum Paranoid RS header", suite: 2, flags: 1, frontHeader: 107328},
	} {
		t.Run(test.name, func(t *testing.T) {
			preamble, err := pcv3.ParsePreamble(admitted, preambleRemainder(3, 1, test.suite, test.flags, test.frontHeader))
			if err != nil {
				t.Fatalf("parse legal preamble: %v", err)
			}
			if preamble.Suite() != pcv3.Suite(test.suite) ||
				preamble.FeatureFlags() != test.flags ||
				preamble.PayloadBodyRS() != (test.flags&1 != 0) ||
				preamble.FrontHeaderLength() != test.frontHeader {
				t.Fatalf("parsed preamble = suite:%d flags:%#x rs:%t header:%d",
					preamble.Suite(), preamble.FeatureFlags(), preamble.PayloadBodyRS(), preamble.FrontHeaderLength())
			}
		})
	}

	for _, length := range []int{0, 11, 13} {
		remainder := make([]byte, length)
		_, err := pcv3.ParsePreamble(admitted, remainder)
		assertStructureFailure(t, err, pcv3.OutcomeInvalidStructurePreKDF, pcv3.StagePreamble)
	}

	for _, test := range []struct {
		name      string
		remainder []byte
	}{
		{name: "unknown major", remainder: preambleRemainder(4, 1, 1, 0, 1112)},
		{name: "unknown schema", remainder: preambleRemainder(3, 2, 1, 0, 1112)},
		{name: "suite below allowlist", remainder: preambleRemainder(3, 1, 0, 0, 1112)},
		{name: "suite above allowlist", remainder: preambleRemainder(3, 1, 3, 0, 1112)},
		{name: "unknown feature bit", remainder: preambleRemainder(3, 1, 1, 2, 1112)},
		{name: "unknown high feature bit", remainder: preambleRemainder(3, 1, 1, 0x8000, 1112)},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := pcv3.ParsePreamble(admitted, test.remainder)
			assertStructureFailure(t, err, pcv3.OutcomeUnsupportedRoutingPreKDF, pcv3.StageRouting)
		})
	}

	for _, frontHeader := range []uint32{0, 976, 1111, 1113, 107327, 107329, 107464, math.MaxUint32} {
		_, err := pcv3.ParsePreamble(admitted, preambleRemainder(3, 1, 1, 0, frontHeader))
		assertStructureFailure(t, err, pcv3.OutcomeInvalidStructurePreKDF, pcv3.StagePreamble)
	}

	badPrefix := admitted
	badPrefix[0] = 'X'
	_, err := pcv3.ParsePreamble(badPrefix, preambleRemainder(3, 1, 1, 0, 1112))
	if !errors.Is(err, pcv3.ErrInvalidFailureMapping) {
		t.Fatalf("unadmitted prefix error = %v; want ErrInvalidFailureMapping", err)
	}
}

func TestValidateDecodedCapsule(t *testing.T) {
	positive := []struct {
		name      string
		mutate    func([]byte)
		role      pcv3.CapsuleRole
		wantMode  pcv3.CredentialMode
		wantKey   pcv3.KeyfileMode
		wantKDF   pcv3.KDFProfile
		wantCount uint16
	}{
		{
			name: "Standard password primary", role: pcv3.CapsuleRolePrimary,
			wantMode: pcv3.CredentialModePassword, wantKey: pcv3.KeyfileModeNone,
			wantKDF: pcv3.KDFProfileNormal,
		},
		{
			name: "Standard password backup", role: pcv3.CapsuleRoleBackup,
			mutate:   func(decoded []byte) { decoded[96] = 1 },
			wantMode: pcv3.CredentialModePassword, wantKey: pcv3.KeyfileModeNone,
			wantKDF: pcv3.KDFProfileNormal,
		},
		{
			name: "Paranoid permits zero writer-random IVs", role: pcv3.CapsuleRolePrimary,
			mutate: func(decoded []byte) {
				binary.BigEndian.PutUint16(decoded[8:10], 2)
				binary.BigEndian.PutUint16(decoded[10:12], 1)
				decoded[99] = 2
			},
			wantMode: pcv3.CredentialModePassword, wantKey: pcv3.KeyfileModeNone,
			wantKDF: pcv3.KDFProfileParanoid,
		},
		{
			name: "Paranoid accepts generated IV bytes", role: pcv3.CapsuleRolePrimary,
			mutate: func(decoded []byte) {
				binary.BigEndian.PutUint16(decoded[8:10], 2)
				decoded[48] = 2
				decoded[84] = 1
				decoded[99] = 2
				decoded[144] = 1
			},
			wantMode: pcv3.CredentialModePassword, wantKey: pcv3.KeyfileModeNone,
			wantKDF: pcv3.KDFProfileParanoid,
		},
		{
			name: "ordered keyfiles lower bound", role: pcv3.CapsuleRolePrimary,
			mutate: func(decoded []byte) {
				decoded[97], decoded[98] = 2, 1
				binary.BigEndian.PutUint16(decoded[100:102], 1)
			},
			wantMode: pcv3.CredentialModeKeyfiles, wantKey: pcv3.KeyfileModeOrdered,
			wantKDF: pcv3.KDFProfileNormal, wantCount: 1,
		},
		{
			name: "unordered keyfiles upper bound", role: pcv3.CapsuleRolePrimary,
			mutate: func(decoded []byte) {
				decoded[97], decoded[98] = 2, 2
				binary.BigEndian.PutUint16(decoded[100:102], 64)
			},
			wantMode: pcv3.CredentialModeKeyfiles, wantKey: pcv3.KeyfileModeUnordered,
			wantKDF: pcv3.KDFProfileNormal, wantCount: 64,
		},
		{
			name: "ordered combined lower bound", role: pcv3.CapsuleRolePrimary,
			mutate: func(decoded []byte) {
				decoded[97], decoded[98] = 3, 1
				binary.BigEndian.PutUint16(decoded[100:102], 1)
			},
			wantMode: pcv3.CredentialModeCombined, wantKey: pcv3.KeyfileModeOrdered,
			wantKDF: pcv3.KDFProfileNormal, wantCount: 1,
		},
		{
			name: "unordered combined upper bound", role: pcv3.CapsuleRolePrimary,
			mutate: func(decoded []byte) {
				decoded[97], decoded[98] = 3, 2
				binary.BigEndian.PutUint16(decoded[100:102], 64)
			},
			wantMode: pcv3.CredentialModeCombined, wantKey: pcv3.KeyfileModeUnordered,
			wantKDF: pcv3.KDFProfileNormal, wantCount: 64,
		},
		{
			name: "maximum comment and plaintext", role: pcv3.CapsuleRolePrimary,
			mutate: func(decoded []byte) {
				binary.BigEndian.PutUint32(decoded[12:16], 107_328)
				binary.BigEndian.PutUint64(decoded[52:60], math.MaxUint64)
				binary.BigEndian.PutUint64(decoded[60:68], 1<<44)
				binary.BigEndian.PutUint32(decoded[92:96], 99_999)
			},
			wantMode: pcv3.CredentialModePassword, wantKey: pcv3.KeyfileModeNone,
			wantKDF: pcv3.KDFProfileNormal,
		},
	}

	for _, test := range positive {
		t.Run(test.name, func(t *testing.T) {
			decoded := validDecodedCapsule()
			if test.mutate != nil {
				test.mutate(decoded)
			}
			candidate, err := pcv3.ValidateDecodedCapsule(decoded, test.role)
			if err != nil {
				t.Fatalf("validate legal decoded capsule: %v", err)
			}
			if candidate.Role() != test.role || candidate.CredentialMode() != test.wantMode ||
				candidate.KeyfileMode() != test.wantKey || candidate.KDFProfile() != test.wantKDF ||
				candidate.KeyfileCount() != test.wantCount {
				t.Fatalf("candidate tuple = role:%d mode:%d keyfile:%d kdf:%d count:%d",
					candidate.Role(), candidate.CredentialMode(), candidate.KeyfileMode(),
					candidate.KDFProfile(), candidate.KeyfileCount())
			}
			if candidate.FrontHeaderLength() != binary.BigEndian.Uint32(decoded[12:16]) ||
				candidate.Suite() != pcv3.Suite(binary.BigEndian.Uint16(decoded[8:10])) ||
				candidate.FeatureFlags() != binary.BigEndian.Uint16(decoded[10:12]) ||
				candidate.PayloadBodyRS() != (binary.BigEndian.Uint16(decoded[10:12])&1 != 0) ||
				candidate.PayloadKind() != pcv3.PayloadKind(decoded[48]) ||
				candidate.PlaintextLength() != binary.BigEndian.Uint64(decoded[52:60]) ||
				candidate.RecordCount() != binary.BigEndian.Uint64(decoded[60:68]) ||
				candidate.CommentLength() != binary.BigEndian.Uint32(decoded[92:96]) {
				t.Fatal("candidate did not retain the validated fixed logical-core fields")
			}
		})
	}

	for _, length := range []int{0, 319, 321} {
		_, err := pcv3.ValidateDecodedCapsule(make([]byte, length), pcv3.CapsuleRolePrimary)
		assertStructureFailure(t, err, pcv3.OutcomeInvalidStructurePreKDF, pcv3.StageCapsuleStructure)
	}

	mutations := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "unknown major", mutate: func(value []byte) { binary.BigEndian.PutUint16(value[4:6], 4) }},
		{name: "unknown schema", mutate: func(value []byte) { binary.BigEndian.PutUint16(value[6:8], 2) }},
		{name: "suite below allowlist", mutate: func(value []byte) { binary.BigEndian.PutUint16(value[8:10], 0) }},
		{name: "suite above allowlist", mutate: func(value []byte) { binary.BigEndian.PutUint16(value[8:10], 3) }},
		{name: "unknown feature", mutate: func(value []byte) { binary.BigEndian.PutUint16(value[10:12], 2) }},
		{name: "front header below bound", mutate: func(value []byte) { binary.BigEndian.PutUint32(value[12:16], 1111) }},
		{name: "front header misaligned", mutate: func(value []byte) { binary.BigEndian.PutUint32(value[12:16], 1113) }},
		{name: "front header disagrees with comment", mutate: func(value []byte) { binary.BigEndian.PutUint32(value[12:16], 1248) }},
		{name: "payload kind below allowlist", mutate: func(value []byte) { value[48] = 0 }},
		{name: "payload kind above allowlist", mutate: func(value []byte) { value[48] = 3 }},
		{name: "unknown record profile", mutate: func(value []byte) { value[49] = 2 }},
		{name: "unknown metadata profile", mutate: func(value []byte) { value[50] = 2 }},
		{name: "core reserved byte", mutate: func(value []byte) { value[51] = 1 }},
		{name: "record count below canonical", mutate: func(value []byte) {
			binary.BigEndian.PutUint64(value[52:60], 1)
		}},
		{name: "record count above canonical", mutate: func(value []byte) {
			binary.BigEndian.PutUint64(value[60:68], 1)
		}},
		{name: "record count exceeds format bound", mutate: func(value []byte) {
			binary.BigEndian.PutUint64(value[60:68], 1<<48)
		}},
		{name: "comment exceeds bound", mutate: func(value []byte) {
			binary.BigEndian.PutUint32(value[92:96], 100_000)
		}},
		{name: "role swap", mutate: func(value []byte) { value[96] = 1 }},
		{name: "unknown role", mutate: func(value []byte) { value[96] = 2 }},
		{name: "first capsule reserved byte", mutate: func(value []byte) { value[102] = 1 }},
		{name: "second capsule reserved byte", mutate: func(value []byte) { value[103] = 1 }},
		{name: "KDF profile disagrees with Standard suite", mutate: func(value []byte) { value[99] = 2 }},
		{name: "KDF profile disagrees with Paranoid suite", mutate: func(value []byte) {
			binary.BigEndian.PutUint16(value[8:10], 2)
			value[99] = 1
		}},
		{name: "unknown credential mode", mutate: func(value []byte) { value[97] = 4 }},
		{name: "password tuple with keyfile mode", mutate: func(value []byte) { value[98] = 1 }},
		{name: "password tuple with keyfile count", mutate: func(value []byte) {
			binary.BigEndian.PutUint16(value[100:102], 1)
		}},
		{name: "keyfiles tuple without keyfile mode", mutate: func(value []byte) {
			value[97] = 2
			binary.BigEndian.PutUint16(value[100:102], 1)
		}},
		{name: "keyfiles tuple with unknown ordering", mutate: func(value []byte) {
			value[97], value[98] = 2, 3
			binary.BigEndian.PutUint16(value[100:102], 1)
		}},
		{name: "keyfiles tuple below count bound", mutate: func(value []byte) {
			value[97], value[98] = 2, 1
		}},
		{name: "keyfiles tuple above count bound", mutate: func(value []byte) {
			value[97], value[98] = 2, 1
			binary.BigEndian.PutUint16(value[100:102], 65)
		}},
		{name: "combined tuple without keyfile mode", mutate: func(value []byte) {
			value[97] = 3
			binary.BigEndian.PutUint16(value[100:102], 1)
		}},
		{name: "combined tuple below count bound", mutate: func(value []byte) {
			value[97], value[98] = 3, 2
		}},
		{name: "combined tuple above count bound", mutate: func(value []byte) {
			value[97], value[98] = 3, 2
			binary.BigEndian.PutUint16(value[100:102], 65)
		}},
	}

	for magicByte := range 4 {
		mutations = append(mutations, struct {
			name   string
			mutate func([]byte)
		}{
			name: fmt.Sprintf("magic byte %d", magicByte),
			mutate: func(value []byte) {
				value[magicByte] ^= 0xff
			},
		})
	}
	for ivByte := range 8 {
		mutations = append(mutations, struct {
			name   string
			mutate func([]byte)
		}{
			name: fmt.Sprintf("Standard core Serpent IV byte %d", ivByte),
			mutate: func(value []byte) {
				value[84+ivByte] = 1
			},
		})
	}
	for ivByte := range 16 {
		mutations = append(mutations, struct {
			name   string
			mutate func([]byte)
		}{
			name: fmt.Sprintf("Standard wrap Serpent IV byte %d", ivByte),
			mutate: func(value []byte) {
				value[144+ivByte] = 1
			},
		})
	}

	for index, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			decoded := validDecodedCapsule()
			test.mutate(decoded)
			_, err := pcv3.ValidateDecodedCapsule(decoded, pcv3.CapsuleRolePrimary)
			if err == nil {
				t.Fatalf("mutation %d was accepted", index)
			}
			assertStructureFailure(t, err, pcv3.OutcomeInvalidStructurePreKDF, pcv3.StageCapsuleStructure)
		})
	}

	_, err := pcv3.ValidateDecodedCapsule(validDecodedCapsule(), pcv3.CapsuleRole(2))
	if !errors.Is(err, pcv3.ErrInvalidFailureMapping) {
		t.Fatalf("unknown expected role error = %v; want ErrInvalidFailureMapping", err)
	}
}

func preambleRemainder(major, schema, suite, flags uint16, frontHeader uint32) []byte {
	remainder := make([]byte, 12)
	binary.BigEndian.PutUint16(remainder[0:2], major)
	binary.BigEndian.PutUint16(remainder[2:4], schema)
	binary.BigEndian.PutUint16(remainder[4:6], suite)
	binary.BigEndian.PutUint16(remainder[6:8], flags)
	binary.BigEndian.PutUint32(remainder[8:12], frontHeader)
	return remainder
}

func validDecodedCapsule() []byte {
	decoded := make([]byte, 320)
	copy(decoded[0:4], "PCV\x00")
	binary.BigEndian.PutUint16(decoded[4:6], 3)
	binary.BigEndian.PutUint16(decoded[6:8], 1)
	binary.BigEndian.PutUint16(decoded[8:10], 1)
	binary.BigEndian.PutUint32(decoded[12:16], 1112)
	decoded[48] = 1
	decoded[49] = 1
	decoded[50] = 1
	decoded[97] = 1
	decoded[99] = 1
	return decoded
}

func assertStructureFailure(t *testing.T, err error, outcome pcv3.Outcome, stage pcv3.Stage) {
	t.Helper()
	var failure pcv3.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T; want pcv3.Failure", err)
	}
	if failure.Outcome() != outcome || failure.Stage() != stage {
		t.Fatalf("failure = %v/%v; want %v/%v", failure.Outcome(), failure.Stage(), outcome, stage)
	}
}
