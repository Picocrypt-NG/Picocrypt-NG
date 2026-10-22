package pcv3

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"testing"
)

func TestRecordHighIndexWireAndPhysicalOffsets(t *testing.T) {
	// Literal schema-1 values: 64 GiB plus one byte, with a separate final record.
	records := []struct {
		index, plaintextOffset, length uint64
		descriptorOffset               [2]int64
		bodyLength                     [2]int
		descriptor, nonce, iv          string
	}{
		{3854, 4041211904, 1048576, [2]int64{4041644664, 4294497896}, [2]int{1048640, 1114248}, "0000000000000f0e0010000000000000", "0000000000000f0e", "000000000f0e0000"},
		{3855, 4042260480, 1048576, [2]int64{4042693352, 4295612192}, [2]int{1048640, 1114248}, "0000000000000f0f0010000000000000", "0000000000000f0f", "000000000f0f0000"},
		{4095, 4293918720, 1048576, [2]int64{4294378472, 4563043232}, [2]int{1048640, 1114248}, "0000000000000fff0010000000000000", "0000000000000fff", "000000000fff0000"},
		{4096, 4294967296, 1048576, [2]int64{4295427160, 4564157528}, [2]int{1048640, 1114248}, "00000000000010000010000000000000", "0000000000001000", "0000000010000000"},
		{65535, 68718428160, 1048576, [2]int64{68725769192, 73025389472}, [2]int{1048640, 1114248}, "000000000000ffff0010000000000000", "000000000000ffff", "00000000ffff0000"},
		{65536, 68719476736, 1, [2]int64{68726817880, 73026503768}, [2]int{65, 136}, "00000000000100000000000100000000", "0000000000010000", "0000000100000000"},
		{65537, 68719476737, 0, [2]int64{68726817993, 73026503952}, [2]int{64, 136}, "00000000000100010000000001000000", "0000000000010001", "0000000100010000"},
	}
	for _, suite := range []Suite{SuiteStandard, SuiteParanoid} {
		for rs, fileSize := range []uint64{68726819113, 73026505144} {
			t.Run(fmt.Sprintf("suite%d/rs%d", suite, rs), func(t *testing.T) {
				core := highIndexRecordCore(t, suite, rs != 0, 68719476737, 65537)
				geometry, err := DeriveGeometry(Candidate{core: core}, fileSize)
				if err != nil {
					t.Fatal(err)
				}
				for _, record := range records {
					t.Run(strconv.FormatUint(record.index, 10), func(t *testing.T) {
						got, err := expectedRecord(core, geometry, record.index)
						if err != nil {
							t.Fatal(err)
						}
						if got.index != record.index || got.plaintextOffset != record.plaintextOffset ||
							got.ciphertextLength != record.length || got.final != (record.index == 65537) ||
							got.descriptorOffset != record.descriptorOffset[rs] || got.bodyOffset != record.descriptorOffset[rs]+48 ||
							got.encodedBodyLength != record.bodyLength[rs] ||
							!bytes.Equal(got.descriptor[:], recordFixtureHex(t, record.descriptor)) ||
							!bytes.Equal(got.nonce[:], recordFixtureHex(t, "000102030405060708090a0b0c0d0e0f"+record.nonce)) {
							t.Fatalf("record %d lost its literal descriptor, nonce, or physical bounds: %+v", record.index, got)
						}
						wantIV := make([]byte, 16)
						if suite == SuiteParanoid {
							wantIV = recordFixtureHex(t, "1011121314151617"+record.iv)
						}
						if !bytes.Equal(got.serpentIV[:], wantIV) {
							t.Fatalf("record %d IV = %x, want %x", record.index, got.serpentIV, wantIV)
						}
					})
				}
			})
		}
	}
}

func TestRecordSignedOffsetLimit(t *testing.T) {
	// These are the last plaintext lengths whose complete wire layout fits int64.
	limits := []struct {
		plaintext, count       uint64
		fileSize, descriptor   int64
		bodyLength             int
		wire, nonce, serpentIV string
	}{
		{9222386979651746727, 8795153598454, 9223372036854775807, 9223372036854774687, 64, "000007ffc80187f60000000001000000", "000007ffc80187f6", "07ffc80187f60000"},
		{8679387305452977472, 8277308755353, 9223372036854775752, 9223372036854774560, 136, "00000787360c4d990000000001000000", "00000787360c4d99", "0787360c4d990000"},
	}
	for _, suite := range []Suite{SuiteStandard, SuiteParanoid} {
		for rs, limit := range limits {
			t.Run(fmt.Sprintf("suite%d/rs%d", suite, rs), func(t *testing.T) {
				core := highIndexRecordCore(t, suite, rs != 0, limit.plaintext, limit.count)
				geometry, err := deriveCanonicalGeometry(Candidate{core: core})
				if err != nil || geometry.FileSize() != limit.fileSize {
					t.Fatalf("last admissible layout: size=%d error=%v", geometry.FileSize(), err)
				}
				final, err := expectedRecord(core, geometry, limit.count)
				if err != nil || !final.final || final.plaintextOffset != limit.plaintext || final.ciphertextLength != 0 ||
					final.descriptorOffset != limit.descriptor || final.bodyOffset != limit.descriptor+48 ||
					final.encodedBodyLength != limit.bodyLength ||
					!bytes.Equal(final.descriptor[:], recordFixtureHex(t, limit.wire)) ||
					!bytes.Equal(final.nonce[:], recordFixtureHex(t, "000102030405060708090a0b0c0d0e0f"+limit.nonce)) {
					t.Fatalf("last admissible final record: %+v error=%v", final, err)
				}
				wantIV := make([]byte, 16)
				if suite == SuiteParanoid {
					wantIV = recordFixtureHex(t, "1011121314151617"+limit.serpentIV)
				}
				if !bytes.Equal(final.serpentIV[:], wantIV) {
					t.Fatalf("last admissible IV = %x, want %x", final.serpentIV, wantIV)
				}
				if _, err := expectedRecord(core, geometry, limit.count+1); err == nil {
					t.Fatal("record after the mandatory final record was admitted")
				}
				core.plaintextLength++
				if !validLogicalCore(core) {
					t.Fatal("overflow case must retain a canonical logical core")
				}
				_, err = deriveCanonicalGeometry(Candidate{core: core})
				var failure Failure
				if !errors.As(err, &failure) || failure.Outcome() != OutcomeInvalidStructurePreKDF || failure.Stage() != StageTailGeometry {
					t.Fatalf("first unrepresentable wire layout: %v", err)
				}
			})
		}
	}
}

func highIndexRecordCore(t *testing.T, suite Suite, rs bool, plaintext, count uint64) logicalCore {
	t.Helper()
	fixture := recordFixtureByName(t, loadRecordFixtureManifest(t), "plus_one_standard_no_rs")
	core := loadRecordFixtureCore(t, fixture)
	core.suite, core.plaintextLength, core.recordCount = suite, plaintext, count
	core.featureFlags, core.commentLength, core.frontHeaderLength = 0, 0, 1112
	if rs {
		core.featureFlags = payloadBodyRSFeatureMask
	}
	core.xChaChaNoncePrefix = [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	core.serpentIVPrefix = [8]byte{}
	if suite == SuiteParanoid {
		core.serpentIVPrefix = [8]byte{16, 17, 18, 19, 20, 21, 22, 23}
	}
	return core
}
