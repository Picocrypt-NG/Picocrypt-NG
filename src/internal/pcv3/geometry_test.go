package pcv3_test

import (
	"Picocrypt-NG/internal/pcv3"
	"encoding/binary"
	"errors"
	"math"
	"testing"
)

func TestDeriveGeometry(t *testing.T) {
	tests := []struct {
		name               string
		plaintextLength    uint64
		recordCount        uint64
		commentLength      uint32
		frontHeaderLength  uint32
		payloadBodyRS      bool
		sourceSize         uint64
		wantMetadataBlocks uint64
		wantPayloadLength  int64
		wantBackupOffset   int64
		wantTrailerOffset  int64
	}{
		{
			name: "empty minimum without payload RS", frontHeaderLength: 1112,
			sourceSize: 2232, wantMetadataBlocks: 1, wantPayloadLength: 112,
			wantBackupOffset: 1224, wantTrailerOffset: 2184,
		},
		{
			name: "empty minimum with payload RS", frontHeaderLength: 1112, payloadBodyRS: true,
			sourceSize: 2304, wantMetadataBlocks: 1, wantPayloadLength: 184,
			wantBackupOffset: 1296, wantTrailerOffset: 2256,
		},
		{
			name: "one byte without payload RS", plaintextLength: 1, recordCount: 1,
			frontHeaderLength: 1112, sourceSize: 2345, wantMetadataBlocks: 1,
			wantPayloadLength: 225, wantBackupOffset: 1337, wantTrailerOffset: 2297,
		},
		{
			name: "one byte with payload RS", plaintextLength: 1, recordCount: 1,
			frontHeaderLength: 1112, payloadBodyRS: true, sourceSize: 2488,
			wantMetadataBlocks: 1, wantPayloadLength: 368,
			wantBackupOffset: 1480, wantTrailerOffset: 2440,
		},
		{
			name:            "one byte below record boundary without payload RS",
			plaintextLength: 1_048_575, recordCount: 1, frontHeaderLength: 1112,
			sourceSize: 1_050_919, wantMetadataBlocks: 1, wantPayloadLength: 1_048_799,
			wantBackupOffset: 1_049_911, wantTrailerOffset: 1_050_871,
		},
		{
			name:            "exact record boundary without payload RS",
			plaintextLength: 1_048_576, recordCount: 1, frontHeaderLength: 1112,
			sourceSize: 1_050_920, wantMetadataBlocks: 1, wantPayloadLength: 1_048_800,
			wantBackupOffset: 1_049_912, wantTrailerOffset: 1_050_872,
		},
		{
			name:            "one byte above record boundary without payload RS",
			plaintextLength: 1_048_577, recordCount: 2, frontHeaderLength: 1112,
			sourceSize: 1_051_033, wantMetadataBlocks: 1, wantPayloadLength: 1_048_913,
			wantBackupOffset: 1_050_025, wantTrailerOffset: 1_050_985,
		},
		{
			name:            "one byte below record boundary with payload RS",
			plaintextLength: 1_048_575, recordCount: 1, frontHeaderLength: 1112,
			payloadBodyRS: true, sourceSize: 1_116_600, wantMetadataBlocks: 1,
			wantPayloadLength: 1_114_480, wantBackupOffset: 1_115_592,
			wantTrailerOffset: 1_116_552,
		},
		{
			name:            "exact record boundary with payload RS",
			plaintextLength: 1_048_576, recordCount: 1, frontHeaderLength: 1112,
			payloadBodyRS: true, sourceSize: 1_116_600, wantMetadataBlocks: 1,
			wantPayloadLength: 1_114_480, wantBackupOffset: 1_115_592,
			wantTrailerOffset: 1_116_552,
		},
		{
			name:            "one byte above record boundary with payload RS",
			plaintextLength: 1_048_577, recordCount: 2, frontHeaderLength: 1112,
			payloadBodyRS: true, sourceSize: 1_116_784, wantMetadataBlocks: 1,
			wantPayloadLength: 1_114_664, wantBackupOffset: 1_115_776,
			wantTrailerOffset: 1_116_736,
		},
		{
			name: "last comment byte in one metadata block", commentLength: 48,
			frontHeaderLength: 1112, sourceSize: 2232, wantMetadataBlocks: 1,
			wantPayloadLength: 112, wantBackupOffset: 1224, wantTrailerOffset: 2184,
		},
		{
			name: "first comment byte in two metadata blocks", commentLength: 49,
			frontHeaderLength: 1248, sourceSize: 2368, wantMetadataBlocks: 2,
			wantPayloadLength: 112, wantBackupOffset: 1360, wantTrailerOffset: 2320,
		},
		{
			name: "maximum comment", commentLength: 99_999,
			frontHeaderLength: 107_328, sourceSize: 108_448, wantMetadataBlocks: 782,
			wantPayloadLength: 112, wantBackupOffset: 107_440, wantTrailerOffset: 108_400,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := geometryCandidate(t, test.plaintextLength, test.recordCount,
				test.commentLength, test.frontHeaderLength, test.payloadBodyRS)
			geometry, err := pcv3.DeriveGeometry(candidate, test.sourceSize)
			if err != nil {
				t.Fatalf("derive canonical geometry: %v", err)
			}
			if geometry.MetadataBlocks() != test.wantMetadataBlocks ||
				geometry.PayloadBodyRS() != test.payloadBodyRS ||
				geometry.RecordCount() != test.recordCount ||
				geometry.FrontHeaderLength() != int64(test.frontHeaderLength) ||
				geometry.PayloadLength() != test.wantPayloadLength ||
				geometry.BackupCapsuleOffset() != test.wantBackupOffset ||
				geometry.TrailerOffset() != test.wantTrailerOffset ||
				geometry.FileSize() != int64(test.sourceSize) {
				t.Fatalf("geometry = blocks:%d rs:%t records:%d front:%d payload:%d backup:%d trailer:%d size:%d",
					geometry.MetadataBlocks(), geometry.PayloadBodyRS(), geometry.RecordCount(),
					geometry.FrontHeaderLength(), geometry.PayloadLength(),
					geometry.BackupCapsuleOffset(), geometry.TrailerOffset(), geometry.FileSize())
			}
		})
	}
}

func TestGeometryRejectsOverflow(t *testing.T) {
	minimum := geometryCandidate(t, 0, 0, 0, 1112, false)
	for _, sourceSize := range []uint64{2231, 2233, uint64(math.MaxInt64) + 1, math.MaxUint64} {
		_, err := pcv3.DeriveGeometry(minimum, sourceSize)
		assertGeometryFailure(t, err, pcv3.StageTailGeometry)
	}

	_, err := pcv3.DeriveGeometry(pcv3.Candidate{}, 0)
	assertGeometryFailure(t, err, pcv3.StageCapsuleStructure)

	for _, test := range []struct {
		name            string
		plaintextLength uint64
		recordCount     uint64
		payloadBodyRS   bool
	}{
		{name: "signed offset without payload RS", plaintextLength: math.MaxInt64, recordCount: 1 << 43},
		{name: "signed offset with payload RS", plaintextLength: math.MaxInt64, recordCount: 1 << 43, payloadBodyRS: true},
		{name: "uint64 overflow without payload RS", plaintextLength: math.MaxUint64, recordCount: 1 << 44},
		{name: "uint64 overflow with payload RS", plaintextLength: math.MaxUint64, recordCount: 1 << 44, payloadBodyRS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := geometryCandidate(t, test.plaintextLength, test.recordCount, 0, 1112, test.payloadBodyRS)
			_, err := pcv3.DeriveGeometry(candidate, math.MaxInt64)
			assertGeometryFailure(t, err, pcv3.StageTailGeometry)
		})
	}
}

func geometryCandidate(
	t *testing.T,
	plaintextLength uint64,
	recordCount uint64,
	commentLength uint32,
	frontHeaderLength uint32,
	payloadBodyRS bool,
) pcv3.Candidate {
	t.Helper()
	decoded := make([]byte, 320)
	copy(decoded[0:4], "PCV\x00")
	binary.BigEndian.PutUint16(decoded[4:6], 3)
	binary.BigEndian.PutUint16(decoded[6:8], 1)
	binary.BigEndian.PutUint16(decoded[8:10], 1)
	if payloadBodyRS {
		binary.BigEndian.PutUint16(decoded[10:12], 1)
	}
	binary.BigEndian.PutUint32(decoded[12:16], frontHeaderLength)
	decoded[48] = 1
	decoded[49] = 1
	decoded[50] = 1
	binary.BigEndian.PutUint64(decoded[52:60], plaintextLength)
	binary.BigEndian.PutUint64(decoded[60:68], recordCount)
	binary.BigEndian.PutUint32(decoded[92:96], commentLength)
	decoded[96] = byte(pcv3.CapsuleRolePrimary)
	decoded[97] = byte(pcv3.CredentialModePassword)
	decoded[98] = byte(pcv3.KeyfileModeNone)
	decoded[99] = byte(pcv3.KDFProfileNormal)

	candidate, err := pcv3.ValidateDecodedCapsule(decoded, pcv3.CapsuleRolePrimary)
	if err != nil {
		t.Fatalf("construct structurally valid candidate: %v", err)
	}
	return candidate
}

func assertGeometryFailure(t *testing.T, err error, stage pcv3.Stage) {
	t.Helper()
	var failure pcv3.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error type = %T; want pcv3.Failure", err)
	}
	if failure.Outcome() != pcv3.OutcomeInvalidStructurePreKDF ||
		failure.Stage() != stage || failure.Code() != pcv3.CodeInvalidStructure {
		t.Fatalf("failure = %v/%v/%v; want invalid-structure-pre-kdf/%v/PCV3_INVALID_STRUCTURE",
			failure.Outcome(), failure.Stage(), failure.Code(), stage)
	}
}
