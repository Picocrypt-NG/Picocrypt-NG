package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

const testKeyBytes = 32

type literalScheduleRow struct {
	root    scheduleRoot
	request KeyRequest
}

func literalRowsForSuite(t *testing.T, suite Suite) []literalScheduleRow {
	t.Helper()
	row := func(
		root scheduleRoot,
		label string,
		role uint8,
	) literalScheduleRow {
		return literalScheduleRow{
			root: root,
			request: KeyRequest{
				Label:       KeyLabel(label),
				Role:        KeyRole(role),
				OutputBytes: 32,
			},
		}
	}
	switch suite {
	case Suite(0x0001):
		return []literalScheduleRow{
			row(scheduleRoot(1), "credential/wrap/xchacha20", 0x00),
			row(scheduleRoot(1), "credential/wrap/xchacha20", 0x01),
			row(scheduleRoot(1), "credential/wrap/mac", 0x00),
			row(scheduleRoot(1), "credential/wrap/mac", 0x01),
			row(scheduleRoot(2), "volume/replica/mac", 0x00),
			row(scheduleRoot(2), "volume/replica/mac", 0x01),
			row(scheduleRoot(2), "volume/metadata/mac", 0xff),
			row(scheduleRoot(2), "volume/payload/xchacha20", 0xff),
			row(scheduleRoot(2), "volume/payload/mac", 0xff),
		}
	case Suite(0x0002):
		return []literalScheduleRow{
			row(scheduleRoot(1), "credential/wrap/xchacha20", 0x00),
			row(scheduleRoot(1), "credential/wrap/xchacha20", 0x01),
			row(scheduleRoot(1), "credential/wrap/serpent", 0x00),
			row(scheduleRoot(1), "credential/wrap/serpent", 0x01),
			row(scheduleRoot(1), "credential/wrap/mac", 0x00),
			row(scheduleRoot(1), "credential/wrap/mac", 0x01),
			row(scheduleRoot(2), "volume/replica/mac", 0x00),
			row(scheduleRoot(2), "volume/replica/mac", 0x01),
			row(scheduleRoot(2), "volume/metadata/mac", 0xff),
			row(scheduleRoot(2), "volume/payload/xchacha20", 0xff),
			row(scheduleRoot(2), "volume/payload/serpent", 0xff),
			row(scheduleRoot(2), "volume/payload/mac", 0xff),
		}
	default:
		t.Fatalf("test has no literal rows for suite %#04x", suite)
		return nil
	}
}

func literalRequestsForSuite(t *testing.T, suite Suite) []KeyRequest {
	t.Helper()
	rows := literalRowsForSuite(t, suite)
	requests := make([]KeyRequest, len(rows))
	for i := range rows {
		requests[i] = rows[i].request
	}
	return requests
}

func requireScheduleCode(
	t *testing.T,
	err error,
	want ScheduleErrorCode,
) *ScheduleError {
	t.Helper()
	var scheduleErr *ScheduleError
	if !errors.As(err, &scheduleErr) {
		t.Fatalf(
			"error = %T %v; want *ScheduleError code %d",
			err,
			err,
			want,
		)
	}
	if scheduleErr.Code != want {
		t.Fatalf(
			"schedule error code = %d; want %d (error %v)",
			scheduleErr.Code,
			want,
			err,
		)
	}
	return scheduleErr
}

func testRootOwners(
	rootFill byte,
	rootBytes int,
	keyFill byte,
	keyBytes int,
) (
	*credentialRoot,
	*volumeKey,
	*crypto.Secret,
	*crypto.Secret,
	[]byte,
	[]byte,
) {
	rootAlias := bytes.Repeat([]byte{rootFill}, rootBytes)
	keyAlias := bytes.Repeat([]byte{keyFill}, keyBytes)
	rootOwner := crypto.SecretFrom(rootAlias)
	keyOwner := crypto.SecretFrom(keyAlias)
	return &credentialRoot{secret: rootOwner},
		&volumeKey{secret: keyOwner},
		rootOwner,
		keyOwner,
		rootAlias,
		keyAlias
}

func testVolumeID() []byte {
	volumeID := make([]byte, testKeyBytes)
	for i := range volumeID {
		volumeID[i] = byte(i)
	}
	return volumeID
}

func testSuccessfulSeams(
	extractCalls *int,
	expandCalls *int,
) (hkdfExtractor, hkdfExpander) {
	return func([]byte, []byte) ([]byte, error) {
			*extractCalls++
			return bytes.Repeat(
				[]byte{byte(0xc0 + *extractCalls)},
				testKeyBytes,
			), nil
		}, func([]byte, string, int) ([]byte, error) {
			*expandCalls++
			return bytes.Repeat(
				[]byte{byte(0xe0 + *expandCalls)},
				testKeyBytes,
			), nil
		}
}

func TestKeyExtractRootsSeparated(t *testing.T) {
	schedule, err := validateKeySchedule(
		Suite(0x0001),
		literalRequestsForSuite(t, Suite(0x0001))[:1],
	)
	if err != nil {
		t.Fatalf("validate one-row schedule: %v", err)
	}

	t.Run("two roots use one immutable volume ID", func(t *testing.T) {
		root, key, rootOwner, keyOwner, rootAlias, keyAlias := testRootOwners(0x11, 32, 0x22, 32)
		volumeID := testVolumeID()
		wantVolumeID := append([]byte(nil), volumeID...)
		defer crypto.SecureZero(wantVolumeID)

		var inputs [][]byte
		var salts [][]byte
		var returnedAliases [][]byte
		extractCalls := 0
		expandCalls := 0
		extract := func(input, salt []byte) ([]byte, error) {
			extractCalls++
			inputs = append(inputs, append([]byte(nil), input...))
			salts = append(salts, append([]byte(nil), salt...))
			returned := bytes.Repeat(
				[]byte{byte(0x70 + extractCalls)},
				testKeyBytes,
			)
			returnedAliases = append(returnedAliases, returned)
			if extractCalls == 1 {
				salt[0] ^= 0xff
				volumeID[0] ^= 0xff
			}
			return returned, nil
		}
		expand := func([]byte, string, int) ([]byte, error) {
			expandCalls++
			return bytes.Repeat([]byte{0x90}, testKeyBytes), nil
		}

		material, err := deriveKeyMaterialWith(
			schedule,
			root,
			key,
			volumeID,
			extract,
			expand,
		)
		for _, captured := range inputs {
			defer crypto.SecureZero(captured)
		}
		for _, captured := range salts {
			defer crypto.SecureZero(captured)
		}
		if err != nil {
			t.Fatalf("deriveKeyMaterialWith failed: %v", err)
		}
		if material == nil {
			t.Fatal("derivation published no material")
		}
		if root.secret != nil || key.secret != nil {
			material.close()
			t.Fatal("derivation did not consume unique root pointers")
		}
		if extractCalls != 2 || expandCalls != 1 {
			material.close()
			t.Fatalf(
				"Extract/Expand calls = %d/%d; want 2/1",
				extractCalls,
				expandCalls,
			)
		}
		if len(inputs) != 2 ||
			!bytes.Equal(inputs[0], bytes.Repeat([]byte{0x11}, 32)) ||
			!bytes.Equal(inputs[1], bytes.Repeat([]byte{0x22}, 32)) {
			material.close()
			t.Fatalf("Extract inputs = %x / %x; want separate roots", inputs[0], inputs[1])
		}
		if len(salts) != 2 ||
			!bytes.Equal(salts[0], wantVolumeID) ||
			!bytes.Equal(salts[1], wantVolumeID) {
			material.close()
			t.Fatalf("Extract salts = %x / %x; want one immutable snapshot", salts[0], salts[1])
		}
		for i, alias := range returnedAliases {
			if !allZero(alias) {
				material.close()
				t.Fatalf("Extract returned alias %d was not cleared", i)
			}
		}
		if material.credentialPRK == nil ||
			material.volumePRK == nil ||
			!bytes.Equal(
				material.credentialPRK.secret.Bytes(),
				bytes.Repeat([]byte{0x71}, 32),
			) ||
			!bytes.Equal(
				material.volumePRK.secret.Bytes(),
				bytes.Repeat([]byte{0x72}, 32),
			) {
			material.close()
			t.Fatal("derived PRKs do not preserve the two exact Extract results")
		}

		credentialPRKAlias := material.credentialPRK.secret.Bytes()
		volumePRKAlias := material.volumePRK.secret.Bytes()
		material.close()
		if rootOwner.Len() != 0 || keyOwner.Len() != 0 ||
			!allZero(rootAlias) || !allZero(keyAlias) ||
			!allZero(credentialPRKAlias) || !allZero(volumePRKAlias) {
			t.Fatal("material close did not clear transferred roots and both PRKs")
		}
	})

	t.Run("second Extract error clears all transferred material", func(t *testing.T) {
		root, key, rootOwner, keyOwner, rootAlias, keyAlias := testRootOwners(0x31, 32, 0x32, 32)
		var returnedAliases [][]byte
		extractCalls := 0
		expandCalls := 0
		material, err := deriveKeyMaterialWith(
			schedule,
			root,
			key,
			testVolumeID(),
			func([]byte, []byte) ([]byte, error) {
				extractCalls++
				returned := bytes.Repeat(
					[]byte{byte(0xa0 + extractCalls)},
					testKeyBytes,
				)
				returnedAliases = append(returnedAliases, returned)
				if extractCalls == 2 {
					return returned, errors.New("private-extract-sentinel")
				}
				return returned, nil
			},
			func([]byte, string, int) ([]byte, error) {
				expandCalls++
				return bytes.Repeat([]byte{0xb0}, testKeyBytes), nil
			},
		)
		scheduleErr := requireScheduleCode(t, err, ScheduleErrorExtract)
		if scheduleErr.Suite != Suite(0x0001) || scheduleErr.Index != -1 {
			t.Fatalf("Extract error metadata = %+v; want suite 1, index -1", scheduleErr)
		}
		if material != nil || extractCalls != 2 || expandCalls != 0 {
			if material != nil {
				material.close()
			}
			t.Fatalf(
				"failed Extract material/calls = %v %d/%d; want nil 2/0",
				material,
				extractCalls,
				expandCalls,
			)
		}
		if root.secret != nil || key.secret != nil ||
			rootOwner.Len() != 0 || keyOwner.Len() != 0 ||
			!allZero(rootAlias) || !allZero(keyAlias) {
			t.Fatal("Extract failure did not clear transferred roots")
		}
		for i, alias := range returnedAliases {
			if !allZero(alias) {
				t.Fatalf("failed Extract returned alias %d was not cleared", i)
			}
		}
		for _, rendered := range []string{
			err.Error(),
			fmt.Sprintf("%v", err),
			fmt.Sprintf("%+v", err),
			fmt.Sprintf("%#v", err),
		} {
			if bytes.Contains([]byte(rendered), []byte("private-extract-sentinel")) {
				t.Fatalf("Extract error disclosed provider sentinel in %q", rendered)
			}
		}
	})
}

func TestReaderCredentialStagesMatchWriterSchedule(t *testing.T) {
	requests := literalRequestsForSuite(t, SuiteStandard1)
	schedule, err := validateKeySchedule(SuiteStandard1, requests)
	if err != nil {
		t.Fatalf("validate Standard-1 schedule: %v", err)
	}
	volumeID := testVolumeID()

	writerRoot, writerKey, _, _, _, _ := testRootOwners(
		0x51,
		credentialRootBytes,
		0x61,
		derivedKeyBytes,
	)
	writer, err := deriveKeyMaterialWith(
		schedule,
		writerRoot,
		writerKey,
		volumeID,
		defaultHKDFExtract,
		defaultHKDFExpand,
	)
	if err != nil {
		t.Fatalf("derive writer material: %v", err)
	}
	defer writer.close()

	readerRoot, readerKey, _, _, _, _ := testRootOwners(
		0x51,
		credentialRootBytes,
		0x61,
		derivedKeyBytes,
	)
	reader, err := newKeyMaterial(schedule, volumeID)
	if err != nil {
		t.Fatalf("create staged reader material: %v", err)
	}
	defer reader.close()
	if err := deriveCredentialRootStageWith(
		reader,
		readerRoot,
		defaultHKDFExtract,
	); err != nil {
		t.Fatalf("derive reader credential stage: %v", err)
	}
	if err := expandKeyMaterialWith(
		reader,
		scheduleRootCredential,
		defaultHKDFExpand,
	); err != nil {
		t.Fatalf("expand reader credential stage: %v", err)
	}
	if err := deriveVolumeKeyStageWith(
		reader,
		readerKey,
		defaultHKDFExtract,
	); err != nil {
		t.Fatalf("derive reader volume stage: %v", err)
	}
	if err := expandKeyMaterialWith(
		reader,
		scheduleRootVolume,
		defaultHKDFExpand,
	); err != nil {
		t.Fatalf("expand reader volume stage: %v", err)
	}

	if len(reader.keys) != len(writer.keys) {
		t.Fatalf(
			"reader/writer key counts = %d/%d; want equal",
			len(reader.keys),
			len(writer.keys),
		)
	}
	for i := range writer.keys {
		if writer.keys[i].row != reader.keys[i].row ||
			!bytes.Equal(
				writer.keys[i].secret.Bytes(),
				reader.keys[i].secret.Bytes(),
			) {
			t.Fatalf("reader key %d drifted from the writer schedule", i)
		}
	}
}

// frozenScheduleInfoForSuite returns the independent expected HKDF Info hex
// for every schedule row, reconstructed from the frozen specification's Info
// construction (domain, version, schema, suite, role, label length, label)
// rather than from any production helper. The first entries of each suite
// match the literals that predate this table.
func frozenScheduleInfoForSuite(t *testing.T, suite Suite) []string {
	t.Helper()
	switch suite {
	case Suite(0x0001):
		return []string{
			"5069636f63727970742d4e472f504356332f484b44460000030001000100001963726564656e7469616c2f777261702f786368616368613230",
			"5069636f63727970742d4e472f504356332f484b44460000030001000101001963726564656e7469616c2f777261702f786368616368613230",
			"5069636f63727970742d4e472f504356332f484b44460000030001000100001363726564656e7469616c2f777261702f6d6163",
			"5069636f63727970742d4e472f504356332f484b44460000030001000101001363726564656e7469616c2f777261702f6d6163",
			"5069636f63727970742d4e472f504356332f484b444600000300010001000012766f6c756d652f7265706c6963612f6d6163",
			"5069636f63727970742d4e472f504356332f484b444600000300010001010012766f6c756d652f7265706c6963612f6d6163",
			"5069636f63727970742d4e472f504356332f484b444600000300010001ff0013766f6c756d652f6d657461646174612f6d6163",
			"5069636f63727970742d4e472f504356332f484b444600000300010001ff0018766f6c756d652f7061796c6f61642f786368616368613230",
			"5069636f63727970742d4e472f504356332f484b444600000300010001ff0012766f6c756d652f7061796c6f61642f6d6163",
		}
	case Suite(0x0002):
		return []string{
			"5069636f63727970742d4e472f504356332f484b44460000030001000200001963726564656e7469616c2f777261702f786368616368613230",
			"5069636f63727970742d4e472f504356332f484b44460000030001000201001963726564656e7469616c2f777261702f786368616368613230",
			"5069636f63727970742d4e472f504356332f484b44460000030001000200001763726564656e7469616c2f777261702f73657270656e74",
			"5069636f63727970742d4e472f504356332f484b44460000030001000201001763726564656e7469616c2f777261702f73657270656e74",
			"5069636f63727970742d4e472f504356332f484b44460000030001000200001363726564656e7469616c2f777261702f6d6163",
			"5069636f63727970742d4e472f504356332f484b44460000030001000201001363726564656e7469616c2f777261702f6d6163",
			"5069636f63727970742d4e472f504356332f484b444600000300010002000012766f6c756d652f7265706c6963612f6d6163",
			"5069636f63727970742d4e472f504356332f484b444600000300010002010012766f6c756d652f7265706c6963612f6d6163",
			"5069636f63727970742d4e472f504356332f484b444600000300010002ff0013766f6c756d652f6d657461646174612f6d6163",
			"5069636f63727970742d4e472f504356332f484b444600000300010002ff0018766f6c756d652f7061796c6f61642f786368616368613230",
			"5069636f63727970742d4e472f504356332f484b444600000300010002ff0016766f6c756d652f7061796c6f61642f73657270656e74",
			"5069636f63727970742d4e472f504356332f484b444600000300010002ff0012766f6c756d652f7061796c6f61642f6d6163",
		}
	default:
		t.Fatalf("test has no frozen Info rows for suite %#04x", suite)
		return nil
	}
}

func TestScheduleExactRows(t *testing.T) {
	total := 0
	for _, suite := range []Suite{Suite(0x0001), Suite(0x0002)} {
		expected := literalRowsForSuite(t, suite)
		rows, err := fixedScheduleForSuite(suite)
		if err != nil {
			t.Fatalf("fixedScheduleForSuite(%#04x): %v", suite, err)
		}
		if len(rows) != len(expected) {
			t.Fatalf(
				"suite %#04x row count = %d; want %d",
				suite,
				len(rows),
				len(expected),
			)
		}
		total += len(rows)
		for i := range expected {
			if rows[i].suite != suite ||
				rows[i].root != expected[i].root ||
				rows[i].request != expected[i].request {
				t.Fatalf(
					"suite %#04x row %d = %+v; want root %d request %+v",
					suite,
					i,
					rows[i],
					expected[i].root,
					expected[i].request,
				)
			}
		}

		rows[0].request.Label = KeyLabel("mutated/test-only")
		fresh, err := fixedScheduleForSuite(suite)
		if err != nil || len(fresh) != len(expected) ||
			fresh[0].request != expected[0].request {
			t.Fatalf("suite %#04x registry returned mutable shared state", suite)
		}
	}
	if total != 21 {
		t.Fatalf("global schedule row count = %d; want 21", total)
	}

	for _, suite := range []Suite{Suite(0x0001), Suite(0x0002)} {
		rows, err := fixedScheduleForSuite(suite)
		if err != nil {
			t.Fatalf("load suite %#04x for Info: %v", suite, err)
		}
		frozen := frozenScheduleInfoForSuite(t, suite)
		if len(rows) != len(frozen) {
			t.Fatalf(
				"suite %#04x Info row count = %d; want %d",
				suite,
				len(rows),
				len(frozen),
			)
		}
		for index := range rows {
			if got := hex.EncodeToString([]byte(scheduleInfo(rows[index]))); got != frozen[index] {
				t.Fatalf(
					"suite %#04x Info row %d = %s; want %s",
					suite,
					index,
					got,
					frozen[index],
				)
			}
		}
	}

	for _, suite := range []Suite{0x0000, 0x0003, 0xffff} {
		rows, err := fixedScheduleForSuite(suite)
		scheduleErr := requireScheduleCode(t, err, ScheduleErrorInvalidSuite)
		if scheduleErr.Suite != suite || scheduleErr.Index != -1 {
			t.Fatalf("unknown-suite metadata = %+v", scheduleErr)
		}
		if rows != nil {
			t.Fatalf("unknown suite %#04x returned rows", suite)
		}
	}
}

func TestScheduleCardinalityBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		suite      Suite
		count      int
		wantCode   ScheduleErrorCode
		wantExpand int
	}{
		{name: "Standard zero", suite: 0x0001, count: 0, wantCode: ScheduleErrorCardinality},
		{name: "Standard one", suite: 0x0001, count: 1, wantExpand: 1},
		{name: "Standard maximum", suite: 0x0001, count: 9, wantExpand: 9},
		{name: "Standard maximum plus one", suite: 0x0001, count: 10, wantCode: ScheduleErrorCardinality},
		{name: "Paranoid zero", suite: 0x0002, count: 0, wantCode: ScheduleErrorCardinality},
		{name: "Paranoid one", suite: 0x0002, count: 1, wantExpand: 1},
		{name: "Paranoid maximum", suite: 0x0002, count: 12, wantExpand: 12},
		{name: "Paranoid maximum plus one", suite: 0x0002, count: 13, wantCode: ScheduleErrorCardinality},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			all := literalRequestsForSuite(t, test.suite)
			requests := append([]KeyRequest(nil), all...)
			switch {
			case test.count == 0:
				requests = nil
			case test.count <= len(all):
				requests = requests[:test.count]
			default:
				for len(requests) < test.count {
					requests = append(requests, all[0])
				}
			}

			schedule, err := validateKeySchedule(test.suite, requests)
			if test.wantCode != 0 {
				scheduleErr := requireScheduleCode(t, err, test.wantCode)
				if scheduleErr.Suite != test.suite || scheduleErr.Index != -1 {
					t.Fatalf("cardinality error metadata = %+v", scheduleErr)
				}
				if schedule != nil {
					t.Fatal("invalid cardinality published a schedule")
				}
				return
			}
			if err != nil {
				t.Fatalf("valid cardinality rejected: %v", err)
			}
			if schedule == nil || len(schedule.rows) != test.count {
				t.Fatalf("validated rows = %v; want %d", schedule, test.count)
			}

			root, key, rootOwner, keyOwner, rootAlias, keyAlias := testRootOwners(0x41, 32, 0x42, 32)
			extractCalls := 0
			expandCalls := 0
			extract, expand := testSuccessfulSeams(&extractCalls, &expandCalls)
			material, err := deriveKeyMaterialWith(
				schedule,
				root,
				key,
				testVolumeID(),
				extract,
				expand,
			)
			if err != nil || material == nil {
				t.Fatalf("valid cardinality derivation = %v, %v", material, err)
			}
			if extractCalls != 2 || expandCalls != test.wantExpand ||
				len(material.keys) != test.wantExpand {
				material.close()
				t.Fatalf(
					"calls/keys = %d/%d/%d; want 2/%d/%d",
					extractCalls,
					expandCalls,
					len(material.keys),
					test.wantExpand,
					test.wantExpand,
				)
			}
			material.close()
			if rootOwner.Len() != 0 || keyOwner.Len() != 0 ||
				!allZero(rootAlias) || !allZero(keyAlias) {
				t.Fatal("cardinality success did not clear transferred roots")
			}
		})
	}
}

func TestScheduleRejectsBeforeExpand(t *testing.T) {
	type invalidRequestCase struct {
		name     string
		suite    Suite
		requests func(*testing.T) []KeyRequest
		want     ScheduleErrorCode
		index    int
	}
	invalidRequests := []invalidRequestCase{
		{
			name:  "unknown role",
			suite: 0x0001,
			requests: func(t *testing.T) []KeyRequest {
				requests := literalRequestsForSuite(t, 0x0001)[:1]
				requests[0].Role = 0x02
				return requests
			},
			want: ScheduleErrorUnknownRequest,
		},
		{
			name:  "unknown credential label",
			suite: 0x0001,
			requests: func(t *testing.T) []KeyRequest {
				requests := literalRequestsForSuite(t, 0x0001)[:1]
				requests[0].Label = "credential/wrap/unknown"
				return requests
			},
			want: ScheduleErrorUnknownRequest,
		},
		{
			name:  "unknown volume label",
			suite: 0x0001,
			requests: func(t *testing.T) []KeyRequest {
				requests := literalRequestsForSuite(t, 0x0001)[4:5]
				requests[0].Label = "volume/unknown"
				return requests
			},
			want: ScheduleErrorUnknownRequest,
		},
		{
			name:  "short output",
			suite: 0x0001,
			requests: func(t *testing.T) []KeyRequest {
				requests := literalRequestsForSuite(t, 0x0001)[:1]
				requests[0].OutputBytes = 31
				return requests
			},
			want: ScheduleErrorUnknownRequest,
		},
		{
			name:  "long output",
			suite: 0x0001,
			requests: func(t *testing.T) []KeyRequest {
				requests := literalRequestsForSuite(t, 0x0001)[:1]
				requests[0].OutputBytes = 33
				return requests
			},
			want: ScheduleErrorUnknownRequest,
		},
		{
			name:  "Standard credential Serpent",
			suite: 0x0001,
			requests: func(*testing.T) []KeyRequest {
				return []KeyRequest{{
					Label:       "credential/wrap/serpent",
					Role:        0x00,
					OutputBytes: 32,
				}}
			},
			want: ScheduleErrorUnknownRequest,
		},
		{
			name:  "Standard volume Serpent",
			suite: 0x0001,
			requests: func(*testing.T) []KeyRequest {
				return []KeyRequest{{
					Label:       "volume/payload/serpent",
					Role:        0xff,
					OutputBytes: 32,
				}}
			},
			want: ScheduleErrorUnknownRequest,
		},
		{
			name:  "non-adjacent duplicate A-B-A",
			suite: 0x0001,
			requests: func(t *testing.T) []KeyRequest {
				all := literalRequestsForSuite(t, 0x0001)
				return []KeyRequest{all[0], all[1], all[0]}
			},
			want:  ScheduleErrorDuplicateRequest,
			index: 2,
		},
	}
	for _, test := range invalidRequests {
		t.Run(test.name, func(t *testing.T) {
			schedule, err := validateKeySchedule(test.suite, test.requests(t))
			scheduleErr := requireScheduleCode(t, err, test.want)
			if scheduleErr.Suite != test.suite ||
				scheduleErr.Index != test.index {
				t.Fatalf(
					"request error metadata = %+v; want suite %#04x index %d",
					scheduleErr,
					test.suite,
					test.index,
				)
			}
			if schedule != nil {
				t.Fatal("invalid request published a schedule")
			}
		})
	}

	for _, suite := range []Suite{0x0000, 0x0003, 0xffff} {
		t.Run(fmt.Sprintf("unknown suite %04x", suite), func(t *testing.T) {
			schedule, err := validateKeySchedule(
				suite,
				[]KeyRequest{{
					Label:       "credential/wrap/xchacha20",
					Role:        0x00,
					OutputBytes: 32,
				}},
			)
			scheduleErr := requireScheduleCode(t, err, ScheduleErrorInvalidSuite)
			if scheduleErr.Suite != suite || scheduleErr.Index != -1 {
				t.Fatalf("unknown-suite error metadata = %+v", scheduleErr)
			}
			if schedule != nil {
				t.Fatal("unknown suite published a schedule")
			}
		})
	}

	validated, err := validateKeySchedule(
		0x0001,
		literalRequestsForSuite(t, 0x0001)[:1],
	)
	if err != nil {
		t.Fatalf("validate root-width schedule: %v", err)
	}
	type inputCase struct {
		name        string
		rootPresent bool
		rootBytes   int
		keyPresent  bool
		keyBytes    int
		volumeBytes int
		nilExtract  bool
		nilExpand   bool
		want        ScheduleErrorCode
	}
	inputs := []inputCase{
		{name: "nil CredentialRoot", keyPresent: true, keyBytes: 32, volumeBytes: 32, want: ScheduleErrorCredentialRoot},
		{name: "closed CredentialRoot", rootPresent: true, rootBytes: 0, keyPresent: true, keyBytes: 32, volumeBytes: 32, want: ScheduleErrorCredentialRoot},
		{name: "short CredentialRoot", rootPresent: true, rootBytes: 31, keyPresent: true, keyBytes: 32, volumeBytes: 32, want: ScheduleErrorCredentialRoot},
		{name: "long CredentialRoot", rootPresent: true, rootBytes: 33, keyPresent: true, keyBytes: 32, volumeBytes: 32, want: ScheduleErrorCredentialRoot},
		{name: "nil VolumeKey", rootPresent: true, rootBytes: 32, volumeBytes: 32, want: ScheduleErrorVolumeKey},
		{name: "closed VolumeKey", rootPresent: true, rootBytes: 32, keyPresent: true, keyBytes: 0, volumeBytes: 32, want: ScheduleErrorVolumeKey},
		{name: "short VolumeKey", rootPresent: true, rootBytes: 32, keyPresent: true, keyBytes: 31, volumeBytes: 32, want: ScheduleErrorVolumeKey},
		{name: "long VolumeKey", rootPresent: true, rootBytes: 32, keyPresent: true, keyBytes: 33, volumeBytes: 32, want: ScheduleErrorVolumeKey},
		{name: "short volume ID", rootPresent: true, rootBytes: 32, keyPresent: true, keyBytes: 32, volumeBytes: 31, want: ScheduleErrorVolumeID},
		{name: "long volume ID", rootPresent: true, rootBytes: 32, keyPresent: true, keyBytes: 32, volumeBytes: 33, want: ScheduleErrorVolumeID},
		{name: "nil Extract", rootPresent: true, rootBytes: 32, keyPresent: true, keyBytes: 32, volumeBytes: 32, nilExtract: true, want: ScheduleErrorInvalidRequest},
		{name: "nil Expand", rootPresent: true, rootBytes: 32, keyPresent: true, keyBytes: 32, volumeBytes: 32, nilExpand: true, want: ScheduleErrorInvalidRequest},
	}
	for _, test := range inputs {
		t.Run(test.name, func(t *testing.T) {
			var root *credentialRoot
			var key *volumeKey
			var rootOwner, keyOwner *crypto.Secret
			var rootAlias, keyAlias []byte
			if test.rootPresent || test.keyPresent {
				builtRoot, builtKey, builtRootOwner, builtKeyOwner,
					builtRootAlias, builtKeyAlias := testRootOwners(
					0x51,
					test.rootBytes,
					0x52,
					test.keyBytes,
				)
				if test.rootPresent {
					root, rootOwner, rootAlias = builtRoot, builtRootOwner, builtRootAlias
				} else {
					builtRoot.close()
				}
				if test.keyPresent {
					key, keyOwner, keyAlias = builtKey, builtKeyOwner, builtKeyAlias
				} else {
					builtKey.close()
				}
			}
			extractCalls := 0
			expandCalls := 0
			extract, expand := testSuccessfulSeams(&extractCalls, &expandCalls)
			if test.nilExtract {
				extract = nil
			}
			if test.nilExpand {
				expand = nil
			}
			material, err := deriveKeyMaterialWith(
				validated,
				root,
				key,
				bytes.Repeat([]byte{0x53}, test.volumeBytes),
				extract,
				expand,
			)
			scheduleErr := requireScheduleCode(t, err, test.want)
			if scheduleErr.Suite != 0x0001 || scheduleErr.Index != -1 {
				t.Fatalf("input error metadata = %+v", scheduleErr)
			}
			if material != nil || extractCalls != 0 || expandCalls != 0 {
				if material != nil {
					material.close()
				}
				t.Fatalf(
					"rejected input material/calls = %v %d/%d; want nil 0/0",
					material,
					extractCalls,
					expandCalls,
				)
			}
			if root != nil && root.secret != nil {
				t.Fatal("rejected input did not consume CredentialRoot")
			}
			if key != nil && key.secret != nil {
				t.Fatal("rejected input did not consume VolumeKey")
			}
			if rootOwner != nil &&
				(rootOwner.Len() != 0 || !allZero(rootAlias)) {
				t.Fatal("rejected input did not clear CredentialRoot")
			}
			if keyOwner != nil &&
				(keyOwner.Len() != 0 || !allZero(keyAlias)) {
				t.Fatal("rejected input did not clear VolumeKey")
			}
		})
	}
}

type recordedExpand struct {
	prk    []byte
	info   string
	length int
}

func runIndependentSchedule(
	t *testing.T,
	suite Suite,
	requests []KeyRequest,
) (map[KeyRequest][]byte, []recordedExpand) {
	t.Helper()
	schedule, err := validateKeySchedule(suite, requests)
	if err != nil {
		t.Fatalf("validate independent schedule: %v", err)
	}
	root, key, _, _, _, _ := testRootOwners(0x61, 32, 0x62, 32)
	extractCalls := 0
	var calls []recordedExpand
	material, err := deriveKeyMaterialWith(
		schedule,
		root,
		key,
		testVolumeID(),
		func([]byte, []byte) ([]byte, error) {
			extractCalls++
			return bytes.Repeat(
				[]byte{byte(0xc0 + extractCalls)},
				testKeyBytes,
			), nil
		},
		func(prk []byte, info string, length int) ([]byte, error) {
			calls = append(calls, recordedExpand{
				prk:    append([]byte(nil), prk...),
				info:   info,
				length: length,
			})
			// This is a routing marker, not an HKDF oracle. Its only purpose is
			// to make a shared stream or order-dependent routing observable.
			hasher := sha3.New256()
			_, _ = hasher.Write(prk)
			_, _ = hasher.Write([]byte(info))
			return hasher.Sum(nil), nil
		},
	)
	if err != nil || material == nil {
		t.Fatalf("derive independent schedule = %v, %v", material, err)
	}
	if extractCalls != 2 || len(calls) != len(requests) ||
		len(material.keys) != len(requests) {
		material.close()
		t.Fatalf(
			"independent calls/keys = %d/%d/%d; want 2/%d/%d",
			extractCalls,
			len(calls),
			len(material.keys),
			len(requests),
			len(requests),
		)
	}
	outputs := make(map[KeyRequest][]byte, len(requests))
	for i := range material.keys {
		if material.keys[i].row.request != requests[i] {
			material.close()
			t.Fatalf(
				"material request %d = %+v; want caller order %+v",
				i,
				material.keys[i].row.request,
				requests[i],
			)
		}
		outputs[material.keys[i].row.request] = append(
			[]byte(nil),
			material.keys[i].secret.Bytes()...,
		)
	}
	material.close()
	return outputs, calls
}

func requireIndependentScheduleInfo(
	t *testing.T,
	calls []recordedExpand,
) {
	t.Helper()
	seenInfo := make(map[string]struct{}, len(calls))
	for i, call := range calls {
		if _, duplicate := seenInfo[call.info]; duplicate {
			t.Fatalf("Expand %d reused Info %x", i, call.info)
		}
		seenInfo[call.info] = struct{}{}
	}
}

func TestScheduleIndependentExpand(t *testing.T) {
	for _, suite := range []Suite{0x0001, 0x0002} {
		t.Run(fmt.Sprintf("suite-%04x", suite), func(t *testing.T) {
			requests := literalRequestsForSuite(t, suite)
			forward, forwardCalls := runIndependentSchedule(t, suite, requests)
			reversedRequests := append([]KeyRequest(nil), requests...)
			for left, right := 0, len(reversedRequests)-1; left < right; left, right = left+1, right-1 {
				reversedRequests[left], reversedRequests[right] = reversedRequests[right], reversedRequests[left]
			}
			reversed, reversedCalls := runIndependentSchedule(
				t,
				suite,
				reversedRequests,
			)
			single, singleCalls := runIndependentSchedule(
				t,
				suite,
				[]KeyRequest{requests[len(requests)/2]},
			)
			defer func() {
				for request := range forward {
					crypto.SecureZero(forward[request])
				}
				for request := range reversed {
					crypto.SecureZero(reversed[request])
				}
				for request := range single {
					crypto.SecureZero(single[request])
				}
				for i := range forwardCalls {
					crypto.SecureZero(forwardCalls[i].prk)
				}
				for i := range reversedCalls {
					crypto.SecureZero(reversedCalls[i].prk)
				}
				for i := range singleCalls {
					crypto.SecureZero(singleCalls[i].prk)
				}
			}()

			for _, request := range requests {
				if !bytes.Equal(forward[request], reversed[request]) {
					t.Fatalf("request %+v depends on schedule order", request)
				}
			}
			middle := requests[len(requests)/2]
			if !bytes.Equal(forward[middle], single[middle]) {
				t.Fatalf("request %+v depends on neighboring requests", middle)
			}

			rows := literalRowsForSuite(t, suite)
			requireIndependentScheduleInfo(t, forwardCalls)
			for i, call := range forwardCalls {
				if call.length != 32 {
					t.Fatalf("Expand %d length = %d; want 32", i, call.length)
				}
				wantPRK := byte(0xc1)
				if rows[i].root == scheduleRoot(2) {
					wantPRK = 0xc2
				}
				if !bytes.Equal(
					call.prk,
					bytes.Repeat([]byte{wantPRK}, 32),
				) {
					t.Fatalf(
						"Expand %d PRK = %x; want root marker %02x",
						i,
						call.prk,
						wantPRK,
					)
				}
			}
			if len(reversedCalls) != len(rows) || len(singleCalls) != 1 {
				t.Fatalf(
					"reverse/single calls = %d/%d; want %d/1",
					len(reversedCalls),
					len(singleCalls),
					len(rows),
				)
			}
		})
	}
}

func TestScheduleIndependentExpandMutation(t *testing.T) {
	requests := literalRequestsForSuite(t, SuiteStandard1)
	outputs, calls := runIndependentSchedule(t, SuiteStandard1, requests)
	defer func() {
		for request := range outputs {
			crypto.SecureZero(outputs[request])
		}
		for i := range calls {
			crypto.SecureZero(calls[i].prk)
		}
	}()
	requireIndependentScheduleInfo(t, calls)
	rows := literalRowsForSuite(t, SuiteStandard1)
	frozen := frozenScheduleInfoForSuite(t, SuiteStandard1)
	if len(calls) != len(rows) {
		t.Fatalf("Expand calls = %d; want one per schedule row %d", len(calls), len(rows))
	}
	for i, call := range calls {
		if call.length != 32 {
			t.Fatalf("Expand %d length = %d; want 32", i, call.length)
		}
		// Every row expands from its own root's PRK: the credential root is the
		// first independent Extract result and the volume root is the second.
		wantPRK := byte(0xc1)
		if rows[i].root == scheduleRoot(2) {
			wantPRK = 0xc2
		}
		if !bytes.Equal(call.prk, bytes.Repeat([]byte{wantPRK}, 32)) {
			t.Fatalf(
				"Expand %d PRK = %x; want root marker %02x",
				i,
				call.prk,
				wantPRK,
			)
		}
		if got := hex.EncodeToString([]byte(call.info)); got != frozen[i] {
			t.Fatalf("Expand %d Info = %s; want frozen row Info %s", i, got, frozen[i])
		}
	}
}

func TestScheduleNoAliasing(t *testing.T) {
	schedule, err := validateKeySchedule(
		0x0001,
		literalRequestsForSuite(t, 0x0001)[:3],
	)
	if err != nil {
		t.Fatalf("validate no-alias schedule: %v", err)
	}

	t.Run("live secret wrappers redact formatting", func(t *testing.T) {
		oneRow, err := validateKeySchedule(
			0x0001,
			literalRequestsForSuite(t, 0x0001)[:1],
		)
		if err != nil {
			t.Fatalf("validate redaction schedule: %v", err)
		}
		root, key, rootOwner, keyOwner, rootAlias, keyAlias := testRootOwners(0x91, 32, 0x92, 32)
		var providerReturns [][]byte
		extractCalls := 0
		material, err := deriveKeyMaterialWith(
			oneRow,
			root,
			key,
			testVolumeID(),
			func([]byte, []byte) ([]byte, error) {
				extractCalls++
				returned := bytes.Repeat(
					[]byte{byte(0xa0 + extractCalls)},
					testKeyBytes,
				)
				providerReturns = append(providerReturns, returned)
				return returned, nil
			},
			func([]byte, string, int) ([]byte, error) {
				returned := bytes.Repeat([]byte{0xb1}, testKeyBytes)
				providerReturns = append(providerReturns, returned)
				return returned, nil
			},
		)
		if err != nil || material == nil {
			t.Fatalf("derive redaction material = %v, %v", material, err)
		}
		if root.secret != nil || key.secret != nil {
			material.close()
			t.Fatal("redaction setup did not consume unique root pointers")
		}

		formatCases := []struct {
			name    string
			subject any
			want    string
		}{
			{"VolumeKey pointer", material.volumeKey, "pcv3credential.volumeKey([REDACTED])"},
			{"VolumeKey value", *material.volumeKey, "pcv3credential.volumeKey([REDACTED])"},
			{"CredentialPRK pointer", material.credentialPRK, "pcv3credential.credentialPRK([REDACTED])"},
			{"CredentialPRK value", *material.credentialPRK, "pcv3credential.credentialPRK([REDACTED])"},
			{"VolumePRK pointer", material.volumePRK, "pcv3credential.volumePRK([REDACTED])"},
			{"VolumePRK value", *material.volumePRK, "pcv3credential.volumePRK([REDACTED])"},
			{"derived key pointer", &material.keys[0], "pcv3credential.derivedKey([REDACTED])"},
			{"derived key value", material.keys[0], "pcv3credential.derivedKey([REDACTED])"},
			{"key material pointer", material, "pcv3credential.keyMaterial([REDACTED])"},
			{"key material value", *material, "pcv3credential.keyMaterial([REDACTED])"},
		}
		for _, formatCase := range formatCases {
			for _, verb := range []string{"%v", "%+v", "%#v"} {
				rendered := fmt.Sprintf(verb, formatCase.subject)
				if rendered != formatCase.want {
					material.close()
					t.Fatalf(
						"%s with %s = %q; want %q",
						formatCase.name,
						verb,
						rendered,
						formatCase.want,
					)
				}
			}
		}

		ownedAliases := [][]byte{
			material.credentialRoot.secret.Bytes(),
			material.volumeKey.secret.Bytes(),
			material.credentialPRK.secret.Bytes(),
			material.volumePRK.secret.Bytes(),
			material.keys[0].secret.Bytes(),
		}
		material.close()
		for i, alias := range ownedAliases {
			if !allZero(alias) {
				t.Fatalf("formatted owner alias %d survived close", i)
			}
		}
		for i, alias := range providerReturns {
			if !allZero(alias) {
				t.Fatalf("redaction provider return %d was not cleared", i)
			}
		}
		if rootOwner.Len() != 0 || keyOwner.Len() != 0 ||
			!allZero(rootAlias) || !allZero(keyAlias) {
			t.Fatal("formatted material retained transferred roots")
		}
	})

	t.Run("reused provider scratch is copied into independent owners", func(t *testing.T) {
		root, key, rootOwner, keyOwner, rootAlias, keyAlias := testRootOwners(0x71, 32, 0x72, 32)
		extractScratch := make([]byte, testKeyBytes)
		expandScratch := make([]byte, testKeyBytes)
		extractCalls := 0
		expandCalls := 0
		material, err := deriveKeyMaterialWith(
			schedule,
			root,
			key,
			testVolumeID(),
			func([]byte, []byte) ([]byte, error) {
				if !allZero(extractScratch) {
					t.Fatal("Extract scratch was retained between calls")
				}
				extractCalls++
				for i := range extractScratch {
					extractScratch[i] = byte(0xa0 + extractCalls)
				}
				return extractScratch, nil
			},
			func([]byte, string, int) ([]byte, error) {
				if !allZero(expandScratch) {
					t.Fatal("Expand scratch was retained between calls")
				}
				expandCalls++
				for i := range expandScratch {
					expandScratch[i] = byte(0xb0 + expandCalls)
				}
				return expandScratch, nil
			},
		)
		if err != nil || material == nil {
			t.Fatalf("derive no-alias material = %v, %v", material, err)
		}
		if extractCalls != 2 || expandCalls != 3 ||
			!allZero(extractScratch) || !allZero(expandScratch) {
			material.close()
			t.Fatal("provider scratch was not cleared after each call")
		}

		aliases := [][]byte{
			material.credentialRoot.secret.Bytes(),
			material.volumeKey.secret.Bytes(),
			material.credentialPRK.secret.Bytes(),
			material.volumePRK.secret.Bytes(),
		}
		for i := range material.keys {
			aliases = append(aliases, material.keys[i].secret.Bytes())
		}
		addresses := make(map[*byte]int, len(aliases))
		for i, alias := range aliases {
			if len(alias) != 32 {
				material.close()
				t.Fatalf("owned alias %d width = %d; want 32", i, len(alias))
			}
			address := &alias[0]
			if previous, duplicate := addresses[address]; duplicate {
				material.close()
				t.Fatalf("owned aliases %d and %d share backing storage", previous, i)
			}
			addresses[address] = i
		}

		beforeSecond := append([]byte(nil), aliases[5]...)
		beforePRK := append([]byte(nil), aliases[2]...)
		defer crypto.SecureZero(beforeSecond)
		defer crypto.SecureZero(beforePRK)
		aliases[4][0] ^= 0xff
		if !bytes.Equal(aliases[5], beforeSecond) ||
			!bytes.Equal(aliases[2], beforePRK) ||
			!bytes.Equal(aliases[0], bytes.Repeat([]byte{0x71}, 32)) ||
			!bytes.Equal(aliases[1], bytes.Repeat([]byte{0x72}, 32)) {
			material.close()
			t.Fatal("mutating one output changed another owned secret")
		}

		material.keys[0].secret.Close()
		if !allZero(aliases[4]) ||
			!bytes.Equal(aliases[5], beforeSecond) ||
			!bytes.Equal(aliases[2], beforePRK) {
			material.close()
			t.Fatal("closing one output changed another live owner")
		}
		material.close()
		material.close()
		for i, alias := range aliases {
			if !allZero(alias) {
				t.Fatalf("material close retained owned alias %d", i)
			}
		}
		if rootOwner.Len() != 0 || keyOwner.Len() != 0 ||
			!allZero(rootAlias) || !allZero(keyAlias) {
			t.Fatal("material close retained transferred root aliases")
		}
	})

	t.Run("provider output widths fail closed", func(t *testing.T) {
		tests := []struct {
			name        string
			stage       string
			width       int
			wantExtract int
			wantExpand  int
			wantIndex   int
		}{
			{name: "short Extract", stage: "extract", width: 31, wantExtract: 1, wantIndex: -1},
			{name: "long Extract", stage: "extract", width: 33, wantExtract: 1, wantIndex: -1},
			{name: "short Expand", stage: "expand", width: 31, wantExtract: 2, wantExpand: 1},
			{name: "long Expand", stage: "expand", width: 33, wantExtract: 2, wantExpand: 1},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				root, key, rootOwner, keyOwner, rootAlias, keyAlias := testRootOwners(0x91, 32, 0x92, 32)
				var providerReturns [][]byte
				var prkBorrows [][]byte
				extractCalls := 0
				expandCalls := 0
				material, err := deriveKeyMaterialWith(
					schedule,
					root,
					key,
					testVolumeID(),
					func([]byte, []byte) ([]byte, error) {
						extractCalls++
						width := testKeyBytes
						if test.stage == "extract" {
							width = test.width
						}
						returned := bytes.Repeat(
							[]byte{byte(0xe0 + extractCalls)},
							width,
						)
						providerReturns = append(providerReturns, returned)
						return returned, nil
					},
					func(prk []byte, _ string, _ int) ([]byte, error) {
						expandCalls++
						prkBorrows = append(prkBorrows, prk)
						width := testKeyBytes
						if test.stage == "expand" {
							width = test.width
						}
						returned := bytes.Repeat(
							[]byte{byte(0xf0 + expandCalls)},
							width,
						)
						providerReturns = append(providerReturns, returned)
						return returned, nil
					},
				)
				scheduleErr := requireScheduleCode(t, err, ScheduleErrorOutput)
				if scheduleErr.Suite != 0x0001 ||
					scheduleErr.Index != test.wantIndex {
					t.Fatalf(
						"output-width error metadata = %+v; want suite 1 index %d",
						scheduleErr,
						test.wantIndex,
					)
				}
				if material != nil ||
					extractCalls != test.wantExtract ||
					expandCalls != test.wantExpand {
					if material != nil {
						material.close()
					}
					t.Fatalf(
						"output-width material/calls = %v %d/%d; want nil %d/%d",
						material,
						extractCalls,
						expandCalls,
						test.wantExtract,
						test.wantExpand,
					)
				}
				if root.secret != nil || key.secret != nil ||
					rootOwner.Len() != 0 || keyOwner.Len() != 0 ||
					!allZero(rootAlias) || !allZero(keyAlias) {
					t.Fatal("output-width failure retained transferred roots")
				}
				for i, alias := range providerReturns {
					if !allZero(alias) {
						t.Fatalf("output-width provider return %d was not cleared", i)
					}
				}
				for i, alias := range prkBorrows {
					if !allZero(alias) {
						t.Fatalf("output-width PRK borrow %d survived failure", i)
					}
				}
			})
		}
	})

	t.Run("provider panics clear transferred material", func(t *testing.T) {
		t.Run("Extract panic", func(t *testing.T) {
			root, key, rootOwner, keyOwner, rootAlias, keyAlias := testRootOwners(0xa1, 32, 0xa2, 32)
			var recovered any
			func() {
				defer func() {
					recovered = recover()
				}()
				_, _ = deriveKeyMaterialWith(
					schedule,
					root,
					key,
					testVolumeID(),
					func([]byte, []byte) ([]byte, error) {
						panic("extract-panic-sentinel")
					},
					func([]byte, string, int) ([]byte, error) {
						t.Fatal("Expand called after Extract panic")
						return nil, nil
					},
				)
			}()
			if recovered != "extract-panic-sentinel" {
				t.Fatalf("recovered panic = %v; want Extract sentinel", recovered)
			}
			if root.secret != nil || key.secret != nil ||
				rootOwner.Len() != 0 || keyOwner.Len() != 0 ||
				!allZero(rootAlias) || !allZero(keyAlias) {
				t.Fatal("Extract panic retained transferred roots")
			}
		})

		t.Run("Expand panic", func(t *testing.T) {
			requests := literalRequestsForSuite(t, 0x0001)
			panicSchedule, err := validateKeySchedule(
				0x0001,
				[]KeyRequest{requests[0], requests[4]},
			)
			if err != nil {
				t.Fatalf("validate panic schedule: %v", err)
			}
			root, key, rootOwner, keyOwner, rootAlias, keyAlias := testRootOwners(0xb1, 32, 0xb2, 32)
			var providerReturns [][]byte
			var prkBorrows [][]byte
			extractCalls := 0
			expandCalls := 0
			var recovered any
			func() {
				defer func() {
					recovered = recover()
				}()
				_, _ = deriveKeyMaterialWith(
					panicSchedule,
					root,
					key,
					testVolumeID(),
					func([]byte, []byte) ([]byte, error) {
						extractCalls++
						returned := bytes.Repeat(
							[]byte{byte(0xc0 + extractCalls)},
							testKeyBytes,
						)
						providerReturns = append(providerReturns, returned)
						return returned, nil
					},
					func(prk []byte, _ string, _ int) ([]byte, error) {
						expandCalls++
						prkBorrows = append(prkBorrows, prk)
						if expandCalls == 2 {
							panic("expand-panic-sentinel")
						}
						returned := bytes.Repeat(
							[]byte{0xd1},
							testKeyBytes,
						)
						providerReturns = append(providerReturns, returned)
						return returned, nil
					},
				)
			}()
			if recovered != "expand-panic-sentinel" {
				t.Fatalf("recovered panic = %v; want Expand sentinel", recovered)
			}
			if extractCalls != 2 || expandCalls != 2 {
				t.Fatalf(
					"panic provider calls = %d/%d; want 2/2",
					extractCalls,
					expandCalls,
				)
			}
			if root.secret != nil || key.secret != nil ||
				rootOwner.Len() != 0 || keyOwner.Len() != 0 ||
				!allZero(rootAlias) || !allZero(keyAlias) {
				t.Fatal("Expand panic retained transferred roots")
			}
			for i, alias := range providerReturns {
				if !allZero(alias) {
					t.Fatalf("panic provider return %d was not cleared", i)
				}
			}
			for i, alias := range prkBorrows {
				if !allZero(alias) {
					t.Fatalf("panic PRK borrow %d survived failure", i)
				}
			}
		})
	})

	t.Run("mid-Expand slice plus error clears partial material", func(t *testing.T) {
		root, key, rootOwner, keyOwner, rootAlias, keyAlias := testRootOwners(0x81, 32, 0x82, 32)
		var providerReturns [][]byte
		var prkBorrows [][]byte
		extractCalls := 0
		expandCalls := 0
		material, err := deriveKeyMaterialWith(
			schedule,
			root,
			key,
			testVolumeID(),
			func([]byte, []byte) ([]byte, error) {
				extractCalls++
				returned := bytes.Repeat(
					[]byte{byte(0xc0 + extractCalls)},
					testKeyBytes,
				)
				providerReturns = append(providerReturns, returned)
				return returned, nil
			},
			func(prk []byte, _ string, _ int) ([]byte, error) {
				expandCalls++
				prkBorrows = append(prkBorrows, prk)
				returned := bytes.Repeat(
					[]byte{byte(0xd0 + expandCalls)},
					testKeyBytes,
				)
				providerReturns = append(providerReturns, returned)
				if expandCalls == 2 {
					return returned, errors.New("private-expand-sentinel")
				}
				return returned, nil
			},
		)
		scheduleErr := requireScheduleCode(t, err, ScheduleErrorExpand)
		if scheduleErr.Suite != 0x0001 || scheduleErr.Index != 1 {
			t.Fatalf("Expand error metadata = %+v; want suite 1 index 1", scheduleErr)
		}
		if material != nil || extractCalls != 2 || expandCalls != 2 {
			if material != nil {
				material.close()
			}
			t.Fatalf(
				"mid-Expand material/calls = %v %d/%d; want nil 2/2",
				material,
				extractCalls,
				expandCalls,
			)
		}
		if rootOwner.Len() != 0 || keyOwner.Len() != 0 ||
			!allZero(rootAlias) || !allZero(keyAlias) {
			t.Fatal("mid-Expand failure retained transferred roots")
		}
		for i, alias := range providerReturns {
			if !allZero(alias) {
				t.Fatalf("provider return %d was not cleared", i)
			}
		}
		for i, alias := range prkBorrows {
			if !allZero(alias) {
				t.Fatalf("owned PRK borrow %d survived failure", i)
			}
		}
		for _, rendered := range []string{
			err.Error(),
			fmt.Sprintf("%v", err),
			fmt.Sprintf("%+v", err),
			fmt.Sprintf("%#v", err),
		} {
			if bytes.Contains([]byte(rendered), []byte("private-expand-sentinel")) {
				t.Fatalf("Expand error disclosed provider sentinel in %q", rendered)
			}
		}
	})
}
