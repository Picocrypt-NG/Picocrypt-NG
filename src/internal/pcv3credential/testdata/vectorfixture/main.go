package main

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	inputSchemaVersion  = 1
	fixtureSchema       = 1
	exactGoVersion      = "go1.26.5"
	exactXCryptoVersion = "v0.54.0"
	publicDataNotice    = "PUBLIC DETERMINISTIC PCV3 TEST DATA; NOT SECRET OR OPERATIONAL CREDENTIALS OR KEYS"
	normalDomain        = "Picocrypt-NG/PCV3/credential/normal\x00"
	hkdfDomain          = "Picocrypt-NG/PCV3/HKDF\x00"
	maxToolFileBytes    = 8 << 20
)

type credentialCaseInput struct {
	ID             string `json:"id"`
	CredentialMode uint8  `json:"credential_mode"`
	KeyfileMode    uint8  `json:"keyfile_mode"`
	TranscriptHex  string `json:"transcript_hex"`
	NormalInputHex string `json:"normal_input_hex"`
}

type scheduleInput struct {
	ID          string `json:"id"`
	Root        string `json:"root"`
	SuiteID     uint16 `json:"suite_id"`
	Role        uint8  `json:"role"`
	Label       string `json:"label"`
	OutputBytes uint16 `json:"output_bytes"`
}

type profileInput struct {
	ID               string          `json:"id"`
	ProfileID        uint8           `json:"profile_id"`
	SuiteID          uint16          `json:"suite_id"`
	Argon2Version    uint8           `json:"argon2_version"`
	Time             uint32          `json:"time"`
	MemoryKiB        uint32          `json:"memory_kib"`
	Parallelism      uint8           `json:"parallelism"`
	OutputBytes      uint32          `json:"output_bytes"`
	ArgonSaltHex     string          `json:"argon_salt_hex"`
	CredentialCaseID string          `json:"credential_case_id"`
	VolumeIDHex      string          `json:"volume_id_hex"`
	VolumeKeyHex     string          `json:"volume_key_hex"`
	Schedule         []scheduleInput `json:"schedule"`
}

type fixtureInput struct {
	SchemaVersion        int                   `json:"schema_version"`
	PublicTestDataNotice string                `json:"public_test_data_notice"`
	CredentialCases      []credentialCaseInput `json:"credential_cases"`
	Profiles             []profileInput        `json:"profiles"`
}

type fixtureProvenance struct {
	InputSHA256     string `json:"input_sha256"`
	GeneratorSHA256 string `json:"generator_sha256"`
	GoVersion       string `json:"go_version"`
	XCryptoVersion  string `json:"x_crypto_version"`
	XCryptoChecksum string `json:"x_crypto_checksum"`
}

type derivedRow struct {
	ID              string `json:"id"`
	Root            string `json:"root"`
	SuiteID         uint16 `json:"suite_id"`
	Role            uint8  `json:"role"`
	Label           string `json:"label"`
	OutputBytes     uint16 `json:"output_bytes"`
	InfoHex         string `json:"info_hex"`
	ExpandOutputHex string `json:"expand_output_hex"`
}

type profileFixture struct {
	ID                string       `json:"id"`
	ArgonCallIndex    int          `json:"argon_call_index"`
	ProfileID         uint8        `json:"profile_id"`
	SuiteID           uint16       `json:"suite_id"`
	Argon2Version     uint8        `json:"argon2_version"`
	Time              uint32       `json:"time"`
	MemoryKiB         uint32       `json:"memory_kib"`
	Parallelism       uint8        `json:"parallelism"`
	OutputBytes       uint32       `json:"output_bytes"`
	CredentialCaseID  string       `json:"credential_case_id"`
	NormalInputHex    string       `json:"normal_input_hex"`
	ArgonSaltHex      string       `json:"argon_salt_hex"`
	CredentialRootHex string       `json:"argon2id_output_hex"`
	VolumeIDHex       string       `json:"volume_id_hex"`
	CredentialPRKHex  string       `json:"wrap_prk_hex"`
	VolumePRKHex      string       `json:"volume_prk_hex"`
	Rows              []derivedRow `json:"rows"`
}

type fixture struct {
	SchemaVersion        int               `json:"schema_version"`
	PublicTestDataNotice string            `json:"public_test_data_notice"`
	Provenance           fixtureProvenance `json:"provenance"`
	Profiles             []profileFixture  `json:"profiles"`
}

type terminalRecord struct {
	Status     string   `json:"status"`
	Profiles   []string `json:"profiles"`
	ArgonCalls int      `json:"argon_calls"`
}

type argonDeriver func(
	profile profileInput,
	credentialInput []byte,
	salt []byte,
) ([]byte, error)

func expectedSchedule(suite uint16) []scheduleInput {
	rows := []scheduleInput{
		newScheduleRow(
			"credential-wrap-xchacha20-primary",
			"credential-prk",
			suite,
			0x00,
			"credential/wrap/xchacha20",
		),
		newScheduleRow(
			"credential-wrap-xchacha20-backup",
			"credential-prk",
			suite,
			0x01,
			"credential/wrap/xchacha20",
		),
	}
	if suite == 0x0002 {
		rows = append(rows,
			newScheduleRow(
				"credential-wrap-serpent-primary",
				"credential-prk",
				suite,
				0x00,
				"credential/wrap/serpent",
			),
			newScheduleRow(
				"credential-wrap-serpent-backup",
				"credential-prk",
				suite,
				0x01,
				"credential/wrap/serpent",
			),
		)
	}
	rows = append(rows,
		newScheduleRow(
			"credential-wrap-mac-primary",
			"credential-prk",
			suite,
			0x00,
			"credential/wrap/mac",
		),
		newScheduleRow(
			"credential-wrap-mac-backup",
			"credential-prk",
			suite,
			0x01,
			"credential/wrap/mac",
		),
		newScheduleRow(
			"volume-replica-mac-primary",
			"volume-prk",
			suite,
			0x00,
			"volume/replica/mac",
		),
		newScheduleRow(
			"volume-replica-mac-backup",
			"volume-prk",
			suite,
			0x01,
			"volume/replica/mac",
		),
		newScheduleRow(
			"volume-metadata-mac",
			"volume-prk",
			suite,
			0xff,
			"volume/metadata/mac",
		),
		newScheduleRow(
			"volume-payload-xchacha20",
			"volume-prk",
			suite,
			0xff,
			"volume/payload/xchacha20",
		),
	)
	if suite == 0x0002 {
		rows = append(rows, newScheduleRow(
			"volume-payload-serpent",
			"volume-prk",
			suite,
			0xff,
			"volume/payload/serpent",
		))
	}
	return append(rows, newScheduleRow(
		"volume-payload-mac",
		"volume-prk",
		suite,
		0xff,
		"volume/payload/mac",
	))
}

func newScheduleRow(
	id string,
	root string,
	suite uint16,
	role uint8,
	label string,
) scheduleInput {
	return scheduleInput{
		ID:          id,
		Root:        root,
		SuiteID:     suite,
		Role:        role,
		Label:       label,
		OutputBytes: 32,
	}
}

func loadInput(path string) (*fixtureInput, []byte, error) {
	input, raw, err := readCanonicalJSON[fixtureInput](path)
	if err != nil {
		return nil, nil, fmt.Errorf("vectorfixture: read input: %w", err)
	}
	if err := validateInput(&input); err != nil {
		return nil, nil, err
	}
	return &input, raw, nil
}

func validateInput(input *fixtureInput) error {
	if input == nil {
		return errors.New("vectorfixture: nil input")
	}
	if input.SchemaVersion != inputSchemaVersion {
		return errors.New("vectorfixture: invalid input schema")
	}
	if input.PublicTestDataNotice != publicDataNotice {
		return errors.New("vectorfixture: public test-data notice mismatch")
	}

	expectedCases := []struct {
		id             string
		credentialMode uint8
		keyfileMode    uint8
		transcriptHex  string
		normalInputHex string
	}{
		{
			"password-only-nfc",
			0x01,
			0x00,
			"0101000000000005436166c3a90000",
			"47156ab898a6329d3388ca7d762b35af622897e7ce3e7da960aa55f9b1051073afeb902632ea30ddef7d6da4fc6f12c34493bb5abda4ee9a3ac191cba09dd011",
		},
		{
			"keyfiles-only-ordered",
			0x02,
			0x01,
			"0102010000000000000208fdf76ad6cbc6d144ac0c77f6a6d9a2e2c0af9b372b1af799540cb8e677e78655037c27d86a76c7d61cce3aa2dc97a778dbefb63cecc9be20adda385935e0d5",
			"b46f148394701876e14463e4e49ea0e47a5ba76bf798f165452413902273081f466f22547c86aeca4185d13e706cd3eec72eaa59a6983fe9115ea27d25715420",
		},
		{
			"combined-ordered",
			0x03,
			0x01,
			"01030100000000036d697800026d6788bf3bb7ebee87c9c2503a97aacdd7912e8b4093d4c99f17843af69f2f549eb695bdf185f656ac1ee1f68647bbd6c2288ef9f8a5c5b9ef3fec6336b7e3e0",
			"d4ac95f6c2f0d7ddfe7eadd0a7a01d527acc8c302876884f9c5fb240446f0655d5e0201aecfb73af77e07ac7e18692271a6bec281bc8fc7b270aec30d99f1b02",
		},
		{
			"combined-unordered",
			0x03,
			0x02,
			"01030200000000036d697800026d6788bf3bb7ebee87c9c2503a97aacdd7912e8b4093d4c99f17843af69f2f549eb695bdf185f656ac1ee1f68647bbd6c2288ef9f8a5c5b9ef3fec6336b7e3e0",
			"5089ee8f6c1fcce5338e0fb2054b8ec9d461d5d5987627d866329e8bc6eb07965af1a1fdd1c3f89c92838ac6e0080629eacf5935decdaff29301678550085544",
		},
	}
	if len(input.CredentialCases) != len(expectedCases) {
		return errors.New("vectorfixture: credential case set mismatch")
	}
	for index, expected := range expectedCases {
		credentialCase := &input.CredentialCases[index]
		if credentialCase.ID != expected.id ||
			credentialCase.CredentialMode != expected.credentialMode ||
			credentialCase.KeyfileMode != expected.keyfileMode {
			return fmt.Errorf(
				"vectorfixture: credential case %d identity mismatch",
				index,
			)
		}
		if err := validateCredentialCase(credentialCase); err != nil {
			return fmt.Errorf(
				"vectorfixture: credential case %s: %w",
				credentialCase.ID,
				err,
			)
		}
		if credentialCase.TranscriptHex != expected.transcriptHex ||
			credentialCase.NormalInputHex != expected.normalInputHex {
			return fmt.Errorf(
				"vectorfixture: credential case %d literal mismatch",
				index,
			)
		}
	}

	if len(input.Profiles) != 2 {
		return errors.New("vectorfixture: profile set mismatch")
	}
	credentialCases := make(map[string]credentialCaseInput, len(input.CredentialCases))
	for _, credentialCase := range input.CredentialCases {
		credentialCases[credentialCase.ID] = credentialCase
	}
	for index := range input.Profiles {
		profile := &input.Profiles[index]
		if err := validateProfile(index, profile, credentialCases); err != nil {
			return fmt.Errorf(
				"vectorfixture: profile %s: %w",
				profile.ID,
				err,
			)
		}
	}
	return nil
}

func validateCredentialCase(credentialCase *credentialCaseInput) error {
	transcript, err := decodeHex(
		"credential transcript",
		credentialCase.TranscriptHex,
		-1,
	)
	if err != nil {
		return err
	}
	if len(transcript) < 10 {
		return errors.New("credential transcript is too short")
	}
	if transcript[0] != 0x01 ||
		transcript[1] != credentialCase.CredentialMode ||
		transcript[2] != credentialCase.KeyfileMode ||
		transcript[3] != 0x00 {
		return errors.New("credential transcript prefix mismatch")
	}

	passwordLength := uint64(binary.BigEndian.Uint32(transcript[4:8]))
	if passwordLength > 1<<20 {
		return errors.New("credential transcript password exceeds 1 MiB")
	}
	if passwordLength > uint64(len(transcript)-10) {
		return errors.New("credential transcript password length mismatch")
	}
	keyfileCountOffset := 8 + int(passwordLength)
	if keyfileCountOffset+2 > len(transcript) {
		return errors.New("credential transcript keyfile count missing")
	}
	keyfileCount := int(binary.BigEndian.Uint16(
		transcript[keyfileCountOffset : keyfileCountOffset+2],
	))
	digestBytes := transcript[keyfileCountOffset+2:]
	if len(digestBytes) != keyfileCount*32 {
		return errors.New("credential transcript keyfile length mismatch")
	}
	if err := validateCredentialShape(
		credentialCase.CredentialMode,
		credentialCase.KeyfileMode,
		passwordLength,
		keyfileCount,
	); err != nil {
		return err
	}
	if err := validateKeyfileDigests(credentialCase.KeyfileMode, digestBytes); err != nil {
		return err
	}

	normalInput, err := decodeHex(
		"normal credential input",
		credentialCase.NormalInputHex,
		64,
	)
	if err != nil {
		return err
	}
	if !bytes.Equal(normalCredentialInput(transcript), normalInput) {
		return errors.New("normal credential input mismatch")
	}
	return nil
}

func normalCredentialInput(transcript []byte) []byte {
	hasher := sha3.New512()
	_, _ = hasher.Write([]byte(normalDomain))
	_, _ = hasher.Write(transcript)
	return hasher.Sum(nil)
}

func validateCredentialShape(
	credentialMode uint8,
	keyfileMode uint8,
	passwordLength uint64,
	keyfileCount int,
) error {
	switch credentialMode {
	case 0x01:
		if passwordLength == 0 || keyfileMode != 0x00 || keyfileCount != 0 {
			return errors.New("invalid password-only credential shape")
		}
	case 0x02:
		if passwordLength != 0 ||
			(keyfileMode != 0x01 && keyfileMode != 0x02) ||
			keyfileCount < 1 || keyfileCount > 64 {
			return errors.New("invalid keyfiles-only credential shape")
		}
	case 0x03:
		if passwordLength == 0 ||
			(keyfileMode != 0x01 && keyfileMode != 0x02) ||
			keyfileCount < 1 || keyfileCount > 64 {
			return errors.New("invalid combined credential shape")
		}
	default:
		return errors.New("unknown credential mode")
	}
	return nil
}

func validateKeyfileDigests(keyfileMode uint8, digestBytes []byte) error {
	digests := make([][]byte, 0, len(digestBytes)/32)
	for offset := 0; offset < len(digestBytes); offset += 32 {
		digest := digestBytes[offset : offset+32]
		for _, previous := range digests {
			if bytes.Equal(previous, digest) {
				return errors.New("duplicate keyfile digest")
			}
		}
		digests = append(digests, digest)
	}
	if keyfileMode == 0x02 && !sort.SliceIsSorted(digests, func(i, j int) bool {
		return bytes.Compare(digests[i], digests[j]) < 0
	}) {
		return errors.New("unordered keyfile digests are not canonical")
	}
	return nil
}

func validateProfile(
	index int,
	profile *profileInput,
	credentialCases map[string]credentialCaseInput,
) error {
	var expected profileInput
	switch index {
	case 0:
		expected = profileInput{
			ID:               "normal-1",
			ProfileID:        0x01,
			SuiteID:          0x0001,
			Argon2Version:    argon2.Version,
			Time:             4,
			MemoryKiB:        1 << 20,
			Parallelism:      4,
			OutputBytes:      32,
			ArgonSaltHex:     "000102030405060708090a0b0c0d0e0f",
			CredentialCaseID: "combined-ordered",
			VolumeIDHex:      "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
			VolumeKeyHex:     "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
		}
	case 1:
		expected = profileInput{
			ID:               "paranoid-1",
			ProfileID:        0x02,
			SuiteID:          0x0002,
			Argon2Version:    argon2.Version,
			Time:             8,
			MemoryKiB:        1 << 20,
			Parallelism:      8,
			OutputBytes:      32,
			ArgonSaltHex:     "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
			CredentialCaseID: "combined-unordered",
			VolumeIDHex:      "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
			VolumeKeyHex:     "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
		}
	default:
		return errors.New("unexpected profile index")
	}
	if profile.ID != expected.ID ||
		profile.ProfileID != expected.ProfileID ||
		profile.SuiteID != expected.SuiteID ||
		profile.Argon2Version != expected.Argon2Version ||
		profile.Time != expected.Time ||
		profile.MemoryKiB != expected.MemoryKiB ||
		profile.Parallelism != expected.Parallelism ||
		profile.OutputBytes != expected.OutputBytes {
		return errors.New("fixed profile tuple mismatch")
	}
	if _, err := decodeHex("Argon2id salt", profile.ArgonSaltHex, 16); err != nil {
		return err
	}
	if _, ok := credentialCases[profile.CredentialCaseID]; !ok {
		return errors.New("unknown credential case")
	}
	if _, err := decodeHex("volume ID", profile.VolumeIDHex, 32); err != nil {
		return err
	}
	if _, err := decodeHex("volume key", profile.VolumeKeyHex, 32); err != nil {
		return err
	}
	if profile.ArgonSaltHex != expected.ArgonSaltHex ||
		profile.CredentialCaseID != expected.CredentialCaseID ||
		profile.VolumeIDHex != expected.VolumeIDHex ||
		profile.VolumeKeyHex != expected.VolumeKeyHex {
		return errors.New("literal profile input mismatch")
	}
	expectedRows := expectedSchedule(profile.SuiteID)
	if len(profile.Schedule) != len(expectedRows) {
		return errors.New("schedule row count mismatch")
	}
	for rowIndex := range expectedRows {
		if profile.Schedule[rowIndex] != expectedRows[rowIndex] {
			return fmt.Errorf("schedule row %d mismatch", rowIndex)
		}
	}
	return nil
}

func generateFixture(
	input *fixtureInput,
	provenance fixtureProvenance,
	deriveArgon argonDeriver,
) (*fixture, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}
	if deriveArgon == nil {
		return nil, errors.New("vectorfixture: nil Argon2id deriver")
	}
	credentialCases := make(map[string]credentialCaseInput, len(input.CredentialCases))
	for _, credentialCase := range input.CredentialCases {
		credentialCases[credentialCase.ID] = credentialCase
	}

	result := &fixture{
		SchemaVersion:        fixtureSchema,
		PublicTestDataNotice: publicDataNotice,
		Provenance:           provenance,
		Profiles:             make([]profileFixture, 0, len(input.Profiles)),
	}
	for index, profile := range input.Profiles {
		credentialCase := credentialCases[profile.CredentialCaseID]
		credentialInput, err := decodeHex(
			"normal credential input",
			credentialCase.NormalInputHex,
			64,
		)
		if err != nil {
			return nil, err
		}
		salt, err := decodeHex("Argon2id salt", profile.ArgonSaltHex, 16)
		if err != nil {
			return nil, err
		}
		credentialRoot, err := deriveArgon(profile, credentialInput, salt)
		if err != nil {
			return nil, fmt.Errorf(
				"vectorfixture: derive profile %s: %w",
				profile.ID,
				err,
			)
		}
		if len(credentialRoot) != 32 {
			return nil, fmt.Errorf(
				"vectorfixture: profile %s returned invalid root width",
				profile.ID,
			)
		}
		profileResult, err := deriveProfile(
			index+1,
			profile,
			credentialCase.NormalInputHex,
			credentialRoot,
		)
		if err != nil {
			return nil, err
		}
		result.Profiles = append(result.Profiles, profileResult)
	}
	if err := validateFixture(input, provenance, result); err != nil {
		return nil, err
	}
	return result, nil
}

func deriveProfile(
	callIndex int,
	profile profileInput,
	credentialInputHex string,
	credentialRoot []byte,
) (profileFixture, error) {
	volumeID, err := decodeHex("volume ID", profile.VolumeIDHex, 32)
	if err != nil {
		return profileFixture{}, err
	}
	volumeKey, err := decodeHex("volume key", profile.VolumeKeyHex, 32)
	if err != nil {
		return profileFixture{}, err
	}
	credentialPRK, err := hkdf.Extract(sha3.New256, credentialRoot, volumeID)
	if err != nil {
		return profileFixture{}, fmt.Errorf(
			"vectorfixture: credential Extract: %w",
			err,
		)
	}
	volumePRK, err := hkdf.Extract(sha3.New256, volumeKey, volumeID)
	if err != nil {
		return profileFixture{}, fmt.Errorf(
			"vectorfixture: volume Extract: %w",
			err,
		)
	}
	rows, err := deriveRows(profile.Schedule, credentialPRK, volumePRK)
	if err != nil {
		return profileFixture{}, err
	}
	return profileFixture{
		ID:                profile.ID,
		ArgonCallIndex:    callIndex,
		ProfileID:         profile.ProfileID,
		SuiteID:           profile.SuiteID,
		Argon2Version:     profile.Argon2Version,
		Time:              profile.Time,
		MemoryKiB:         profile.MemoryKiB,
		Parallelism:       profile.Parallelism,
		OutputBytes:       profile.OutputBytes,
		CredentialCaseID:  profile.CredentialCaseID,
		NormalInputHex:    credentialInputHex,
		ArgonSaltHex:      profile.ArgonSaltHex,
		CredentialRootHex: hex.EncodeToString(credentialRoot),
		VolumeIDHex:       profile.VolumeIDHex,
		CredentialPRKHex:  hex.EncodeToString(credentialPRK),
		VolumePRKHex:      hex.EncodeToString(volumePRK),
		Rows:              rows,
	}, nil
}

func deriveRows(
	schedule []scheduleInput,
	credentialPRK []byte,
	volumePRK []byte,
) ([]derivedRow, error) {
	rows := make([]derivedRow, 0, len(schedule))
	for _, scheduled := range schedule {
		info, err := encodeInfo(scheduled)
		if err != nil {
			return nil, err
		}
		var root []byte
		switch scheduled.Root {
		case "credential-prk":
			root = credentialPRK
		case "volume-prk":
			root = volumePRK
		default:
			return nil, errors.New("vectorfixture: unknown schedule root")
		}
		key, err := hkdf.Expand(
			sha3.New256,
			root,
			string(info),
			int(scheduled.OutputBytes),
		)
		if err != nil {
			return nil, fmt.Errorf("vectorfixture: Expand row %s: %w", scheduled.ID, err)
		}
		rows = append(rows, derivedRow{
			ID:              scheduled.ID,
			Root:            scheduled.Root,
			SuiteID:         scheduled.SuiteID,
			Role:            scheduled.Role,
			Label:           scheduled.Label,
			OutputBytes:     scheduled.OutputBytes,
			InfoHex:         hex.EncodeToString(info),
			ExpandOutputHex: hex.EncodeToString(key),
		})
	}
	return rows, nil
}

func encodeInfo(row scheduleInput) ([]byte, error) {
	if len(row.Label) > int(^uint16(0)) {
		return nil, errors.New("vectorfixture: HKDF label too long")
	}
	for index := range row.Label {
		if row.Label[index] > 0x7f {
			return nil, errors.New("vectorfixture: HKDF label is not ASCII")
		}
	}
	info := make([]byte, 0, len(hkdfDomain)+9+len(row.Label))
	info = append(info, []byte(hkdfDomain)...)
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], 0x0003)
	info = append(info, encoded[:]...)
	binary.BigEndian.PutUint16(encoded[:], 0x0001)
	info = append(info, encoded[:]...)
	binary.BigEndian.PutUint16(encoded[:], row.SuiteID)
	info = append(info, encoded[:]...)
	info = append(info, row.Role)
	binary.BigEndian.PutUint16(encoded[:], uint16(len(row.Label)))
	info = append(info, encoded[:]...)
	return append(info, []byte(row.Label)...), nil
}

func validateFixture(
	input *fixtureInput,
	provenance fixtureProvenance,
	value *fixture,
) error {
	if value == nil {
		return errors.New("vectorfixture: nil fixture")
	}
	if value.SchemaVersion != fixtureSchema ||
		value.PublicTestDataNotice != publicDataNotice {
		return errors.New("vectorfixture: fixture schema or notice mismatch")
	}
	if value.Provenance != provenance {
		return errors.New("vectorfixture: fixture provenance mismatch")
	}
	if len(value.Profiles) != len(input.Profiles) {
		return errors.New("vectorfixture: fixture profile count mismatch")
	}
	credentialCases := make(map[string]credentialCaseInput, len(input.CredentialCases))
	for _, credentialCase := range input.CredentialCases {
		credentialCases[credentialCase.ID] = credentialCase
	}
	for index, profile := range input.Profiles {
		actual := &value.Profiles[index]
		credentialCase := credentialCases[profile.CredentialCaseID]
		if actual.ID != profile.ID ||
			actual.ArgonCallIndex != index+1 ||
			actual.ProfileID != profile.ProfileID ||
			actual.SuiteID != profile.SuiteID ||
			actual.Argon2Version != profile.Argon2Version ||
			actual.Time != profile.Time ||
			actual.MemoryKiB != profile.MemoryKiB ||
			actual.Parallelism != profile.Parallelism ||
			actual.OutputBytes != profile.OutputBytes ||
			actual.CredentialCaseID != profile.CredentialCaseID ||
			actual.NormalInputHex != credentialCase.NormalInputHex ||
			actual.ArgonSaltHex != profile.ArgonSaltHex ||
			actual.VolumeIDHex != profile.VolumeIDHex {
			return fmt.Errorf(
				"vectorfixture: fixture profile %s metadata mismatch",
				profile.ID,
			)
		}
		credentialRoot, err := decodeHex(
			"credential root",
			actual.CredentialRootHex,
			32,
		)
		if err != nil {
			return err
		}
		expected, err := deriveProfile(
			index+1,
			profile,
			credentialCase.NormalInputHex,
			credentialRoot,
		)
		if err != nil {
			return err
		}
		if actual.CredentialPRKHex != expected.CredentialPRKHex ||
			actual.VolumePRKHex != expected.VolumePRKHex {
			return fmt.Errorf(
				"vectorfixture: fixture profile %s root separation mismatch",
				profile.ID,
			)
		}
		if len(actual.Rows) != len(expected.Rows) {
			return fmt.Errorf(
				"vectorfixture: fixture profile %s row count mismatch",
				profile.ID,
			)
		}
		for rowIndex := range expected.Rows {
			if actual.Rows[rowIndex] != expected.Rows[rowIndex] {
				return fmt.Errorf(
					"vectorfixture: fixture profile %s row %d mismatch",
					profile.ID,
					rowIndex,
				)
			}
		}
	}
	return nil
}

func realArgonDeriver(
	profile profileInput,
	credentialInput []byte,
	salt []byte,
) ([]byte, error) {
	if profile.Argon2Version != argon2.Version {
		return nil, errors.New("vectorfixture: Argon2id version mismatch")
	}
	return argon2.IDKey(
		credentialInput,
		salt,
		profile.Time,
		profile.MemoryKiB,
		profile.Parallelism,
		profile.OutputBytes,
	), nil
}

func buildProvenance(
	inputBytes []byte,
	sourcePath string,
	goSumPath string,
) (fixtureProvenance, error) {
	if runtime.Version() != exactGoVersion {
		return fixtureProvenance{}, fmt.Errorf(
			"vectorfixture: Go version %s; require %s",
			runtime.Version(),
			exactGoVersion,
		)
	}
	if err := validateGeneratorSourceSet(sourcePath); err != nil {
		return fixtureProvenance{}, err
	}
	sourceBytes, err := readBoundedFile(sourcePath)
	if err != nil {
		return fixtureProvenance{}, fmt.Errorf(
			"vectorfixture: read generator source: %w",
			err,
		)
	}
	version, buildChecksum, err := xCryptoBuildIdentity()
	if err != nil {
		return fixtureProvenance{}, err
	}
	if version != exactXCryptoVersion {
		return fixtureProvenance{}, fmt.Errorf(
			"vectorfixture: x/crypto version %s; require %s",
			version,
			exactXCryptoVersion,
		)
	}
	goSumBytes, err := readBoundedFile(goSumPath)
	if err != nil {
		return fixtureProvenance{}, fmt.Errorf("vectorfixture: read go.sum: %w", err)
	}
	goSumChecksum, err := xCryptoGoSumChecksum(goSumBytes, version)
	if err != nil {
		return fixtureProvenance{}, err
	}
	if buildChecksum != goSumChecksum {
		return fixtureProvenance{}, errors.New(
			"vectorfixture: x/crypto build and go.sum checksums differ",
		)
	}
	inputHash := sha256.Sum256(inputBytes)
	sourceHash := sha256.Sum256(sourceBytes)
	return fixtureProvenance{
		InputSHA256:     hex.EncodeToString(inputHash[:]),
		GeneratorSHA256: hex.EncodeToString(sourceHash[:]),
		GoVersion:       runtime.Version(),
		XCryptoVersion:  version,
		XCryptoChecksum: goSumChecksum,
	}, nil
}

func validateGeneratorSourceSet(sourcePath string) error {
	cleaned := filepath.Clean(sourcePath)
	if filepath.Base(cleaned) != "main.go" {
		return errors.New("vectorfixture: generator source must be main.go")
	}
	sourceInfo, err := os.Lstat(cleaned)
	if err != nil {
		return fmt.Errorf("vectorfixture: inspect generator source: %w", err)
	}
	if !sourceInfo.Mode().IsRegular() {
		return errors.New("vectorfixture: generator source is not a regular file")
	}
	entries, err := os.ReadDir(filepath.Dir(cleaned))
	if err != nil {
		return fmt.Errorf("vectorfixture: inspect generator directory: %w", err)
	}
	required := map[string]bool{
		"main.go":      false,
		"main_test.go": false,
	}
	for _, entry := range entries {
		seen, ok := required[entry.Name()]
		if !ok || seen {
			return errors.New("vectorfixture: unexpected generator-directory entry")
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return fmt.Errorf("vectorfixture: inspect generator entry: %w", infoErr)
		}
		if !info.Mode().IsRegular() {
			return errors.New("vectorfixture: generator entry is not a regular file")
		}
		required[entry.Name()] = true
	}
	if !required["main.go"] || !required["main_test.go"] {
		return errors.New("vectorfixture: incomplete generator source set")
	}
	return nil
}

func xCryptoBuildIdentity() (string, string, error) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", "", errors.New("vectorfixture: Go build info unavailable")
	}
	for _, dependency := range info.Deps {
		if dependency.Path != "golang.org/x/crypto" {
			continue
		}
		if dependency.Replace != nil {
			return "", "", errors.New("vectorfixture: x/crypto replacement rejected")
		}
		if dependency.Version == "" || dependency.Sum == "" {
			return "", "", errors.New("vectorfixture: incomplete x/crypto build identity")
		}
		return dependency.Version, dependency.Sum, nil
	}
	return "", "", errors.New("vectorfixture: x/crypto build dependency missing")
}

func xCryptoGoSumChecksum(goSum []byte, version string) (string, error) {
	var checksum string
	for _, line := range strings.Split(string(goSum), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 ||
			fields[0] != "golang.org/x/crypto" ||
			fields[1] != version {
			continue
		}
		if checksum != "" {
			return "", errors.New("vectorfixture: duplicate x/crypto go.sum entry")
		}
		if !strings.HasPrefix(fields[2], "h1:") {
			return "", errors.New("vectorfixture: invalid x/crypto go.sum checksum")
		}
		checksum = fields[2]
	}
	if checksum == "" {
		return "", errors.New("vectorfixture: x/crypto go.sum entry missing")
	}
	return checksum, nil
}

func run(args []string, stdout io.Writer, deriveArgon argonDeriver) error {
	if len(args) == 0 {
		return errors.New("vectorfixture: require generate or check")
	}
	switch args[0] {
	case "generate":
		return runGenerate(args[1:], stdout, deriveArgon)
	case "check":
		return runCheck(args[1:], stdout)
	default:
		return fmt.Errorf("vectorfixture: unknown command %q", args[0])
	}
}

func runGenerate(
	args []string,
	stdout io.Writer,
	deriveArgon argonDeriver,
) error {
	flags := flag.NewFlagSet("generate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "", "canonical literal input")
	sourcePath := flags.String("source", "", "generator source")
	goSumPath := flags.String("go-sum", "", "module go.sum")
	outputPath := flags.String("output", "", "create-exclusive fixture")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("vectorfixture: generate flags: %w", err)
	}
	if flags.NArg() != 0 ||
		*inputPath == "" ||
		*sourcePath == "" ||
		*goSumPath == "" ||
		*outputPath == "" {
		return errors.New("vectorfixture: incomplete generate arguments")
	}

	input, inputBytes, err := loadInput(*inputPath)
	if err != nil {
		return err
	}
	provenance, err := buildProvenance(inputBytes, *sourcePath, *goSumPath)
	if err != nil {
		return err
	}
	output, err := reserveOutput(*outputPath)
	if err != nil {
		return err
	}
	defer func() {
		if output != nil {
			_ = output.Close()
		}
	}()

	value, err := generateFixture(input, provenance, deriveArgon)
	if err != nil {
		return err
	}
	encoded, err := canonicalJSON(value)
	if err != nil {
		return err
	}
	if _, err := output.Write(encoded); err != nil {
		return fmt.Errorf("vectorfixture: write fixture: %w", err)
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("vectorfixture: sync fixture: %w", err)
	}
	outputInfo, err := output.Stat()
	if err != nil {
		return fmt.Errorf("vectorfixture: inspect fixture output: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("vectorfixture: close fixture: %w", err)
	}
	output = nil
	if err := verifyOutputIdentity(*outputPath, outputInfo); err != nil {
		return err
	}
	return writeTerminal(stdout, terminalRecord{
		Status:     "generated",
		Profiles:   []string{"normal-1", "paranoid-1"},
		ArgonCalls: 2,
	})
}

func runCheck(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "", "canonical literal input")
	sourcePath := flags.String("source", "", "generator source")
	goSumPath := flags.String("go-sum", "", "module go.sum")
	fixturePath := flags.String("fixture", "", "canonical fixture")
	if err := flags.Parse(args); err != nil {
		return fmt.Errorf("vectorfixture: check flags: %w", err)
	}
	if flags.NArg() != 0 ||
		*inputPath == "" ||
		*sourcePath == "" ||
		*goSumPath == "" ||
		*fixturePath == "" {
		return errors.New("vectorfixture: incomplete check arguments")
	}
	input, inputBytes, err := loadInput(*inputPath)
	if err != nil {
		return err
	}
	provenance, err := buildProvenance(inputBytes, *sourcePath, *goSumPath)
	if err != nil {
		return err
	}
	value, _, err := readCanonicalJSON[fixture](*fixturePath)
	if err != nil {
		return fmt.Errorf("vectorfixture: read fixture: %w", err)
	}
	if err := validateFixture(input, provenance, &value); err != nil {
		return err
	}
	return writeTerminal(stdout, terminalRecord{
		Status:     "checked",
		Profiles:   []string{"normal-1", "paranoid-1"},
		ArgonCalls: 0,
	})
}

func reserveOutput(path string) (*os.File, error) {
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, fmt.Errorf("vectorfixture: reserve output: %w", err)
	}
	return output, nil
}

func verifyOutputIdentity(path string, expected os.FileInfo) error {
	actual, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("vectorfixture: inspect final output path: %w", err)
	}
	if expected == nil ||
		!expected.Mode().IsRegular() ||
		!actual.Mode().IsRegular() ||
		!os.SameFile(expected, actual) {
		return errors.New("vectorfixture: final output identity changed")
	}
	return nil
}

func writeTerminal(stdout io.Writer, record terminalRecord) error {
	encoded, err := canonicalJSON(record)
	if err != nil {
		return err
	}
	if _, err := stdout.Write(encoded); err != nil {
		return fmt.Errorf("vectorfixture: write terminal record: %w", err)
	}
	return nil
}

func canonicalJSON(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("vectorfixture: encode canonical JSON: %w", err)
	}
	return append(encoded, '\n'), nil
}

func readCanonicalJSON[T any](path string) (T, []byte, error) {
	var value T
	raw, err := readBoundedFile(path)
	if err != nil {
		return value, nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, nil, fmt.Errorf("decode JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return value, nil, errors.New("multiple JSON values")
		}
		return value, nil, fmt.Errorf("decode trailing JSON: %w", err)
	}
	canonical, err := canonicalJSON(value)
	if err != nil {
		return value, nil, err
	}
	if !bytes.Equal(raw, canonical) {
		return value, nil, errors.New("noncanonical JSON")
	}
	return value, raw, nil
}

func readBoundedFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maxToolFileBytes {
		return nil, errors.New("file is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxToolFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxToolFileBytes {
		return nil, errors.New("file exceeds size limit")
	}
	return raw, nil
}

func decodeHex(name string, encoded string, size int) ([]byte, error) {
	if encoded == "" || strings.ToLower(encoded) != encoded {
		return nil, fmt.Errorf("vectorfixture: %s is not canonical lowercase hex", name)
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || hex.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("vectorfixture: %s is invalid hex", name)
	}
	if size >= 0 && len(decoded) != size {
		return nil, fmt.Errorf("vectorfixture: %s has invalid width", name)
	}
	return decoded, nil
}

func main() {
	if err := run(os.Args[1:], os.Stdout, realArgonDeriver); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
