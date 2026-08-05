package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	pcencoding "Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"Picocrypt-NG/internal/pcv3governance"
)

// These are literal schema-1 fixture dimensions, deliberately independent of
// production constants. The normal writer tests decode only systematic bytes
// needed as writer inputs; the complete frozen volume remains the oracle.
const (
	writerFixturePrimaryOffset = 16
	writerFixtureCapsuleData   = 320
	writerFixtureRS64Data      = 64
	writerFixtureRS64Total     = 192
	writerFixtureSuffix        = 1008
)

type normalLiteralWriteMaterial struct {
	metadata      normalWriteCredentialMetadata
	keys          normalWriteKeys
	metadataCalls int
	keyCalls      int
	borrowed      *normalWriteKeys
	failure       error
}

func (material *normalLiteralWriteMaterial) credentialMetadata() (
	normalWriteCredentialMetadata,
	error,
) {
	material.metadataCalls++
	if material.failure != nil {
		return normalWriteCredentialMetadata{}, material.failure
	}
	return material.metadata, nil
}

func (material *normalLiteralWriteMaterial) copyKeys(
	ctx context.Context,
	suite Suite,
	destination *normalWriteKeys,
) error {
	material.keyCalls++
	material.borrowed = destination
	if material.failure != nil {
		return material.failure
	}
	if ctx == nil || ctx.Err() != nil || destination == nil || suite != material.metadata.suite {
		return errors.New("TEST ONLY literal writer material rejected")
	}
	*destination = material.keys
	return nil
}

type normalIOProbe struct {
	reader       io.Reader
	writer       bytes.Buffer
	readCalls    int
	readBytes    int
	maxRead      int
	writeCalls   int
	writtenBytes int
	maxWrite     int
}

func (probe *normalIOProbe) Read(destination []byte) (int, error) {
	probe.readCalls++
	probe.maxRead = max(probe.maxRead, len(destination))
	count, err := probe.reader.Read(destination)
	probe.readBytes += count
	return count, err
}

func (probe *normalIOProbe) Write(source []byte) (int, error) {
	probe.writeCalls++
	probe.maxWrite = max(probe.maxWrite, len(source))
	count, err := probe.writer.Write(source)
	probe.writtenBytes += count
	return count, err
}

type normalCountingEntropy struct {
	reader io.Reader
	calls  int
	bytes  int
}

func (entropy *normalCountingEntropy) Read(destination []byte) (int, error) {
	entropy.calls++
	count, err := entropy.reader.Read(destination)
	entropy.bytes += count
	return count, err
}

func TestWriteNormalVolumeRequiresAuthorizationBeforeWork(t *testing.T) {
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("create TEST ONLY RS codecs: %v", err)
	}
	entropy := &normalCountingEntropy{reader: bytes.NewReader(make([]byte, 128))}
	source := &normalIOProbe{reader: bytes.NewReader(nil)}
	sink := &normalIOProbe{}
	material := &normalLiteralWriteMaterial{}

	completion, err := writeNormalVolumeWithSeams(
		context.Background(),
		&pcv3governance.EmissionAuthorization{},
		normalWriteRequest{},
		source,
		sink,
		material,
		normalWriteSeams{entropy: entropy, codecs: codecs},
	)
	if completion != nil {
		t.Fatal("rejected writer minted completion")
	}
	var refusal *pcv3governance.RefusalError
	if !errors.As(err, &refusal) || refusal.Reason != pcv3governance.ReasonAuthorizationMissing {
		t.Fatalf("rejected writer error = %v; want authorization-missing refusal", err)
	}
	if entropy.calls != 0 || entropy.bytes != 0 ||
		material.metadataCalls != 0 || material.keyCalls != 0 ||
		source.readCalls != 0 || source.readBytes != 0 ||
		sink.writeCalls != 0 || sink.writtenBytes != 0 {
		t.Fatalf(
			"work before authorization: entropy=%d/%d metadata=%d keys=%d source=%d/%d sink=%d/%d",
			entropy.calls, entropy.bytes, material.metadataCalls, material.keyCalls,
			source.readCalls, source.readBytes, sink.writeCalls, sink.writtenBytes,
		)
	}
}

func TestSerializeNormalVolumeIndependentBytes(t *testing.T) {
	testNormalWriterFixtures(t, []string{
		"normal-standard-keyfiles-only-small",
		"normal-standard-combined-unordered-rs-small",
		"normal-paranoid-combined-unordered-rs-small",
	}, false)
}

func TestSerializeNormalVolumeBoundaries(t *testing.T) {
	testNormalWriterFixtures(t, []string{
		"normal-standard-combined-ordered-empty",
		"normal-standard-combined-ordered-one",
		"normal-standard-combined-ordered-before-mib",
		"normal-standard-combined-ordered-exact-mib",
		"normal-standard-combined-ordered-after-mib",
		"normal-standard-combined-ordered-two-mib",
	}, true)
}

func testNormalWriterFixtures(t *testing.T, fixtureIDs []string, assertStreaming bool) {
	t.Helper()
	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("create TEST ONLY RS codecs: %v", err)
	}
	for _, fixtureID := range fixtureIDs {
		fixture := requireNormalFixture(t, fixtures, fixtureID)
		t.Run(fixtureID, func(t *testing.T) {
			volume := readNormalFixtureArtifact(t, fixture.Volume)
			plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
			request, material, entropyBytes := decodeNormalWriterFixtureInputs(t, fixture, volume)
			defer material.keys.close()
			entropy := &normalCountingEntropy{reader: bytes.NewReader(entropyBytes)}
			ioProbe := &normalIOProbe{reader: bytes.NewReader(plaintext)}

			completion, err := serializeNormalVolume(
				context.Background(),
				request,
				ioProbe,
				ioProbe,
				material,
				normalWriteSeams{entropy: entropy, codecs: codecs},
			)
			if err != nil || completion == nil {
				t.Fatalf("serialize independent TEST ONLY volume = completion %v, error %v", completion != nil, err)
			}
			if !bytes.Equal(ioProbe.writer.Bytes(), volume) {
				wantDigest := sha256.Sum256(volume)
				gotDigest := sha256.Sum256(ioProbe.writer.Bytes())
				t.Fatalf("serialized volume SHA-256 = %x; want frozen independent %x", gotDigest, wantDigest)
			}
			if entropy.bytes != len(entropyBytes) || material.metadataCalls != 1 || material.keyCalls != 1 {
				t.Fatalf(
					"serializer ownership calls: entropy=%d/%d metadata=%d keys=%d; want exact single traversal",
					entropy.bytes, len(entropyBytes), material.metadataCalls, material.keyCalls,
				)
			}
			if material.borrowed == nil || !material.borrowed.isZero() {
				t.Fatal("serializer retained nonzero writer-owned key material after success")
			}
			if assertStreaming && fixtureID == "normal-standard-combined-ordered-two-mib" {
				if ioProbe.readBytes != len(plaintext) || ioProbe.maxRead > recordPlaintextMax || ioProbe.readCalls != 3 {
					t.Fatalf(
						"2 MiB source traversal = calls %d bytes %d max %d; want two bounded records plus EOF probe",
						ioProbe.readCalls, ioProbe.readBytes, ioProbe.maxRead,
					)
				}
				if ioProbe.maxWrite > recordPlaintextMax+int(recordTagSize) {
					t.Fatalf("2 MiB sink max write = %d; want at most one semantic record", ioProbe.maxWrite)
				}
			}
		})
	}
}

func decodeNormalWriterFixtureInputs(
	t *testing.T,
	fixture normalFixture,
	volume []byte,
) (normalWriteRequest, *normalLiteralWriteMaterial, []byte) {
	t.Helper()
	if len(volume) < writerFixturePrimaryOffset+writerFixtureCapsuleData+writerFixtureSuffix {
		t.Fatal("independent TEST ONLY normal volume is too short")
	}
	primary := decodeWriterFixtureCapsule(t, volume, writerFixturePrimaryOffset)
	backup := decodeWriterFixtureCapsule(t, volume, len(volume)-writerFixtureSuffix)
	if !bytes.Equal(primary[:96], backup[:96]) || !bytes.Equal(primary[104:120], backup[104:120]) {
		t.Fatal("independent TEST ONLY replicas disagree on canonical writer inputs")
	}

	comment := decodeNormalFixtureHex(t, fixture.CommentHex, len(fixture.CommentHex)/2)
	core := primary[:96]
	suite := Suite(binary.BigEndian.Uint16(core[8:10]))
	request := normalWriteRequest{
		suite:           suite,
		payloadKind:     PayloadKind(core[48]),
		payloadBodyRS:   binary.BigEndian.Uint16(core[10:12])&1 != 0,
		plaintextLength: binary.BigEndian.Uint64(core[52:60]),
		comment:         comment,
	}
	material := &normalLiteralWriteMaterial{
		metadata: normalWriteCredentialMetadata{
			suite:          suite,
			credentialMode: CredentialMode(primary[97]),
			keyfileMode:    KeyfileMode(primary[98]),
			keyfileCount:   binary.BigEndian.Uint16(primary[100:102]),
			kdfProfile:     KDFProfile(primary[99]),
		},
	}
	copy(material.metadata.argonSalt[:], primary[104:120])
	copy(material.metadata.volumeID[:], core[16:48])
	material.keys = normalFixtureWriteKeys(t, fixture.Keys)

	entropy := make([]byte, 0, 104)
	entropy = append(entropy, core[68:84]...)
	if suite == SuiteParanoid {
		entropy = append(entropy, core[84:92]...)
	}
	entropy = append(entropy, primary[120:144]...)
	if suite == SuiteParanoid {
		entropy = append(entropy, primary[144:160]...)
	}
	entropy = append(entropy, backup[120:144]...)
	if suite == SuiteParanoid {
		entropy = append(entropy, backup[144:160]...)
	}
	return request, material, entropy
}

func decodeWriterFixtureCapsule(t *testing.T, volume []byte, offset int) [writerFixtureCapsuleData]byte {
	t.Helper()
	var decoded [writerFixtureCapsuleData]byte
	for lane := range writerFixtureCapsuleData / writerFixtureRS64Data {
		encodedStart := offset + lane*writerFixtureRS64Total
		encodedEnd := encodedStart + writerFixtureRS64Data
		if encodedStart < 0 || encodedEnd > len(volume) {
			t.Fatal("independent TEST ONLY capsule extent is out of bounds")
		}
		copy(decoded[lane*writerFixtureRS64Data:(lane+1)*writerFixtureRS64Data], volume[encodedStart:encodedEnd])
	}
	return decoded
}

func normalFixtureWriteKeys(t *testing.T, encoded normalFixtureKeys) normalWriteKeys {
	t.Helper()
	provider := newNormalFixtureCredentialProvider(t, encoded)
	defer provider.close()
	return normalWriteKeys{
		volumeKey:        provider.access.volumeKey,
		capsuleWrap:      provider.access.wrap,
		replicaMAC:       provider.access.replicaMAC,
		metadataMAC:      provider.metadataMAC,
		payloadXChaCha20: provider.payloadXChaCha,
		payloadSerpent:   provider.payloadSerpent,
		payloadMAC:       provider.payloadMAC,
	}
}
