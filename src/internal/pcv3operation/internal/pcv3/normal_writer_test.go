package pcv3

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	pcencoding "Picocrypt-NG/internal/encoding"
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
	metadataFault error
	keyFault      error
}

func (material *normalLiteralWriteMaterial) credentialMetadata() (
	normalWriteCredentialMetadata,
	error,
) {
	material.metadataCalls++
	if material.metadataFault != nil {
		return normalWriteCredentialMetadata{}, material.metadataFault
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
	if ctx == nil || ctx.Err() != nil || destination == nil || suite != material.metadata.suite {
		return errors.New("TEST ONLY literal writer material rejected")
	}
	*destination = material.keys
	if material.keyFault != nil {
		return material.keyFault
	}
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

type normalShortWriter struct {
	written bytes.Buffer
	zero    bool
	calls   int
}

func (writer *normalShortWriter) Write(source []byte) (int, error) {
	writer.calls++
	count := len(source) - 1
	if writer.zero || count < 0 {
		count = 0
	}
	_, _ = writer.written.Write(source[:count])
	return count, nil
}

type normalFinalEOFReader struct {
	data  []byte
	done  bool
	calls int
}

func (reader *normalFinalEOFReader) Read(destination []byte) (int, error) {
	reader.calls++
	if reader.done {
		return 0, io.EOF
	}
	reader.done = true
	count := copy(destination, reader.data)
	return count, io.EOF
}

type normalCancelReader struct {
	reader io.Reader
	cancel context.CancelFunc
	calls  int
}

func (reader *normalCancelReader) Read(destination []byte) (int, error) {
	reader.calls++
	count, err := reader.reader.Read(destination)
	reader.cancel()
	return count, err
}

func (entropy *normalCountingEntropy) Read(destination []byte) (int, error) {
	entropy.calls++
	count, err := entropy.reader.Read(destination)
	entropy.bytes += count
	return count, err
}

func TestSerializeNormalVolumeIndependentBytes(t *testing.T) {
	testNormalWriterFixtures(t, []string{
		"normal-standard-password-only-small",
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

func TestSerializeNormalVolumeShortIO(t *testing.T) {
	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("create TEST ONLY RS codecs: %v", err)
	}

	run := func(
		t *testing.T,
		ctx context.Context,
		source io.Reader,
		destination io.Writer,
	) (*normalWriteCompletion, *normalLiteralWriteMaterial, error) {
		t.Helper()
		request, material, entropyBytes := decodeNormalWriterFixtureInputs(t, fixture, volume)
		t.Cleanup(material.keys.close)
		completion, err := serializeNormalVolume(
			ctx,
			request,
			source,
			destination,
			material,
			normalWriteSeams{
				entropy: bytes.NewReader(entropyBytes),
				codecs:  codecs,
			},
		)
		return completion, material, err
	}

	t.Run("early EOF cannot mint a complete volume", func(t *testing.T) {
		completion, material, err := run(t, context.Background(), bytes.NewReader(nil), io.Discard)
		assertNormalWriteFailure(t, completion, err, StageInputIO)
		if material.borrowed == nil || !normalWriteKeysAreZero(material.borrowed) {
			t.Fatal("early EOF retained writer-owned keys")
		}
	})

	t.Run("trailing source byte cannot be hidden after declared payload", func(t *testing.T) {
		source := append(append([]byte(nil), plaintext...), 0xa5)
		completion, material, err := run(t, context.Background(), bytes.NewReader(source), io.Discard)
		assertNormalWriteFailure(t, completion, err, StageInputIO)
		if material.borrowed == nil || !normalWriteKeysAreZero(material.borrowed) {
			t.Fatal("trailing source rejection retained writer-owned keys")
		}
	})

	t.Run("final data returned with EOF remains valid Reader behavior", func(t *testing.T) {
		source := &normalFinalEOFReader{data: plaintext}
		var destination bytes.Buffer
		completion, material, err := run(t, context.Background(), source, &destination)
		if err != nil || completion == nil {
			t.Fatalf("full final read with EOF = completion %v, error %v", completion != nil, err)
		}
		if source.calls != 2 || !bytes.Equal(destination.Bytes(), volume) {
			t.Fatalf("full+EOF traversal calls=%d exact-volume=%v; want two reads and frozen bytes", source.calls, bytes.Equal(destination.Bytes(), volume))
		}
		if material.borrowed == nil || !normalWriteKeysAreZero(material.borrowed) {
			t.Fatal("full+EOF success retained writer-owned keys")
		}
	})

	for _, test := range []struct {
		name string
		zero bool
	}{
		{name: "short nil-error write is a contract failure"},
		{name: "zero-progress write is a contract failure", zero: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			destination := &normalShortWriter{zero: test.zero}
			source := &normalIOProbe{reader: bytes.NewReader(plaintext)}
			completion, material, err := run(t, context.Background(), source, destination)
			assertNormalWriteFailure(t, completion, err, StageOutputWrite)
			if destination.calls != 1 || source.readCalls != 0 {
				t.Fatalf("short writer calls=%d source reads=%d; want rejection on first preamble write", destination.calls, source.readCalls)
			}
			if material.borrowed == nil || !normalWriteKeysAreZero(material.borrowed) {
				t.Fatal("short writer retained writer-owned keys")
			}
		})
	}

	t.Run("cancellation during source read stops before record body", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		source := &normalCancelReader{reader: bytes.NewReader(plaintext), cancel: cancel}
		var destination bytes.Buffer
		completion, material, err := run(t, ctx, source, &destination)
		assertNormalWriteFailure(t, completion, err, StageCancellation)
		if source.calls != 1 || destination.Len() != int(binary.BigEndian.Uint32(volume[12:16]))+48 {
			t.Fatalf("cancelled traversal source calls=%d bytes=%d; want header plus descriptor only", source.calls, destination.Len())
		}
		if material.borrowed == nil || !normalWriteKeysAreZero(material.borrowed) {
			t.Fatal("cancelled source retained writer-owned keys")
		}
	})
}

func TestSerializeNormalVolumePreEmissionFailures(t *testing.T) {
	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("create TEST ONLY RS codecs: %v", err)
	}

	t.Run("entropy truncation performs no key source or sink work", func(t *testing.T) {
		request, material, entropy := decodeNormalWriterFixtureInputs(t, fixture, volume)
		defer material.keys.close()
		source := &normalIOProbe{reader: bytes.NewReader([]byte{1})}
		sink := &normalIOProbe{}
		completion, err := serializeNormalVolume(
			context.Background(), request, source, sink, material,
			normalWriteSeams{entropy: bytes.NewReader(entropy[:len(entropy)-1]), codecs: codecs},
		)
		assertNormalWriteFailure(t, completion, err, StageRNG)
		if material.metadataCalls != 1 || material.keyCalls != 0 ||
			source.readCalls != 0 || sink.writeCalls != 0 {
			t.Fatalf("work after truncated entropy: metadata=%d keys=%d source=%d sink=%d", material.metadataCalls, material.keyCalls, source.readCalls, sink.writeCalls)
		}
	})

	t.Run("key copy failure clears partial owned bundle before output", func(t *testing.T) {
		request, material, entropy := decodeNormalWriterFixtureInputs(t, fixture, volume)
		defer material.keys.close()
		material.keyFault = errors.New("TEST ONLY key-copy fault")
		source := &normalIOProbe{reader: bytes.NewReader([]byte{1})}
		sink := &normalIOProbe{}
		completion, err := serializeNormalVolume(
			context.Background(), request, source, sink, material,
			normalWriteSeams{entropy: bytes.NewReader(entropy), codecs: codecs},
		)
		assertNormalWriteFailure(t, completion, err, StageCredentialPolicy)
		if material.metadataCalls != 1 || material.keyCalls != 1 || material.borrowed == nil ||
			!normalWriteKeysAreZero(material.borrowed) || source.readCalls != 0 || sink.writeCalls != 0 {
			t.Fatalf("key-copy closure: metadata=%d keys=%d zero=%v source=%d sink=%d", material.metadataCalls, material.keyCalls, normalWriteKeysAreZero(material.borrowed), source.readCalls, sink.writeCalls)
		}
	})

	t.Run("unrepresentable volume geometry fails before keys or output", func(t *testing.T) {
		request, material, entropy := decodeNormalWriterFixtureInputs(t, fixture, volume)
		defer material.keys.close()
		request.plaintextLength = ^uint64(0)
		source := &normalIOProbe{reader: bytes.NewReader(nil)}
		sink := &normalIOProbe{}
		completion, err := serializeNormalVolume(
			context.Background(), request, source, sink, material,
			normalWriteSeams{entropy: bytes.NewReader(entropy), codecs: codecs},
		)
		assertNormalWriteFailure(t, completion, err, StageTailGeometry)
		if material.keyCalls != 0 || source.readCalls != 0 || sink.writeCalls != 0 {
			t.Fatalf("overflow work: keys=%d source=%d sink=%d", material.keyCalls, source.readCalls, sink.writeCalls)
		}
	})
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
			if material.borrowed == nil || !normalWriteKeysAreZero(material.borrowed) {
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

func normalWriteKeysAreZero(keys *normalWriteKeys) bool {
	if keys == nil {
		return false
	}
	zero := normalWriteKeys{}
	return *keys == zero
}

func assertNormalWriteFailure(
	t *testing.T,
	completion *normalWriteCompletion,
	err error,
	wantStage Stage,
) {
	t.Helper()
	if completion != nil || err == nil {
		t.Fatalf("failed serializer = completion %v, error %v; want no completion and fixed failure", completion != nil, err)
	}
	var failure *normalWriteFailure
	if !errors.As(err, &failure) || failure.Stage() != wantStage {
		t.Fatalf("normal writer failure = %T stage %v; want %v", err, failure.Stage(), wantStage)
	}
}
