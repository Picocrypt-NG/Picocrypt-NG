package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"testing"
)

func TestD1WritePlanReusesCanonicalNormalGeometry(t *testing.T) {
	request := normalWriteRequest{
		suite:       SuiteStandard,
		payloadKind: PayloadKindRaw,
	}
	plan, err := planD1Write(request)
	if err != nil {
		t.Fatalf("plan empty D1 write: %v", err)
	}
	const wantNormalLength = int64(2232)
	const wantOuterPlaintextLength = uint64(2248)
	const wantOuterBodyLength = uint64(2312)
	const wantD1Length = uint64(2760)
	if plan.normal.geometry.fileSize != wantNormalLength ||
		plan.outer.plaintextLength != wantOuterPlaintextLength ||
		plan.outer.bodyLength != wantOuterBodyLength ||
		plan.fileSize != wantD1Length {
		t.Fatalf("empty D1 plan = %+v; want normal=%d plaintext=%d body=%d file=%d", plan, wantNormalLength, wantOuterPlaintextLength, wantOuterBodyLength, wantD1Length)
	}
	if direct, err := planNormalWrite(request); err != nil || direct != plan.normal {
		t.Fatalf("D1 normal plan diverged from serializer plan: direct=%+v err=%v D1=%+v", direct, err, plan.normal)
	}
}

func TestD1PureGeometryRejectsOverflowWithoutDependencies(t *testing.T) {
	request := normalWriteRequest{
		suite:           SuiteParanoid,
		payloadKind:     PayloadKindArchive,
		payloadBodyRS:   true,
		plaintextLength: math.MaxUint64,
	}
	if _, err := planD1Write(request); err == nil {
		t.Fatal("overflowing normal/D1 geometry was accepted")
	}
}

func TestD1WriterUsesCanonicalNormalSerializerSynchronously(t *testing.T) {
	request := normalWriteRequest{
		suite:       SuiteStandard,
		payloadKind: PayloadKindRaw,
	}
	material := newD1TestNormalMaterial()
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("create RS codecs: %v", err)
	}
	access, owner := newD1TestOuterAccess(t, 0x85)
	defer owner.Close()
	destination := &d1WriteProbe{}
	completion, err := writeD1NormalBody(
		context.Background(),
		request,
		bytes.NewReader(nil),
		destination,
		material,
		normalWriteSeams{
			entropy: bytes.NewReader(bytes.Repeat([]byte{0x96}, 128)),
			codecs:  codecs,
		},
		access,
	)
	if err != nil || completion == nil {
		t.Fatalf("write D1 normal body = completion %v, err %v", completion != nil, err)
	}
	if material.metadataCalls != 1 || material.keyCalls != 1 {
		t.Fatalf("normal serializer calls = metadata %d keys %d; want 1/1", material.metadataCalls, material.keyCalls)
	}
	if destination.maxWrite > d1OuterChunkSize {
		t.Fatalf("outer destination write = %d; want at most one chunk", destination.maxWrite)
	}

	reader, err := newD1InnerReader(
		context.Background(),
		bytes.NewReader(destination.Bytes()),
		0,
		uint64(destination.Len()),
		access,
	)
	if err != nil {
		t.Fatalf("authenticate emitted body: %v", err)
	}
	defer reader.Close()
	inner := make([]byte, reader.Size())
	if count, err := reader.ReadAt(inner, 0); err != nil || count != len(inner) {
		t.Fatalf("read emitted inner = %d, %v; want %d", count, err, len(inner))
	}
	plan, err := planNormalWrite(request)
	if err != nil || int64(len(inner)) != plan.geometry.fileSize {
		t.Fatalf("emitted normal length = %d, plan=%+v err=%v", len(inner), plan, err)
	}
	route, _, err := Probe(bytes.NewReader(inner), int64(len(inner)))
	if err != nil || route != RouteNormalPCV {
		t.Fatalf("emitted inner probe = route %v err %v; want canonical normal PCV", route, err)
	}
}

func TestD1WriterMandatoryFinalShortWriteAndCancellation(t *testing.T) {
	access, owner := newD1TestOuterAccess(t, 0x97)
	defer owner.Close()
	geometry, err := deriveD1OuterGeometry(d1OuterChunkSize - d1OuterPrefixLength)
	if err != nil {
		t.Fatalf("derive exact-full geometry: %v", err)
	}

	t.Run("mandatory final", func(t *testing.T) {
		codec, err := newD1OuterCodec(context.Background(), access)
		if err != nil {
			t.Fatalf("create codec: %v", err)
		}
		defer codec.Close()
		var destination bytes.Buffer
		writer, err := newD1OuterStreamWriter(context.Background(), &destination, codec, geometry)
		if err != nil {
			t.Fatalf("create writer: %v", err)
		}
		if _, err := writer.Write(make([]byte, geometry.plaintextLength)); err != nil {
			t.Fatalf("write exact-full plaintext: %v", err)
		}
		if err := writer.Finish(); err != nil {
			t.Fatalf("finish exact-full plaintext: %v", err)
		}
		if uint64(destination.Len()) != d1OuterChunkSize+2*d1OuterTagSize {
			t.Fatalf("exact-full encoded length = %d; mandatory final tag missing", destination.Len())
		}
	})

	t.Run("short write", func(t *testing.T) {
		codec, err := newD1OuterCodec(context.Background(), access)
		if err != nil {
			t.Fatalf("create codec: %v", err)
		}
		defer codec.Close()
		destination := &d1ShortWriter{}
		writer, err := newD1OuterStreamWriter(context.Background(), destination, codec, geometry)
		if err != nil {
			t.Fatalf("create writer: %v", err)
		}
		if _, err := writer.Write(make([]byte, geometry.plaintextLength)); err == nil || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short destination write = %v; want io.ErrShortWrite", err)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		codec, err := newD1OuterCodec(context.Background(), access)
		if err != nil {
			t.Fatalf("create codec: %v", err)
		}
		defer codec.Close()
		var destination bytes.Buffer
		writer, err := newD1OuterStreamWriter(ctx, &destination, codec, geometry)
		if err != nil {
			t.Fatalf("create writer: %v", err)
		}
		if _, err := writer.Write([]byte{1}); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled write = %v; want context.Canceled", err)
		}
		if destination.Len() != 0 {
			t.Fatalf("cancelled writer emitted %d bytes", destination.Len())
		}
	})
}

type d1WriteProbe struct {
	bytes.Buffer
	maxWrite int
}

func (probe *d1WriteProbe) Write(source []byte) (int, error) {
	probe.maxWrite = max(probe.maxWrite, len(source))
	return probe.Buffer.Write(source)
}

type d1ShortWriter struct{}

func (*d1ShortWriter) Write(source []byte) (int, error) {
	return max(0, len(source)-1), nil
}

func newD1TestNormalMaterial() *normalLiteralWriteMaterial {
	material := &normalLiteralWriteMaterial{
		metadata: normalWriteCredentialMetadata{
			suite:          SuiteStandard,
			credentialMode: CredentialModePassword,
			keyfileMode:    KeyfileModeNone,
			kdfProfile:     KDFProfileNormal,
		},
	}
	for index := range material.metadata.argonSalt {
		material.metadata.argonSalt[index] = byte(index + 1)
	}
	for index := range material.metadata.volumeID {
		material.metadata.volumeID[index] = byte(index + 33)
	}
	fillD1TestNormalKeys(&material.keys, 0x31)
	return material
}

func fillD1TestNormalKeys(keys *normalWriteKeys, seed byte) {
	fill := func(destination []byte, value byte) {
		for index := range destination {
			destination[index] = value + byte(index)
		}
	}
	fill(keys.volumeKey[:], seed)
	for role := range keys.capsuleWrap {
		fill(keys.capsuleWrap[role].xChaCha20[:], seed+byte(role)+1)
		fill(keys.capsuleWrap[role].serpent[:], seed+byte(role)+3)
		fill(keys.capsuleWrap[role].mac[:], seed+byte(role)+5)
		fill(keys.replicaMAC[role][:], seed+byte(role)+7)
	}
	fill(keys.metadataMAC[:], seed+9)
	fill(keys.payloadXChaCha20[:], seed+10)
	fill(keys.payloadSerpent[:], seed+11)
	fill(keys.payloadMAC[:], seed+12)
}
