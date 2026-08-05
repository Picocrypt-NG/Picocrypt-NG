package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

var errNormalFuzzWrite = errors.New("TEST ONLY normal fuzz write fault")

// Keep mutated payloads small enough for rapid fuzz iteration. This is a
// harness liveness bound, not a PCV3 format limit.
const (
	normalWriterFuzzInputLimit  = 64 << 10
	normalWriterFuzzRecordLimit = 1 << 20
	normalWriterFuzzTagLimit    = 64
)

type normalFuzzDestination struct {
	buffer     bytes.Buffer
	cancel     context.CancelFunc
	mode       uint8
	faultAt    int
	calls      int
	maxRequest int
	triggered  bool
}

func (destination *normalFuzzDestination) Write(source []byte) (int, error) {
	destination.calls++
	destination.maxRequest = max(destination.maxRequest, len(source))
	if destination.mode == 0 || destination.calls != destination.faultAt {
		return destination.buffer.Write(source)
	}

	destination.triggered = true
	switch destination.mode {
	case 1:
		count := max(0, len(source)-1)
		_, _ = destination.buffer.Write(source[:count])
		return count, nil
	case 2:
		return 0, errNormalFuzzWrite
	case 3:
		count, err := destination.buffer.Write(source)
		destination.cancel()
		return count, err
	default:
		panic("unreachable TEST ONLY normal fuzz writer mode")
	}
}

func FuzzSerializeNormalVolume(f *testing.F) {
	manifest := loadNormalFixtureManifest(f)
	var fixture normalFixture
	for _, candidate := range manifest.Fixtures {
		if candidate.ID == "normal-standard-password-only-small" {
			fixture = candidate
			break
		}
	}
	if fixture.ID == "" {
		f.Fatal("TEST ONLY writer fuzz fixture is unavailable")
	}
	frozenVolume := readNormalFixtureArtifact(f, fixture.Volume)
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		f.Fatalf("create TEST ONLY RS codecs: %v", err)
	}

	for _, seed := range []struct {
		plaintext       []byte
		options         uint8
		sourceMode      uint8
		destinationMode uint8
		faultAt         uint16
	}{
		{plaintext: nil},
		{plaintext: []byte("a")},
		{plaintext: []byte("paranoid-rs"), options: 0x03},
		{plaintext: []byte("comment"), options: 0x04},
		{plaintext: []byte("archive"), options: 0x18},
		{plaintext: []byte("shorter"), sourceMode: 1},
		{plaintext: []byte("longer"), sourceMode: 2},
		{plaintext: []byte("geometry"), sourceMode: 3},
		{plaintext: []byte("cancel-source"), sourceMode: 4},
		{plaintext: []byte("final-eof"), sourceMode: 5},
		{plaintext: []byte("short-write"), destinationMode: 1, faultAt: 4},
		{plaintext: []byte("write-error"), destinationMode: 2, faultAt: 5},
		{plaintext: []byte("cancel-write"), destinationMode: 3, faultAt: 6},
		{plaintext: []byte("invalid-comment"), options: 0x0c},
	} {
		f.Add(seed.plaintext, seed.options, seed.sourceMode, seed.destinationMode, seed.faultAt)
	}

	f.Fuzz(func(
		t *testing.T,
		plaintext []byte,
		options uint8,
		sourceMode uint8,
		destinationMode uint8,
		faultAt uint16,
	) {
		if len(plaintext) > normalWriterFuzzInputLimit {
			plaintext = plaintext[:normalWriterFuzzInputLimit]
		}
		plaintext = bytes.Clone(plaintext)
		request, material, _ := decodeNormalWriterFixtureInputs(t, fixture, frozenVolume)
		defer material.keys.close()
		configureNormalWriterFuzzRequest(&request, material, options)

		sourceBytes := plaintext
		sourceMode %= 6
		switch sourceMode {
		case 1:
			if len(sourceBytes) == 0 {
				sourceBytes = []byte{0xa5}
				request.plaintextLength = 0
			} else {
				request.plaintextLength = uint64(len(sourceBytes) - 1)
			}
		case 2:
			request.plaintextLength = uint64(len(sourceBytes)) + 1
		case 3:
			request.plaintextLength = ^uint64(0)
		default:
			request.plaintextLength = uint64(len(sourceBytes))
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var source io.Reader = bytes.NewReader(sourceBytes)
		if sourceMode == 4 {
			source = &normalCancelReader{reader: source, cancel: cancel}
		} else if sourceMode == 5 {
			source = &normalFinalEOFReader{data: sourceBytes}
		}
		sourceProbe := &normalIOProbe{reader: source}
		destination := &normalFuzzDestination{
			cancel:  cancel,
			mode:    destinationMode % 4,
			faultAt: int(faultAt%8) + 1,
		}
		entropy := make([]byte, 104)
		for index := range entropy {
			entropy[index] = byte(index*29 + 7)
		}

		completion, err := serializeNormalVolume(
			ctx,
			request,
			sourceProbe,
			destination,
			material,
			normalWriteSeams{entropy: bytes.NewReader(entropy), codecs: codecs},
		)
		if (completion != nil) != (err == nil) {
			t.Fatalf("serializer completion/error mismatch = %v/%v", completion != nil, err != nil)
		}
		if err != nil {
			var failure *normalWriteFailure
			if !errors.As(err, &failure) {
				t.Fatalf("serializer returned untyped failure %T", err)
			}
		}
		if material.borrowed != nil && !normalWriteKeysAreZero(material.borrowed) {
			t.Fatal("fuzzed serializer retained writer-owned key material")
		}
		if sourceProbe.maxRead > normalWriterFuzzRecordLimit {
			t.Fatalf("serializer source request = %d; exceeds one plaintext record", sourceProbe.maxRead)
		}
		if destination.maxRequest > normalWriterFuzzRecordLimit+normalWriterFuzzTagLimit {
			t.Fatalf("serializer destination request = %d; exceeds one semantic record", destination.maxRequest)
		}

		invalidComment := (options>>2)&3 == 3
		mustFail := invalidComment || sourceMode == 1 || sourceMode == 2 || sourceMode == 3 ||
			sourceMode == 4 || destination.triggered
		if mustFail && completion != nil {
			t.Fatal("invalid, interrupted, or faulted serialization minted completion")
		}
		if !mustFail && completion == nil {
			t.Fatalf("valid bounded serialization failed: %v", err)
		}
		if completion == nil {
			return
		}
		if sourceProbe.readBytes != len(sourceBytes) {
			t.Fatalf("successful serializer consumed %d bytes; want %d", sourceProbe.readBytes, len(sourceBytes))
		}
		volume := destination.buffer.Bytes()
		probeSource := &normalBorrowedSource{reader: bytes.NewReader(volume)}
		route, _, probeErr := Probe(probeSource, int64(len(volume)))
		if probeErr != nil || route != RouteNormalPCV {
			t.Fatalf("successful fuzz serialization is not a normal PCV: route %v, error %v", route, probeErr)
		}
	})
}

func configureNormalWriterFuzzRequest(
	request *normalWriteRequest,
	material *normalLiteralWriteMaterial,
	options uint8,
) {
	if options&1 != 0 {
		request.suite = SuiteParanoid
		material.metadata.suite = SuiteParanoid
		material.metadata.kdfProfile = KDFProfileParanoid
	} else {
		request.suite = SuiteStandard
		material.metadata.suite = SuiteStandard
		material.metadata.kdfProfile = KDFProfileNormal
	}
	request.payloadBodyRS = options&2 != 0
	if options&0x10 != 0 {
		request.payloadKind = PayloadKindArchive
	} else {
		request.payloadKind = PayloadKindRaw
	}
	switch (options >> 2) & 3 {
	case 0:
		request.comment = nil
	case 1:
		request.comment = []byte("TEST ONLY writer fuzz")
	case 2:
		request.comment = []byte("PCV3 안전")
	case 3:
		request.comment = []byte{0xff}
	}
}
