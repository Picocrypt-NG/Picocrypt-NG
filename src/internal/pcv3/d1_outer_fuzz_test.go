package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const d1FuzzInputLimit = 64 << 10

var errD1FuzzReadBound = errors.New("TEST ONLY D1 fuzz read bound")

type d1ReaderFuzzMode uint8

const (
	d1ReaderFuzzRecordTamper d1ReaderFuzzMode = iota
	d1ReaderFuzzFinalTamper
	d1ReaderFuzzTruncation
	d1ReaderFuzzLengthArithmetic
	d1ReaderFuzzShortRead
	d1ReaderFuzzCancellation
)

type d1WriterFuzzMode uint8

const (
	d1WriterFuzzFraming d1WriterFuzzMode = iota
	d1WriterFuzzShortWrite
	d1WriterFuzzCancellation
)

type d1ReaderFuzzSeed struct {
	name      string
	risk      string
	oracle    string
	payload   []byte
	mode      d1ReaderFuzzMode
	parameter uint64
}

var d1ReaderFuzzSeeds = []d1ReaderFuzzSeed{
	{
		name:    "record tamper",
		risk:    "tampered outer ciphertext reaches record authentication",
		oracle:  "the reader returns no inner ReaderAt capability",
		payload: []byte("public synthetic D1 record-tamper seed"),
		mode:    d1ReaderFuzzRecordTamper,
	},
	{
		name:    "final tamper",
		risk:    "tampered mandatory-final tag reaches final authentication",
		oracle:  "the reader returns no inner ReaderAt capability",
		payload: []byte("public synthetic D1 final-tamper seed"),
		mode:    d1ReaderFuzzFinalTamper,
	},
	{
		name:    "truncation",
		risk:    "a truncated authenticated body is read under its declared geometry",
		oracle:  "the reader returns no inner ReaderAt capability",
		payload: []byte("public synthetic D1 truncation seed"),
		mode:    d1ReaderFuzzTruncation,
	},
	{
		name:      "length arithmetic",
		risk:      "hostile outer body length reaches the canonical geometry parser",
		oracle:    "the parser returns no inner ReaderAt capability",
		payload:   []byte("public synthetic D1 length seed"),
		mode:      d1ReaderFuzzLengthArithmetic,
		parameter: ^uint64(0),
	},
	{
		name:    "short read",
		risk:    "a bounded ReaderAt returns an incomplete semantic record",
		oracle:  "the reader returns no inner ReaderAt capability",
		payload: []byte("public synthetic D1 short-read seed"),
		mode:    d1ReaderFuzzShortRead,
	},
	{
		name:    "cancellation",
		risk:    "cancellation races authenticated outer admission",
		oracle:  "the reader returns no inner ReaderAt capability with cancellation",
		payload: []byte("public synthetic D1 cancellation seed"),
		mode:    d1ReaderFuzzCancellation,
	},
}

type d1WriterFuzzSeed struct {
	name    string
	risk    string
	oracle  string
	payload []byte
	mode    d1WriterFuzzMode
}

var d1WriterFuzzSeeds = []d1WriterFuzzSeed{
	{
		name:    "framing",
		risk:    "declared inner framing exceeds the available source",
		oracle:  "no completion, destination, stage, or clear-inner artifact is published",
		payload: []byte("public synthetic D1 framing seed"),
		mode:    d1WriterFuzzFraming,
	},
	{
		name:    "short write",
		risk:    "the outer writer receives a short semantic write",
		oracle:  "no completion, destination, stage, or clear-inner artifact is published",
		payload: []byte("public synthetic D1 short-write seed"),
		mode:    d1WriterFuzzShortWrite,
	},
	{
		name:    "cancellation",
		risk:    "cancellation interrupts the outer writer and live composer stage",
		oracle:  "no completion, destination, stage, or clear-inner artifact is published",
		payload: []byte("public synthetic D1 writer-cancellation seed"),
		mode:    d1WriterFuzzCancellation,
	},
}

// FuzzReadD1Volume explores robustness at the production geometry parser and
// authenticated bounded ReaderAt. No-panic fuzzing is not vector conformance;
// TestD1FuzzSeedsReachProductionSeams owns the named behavioral seed oracles.
func FuzzReadD1Volume(f *testing.F) {
	for _, seed := range d1ReaderFuzzSeeds {
		f.Add(bytes.Clone(seed.payload), uint8(seed.mode), seed.parameter)
	}

	f.Fuzz(func(t *testing.T, payload []byte, mode uint8, parameter uint64) {
		runD1ReaderFuzzCase(
			t,
			boundedD1FuzzPayload(payload),
			d1ReaderFuzzMode(mode%uint8(d1ReaderFuzzCancellation+1)),
			parameter,
			"mutated D1 outer reader input",
			"no inner ReaderAt capability",
			false,
		)
	})
}

// FuzzWriteD1Volume explores robustness at the canonical normal serializer,
// outer stream writer, and real-stage composer. The deterministic seed test,
// not a no-panic fuzz iteration, owns the publication and residue oracles.
func FuzzWriteD1Volume(f *testing.F) {
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		f.Fatal("create TEST ONLY D1 fuzz codecs")
	}
	for _, seed := range d1WriterFuzzSeeds {
		f.Add(bytes.Clone(seed.payload), uint8(seed.mode))
	}

	f.Fuzz(func(t *testing.T, payload []byte, mode uint8) {
		runD1WriterFuzzCase(
			t,
			boundedD1FuzzPayload(payload),
			d1WriterFuzzMode(mode%uint8(d1WriterFuzzCancellation+1)),
			"mutated D1 outer writer input",
			"no completion or published filesystem artifact",
			codecs,
		)
	})
}

func TestD1FuzzSeedsReachProductionSeams(t *testing.T) {
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatal("create TEST ONLY D1 seed codecs")
	}

	t.Run("reader", func(t *testing.T) {
		for _, seed := range d1ReaderFuzzSeeds {
			t.Run(seed.name, func(t *testing.T) {
				runD1ReaderFuzzCase(t, seed.payload, seed.mode, seed.parameter, seed.risk, seed.oracle, true)
			})
		}
	})

	t.Run("writer", func(t *testing.T) {
		for _, seed := range d1WriterFuzzSeeds {
			t.Run(seed.name, func(t *testing.T) {
				runD1WriterFuzzCase(t, seed.payload, seed.mode, seed.risk, seed.oracle, codecs)
			})
		}
	})
}

type d1FuzzReaderAt struct {
	reader     *bytes.Reader
	callLimit  int
	maxRequest int
	calls      int
	shortRead  bool
	faulted    bool
	violation  bool
}

func (source *d1FuzzReaderAt) ReadAt(destination []byte, offset int64) (int, error) {
	source.calls++
	if source.calls > source.callLimit || offset < 0 || len(destination) > source.maxRequest {
		source.violation = true
		return 0, errD1FuzzReadBound
	}
	if source.shortRead && !source.faulted {
		source.faulted = true
		count := len(destination) / 2
		if count == 0 {
			return 0, io.ErrUnexpectedEOF
		}
		read, _ := source.reader.ReadAt(destination[:count], offset)
		return read, io.ErrUnexpectedEOF
	}
	return source.reader.ReadAt(destination, offset)
}

func (source *d1FuzzReaderAt) assertBounded(t *testing.T, risk, oracle string) {
	t.Helper()
	if source.violation {
		t.Fatalf("%s: production reader exceeded the bounded ReaderAt; oracle: %s", risk, oracle)
	}
}

func newD1FuzzReaderAt(source []byte, shortRead bool) *d1FuzzReaderAt {
	return &d1FuzzReaderAt{
		reader:     bytes.NewReader(source),
		callLimit:  8,
		maxRequest: d1OuterChunkSize,
		shortRead:  shortRead,
	}
}

func runD1ReaderFuzzCase(
	t *testing.T,
	payload []byte,
	mode d1ReaderFuzzMode,
	parameter uint64,
	risk string,
	oracle string,
	verifyBaseline bool,
) {
	t.Helper()
	access, owner := newD1TestOuterAccess(t, 0x4d)
	defer owner.Close()
	inner := d1FuzzReaderInner(payload, mode)
	body := encodeD1TestBody(t, access, inner)
	if mode == d1ReaderFuzzRecordTamper {
		const wantInnerLength = d1OuterChunkSize - d1OuterPrefixLength + 1
		const wantBodyLength = d1OuterChunkSize + d1OuterTagSize + 1 + d1OuterTagSize
		if len(inner) != wantInnerLength || len(body) != wantBodyLength {
			t.Fatalf("%s: record-tamper seed lacks one non-final and one final record; oracle: %s", risk, oracle)
		}
	}

	if verifyBaseline {
		baselineSource := newD1FuzzReaderAt(body, false)
		baseline, err := newD1InnerReader(context.Background(), baselineSource, uint64(len(body)), access)
		baselineSource.assertBounded(t, risk, oracle)
		if err != nil || baseline == nil {
			t.Fatalf("%s: synthetic authenticated precondition failed; oracle: %s", risk, oracle)
		}
		baseline.Close()
	}

	ctx := context.Background()
	sourceBytes := bytes.Clone(body)
	bodyLength := uint64(len(body))
	shortRead := false
	switch mode {
	case d1ReaderFuzzRecordTamper:
		sourceBytes[0] ^= 0x80
	case d1ReaderFuzzFinalTamper:
		sourceBytes[len(sourceBytes)-1] ^= 0x80
	case d1ReaderFuzzTruncation:
		sourceBytes = sourceBytes[:len(sourceBytes)-1]
	case d1ReaderFuzzLengthArithmetic:
		bodyLength = ^uint64(0) - parameter%1024
	case d1ReaderFuzzShortRead:
		shortRead = true
	case d1ReaderFuzzCancellation:
		cancelled, cancel := context.WithCancel(context.Background())
		cancel()
		ctx = cancelled
	default:
		t.Fatalf("%s: invalid reader fuzz mode; oracle: %s", risk, oracle)
	}

	source := newD1FuzzReaderAt(sourceBytes, shortRead)
	reader, err := newD1InnerReader(ctx, source, bodyLength, access)
	source.assertBounded(t, risk, oracle)
	if reader != nil {
		reader.Close()
		t.Fatalf("%s: damaged input minted an inner ReaderAt capability; oracle: %s", risk, oracle)
	}
	if err == nil {
		t.Fatalf("%s: damaged input returned no typed failure; oracle: %s", risk, oracle)
	}
	switch mode {
	case d1ReaderFuzzRecordTamper, d1ReaderFuzzFinalTamper, d1ReaderFuzzTruncation:
		requireD1FuzzOuterFailure(t, err, StageD1Body, errD1OuterAuthentication, risk, oracle)
	case d1ReaderFuzzLengthArithmetic:
		requireD1FuzzOuterFailure(t, err, StageD1Body, errInvalidD1OuterGeometry, risk, oracle)
	case d1ReaderFuzzShortRead:
		if !source.faulted {
			t.Fatalf("%s: short-read seam was not reached; oracle: %s", risk, oracle)
		}
		requireD1FuzzOuterFailure(t, err, StageD1Body, errD1OuterAuthentication, risk, oracle)
	case d1ReaderFuzzCancellation:
		requireD1FuzzOuterFailure(t, err, StageCancellation, context.Canceled, risk, oracle)
	}
}

func d1FuzzReaderInner(payload []byte, mode d1ReaderFuzzMode) []byte {
	if mode != d1ReaderFuzzRecordTamper {
		return payload
	}
	inner := make([]byte, d1OuterChunkSize-d1OuterPrefixLength+1)
	for offset := 0; offset < len(inner); {
		offset += copy(inner[offset:], payload)
	}
	return inner
}

type d1FuzzDestination struct {
	bytes.Buffer
	mode      d1WriterFuzzMode
	cancel    context.CancelFunc
	triggered bool
}

func (destination *d1FuzzDestination) Write(source []byte) (int, error) {
	switch destination.mode {
	case d1WriterFuzzShortWrite:
		destination.triggered = true
		count := max(0, len(source)-1)
		_, _ = destination.Buffer.Write(source[:count])
		return count, nil
	case d1WriterFuzzCancellation:
		destination.triggered = true
		count, err := destination.Buffer.Write(source)
		destination.cancel()
		return count, err
	default:
		return destination.Buffer.Write(source)
	}
}

func runD1WriterFuzzCase(
	t *testing.T,
	payload []byte,
	mode d1WriterFuzzMode,
	risk string,
	oracle string,
	codecs *pcencoding.RSCodecs,
) {
	t.Helper()
	request := normalWriteRequest{
		suite:           SuiteParanoid,
		payloadKind:     PayloadKindRaw,
		plaintextLength: uint64(len(payload)),
	}
	if mode == d1WriterFuzzFraming {
		request.plaintextLength++
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	destination := &d1FuzzDestination{mode: mode, cancel: cancel}
	material := newD1TestNormalMaterial()
	material.metadata.suite = SuiteParanoid
	material.metadata.kdfProfile = KDFProfileParanoid
	defer material.keys.close()
	access, owner := newD1TestOuterAccess(t, 0x5e)
	defer owner.Close()
	entropy := make([]byte, 104)
	for index := range entropy {
		entropy[index] = byte(index*31 + 9)
	}

	completion, err := writeD1NormalBody(
		ctx,
		request,
		bytes.NewReader(payload),
		destination,
		material,
		normalWriteSeams{entropy: bytes.NewReader(entropy), codecs: codecs},
		access,
	)
	if completion != nil || err == nil {
		t.Fatalf("%s: faulted serializer minted completion; oracle: %s", risk, oracle)
	}
	if mode != d1WriterFuzzFraming && !destination.triggered {
		t.Fatalf("%s: configured outer-writer fault was not reached; oracle: %s", risk, oracle)
	}
	switch mode {
	case d1WriterFuzzFraming:
		requireNormalFuzzWriteFailure(t, err, StageInputIO, errNormalWriteSourceLength, risk, oracle)
	case d1WriterFuzzShortWrite:
		requireD1FuzzOuterFailure(t, err, StageOutputWrite, io.ErrShortWrite, risk, oracle)
	case d1WriterFuzzCancellation:
		requireD1FuzzOuterFailure(t, err, StageCancellation, context.Canceled, risk, oracle)
	}

	runD1FuzzComposerFailure(t, payload, mode, risk, oracle)
}

func runD1FuzzComposerFailure(
	t *testing.T,
	payload []byte,
	mode d1WriterFuzzMode,
	risk string,
	oracle string,
) {
	t.Helper()
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.bin")
	destinationPath := filepath.Join(directory, "destination.pcv")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatal("create TEST ONLY public D1 fuzz source")
	}
	request := &d1CreationRequest{
		route: d1RouteRequest{
			mode:            d1RouteExplicit,
			sourcePath:      sourcePath,
			destinationPath: destinationPath,
		},
		normal: normalWriteRequest{
			suite:           SuiteParanoid,
			payloadKind:     PayloadKindRaw,
			plaintextLength: uint64(len(payload)),
		},
		factors:  &pcv3credential.FactorRequest{},
		admitter: d1CreationTestAdmitter{},
	}
	fixture := &d1CreationTestFixture{
		directory:       directory,
		sourcePath:      sourcePath,
		destinationPath: destinationPath,
		sourceBytes:     bytes.Clone(payload),
		request:         request,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stageObserved := false
	cancellationFaulted := false
	shortWriteFaulted := false
	seams := newD1LiteralStageIntegrationSeams(t, func(
		boundary d1CreationBoundary,
		stage *pcv3publication.Stage,
	) error {
		stagePath := requireD1LiveStage(t, fixture, stage)
		requireD1FuzzOnlyLiveStage(t, directory, sourcePath, stagePath, risk, oracle)
		stageObserved = true
		if mode == d1WriterFuzzCancellation && boundary == d1BoundaryBody {
			cancellationFaulted = true
			cancel()
		}
		return nil
	})
	switch mode {
	case d1WriterFuzzFraming:
		request.normal.plaintextLength++
	case d1WriterFuzzShortWrite:
		seams.flush = func(*bufio.Writer) error {
			shortWriteFaulted = true
			return io.ErrShortWrite
		}
	case d1WriterFuzzCancellation:
	default:
		t.Fatalf("%s: invalid writer fuzz mode; oracle: %s", risk, oracle)
	}

	result, err := composeD1OuterStage(ctx, request, seams)
	if result != nil || err == nil {
		t.Fatalf("%s: faulted composer published a result; oracle: %s", risk, oracle)
	}
	if !stageObserved {
		t.Fatalf("%s: composer fault occurred before the live stage seam; oracle: %s", risk, oracle)
	}
	switch mode {
	case d1WriterFuzzFraming:
		requireD1FuzzOuterFailure(t, err, StageInputIO, errInvalidD1Creation, risk, oracle)
	case d1WriterFuzzShortWrite:
		if !shortWriteFaulted {
			t.Fatalf("%s: composer short-write seam was not reached; oracle: %s", risk, oracle)
		}
		requireD1FuzzOuterFailure(t, err, StageOutputWrite, io.ErrShortWrite, risk, oracle)
	case d1WriterFuzzCancellation:
		if !cancellationFaulted {
			t.Fatalf("%s: composer cancellation seam was not reached; oracle: %s", risk, oracle)
		}
		requireD1FuzzOuterFailure(t, err, StageCancellation, context.Canceled, risk, oracle)
	}
	if _, err := os.Lstat(destinationPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s: destination exists after failed composition; oracle: %s", risk, oracle)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal("list TEST ONLY D1 fuzz directory")
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(sourcePath) {
		t.Fatalf("%s: failed composition retained a stage or clear-inner artifact; oracle: %s", risk, oracle)
	}
	retained, err := os.ReadFile(sourcePath)
	if err != nil || !bytes.Equal(retained, payload) {
		t.Fatalf("%s: failed composition changed its source; oracle: %s", risk, oracle)
	}
}

func requireD1FuzzOnlyLiveStage(
	t *testing.T,
	directory string,
	sourcePath string,
	stagePath string,
	risk string,
	oracle string,
) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal("list TEST ONLY live D1 fuzz stage directory")
	}
	sourceName := filepath.Base(sourcePath)
	stageName := filepath.Base(stagePath)
	if len(entries) != 2 {
		t.Fatalf("%s: live composer has a second stage or clear-inner file; oracle: %s", risk, oracle)
	}
	for _, entry := range entries {
		if entry.Name() != sourceName && entry.Name() != stageName {
			t.Fatalf("%s: live composer has a second stage or clear-inner file; oracle: %s", risk, oracle)
		}
	}
}

func requireD1FuzzOuterFailure(
	t *testing.T,
	err error,
	wantStage Stage,
	wantCause error,
	risk string,
	oracle string,
) {
	t.Helper()
	var failure *d1OuterFailure
	if !errors.As(err, &failure) || failure.Stage() != wantStage || !errors.Is(err, wantCause) {
		t.Fatalf("%s: wrong D1 failure type, stage, or cause; oracle: %s", risk, oracle)
	}
}

func requireNormalFuzzWriteFailure(
	t *testing.T,
	err error,
	wantStage Stage,
	wantCause error,
	risk string,
	oracle string,
) {
	t.Helper()
	var failure *normalWriteFailure
	if !errors.As(err, &failure) || failure.Stage() != wantStage || !errors.Is(err, wantCause) {
		t.Fatalf("%s: wrong normal-writer failure type, stage, or cause; oracle: %s", risk, oracle)
	}
}

func boundedD1FuzzPayload(payload []byte) []byte {
	if len(payload) == 0 {
		return []byte{0}
	}
	if len(payload) > d1FuzzInputLimit {
		payload = payload[:d1FuzzInputLimit]
	}
	return bytes.Clone(payload)
}
