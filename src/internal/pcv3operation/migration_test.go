package pcv3operation

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3governance"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

var (
	errMigrationTestProducer = errors.New("migration test: final legacy authentication failed")
	errMigrationTestConsumer = errors.New("migration test: canonical writer failed")
)

type migrationObservedReader struct {
	reader     *bytes.Reader
	readCalls  int
	closeCalls int
}

func (reader *migrationObservedReader) Read(destination []byte) (int, error) {
	reader.readCalls++
	return reader.reader.Read(destination)
}

func (reader *migrationObservedReader) Close() error {
	reader.closeCalls++
	return nil
}

type migrationStreamProbe struct {
	payload         []byte
	mode            volume.LegacyDecodeMode
	streamErr       error
	panicAfterWrite bool
	streamCalls     int
	modeCalls       int
	exited          bool
}

func (source *migrationStreamProbe) Len() int64 { return int64(len(source.payload)) }

func (source *migrationStreamProbe) DecodeMode() volume.LegacyDecodeMode {
	source.modeCalls++
	return source.mode
}

func (source *migrationStreamProbe) StreamTo(destination io.Writer) error {
	source.streamCalls++
	defer func() { source.exited = true }()
	if _, err := destination.Write(source.payload); err != nil {
		return err
	}
	if source.panicAfterWrite {
		panic("migration test: producer panic")
	}
	return source.streamErr
}

func (source *migrationStreamProbe) Close() error { return nil }

type migrationDerivationPhaseSource struct {
	payload []byte
	started chan struct{}
	allow   chan struct{}
	phase   atomic.Uint32
	exited  bool
}

func (source *migrationDerivationPhaseSource) Len() int64 {
	return int64(len(source.payload))
}

func (*migrationDerivationPhaseSource) DecodeMode() volume.LegacyDecodeMode {
	return volume.LegacyDecodePlain
}

func (source *migrationDerivationPhaseSource) StreamTo(destination io.Writer) error {
	defer func() { source.exited = true }()
	source.phase.Store(1)
	close(source.started)
	<-source.allow
	source.phase.Store(2)
	_, err := destination.Write(source.payload)
	return err
}

func (*migrationDerivationPhaseSource) Close() error { return nil }

type migrationAdmitterProbe struct {
	calls int
}

func (probe *migrationAdmitterProbe) AdmitKDF(
	context.Context,
	pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	probe.calls++
	return pcv3credential.KDFAdmissionDenied, nil
}

func TestMigrationWriterDisabledBeforeEveryEffect(t *testing.T) {
	root := t.TempDir()
	sourcePath := filepath.Join(root, "legacy.pcv")
	sourceBytes := []byte("frozen legacy ciphertext")
	if err := os.WriteFile(sourcePath, sourceBytes, 0o600); err != nil {
		t.Fatalf("seed legacy source: %v", err)
	}
	prepared, err := volume.PrepareDecryptInput(sourcePath, false)
	if err != nil {
		t.Fatalf("prepare routed legacy descriptor: %v", err)
	}
	codecs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("create legacy codecs: %v", err)
	}
	oldPassword := []byte("old credential")
	newPassword := []byte("new credential")
	keyfile := &migrationObservedReader{reader: bytes.NewReader([]byte("new keyfile"))}
	reporterCalls := 0
	request := &Request{
		Mode:   ModeMigrate,
		Target: filepath.Join(root, "migrated.pcv"),
		Reporter: func(Status) error {
			reporterCalls++
			return nil
		},
		Migration: &MigrationRequest{
			Prepared: prepared,
			Legacy: &volume.DecryptRequest{
				InputFile: sourcePath,
				Password:  oldPassword,
				RSCodecs:  codecs,
			},
			NewFactors: &pcv3credential.FactorRequest{
				Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
				KeyfileMode:    pcv3credential.KeyfileModeOrdered,
				ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
				Password:       newPassword,
				Keyfiles: []*pcv3credential.KeyfileReader{
					pcv3credential.OwnKeyfileReader(keyfile),
				},
			},
			Suite:       pcv3.SuiteStandard,
			PayloadKind: pcv3.PayloadKindRaw,
		},
	}

	result := Run(context.Background(), request)

	if result == nil || result.Outcome() != pcv3.OutcomeUnsupportedRoutingPreKDF ||
		result.Stage() != pcv3.StageRouting || result.Diagnostic() != DiagnosticGovernanceRefusal ||
		result.PublicationAttempted() {
		t.Fatalf("migration refusal = %#v; want governance refusal before publication", result)
	}
	if reporterCalls != 0 || keyfile.readCalls != 0 {
		t.Fatalf("disabled migration effects: reporter=%d keyfile reads=%d; want zero", reporterCalls, keyfile.readCalls)
	}
	if keyfile.closeCalls != 1 {
		t.Fatalf("transferred new keyfile close calls = %d; want one cleanup", keyfile.closeCalls)
	}
	assertMigrationZero(t, oldPassword)
	assertMigrationZero(t, newPassword)
	gotSource, err := os.ReadFile(sourcePath)
	if err != nil || !bytes.Equal(gotSource, sourceBytes) {
		t.Fatalf("disabled migration changed legacy source: bytes=%q err=%v", gotSource, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "migrated.pcv")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disabled migration destination exists or is indeterminate: %v", err)
	}
	if request.Mode != 0 || request.Migration != nil || request.Target != "" || request.Reporter != nil {
		t.Fatalf("migration request retained transferred fields: %#v", request)
	}

	adapterPassword := []byte("adapter credential")
	adapterKeyfile := &migrationObservedReader{reader: bytes.NewReader([]byte("adapter keyfile"))}
	adapterSource := &migrationObservedReader{reader: bytes.NewReader([]byte("adapter plaintext"))}
	adapterFactors := &pcv3credential.FactorRequest{
		Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
		KeyfileMode:    pcv3credential.KeyfileModeOrdered,
		ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
		Password:       adapterPassword,
		Keyfiles: []*pcv3credential.KeyfileReader{
			pcv3credential.OwnKeyfileReader(adapterKeyfile),
		},
	}
	defer adapterFactors.Close()
	admitter := &migrationAdmitterProbe{}
	var destination bytes.Buffer
	adapterRequest := &pcv3.NativeNormalWriteRequest{
		Suite:           pcv3.SuiteStandard,
		PayloadKind:     pcv3.PayloadKindRaw,
		PlaintextLength: uint64(adapterSource.reader.Len()),
		Comment:         []byte("public comment"),
		Factors:         adapterFactors,
		Admitter:        admitter,
		Source:          adapterSource,
		Destination:     &destination,
	}
	err = pcv3.RunNativeNormalWrite(context.Background(), nil, adapterRequest)
	var refusal *pcv3governance.RefusalError
	if !errors.As(err, &refusal) || refusal.Reason != pcv3governance.ReasonAuthorizationMissing {
		t.Fatalf("native writer refusal = %v; want missing-authorization refusal", err)
	}
	if adapterKeyfile.readCalls != 0 || adapterSource.readCalls != 0 ||
		admitter.calls != 0 || destination.Len() != 0 {
		t.Fatalf(
			"native writer effects: keyfile reads=%d source reads=%d admissions=%d output=%d; want zero",
			adapterKeyfile.readCalls,
			adapterSource.readCalls,
			admitter.calls,
			destination.Len(),
		)
	}
	if adapterRequest.Suite != pcv3.SuiteStandard ||
		adapterRequest.PayloadKind != pcv3.PayloadKindRaw ||
		adapterRequest.PlaintextLength != uint64(len("adapter plaintext")) ||
		!bytes.Equal(adapterRequest.Comment, []byte("public comment")) ||
		adapterRequest.Factors != adapterFactors || adapterRequest.Admitter != admitter ||
		adapterRequest.Source != adapterSource || adapterRequest.Destination != &destination {
		t.Fatal("native writer mutated the borrowed request before authorization")
	}
	if err := adapterFactors.Close(); err != nil {
		t.Fatalf("close untransferred adapter factors: %v", err)
	}
	assertMigrationZero(t, adapterPassword)
	if adapterKeyfile.closeCalls != 1 {
		t.Fatalf("untransferred adapter keyfile close calls = %d; want one", adapterKeyfile.closeCalls)
	}
}

func TestMigrationPinsDecodeModeAndJoinsEveryPipeExit(t *testing.T) {
	payload := bytes.Repeat([]byte("authenticated legacy payload"), 4096)
	tests := []struct {
		name          string
		ctx           func() (context.Context, context.CancelFunc)
		producer      error
		panicProducer bool
		consume       migrationConsumer
		want          error
		wantMode      volume.LegacyDecodeMode
	}{
		{
			name: "success joins after the final legacy MAC pass",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			consume: func(_ context.Context, source io.Reader, length int64, mode volume.LegacyDecodeMode, _ pcv3.PayloadKind) error {
				got, err := io.ReadAll(source)
				if err != nil {
					return err
				}
				if int64(len(got)) != length || !bytes.Equal(got, payload) || mode != volume.LegacyDecodeRSFull {
					return errMigrationTestConsumer
				}
				return nil
			},
			wantMode: volume.LegacyDecodeRSFull,
		},
		{
			name:     "final authentication failure outranks consumer observation",
			ctx:      func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			producer: errMigrationTestProducer,
			consume: func(_ context.Context, source io.Reader, _ int64, _ volume.LegacyDecodeMode, _ pcv3.PayloadKind) error {
				_, _ = io.Copy(io.Discard, source)
				return errMigrationTestConsumer
			},
			want:     errMigrationTestProducer,
			wantMode: volume.LegacyDecodeRSFull,
		},
		{
			name: "consumer failure closes both pipe ends and joins producer",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			consume: func(_ context.Context, source io.Reader, _ int64, _ volume.LegacyDecodeMode, _ pcv3.PayloadKind) error {
				var first [1]byte
				_, _ = io.ReadFull(source, first[:])
				return errMigrationTestConsumer
			},
			want:     errMigrationTestConsumer,
			wantMode: volume.LegacyDecodeRSFull,
		},
		{
			name:          "producer panic is contained classified and joined",
			ctx:           func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			panicProducer: true,
			consume: func(_ context.Context, source io.Reader, _ int64, _ volume.LegacyDecodeMode, _ pcv3.PayloadKind) error {
				_, _ = io.Copy(io.Discard, source)
				return nil
			},
			want:     errMigrationProducerPanicked,
			wantMode: volume.LegacyDecodeRSFull,
		},
		{
			name: "consumer panic is contained and producer is joined",
			ctx:  func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
			consume: func(_ context.Context, source io.Reader, _ int64, _ volume.LegacyDecodeMode, _ pcv3.PayloadKind) error {
				var first [1]byte
				_, _ = io.ReadFull(source, first[:])
				panic("migration test: consumer panic")
			},
			want:     errMigrationConsumerPanicked,
			wantMode: volume.LegacyDecodeRSFull,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := test.ctx()
			defer cancel()
			source := &migrationStreamProbe{
				payload:         payload,
				mode:            test.wantMode,
				streamErr:       test.producer,
				panicAfterWrite: test.panicProducer,
			}
			err := streamVerifiedMigration(ctx, source, pcv3.PayloadKindRaw, test.consume)
			if !errors.Is(err, test.want) || (test.want == nil && err != nil) {
				t.Fatalf("stream result = %v; want %v", err, test.want)
			}
			if source.streamCalls != 1 || source.modeCalls != 1 || !source.exited {
				t.Fatalf("joined stream lifecycle = streams %d modes %d exited %v; want 1/1/true", source.streamCalls, source.modeCalls, source.exited)
			}
		})
	}

	t.Run("context cancellation closes both pipe ends and joins producer", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		source := &migrationStreamProbe{payload: payload, mode: volume.LegacyDecodeRSFull}
		err := streamVerifiedMigration(
			ctx,
			source,
			pcv3.PayloadKindRaw,
			func(_ context.Context, input io.Reader, _ int64, _ volume.LegacyDecodeMode, _ pcv3.PayloadKind) error {
				var first [1]byte
				if _, err := io.ReadFull(input, first[:]); err != nil {
					return err
				}
				cancel()
				return ctx.Err()
			},
		)
		if !errors.Is(err, context.Canceled) || source.streamCalls != 1 || !source.exited {
			t.Fatalf("cancelled stream = err %v streams %d exited %v; want cancelled/1/true", err, source.streamCalls, source.exited)
		}
	})
}

func TestMigrationSerializesLegacyAndPCV3MemoryPhases(t *testing.T) {
	t.Run("consumer starts only after legacy derivation reaches first plaintext write", func(t *testing.T) {
		source := &migrationDerivationPhaseSource{
			payload: []byte("verified legacy plaintext"),
			started: make(chan struct{}),
			allow:   make(chan struct{}),
		}
		result := make(chan error, 1)
		go func() {
			result <- streamVerifiedMigration(
				context.Background(),
				source,
				pcv3.PayloadKindRaw,
				func(_ context.Context, input io.Reader, _ int64, _ volume.LegacyDecodeMode, _ pcv3.PayloadKind) error {
					if source.phase.Load() != 2 {
						return errMigrationTestConsumer
					}
					got, err := io.ReadAll(input)
					if err != nil || !bytes.Equal(got, source.payload) {
						return errMigrationTestConsumer
					}
					return nil
				},
			)
		}()
		<-source.started
		if source.phase.Load() != 1 {
			t.Fatalf("legacy derivation phase = %d; want active before first write", source.phase.Load())
		}
		close(source.allow)
		if err := <-result; err != nil || !source.exited {
			t.Fatalf("serialized derivation result = %v exited=%v; want nil/true", err, source.exited)
		}
	})

	t.Run("zero byte success starts consumer only after producer completion", func(t *testing.T) {
		source := &migrationStreamProbe{mode: volume.LegacyDecodePlain}
		consumerCalls := 0
		err := streamVerifiedMigration(
			context.Background(),
			source,
			pcv3.PayloadKindRaw,
			func(_ context.Context, input io.Reader, _ int64, _ volume.LegacyDecodeMode, _ pcv3.PayloadKind) error {
				consumerCalls++
				payload, err := io.ReadAll(input)
				if err != nil || len(payload) != 0 || !source.exited {
					return errMigrationTestConsumer
				}
				return nil
			},
		)
		if err != nil || consumerCalls != 1 || !source.exited {
			t.Fatalf("zero byte migration = %v calls=%d exited=%v; want nil/1/true", err, consumerCalls, source.exited)
		}
	})

	t.Run("zero byte producer failure never starts consumer", func(t *testing.T) {
		source := &migrationStreamProbe{
			mode:      volume.LegacyDecodePlain,
			streamErr: errMigrationTestProducer,
		}
		consumerCalls := 0
		err := streamVerifiedMigration(
			context.Background(),
			source,
			pcv3.PayloadKindRaw,
			func(context.Context, io.Reader, int64, volume.LegacyDecodeMode, pcv3.PayloadKind) error {
				consumerCalls++
				return nil
			},
		)
		if !errors.Is(err, errMigrationTestProducer) || consumerCalls != 0 || !source.exited {
			t.Fatalf("zero byte producer failure = %v calls=%d exited=%v; want producer error/0/true", err, consumerCalls, source.exited)
		}
	})
}

func TestMigrationRequiresExplicitPayloadKindBeforeStreaming(t *testing.T) {
	for name, kind := range map[string]pcv3.PayloadKind{
		"raw": pcv3.PayloadKindRaw, "archive": pcv3.PayloadKindArchive,
	} {
		t.Run(name, func(t *testing.T) {
			source := &migrationStreamProbe{payload: []byte("payload"), mode: volume.LegacyDecodePlain}
			seen := pcv3.PayloadKind(0)
			err := streamVerifiedMigration(
				context.Background(),
				source,
				kind,
				func(_ context.Context, input io.Reader, _ int64, _ volume.LegacyDecodeMode, got pcv3.PayloadKind) error {
					seen = got
					_, err := io.Copy(io.Discard, input)
					return err
				},
			)
			if err != nil || seen != kind || source.streamCalls != 1 {
				t.Fatalf("explicit kind plumbing = seen %v streams %d err %v; want %v/1/nil", seen, source.streamCalls, err, kind)
			}
		})
	}

	invalid := &migrationStreamProbe{payload: []byte("must not stream"), mode: volume.LegacyDecodePlain}
	if err := streamVerifiedMigration(context.Background(), invalid, 0, func(context.Context, io.Reader, int64, volume.LegacyDecodeMode, pcv3.PayloadKind) error {
		return nil
	}); err == nil || invalid.streamCalls != 0 {
		t.Fatalf("implicit payload kind result = %v streams=%d; want refusal before stream", err, invalid.streamCalls)
	}
}

func assertMigrationZero(t *testing.T, value []byte) {
	t.Helper()
	for index, element := range value {
		if element != 0 {
			t.Fatalf("owned credential byte %d survived cleanup: 0x%02x", index, element)
		}
	}
}
