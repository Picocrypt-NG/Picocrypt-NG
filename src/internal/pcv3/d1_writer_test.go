package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3governance"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func TestD1CreationStagePrecedesEntropyFactorsAndKDF(t *testing.T) {
	fixture := newD1CreationTestFixture(t)
	var events []d1CreationBoundary
	seams := newD1CreationTestSeams(t, func(
		boundary d1CreationBoundary,
		stage *pcv3publication.Stage,
	) error {
		requireD1LiveStage(t, fixture, stage)
		events = append(events, boundary)
		return nil
	})

	result, err := composeD1OuterStage(context.Background(), fixture.request, seams)
	if err != nil {
		t.Fatalf("compose D1 stage: %v", err)
	}
	if result == nil || result.State() != pcv3publication.StatePublishedDurable ||
		result.Outcome() != OutcomeSuccess {
		t.Fatalf("D1 publication result = %T %v", result, result)
	}
	if len(events) == 0 || events[0] != d1BoundaryStageCreated {
		t.Fatalf("first D1 effect = %v; want stage creation", events)
	}
	wantKDF := []d1CreationBoundary{
		d1BoundaryKDFFront,
		d1BoundaryKDFTail,
		d1BoundaryKDFInner,
	}
	var gotKDF []d1CreationBoundary
	for _, event := range events {
		switch event {
		case d1BoundaryKDFFront, d1BoundaryKDFTail, d1BoundaryKDFInner:
			gotKDF = append(gotKDF, event)
		}
	}
	if !slices.Equal(gotKDF, wantKDF) {
		t.Fatalf("D1 KDF boundaries = %v; want %v", gotKDF, wantKDF)
	}
	for _, boundary := range []d1CreationBoundary{
		d1BoundaryOuterEntropy,
		d1BoundaryFactors,
		d1BoundaryKDFFront,
	} {
		if d1BoundaryIndex(events, boundary) <= 0 {
			t.Fatalf("D1 boundary %v did not follow real stage creation: %v", boundary, events)
		}
	}
	requireD1SourceUnchanged(t, fixture)
	requireD1NoStageResidue(t, fixture.directory)
	if !allZero(fixture.passwordAlias) {
		t.Fatal("successful D1 composition retained the transferred password")
	}
	plan, err := planD1Write(fixture.request.normal)
	if err != nil {
		t.Fatalf("plan completed D1 file: %v", err)
	}
	info, err := os.Stat(fixture.destinationPath)
	if err != nil || uint64(info.Size()) != plan.fileSize {
		t.Fatalf("published D1 size = %v, %v; want %d", info, err, plan.fileSize)
	}
}

func TestD1WriterRefusalUsesGuardedProductionEntry(t *testing.T) {
	fixture := newD1CreationTestFixture(t)

	result, err := writeD1Volume(
		context.Background(),
		&pcv3governance.EmissionAuthorization{},
		fixture.request,
	)
	if result != nil {
		t.Fatalf("guarded D1 refusal returned publication result %v", result)
	}
	var failure Failure
	if !errors.As(err, &failure) || failure.Code() != CodeUnsupported {
		t.Fatalf("guarded D1 refusal = %T %v; want closed unsupported failure", err, err)
	}
	if allZero(fixture.passwordAlias) {
		t.Fatal("guarded D1 refusal consumed factors before authorization")
	}
	requireD1SourceUnchanged(t, fixture)
	if _, statErr := os.Lstat(fixture.destinationPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("guarded D1 refusal changed destination: %v", statErr)
	}
	requireD1NoStageResidue(t, fixture.directory)
	if closeErr := fixture.request.factors.Close(); closeErr != nil {
		t.Fatalf("close refused D1 factors: %v", closeErr)
	}
	if !allZero(fixture.passwordAlias) {
		t.Fatal("explicit refused-factor cleanup retained password bytes")
	}
}

func TestD1PureGeometryHasNoSideEffects(t *testing.T) {
	fixture := newD1CreationTestFixture(t)
	fixture.request.normal.plaintextLength = math.MaxUint64
	effects := 0
	seams := newD1CreationTestSeams(t, func(
		_ d1CreationBoundary,
		_ *pcv3publication.Stage,
	) error {
		effects++
		return nil
	})

	result, err := composeD1OuterStage(context.Background(), fixture.request, seams)
	if err == nil || result != nil {
		t.Fatalf("overflowing D1 composition = result %v, error %v", result, err)
	}
	if effects != 0 {
		t.Fatalf("pure D1 refusal observed %d stage/entropy/factor/KDF effects", effects)
	}
	if allZero(fixture.passwordAlias) {
		t.Fatal("pure D1 refusal consumed factors before stage creation")
	}
	requireD1SourceUnchanged(t, fixture)
	if _, statErr := os.Lstat(fixture.destinationPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("pure D1 refusal changed destination: %v", statErr)
	}
	requireD1NoStageResidue(t, fixture.directory)
	if closeErr := fixture.request.factors.Close(); closeErr != nil {
		t.Fatalf("close refused D1 factors: %v", closeErr)
	}
	if !allZero(fixture.passwordAlias) {
		t.Fatal("explicit factor cleanup retained password bytes")
	}
}

func TestD1WriterCleanup(t *testing.T) {
	injected := errors.New("TEST ONLY D1 injected boundary failure")
	for _, boundary := range []d1CreationBoundary{
		d1BoundaryStageCreated,
		d1BoundaryOuterEntropy,
		d1BoundaryFactors,
		d1BoundaryKDFFront,
		d1BoundaryFrontBootstrap,
		d1BoundaryBody,
		d1BoundaryTailBootstrap,
		d1BoundaryFlush,
		d1BoundaryPublish,
	} {
		t.Run(boundary.String(), func(t *testing.T) {
			fixture := newD1CreationTestFixture(t)
			seams := newD1CreationTestSeams(t, func(
				observed d1CreationBoundary,
				stage *pcv3publication.Stage,
			) error {
				requireD1LiveStage(t, fixture, stage)
				if observed == boundary {
					return injected
				}
				return nil
			})

			result, err := composeD1OuterStage(context.Background(), fixture.request, seams)
			if result != nil || !errors.Is(err, injected) {
				t.Fatalf("injected D1 boundary %v = result %v, error %v", boundary, result, err)
			}
			requireD1SourceUnchanged(t, fixture)
			if _, statErr := os.Lstat(fixture.destinationPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed D1 boundary published destination: %v", statErr)
			}
			requireD1NoStageResidue(t, fixture.directory)
			if !allZero(fixture.passwordAlias) {
				t.Fatal("failed D1 boundary retained the transferred password")
			}
		})
	}

	t.Run("cancellation before body", func(t *testing.T) {
		fixture := newD1CreationTestFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		seams := newD1CreationTestSeams(t, func(
			boundary d1CreationBoundary,
			stage *pcv3publication.Stage,
		) error {
			requireD1LiveStage(t, fixture, stage)
			if boundary == d1BoundaryBody {
				cancel()
			}
			return nil
		})
		result, err := composeD1OuterStage(ctx, fixture.request, seams)
		if result != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled D1 composition = result %v, error %v", result, err)
		}
		requireD1SourceUnchanged(t, fixture)
		requireD1NoStageResidue(t, fixture.directory)
	})
}

func TestD1WriterNeverCreatesClearInnerArtifact(t *testing.T) {
	fixture := newD1CreationTestFixture(t)
	seams := newD1CreationTestSeams(t, func(
		_ d1CreationBoundary,
		stage *pcv3publication.Stage,
	) error {
		stagePath := requireD1LiveStage(t, fixture, stage)
		raw, err := os.ReadFile(stagePath)
		if err != nil {
			t.Fatalf("read live D1 stage: %v", err)
		}
		if len(raw) >= d1BootstrapLength+len(normalDiscriminator) &&
			bytes.Equal(raw[d1BootstrapLength:d1BootstrapLength+len(normalDiscriminator)], []byte(normalDiscriminator)) {
			t.Fatal("live D1 stage exposed the clear inner normal preamble")
		}
		return nil
	})
	result, err := composeD1OuterStage(context.Background(), fixture.request, seams)
	if err != nil || result == nil || result.State() != pcv3publication.StatePublishedDurable {
		t.Fatalf("publish D1 artifact = result %v, error %v", result, err)
	}

	raw, err := os.ReadFile(fixture.destinationPath)
	if err != nil {
		t.Fatalf("read published D1 artifact: %v", err)
	}
	if bytes.Equal(raw[d1BootstrapLength:d1BootstrapLength+len(normalDiscriminator)], []byte(normalDiscriminator)) {
		t.Fatal("published D1 body exposed the clear inner normal preamble")
	}
	entries, err := os.ReadDir(fixture.directory)
	if err != nil {
		t.Fatalf("list D1 output directory: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("D1 output directory entries = %d; want source and one destination", len(entries))
	}

	outerAccess, outerOwner := newD1TestOuterAccess(t, d1CreationTestOuterKeySeed)
	defer outerOwner.Close()
	bodyLength := uint64(len(raw) - 2*d1BootstrapLength)
	for _, bootstrap := range []struct {
		role   D1BootstrapRole
		raw    []byte
		access *d1TestBootstrapCredentialAccess
	}{
		{
			role:   D1BootstrapFront,
			raw:    raw[:d1BootstrapLength],
			access: newD1CreationTestBootstrapAccess(D1BootstrapFront, 0x31),
		},
		{
			role:   D1BootstrapTail,
			raw:    raw[len(raw)-d1BootstrapLength:],
			access: newD1CreationTestBootstrapAccess(D1BootstrapTail, 0x71),
		},
	} {
		attempt := authenticateD1BootstrapTestFixture(
			t,
			bootstrap.raw,
			bootstrap.role,
			bootstrap.access,
		)
		if attempt.authenticated == nil || attempt.authenticated.secret == nil ||
			attempt.authenticated.secret.bodyLength != bodyLength {
			attempt.Close()
			t.Fatalf("composed D1 %v bootstrap body length mismatch", bootstrap.role)
		}
		attempt.Close()
	}
	reader, err := newD1InnerReader(
		context.Background(),
		bytes.NewReader(raw[d1BootstrapLength:len(raw)-d1BootstrapLength]),
		bodyLength,
		outerAccess,
	)
	if err != nil {
		t.Fatalf("authenticate composed D1 body: %v", err)
	}
	defer reader.Close()
	inner := make([]byte, reader.Size())
	if count, readErr := reader.ReadAt(inner, 0); readErr != nil || count != len(inner) {
		t.Fatalf("read composed D1 inner = %d, %v; want %d", count, readErr, len(inner))
	}
	route, _, err := Probe(bytes.NewReader(inner), int64(len(inner)))
	if err != nil || route != RouteNormalPCV {
		t.Fatalf("composed D1 inner probe = route %v, error %v", route, err)
	}
}

func TestD1WriterPublicationOutcome(t *testing.T) {
	for _, test := range []struct {
		name      string
		collision bool
		wantState pcv3publication.State
		wantCode  pcv3publication.Code
	}{
		{
			name:      "durable",
			wantState: pcv3publication.StatePublishedDurable,
			wantCode:  pcv3publication.CodePublishedDurable,
		},
		{
			name:      "destination appears before publish",
			collision: true,
			wantState: pcv3publication.StateNotPublished,
			wantCode:  pcv3publication.CodeDestinationExists,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newD1CreationTestFixture(t)
			foreign := []byte("TEST ONLY foreign destination")
			seams := newD1CreationTestSeams(t, func(
				boundary d1CreationBoundary,
				stage *pcv3publication.Stage,
			) error {
				requireD1LiveStage(t, fixture, stage)
				if test.collision && boundary == d1BoundaryPublish {
					if err := os.WriteFile(fixture.destinationPath, foreign, 0o600); err != nil {
						t.Fatalf("create TEST ONLY publication collision: %v", err)
					}
				}
				return nil
			})

			result, err := composeD1OuterStage(context.Background(), fixture.request, seams)
			if err != nil {
				t.Fatalf("compose D1 publication outcome: %v", err)
			}
			if result == nil || result.State() != test.wantState || result.Code() != test.wantCode {
				t.Fatalf("D1 sealed result = %T %v; want %v/%v", result, result, test.wantState, test.wantCode)
			}
			requireD1SourceUnchanged(t, fixture)
			requireD1NoStageResidue(t, fixture.directory)
			if test.collision {
				got, readErr := os.ReadFile(fixture.destinationPath)
				if readErr != nil || !bytes.Equal(got, foreign) {
					t.Fatalf("publication collision changed foreign destination: %q, %v", got, readErr)
				}
			}
		})
	}
}

const d1CreationTestOuterKeySeed = 0x85

type d1CreationTestFixture struct {
	directory       string
	sourcePath      string
	destinationPath string
	sourceBytes     []byte
	passwordAlias   []byte
	request         *d1CreationRequest
}

type d1CreationTestAdmitter struct{}

func (d1CreationTestAdmitter) AdmitKDF(
	context.Context,
	pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	return pcv3credential.KDFAdmissionGranted, nil
}

func newD1CreationTestFixture(t *testing.T) *d1CreationTestFixture {
	t.Helper()
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.bin")
	destinationPath := filepath.Join(directory, "destination.pcv")
	sourceBytes := make([]byte, 4096)
	for index := range sourceBytes {
		sourceBytes[index] = byte(index*29 + 7)
	}
	if err := os.WriteFile(sourcePath, sourceBytes, 0o600); err != nil {
		t.Fatalf("write TEST ONLY D1 source: %v", err)
	}
	passwordAlias := []byte("TEST ONLY D1 creation password")
	return &d1CreationTestFixture{
		directory:       directory,
		sourcePath:      sourcePath,
		destinationPath: destinationPath,
		sourceBytes:     append([]byte(nil), sourceBytes...),
		passwordAlias:   passwordAlias,
		request: &d1CreationRequest{
			route: d1RouteRequest{
				mode:            d1RouteExplicit,
				sourcePath:      sourcePath,
				destinationPath: destinationPath,
			},
			normal: normalWriteRequest{
				suite:           SuiteParanoid,
				payloadKind:     PayloadKindRaw,
				plaintextLength: uint64(len(sourceBytes)),
			},
			factors: &pcv3credential.FactorRequest{
				Mode:           pcv3credential.CredentialModePasswordOnly,
				KeyfileMode:    pcv3credential.KeyfileModeNone,
				ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly,
				Password:       passwordAlias,
			},
			admitter: d1CreationTestAdmitter{},
		},
	}
}

func newD1CreationTestSeams(
	t *testing.T,
	observer d1CreationObserver,
) d1CreationSeams {
	t.Helper()
	seams := defaultD1CreationSeams()
	entropy := make([]byte, 4096)
	for index := range entropy {
		entropy[index] = byte(index*37 + 11)
	}
	seams.entropy = bytes.NewReader(entropy)
	seams.observe = observer
	seams.credentials = func(
		ctx context.Context,
		request *pcv3credential.FactorRequest,
		secrets *d1CreationSecrets,
		admitter pcv3credential.Admitter,
		observe func(d1CreationBoundary) error,
		callback func(
			d1BootstrapCredentialAccess,
			d1BootstrapCredentialAccess,
			d1OuterKeyAccess,
			normalWriteMaterial,
		) error,
	) error {
		if ctx == nil || request == nil || secrets == nil || admitter == nil ||
			observe == nil || callback == nil {
			return errors.New("TEST ONLY invalid D1 credential session")
		}
		defer func() { _ = request.Close() }()
		for _, boundary := range []d1CreationBoundary{
			d1BoundaryFactors,
			d1BoundaryKDFFront,
			d1BoundaryKDFTail,
			d1BoundaryKDFInner,
		} {
			if err := observe(boundary); err != nil {
				return err
			}
		}

		front := newD1CreationTestBootstrapAccess(D1BootstrapFront, 0x31)
		tail := newD1CreationTestBootstrapAccess(D1BootstrapTail, 0x71)
		outerAccess, outerOwner := newD1TestOuterAccess(t, d1CreationTestOuterKeySeed)
		defer outerOwner.Close()
		normal := newD1TestNormalMaterial()
		normal.metadata.suite = SuiteParanoid
		normal.metadata.kdfProfile = KDFProfileParanoid
		normal.metadata.argonSalt = secrets.innerSalt
		normal.metadata.volumeID = secrets.volumeID
		copy(normal.keys.volumeKey[:], secrets.volumeKey)
		defer normal.keys.close()
		return callback(front, tail, outerAccess, normal)
	}
	return seams
}

func newD1CreationTestBootstrapAccess(
	role D1BootstrapRole,
	seed byte,
) *d1TestBootstrapCredentialAccess {
	access := &d1TestBootstrapCredentialAccess{bootstrapRole: role}
	fillD1TestBytes(access.keys.xChaCha20[:], seed)
	fillD1TestBytes(access.keys.serpent[:], seed+0x20)
	fillD1TestBytes(access.keys.mac[:], seed+0x40)
	return access
}

func requireD1LiveStage(
	t *testing.T,
	fixture *d1CreationTestFixture,
	stage *pcv3publication.Stage,
) string {
	t.Helper()
	if stage == nil || stage.File() == nil {
		t.Fatal("D1 boundary did not expose the live production stage")
	}
	openInfo, err := stage.File().Stat()
	if err != nil || !openInfo.Mode().IsRegular() || openInfo.Mode().Perm() != 0o600 {
		t.Fatalf("live D1 stage mode = %v, error %v; want regular 0600", openInfo, err)
	}
	entries, err := os.ReadDir(fixture.directory)
	if err != nil {
		t.Fatalf("list live D1 stage directory: %v", err)
	}
	var stagePaths []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
			stagePaths = append(stagePaths, filepath.Join(fixture.directory, entry.Name()))
		}
	}
	if len(stagePaths) != 1 {
		t.Fatalf("live D1 stage count = %d; want exactly one unpredictable sibling", len(stagePaths))
	}
	pathInfo, err := os.Lstat(stagePaths[0])
	if err != nil || !os.SameFile(openInfo, pathInfo) {
		t.Fatalf("live D1 stage path identity mismatch: %v", err)
	}
	requireD1SourceUnchanged(t, fixture)
	return stagePaths[0]
}

func requireD1NoStageResidue(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("list D1 directory after cleanup: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
			t.Fatalf("D1 cleanup retained operation-owned stage %q", entry.Name())
		}
	}
}

func requireD1SourceUnchanged(t *testing.T, fixture *d1CreationTestFixture) {
	t.Helper()
	got, err := os.ReadFile(fixture.sourcePath)
	if err != nil || !bytes.Equal(got, fixture.sourceBytes) {
		t.Fatalf("D1 composition changed source bytes: %v", err)
	}
}

func d1BoundaryIndex(events []d1CreationBoundary, wanted d1CreationBoundary) int {
	for index, event := range events {
		if event == wanted {
			return index
		}
	}
	return -1
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
