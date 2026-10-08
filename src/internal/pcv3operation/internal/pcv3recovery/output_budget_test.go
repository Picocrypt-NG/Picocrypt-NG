package pcv3recovery

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestOutputAdmissionRefusesBeforeWritingAndPreservesFiles(t *testing.T) {
	for _, tc := range []struct {
		name      string
		available int64
		probeErr  error
		length    uint64
	}{
		{"unknown", 0, errors.New("unknown filesystem"), 5},
		{"reserve", 64 << 20, nil, 5},
		{"overflow", 1 << 62, nil, ^uint64(0)},
		{"admitted", (64 << 20) + 5, nil, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "source")
			foreign := filepath.Join(dir, "foreign")
			target := filepath.Join(dir, "result")
			if err := os.WriteFile(source, []byte("original"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
				t.Fatal(err)
			}
			writes := 0
			request := &Request{Target: target, Protected: []string{source}, availableSpace: func(f *os.File) (int64, error) {
				if f == nil {
					t.Fatal("no held stage")
				}
				return tc.available, tc.probeErr
			}, stageWriter: func(w io.Writer) io.Writer { return countingOutputWriter{w: w, count: &writes} }}
			runner := func(_ context.Context, _ *Request, output operationOutput) (operationSemantic, error) {
				semantic := operationSemantic{outcome: pcv3.OutcomeSuccess, code: pcv3.CodeSuccess}
				err := output(semantic, operationRoleCapsulePrimary, "", tc.length, func(sink operationSegmentSink) error { return sink(operationRange{}, []byte("hello")) })
				if err != nil {
					return operationSemantic{outcome: pcv3.OutcomeOperationFailed, stage: pcv3.StageOutputWrite, code: pcv3.CodeOperationFailed}, err
				}
				return semantic, nil
			}
			result := runWithCoreOptions(context.Background(), request, runner, ExecutionOptions{})
			for path, want := range map[string]string{source: "original", foreign: "foreign"} {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, []byte(want)) {
					t.Fatalf("changed %s", path)
				}
			}
			if tc.name == "admitted" {
				got, err := os.ReadFile(target)
				if err != nil || string(got) != "hello" || writes == 0 {
					t.Fatalf("not admitted: %v", err)
				}
			} else {
				if writes != 0 || result.Outcome() != pcv3.OutcomeOperationFailed {
					t.Fatalf("writes=%d outcome=%v", writes, result.Outcome())
				}
				if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("target: %v", err)
				}
			}
			entries, _ := os.ReadDir(dir)
			want := 2
			if tc.name == "admitted" {
				want++
			}
			if len(entries) != want {
				t.Fatalf("owned stage residue: %v", entries)
			}
		})
	}
}

type countingOutputWriter struct {
	w     io.Writer
	count *int
}

func (w countingOutputWriter) Write(p []byte) (int, error) { *w.count++; return w.w.Write(p) }

func TestUnverifiedTableAmplificationUsesReadableSourceExtent(t *testing.T) {
	// 1,677,722 entries produce 67,108,880 table bytes, just over 64 MiB.
	const count uint64 = 1677722
	b, err := pcv3ranges.NewBuilder(count*(1<<20), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err = b.FinishMissingTail(); err != nil {
		t.Fatal(err)
	}
	m, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	semantic := operationSemantic{outcome: pcv3.OutcomeForceUnverified, provenance: pcv3.ForceProvenanceUnverified, stage: pcv3.StageFinalRecord, code: pcv3.CodeForceUnverified, plaintextLength: count * (1 << 20), ranges: m, final: pcv3.RecoveryFinalUnverified}
	descriptor, err := artifactDescriptor(semantic, operationRoleCapsulePrimary)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := pcv3artifact.Prepare(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	request := &Request{SourceSize: 4096, availableSpace: func(*os.File) (int64, error) { return 1 << 40, nil }}
	if err := admitOutput(context.Background(), request, nil, semantic, plan, plan.Metadata().TotalLength); err == nil {
		t.Fatal("tiny source admitted amplified unverified table")
	}
	request.SourceSize = 67108880
	if err := admitOutput(context.Background(), request, nil, semantic, plan, plan.Metadata().TotalLength); err != nil {
		t.Fatalf("readable extent did not admit table: %v", err)
	}
	// The table rule does not apply to authenticated evidence even when almost
	// all of the source has been lost. Disk capacity remains mandatory.
	semantic.outcome = pcv3.OutcomeForcePartial
	request.SourceSize = 4096
	if err := admitOutput(context.Background(), request, nil, semantic, plan, plan.Metadata().TotalLength); err != nil {
		t.Fatalf("anchored tail rejected by ratio: %v", err)
	}
}

func TestHugeUnverifiedTableRefusalCleansOwnedStageBeforeEmitter(t *testing.T) {
	const length uint64 = 1 << 50
	b, err := pcv3ranges.NewBuilder(length, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err = b.FinishMissingTail(); err != nil {
		t.Fatal(err)
	}
	m, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	semantic := operationSemantic{outcome: pcv3.OutcomeForceUnverified, provenance: pcv3.ForceProvenanceUnverified, stage: pcv3.StageFinalRecord, code: pcv3.CodeForceUnverified, plaintextLength: length, ranges: m, final: pcv3.RecoveryFinalUnverified}
	dir := t.TempDir()
	target := filepath.Join(dir, "artifact")
	called := false
	runner := func(_ context.Context, _ *Request, output operationOutput) (operationSemantic, error) {
		err := output(semantic, operationRoleCapsulePrimary, "", length, func(operationSegmentSink) error { called = true; return nil })
		// Production core recognizes this typed failure and cannot retain Force
		// success when refusal occurred before invoking its emitter.
		var outputError pcv3.Failure
		if !errors.As(err, &outputError) || outputError.Stage() != pcv3.StageOutputWrite {
			t.Fatalf("pre-emitter refusal not typed: %T", err)
		}
		return operationSemantic{outcome: pcv3.OutcomeOperationFailed, stage: pcv3.StageOutputWrite, code: pcv3.CodeOperationFailed}, err
	}
	result := runWithCoreOptions(context.Background(), &Request{Target: target, SourceSize: 4096}, runner, ExecutionOptions{})
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 || called || result.Outcome() != pcv3.OutcomeOperationFailed {
		t.Fatalf("refusal leak: entries=%v called=%v outcome=%v err=%v", entries, called, result.Outcome(), err)
	}
}

func TestInspectionPagesImplicitTailAfterOriginalReferenceReleased(t *testing.T) {
	const length uint64 = (1 << 50) + 7
	b, err := pcv3ranges.NewBuilder(length, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Append(pcv3ranges.Verified); err != nil {
		t.Fatal(err)
	}
	if err = b.FinishMissingTail(); err != nil {
		t.Fatal(err)
	}
	m, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	descriptor := pcv3artifact.Descriptor{State: pcv3artifact.StatePartial, Final: pcv3artifact.FinalMissing, PlaintextLength: length, Ranges: m}
	inspection := artifactInspectionFromEncodedDescriptor(descriptor)
	b.Close()
	descriptor.Ranges = nil
	*m = pcv3ranges.Map{}
	last := inspection.Metadata().RangeCount - 1
	page, ok := inspection.Page(last, 128)
	if !ok || len(page) != 1 || page[0].Start != 1<<50 || page[0].End != length || page[0].Status != pcv3artifact.RangeMissing {
		t.Fatalf("tail: %+v %v", page, ok)
	}
	page[0].Status = pcv3artifact.RangeVerified
	again, _ := inspection.Page(last, 1)
	if again[0].Status != pcv3artifact.RangeMissing {
		t.Fatal("page mutated sealed map")
	}
}

func TestProductionRecoveryBudgetFailureClearsSuccessfulSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, file string
		mode       pcv3.RecoveryMode
		cancel     bool
		enospc     bool
	}{
		{"ordinary", "normal-degraded-capsule", pcv3.RecoveryModeNormalV3, false, false},
		{"force", "normal-negative-record", pcv3.RecoveryModeForce, false, false},
		{"cancel before emitter", "normal-negative-record", pcv3.RecoveryModeForce, true, false},
		{"late ENOSPC", "normal-negative-record", pcv3.RecoveryModeForce, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture, err := os.ReadFile("../pcv3/testdata/normal/volumes/" + tc.file + ".pcv")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			source := filepath.Join(dir, "source.pcv")
			target := filepath.Join(dir, "output")
			if err = os.WriteFile(source, fixture, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			factors := &pcv3credential.FactorRequest{Mode: pcv3credential.CredentialModePasswordAndKeyfiles, KeyfileMode: pcv3credential.KeyfileModeOrdered, ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles, Password: []byte("mix"), Keyfiles: []*pcv3credential.KeyfileReader{
				pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewBufferString("red"))), pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewBufferString("blue"))),
			}}
			result := Run(ctx, &Request{Source: bytes.NewReader(fixture), SourceSize: int64(len(fixture)), Factors: factors, Admitter: recoveryOperationAdmitter{}, Mode: tc.mode, Target: target, Protected: []string{source}, availableSpace: func(*os.File) (int64, error) {
				if tc.cancel {
					cancel()
					return 1 << 40, nil
				}
				if tc.enospc {
					return 1 << 40, nil
				}
				return 64 << 20, nil
			}, stageWriter: func(io.Writer) io.Writer {
				if tc.enospc {
					return &failingStageWriter{cause: syscall.ENOSPC}
				}
				t.Fatal("budget denial reached first write")
				return nil
			}})
			wantStage := pcv3.StageOutputWrite
			if tc.cancel {
				wantStage = pcv3.StageCancellation
			}
			if result.Outcome() != pcv3.OutcomeOperationFailed || result.Stage() != wantStage || result.Code() != pcv3.CodeOperationFailed || result.ForceProvenance() != pcv3.ForceProvenanceNone {
				t.Fatalf("budget semantic = %v/%v/%v/%v", result.Outcome(), result.Stage(), result.Code(), result.ForceProvenance())
			}
			assertFileBytesAndMode(t, source, fixture, 0o600)
			assertNoRecoveryStageResidue(t, dir)
			if _, err = os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refusal output exists: %v", err)
			}
		})
	}
}

// Ordinary D1 success intentionally exposes no recovery-map length. Disk
// admission must use the private output plan, including when Force recovers an
// intact volume. The independent fixture drives the real KDF and D1 reader.
func TestProductionD1OutputAdmissionUsesSelectedLength(t *testing.T) {
	fixtureFile := func(t *testing.T, name string) []byte {
		t.Helper()
		data, err := os.ReadFile(filepath.Join("../pcv3/testdata/d1/independent", name))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	ciphertext, plaintext := fixtureFile(t, "d1.pcv"), fixtureFile(t, "plaintext.bin")
	for _, tc := range []struct {
		name  string
		mode  pcv3.RecoveryMode
		allow bool
	}{
		{"ordinary refuses before write", pcv3.RecoveryModeNormalV3, false},
		{"force refuses before write", pcv3.RecoveryModeForce, false},
		{"exact output plus reserve admitted", pcv3.RecoveryModeNormalV3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			source, foreign, target := filepath.Join(dir, "source.pcv"), filepath.Join(dir, "foreign"), filepath.Join(dir, "output")
			if err := os.WriteFile(source, ciphertext, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(foreign, []byte("foreign sentinel"), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(source)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			sourceInfo, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			factors := &pcv3credential.FactorRequest{
				Mode: pcv3credential.CredentialModePasswordAndKeyfiles, ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
				KeyfileMode: pcv3credential.KeyfileModeOrdered, Password: fixtureFile(t, "password.bin"),
				Keyfiles: []*pcv3credential.KeyfileReader{
					pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader(fixtureFile(t, "keyfile-alpha.bin")))),
					pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader(fixtureFile(t, "keyfile-beta.bin")))),
				},
			}
			writes, observations := 0, 0
			result := RunD1(context.Background(), &Request{
				Source: file, SourceSize: int64(len(ciphertext)), Factors: factors, Admitter: recoveryOperationAdmitter{},
				Mode: tc.mode, Target: target, Protected: []string{source},
				availableSpace: func(stage *os.File) (int64, error) {
					if stage == nil {
						t.Fatal("output admission lost the held stage")
					}
					observations++
					available := int64(64 << 20)
					if tc.allow {
						available += int64(len(plaintext))
					}
					return available, nil
				},
				stageWriter: func(w io.Writer) io.Writer { return countingOutputWriter{w: w, count: &writes} },
			})
			if observations != 1 {
				t.Fatalf("disk observations = %d; fixture must reach real output admission", observations)
			}
			if tc.allow {
				if result.Outcome() != pcv3.OutcomeSuccess || writes == 0 {
					t.Fatalf("exact budget refused ordinary D1: outcome=%v stage=%v writes=%d", result.Outcome(), result.Stage(), writes)
				}
				assertFileBytesAndMode(t, target, plaintext, 0o600)
			} else {
				if result.Outcome() != pcv3.OutcomeOperationFailed || result.Stage() != pcv3.StageOutputWrite || result.Code() != pcv3.CodeOperationFailed || writes != 0 {
					t.Fatalf("D1 budget refusal = %v/%v/%v writes=%d", result.Outcome(), result.Stage(), result.Code(), writes)
				}
				if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("refusal published output: %v", err)
				}
			}
			currentInfo, err := os.Stat(source)
			if err != nil || !os.SameFile(sourceInfo, currentInfo) {
				t.Fatalf("source identity changed: %v", err)
			}
			assertFileBytesAndMode(t, source, ciphertext, 0o600)
			assertFileBytesAndMode(t, foreign, []byte("foreign sentinel"), 0o600)
			assertNoRecoveryStageResidue(t, dir)
		})
	}
}

func TestOperationFreezesEvidenceBeforeStageCallbacks(t *testing.T) {
	m := fixtureRangeMap([]operationRange{{recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeVerified}})
	semantic := operationSemantic{outcome: pcv3.OutcomeForcePartial, provenance: pcv3.ForceProvenancePartial, stage: pcv3.StageFinalRecord, code: pcv3.CodeForcePartial, plaintextLength: 5, ranges: m, final: pcv3.RecoveryFinalMissing}
	runner := func(_ context.Context, _ *Request, output operationOutput) (operationSemantic, error) {
		err := output(semantic, operationRoleCapsulePrimary, "", 5, func(sink operationSegmentSink) error {
			return sink(operationRange{recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeVerified}, []byte("hello"))
		})
		return semantic, err
	}
	target := filepath.Join(t.TempDir(), "artifact")
	result := runWithCore(context.Background(), &Request{Target: target, stageWriter: func(w io.Writer) io.Writer { *m = pcv3ranges.Map{}; return w }}, runner)
	inspection := result.ArtifactInspection()
	requireNativeRecoveryPublication(t, result)
	if (inspection != nil) != (runtime.GOOS != "windows") {
		t.Fatalf("mutated callback changed native inspection authority: %v/%v", result.Outcome(), result.PublicationState())
	}
	if inspection != nil {
		page, ok := inspection.Page(0, 1)
		if !ok || len(page) != 1 || page[0].End != 5 || page[0].Status != pcv3artifact.RangeVerified {
			t.Fatalf("evidence changed: %+v", page)
		}
	}
	contents, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := pcv3artifact.Parse(context.Background(), bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		t.Fatal(err)
	}
	visits := 0
	if err := artifact.VisitRanges(context.Background(), func(entry pcv3artifact.Entry, reader io.Reader) error {
		visits++
		if entry.RecordIndex != 0 || entry.Start != 0 || entry.End != 5 || entry.Status != pcv3artifact.RangeVerified || reader == nil {
			t.Fatalf("published frozen range changed: %+v", entry)
		}
		data, err := io.ReadAll(reader)
		if err != nil || string(data) != "hello" {
			t.Fatalf("published frozen payload changed: %q %v", data, err)
		}
		return nil
	}); err != nil || visits != 1 {
		t.Fatalf("published frozen ranges=%d err=%v", visits, err)
	}
}

func TestCancelledHugeMissingTableCleansStageAndPreservesOriginals(t *testing.T) {
	const length uint64 = 1 << 50
	b, err := pcv3ranges.NewBuilder(length, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err = b.FinishMissingTail(); err != nil {
		t.Fatal(err)
	}
	m, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	semantic := operationSemantic{outcome: pcv3.OutcomeForcePartial, provenance: pcv3.ForceProvenancePartial, stage: pcv3.StageDescriptor, code: pcv3.CodeForcePartial, plaintextLength: length, ranges: m, final: pcv3.RecoveryFinalVerified}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	foreign := filepath.Join(dir, "foreign")
	target := filepath.Join(dir, "artifact")
	if err = os.WriteFile(source, []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	var writer *cancelStageWriter
	runner := func(_ context.Context, _ *Request, output operationOutput) (operationSemantic, error) {
		err := output(semantic, operationRoleCapsulePrimary, "", length, func(operationSegmentSink) error { t.Fatal("cancelled table invoked emitter"); return nil })
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
		return operationSemantic{outcome: pcv3.OutcomeOperationFailed, stage: pcv3.StageCancellation, code: pcv3.CodeOperationFailed}, err
	}
	result := runWithCore(ctx, &Request{Target: target, SourceSize: 6, Protected: []string{source}, availableSpace: func(*os.File) (int64, error) { return 1 << 40, nil }, stageWriter: func(w io.Writer) io.Writer {
		writer = &cancelStageWriter{destination: w, cancel: cancel}
		return writer
	}}, runner)
	if writer == nil || writer.bytes > 80+(64<<10) || result.Stage() != pcv3.StageCancellation {
		t.Fatalf("table cancellation unbounded: %+v %v", writer, result.Stage())
	}
	assertFileBytesAndMode(t, source, []byte("source"), 0o600)
	assertFileBytesAndMode(t, foreign, []byte("foreign"), 0o600)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("output residue: %v %v", entries, err)
	}
}

type cancelStageWriter struct {
	destination io.Writer
	cancel      context.CancelFunc
	bytes       int
}

func (w *cancelStageWriter) Write(p []byte) (int, error) {
	n, err := w.destination.Write(p)
	w.bytes += n
	if w.bytes > 80 {
		w.cancel()
	}
	return n, err
}
