package pcv3artifact

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func missingPlan(t *testing.T, length uint64) *Plan {
	t.Helper()
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
	plan, err := Prepare(Descriptor{State: StatePartial, Final: FinalVerified, PlaintextLength: length, Ranges: m})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestHugeMissingTableCancellationStopsBeforeSecondBatch(t *testing.T) {
	plan := missingPlan(t, 1<<50)
	if plan.Metadata().TotalLength != 80+40*(1<<30) {
		t.Fatal(plan.Metadata())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	writer := &cancelTableWriter{cancel: cancel}
	err := Encode(ctx, writer, plan, nil)
	if !errors.Is(err, context.Canceled) || writer.bytes > 80+64<<10 {
		t.Fatalf("err=%v bytes=%d", err, writer.bytes)
	}
}

type cancelTableWriter struct {
	cancel context.CancelFunc
	bytes  int
}

func (w *cancelTableWriter) Write(p []byte) (int, error) {
	w.bytes += len(p)
	if w.bytes > 80 {
		w.cancel()
	}
	return len(p), nil
}

func TestCancelledArtifactPassesReadAndWriteNothing(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var dst bytes.Buffer
	if err := Encode(ctx, &dst, missingPlan(t, 1<<50), nil); !errors.Is(err, context.Canceled) || dst.Len() != 0 {
		t.Fatalf("err=%v bytes=%d", err, dst.Len())
	}
	r := &noReadReader{t: t}
	if _, err := Parse(ctx, r, 120); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type noReadReader struct{ t *testing.T }

func (r *noReadReader) ReadAt([]byte, int64) (int, error) {
	r.t.Error("read after cancellation")
	return 0, io.EOF
}

func TestParseAndVisitCancelDuringValidationBeforeVisitor(t *testing.T) {
	literal := readLiteralArtifact(t, "partial")
	for _, visit := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		reader := &cancelReadAt{source: bytes.NewReader(literal), cancel: cancel}
		if !visit {
			_, err := Parse(ctx, reader, int64(len(literal)))
			if !errors.Is(err, context.Canceled) || reader.calls != 1 {
				t.Fatalf("parse err=%v calls=%d", err, reader.calls)
			}
		} else {
			artifact, err := Parse(context.Background(), bytes.NewReader(literal), int64(len(literal)))
			if err != nil {
				t.Fatal(err)
			}
			artifact.source = reader
			err = artifact.VisitRanges(ctx, func(Entry, io.Reader) error { t.Fatal("visitor after cancelled validation"); return nil })
			if !errors.Is(err, context.Canceled) || reader.calls != 1 {
				t.Fatalf("visit err=%v calls=%d", err, reader.calls)
			}
		}
		cancel()
	}
}

type cancelReadAt struct {
	source io.ReaderAt
	cancel context.CancelFunc
	calls  int
}

func (r *cancelReadAt) ReadAt(p []byte, off int64) (int, error) {
	r.calls++
	n, err := r.source.ReadAt(p, off)
	r.cancel()
	return n, err
}

func TestPlanRetainsSealedMapAfterBuilderCloseAndDescriptorChange(t *testing.T) {
	b, err := pcv3ranges.NewBuilder(5, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Append(pcv3ranges.Verified); err != nil {
		t.Fatal(err)
	}
	m, err := b.Seal()
	if err != nil {
		t.Fatal(err)
	}
	d := Descriptor{State: StatePartial, Final: FinalMissing, PlaintextLength: 5, Ranges: m}
	plan, err := Prepare(d)
	if err != nil {
		t.Fatal(err)
	}
	b.Close()
	d.Ranges = nil
	d.Final = FinalVerified
	r, _ := m.At(0)
	r.State = pcv3ranges.Missing
	*m = pcv3ranges.Map{}
	var output bytes.Buffer
	err = Encode(context.Background(), &output, plan, func(yield func(uint64, io.Reader) error) error { return yield(0, bytes.NewBufferString("VFY!\n")) })
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(output.Bytes(), readLiteralArtifact(t, "partial")) {
		t.Fatal("sealed plan mutated")
	}
}

func TestEncodeFreezesPlanBeforeWriterCallback(t *testing.T) {
	plan := missingPlan(t, 1)
	original := plan.Metadata()
	var destination bytes.Buffer
	writer := planMutatingWriter{destination: &destination, plan: plan}
	if err := Encode(context.Background(), writer, plan, nil); err != nil {
		t.Fatal(err)
	}
	artifact, err := Parse(context.Background(), bytes.NewReader(destination.Bytes()), int64(destination.Len()))
	if err != nil || artifact.Metadata() != original {
		t.Fatalf("writer changed plan: %v", err)
	}
}

type planMutatingWriter struct {
	destination io.Writer
	plan        *Plan
}

func (w planMutatingWriter) Write(p []byte) (int, error) {
	*w.plan = Plan{}
	return w.destination.Write(p)
}

func TestCancelledFinalTableBatchDoesNotInvokeSegmentSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	err := Encode(ctx, &cancelTableWriter{cancel: cancel}, missingPlan(t, 1), func(func(uint64, io.Reader) error) error { called = true; return nil })
	if !errors.Is(err, context.Canceled) || called {
		t.Fatalf("final table cancellation err=%v source-called=%v", err, called)
	}
}
