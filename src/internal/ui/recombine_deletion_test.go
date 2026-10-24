package ui

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/volume"
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func prepareRecombineDeletionTest(t *testing.T) (operationInput, map[string][]byte) {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(t.TempDir(), "input.pcv")
	chunks := map[string][]byte{base + ".0": fixture[:len(fixture)/2], base + ".1": fixture[len(fixture)/2:]}
	for path, body := range chunks {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return operationInput{mode: "decrypt", inputFile: base + ".0", outputFile: base + ".plaintext", password: []byte("test"), recombine: true, delete: true, zipBudget: fileops.NewZIPResourceBudget()}, chunks
}

func TestRecombineDeletionSnapshotSharesCapturedInputs(t *testing.T) {
	input, chunks := prepareRecombineDeletionTest(t)
	manifest, err := captureOperationDeletionManifestWithBudget(context.Background(), input, input.zipBudget)
	if err != nil {
		t.Fatal(err)
	}
	defer input.zipBudget.Release(manifest.charged)
	if len(manifest.recombineInputs) != 2 || cap(manifest.recombineInputs) != 2 {
		t.Fatalf("captured chunk authority=%v; want ordered exact-capacity list", manifest.recombineInputs)
	}
	for i, source := range manifest.files {
		if manifest.recombineInputs[i] != source.info {
			t.Fatal("reader and remover must borrow the same captured FileInfo")
		}
		if source.path != strings.TrimSuffix(input.inputFile, ".0")+"."+strconv.Itoa(i) {
			t.Fatalf("unexpected capture order: %s", source.path)
		}
	}
	seen := false
	refusal := errors.New("test executor stops before decryption")
	result := (&App{}).runCapturedOperation(context.Background(), func(_ context.Context, captured operationInput, _ volume.ProgressReporter) operationResult {
		seen = true
		if len(captured.recombineInputs) != 2 {
			t.Fatalf("reader lost captured deletion identities: %v", captured.recombineInputs)
		}
		return operationResult{err: refusal}
	}, nil, input)
	if !seen || !errors.Is(result.err, refusal) || result.completed {
		t.Fatalf("capture result=%+v", result)
	}
	for path, want := range chunks {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("refused source changed: %s %v", path, err)
		}
	}
}

func TestRecombineDeletionSnapshotMetadataReservation(t *testing.T) {
	input, chunks := prepareRecombineDeletionTest(t)
	base := strings.TrimSuffix(input.inputFile, ".0")
	var pathCharge uint64
	for _, path := range []string{base, base, base + ".0", base + ".1"} {
		cost, err := fileops.ReserveZIPInputPath(input.zipBudget, len(path))
		if err != nil {
			t.Fatal(err)
		}
		pathCharge += cost
	}
	input.zipBudget.Release(pathCharge)
	manifest, err := captureOperationDeletionManifestWithBudget(context.Background(), input, input.zipBudget)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.charged != pathCharge+128 || input.zipBudget.CurrentBytes() != manifest.charged {
		t.Fatalf("captured allowance=%d; want path charge %d plus 128 bytes", manifest.charged, pathCharge)
	}
	input.zipBudget.Release(manifest.charged)
	// Two interfaces require the explicit 64 + 32*N = 128 byte allowance.
	// Paths fit, but this allowance exceeds the remaining headroom by one.
	baseline := input.zipBudget.LimitBytes() - pathCharge - 127
	if err := input.zipBudget.Reserve(baseline); err != nil {
		t.Fatal(err)
	}
	executed := false
	result := (&App{}).runCapturedOperation(context.Background(), func(context.Context, operationInput, volume.ProgressReporter) operationResult {
		executed = true
		return operationResult{}
	}, nil, input)
	if executed || !errors.Is(result.err, fileops.ErrZIPMetadataLimit) {
		t.Fatalf("metadata refusal executed=%v result=%+v", executed, result)
	}
	if got := input.zipBudget.CurrentBytes(); got != baseline {
		t.Fatalf("refusal retained charge: %d, want %d", got, baseline)
	}
	for path, want := range chunks {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("source changed: %s %v", path, err)
		}
	}
}

// A missing identity check must fail the test before a production KDF can run.
type recombineDeletionNoKDFReporter struct{ t *testing.T }

func (r recombineDeletionNoKDFReporter) SetStatus(status string) {
	if status == "Deriving key..." {
		r.t.Fatal("metadata mismatch reached production KDF")
	}
}
func (recombineDeletionNoKDFReporter) SetProgress(float32, string) {}
func (recombineDeletionNoKDFReporter) SetCanCancel(bool)           {}
func (recombineDeletionNoKDFReporter) Update()                     {}
func (recombineDeletionNoKDFReporter) IsCancelled() bool           { return false }

func TestRecombineDeletionSnapshotRejectsChangedInputs(t *testing.T) {
	for _, tc := range []struct{ name, want string }{
		{"first_identity", "chunk 0 changed"},
		{"later_identity", "chunk 1 changed"},
		{"first_size", "chunk 0 changed"},
		{"later_size", "chunk 1 changed"},
		{"added_count", "expected 2 chunk identities, found 3"},
		{"deleted_count", "expected 2 chunk identities, found 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, preserved := prepareRecombineDeletionTest(t)
			base := strings.TrimSuffix(input.inputFile, ".0")
			result := (&App{}).runCapturedOperation(context.Background(), func(ctx context.Context, captured operationInput, reporter volume.ProgressReporter) operationResult {
				if len(captured.recombineInputs) != 2 {
					t.Fatal("missing captured reader identities")
				}
				switch tc.name {
				case "first_identity", "later_identity":
					index := "0"
					if tc.name == "later_identity" {
						index = "1"
					}
					path := base + "." + index
					if err := os.Rename(path, path+".captured"); err != nil {
						t.Fatal(err)
					}
					preserved[path+".captured"] = preserved[path]
					if err := os.WriteFile(path, preserved[path], 0o600); err != nil {
						t.Fatal(err)
					}
				case "first_size", "later_size":
					index := "0"
					if tc.name == "later_size" {
						index = "1"
					}
					path := base + "." + index
					preserved[path] = append(append([]byte(nil), preserved[path]...), 0)
					if err := os.WriteFile(path, preserved[path], 0o600); err != nil {
						t.Fatal(err)
					}
				case "added_count":
					preserved[base+".2"] = []byte("late")
					if err := os.WriteFile(base+".2", preserved[base+".2"], 0o600); err != nil {
						t.Fatal(err)
					}
				case "deleted_count":
					if err := os.Rename(base+".1", base+".1.captured"); err != nil {
						t.Fatal(err)
					}
					preserved[base+".1.captured"] = preserved[base+".1"]
					delete(preserved, base+".1")
				}
				return executeVolumeOperation(ctx, captured, reporter)
			}, recombineDeletionNoKDFReporter{t}, input)
			if result.err == nil || !strings.Contains(result.err.Error(), tc.want) || result.completed || result.succeeded != 0 || result.failed != 1 || result.deleteFailed {
				t.Fatalf("mismatch result=%+v; want %q", result, tc.want)
			}
			for path, want := range preserved {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("mismatch changed source %s: %v", path, err)
				}
			}
			entries, err := os.ReadDir(filepath.Dir(base))
			if err != nil || len(entries) != len(preserved) {
				t.Fatalf("mismatch left output/staging: %v %v", entries, err)
			}
			if input.zipBudget.CurrentBytes() != 0 {
				t.Fatal("mismatch retained manifest charge")
			}
		})
	}
}

func TestRecombineDeletionSnapshotNonDeleteCompatibility(t *testing.T) {
	input, _ := prepareRecombineDeletionTest(t)
	input.delete = false
	seen := false
	refusal := errors.New("stop before decryption")
	result := (&App{}).runCapturedOperation(context.Background(), func(_ context.Context, captured operationInput, _ volume.ProgressReporter) operationResult {
		seen = true
		if captured.recombineInputs != nil || input.zipBudget.CurrentBytes() != 0 {
			t.Fatal("non-delete caller gained deletion capture metadata")
		}
		return operationResult{err: refusal}
	}, nil, input)
	if !seen || !errors.Is(result.err, refusal) || result.completed {
		t.Fatalf("non-delete result=%+v", result)
	}
}

func TestRecombineDeletionSnapshotRetiresChargeAfterFailureAndCancel(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(strconv.FormatBool(cancel), func(t *testing.T) {
			input, _ := prepareRecombineDeletionTest(t)
			const baseline = 73
			if err := input.zipBudget.Reserve(baseline); err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			refusal := errors.New("executor failed")
			result := (&App{}).runCapturedOperation(ctx, func(context.Context, operationInput, volume.ProgressReporter) operationResult {
				if input.zipBudget.CurrentBytes() <= baseline {
					t.Fatal("manifest retired before executor returned")
				}
				if cancel {
					stop()
				}
				return operationResult{err: refusal}
			}, nil, input)
			if !errors.Is(result.err, refusal) || result.cancelled != cancel || input.zipBudget.CurrentBytes() != baseline {
				t.Fatalf("retirement result=%+v live=%d", result, input.zipBudget.CurrentBytes())
			}
		})
	}
}

func TestRecombineDeletionSnapshotFrozenVolume(t *testing.T) {
	const child = "PICOCRYPT_TEST_RECOMBINE_DELETION_CHILD"
	if os.Getenv(child) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(executable, "-test.run=^TestRecombineDeletionSnapshotFrozenVolume$", "-test.count=1", "-test.timeout=5m", "-test.v")
		command.Env = append(os.Environ(), child+"=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated frozen-volume decrypt: %v\n%s", err, output)
		}
		if !bytes.Contains(output, []byte("--- PASS: "+t.Name()+" (")) {
			t.Fatalf("isolated frozen-volume decrypt did not pass\n%s", output)
		}
		t.Logf("%s", output)
		return
	}
	input, chunks := prepareRecombineDeletionTest(t)
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	input.rsCodecs = rs
	want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	removed := 0
	var live uint64
	a := &App{operationSourceRemover: func(ctx context.Context, source deletionSource, directory bool) error {
		if input.zipBudget.CurrentBytes() != live || live == 0 {
			t.Fatal("manifest retired before source cleanup")
		}
		got, err := os.ReadFile(input.outputFile)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("source cleanup preceded exact plaintext publication: %v", err)
		}
		removed++
		return removeOperationSource(ctx, source, directory)
	}}
	result := a.runCapturedOperation(context.Background(), func(ctx context.Context, captured operationInput, reporter volume.ProgressReporter) operationResult {
		if len(captured.recombineInputs) != len(chunks) {
			t.Fatal("frozen reader lacks captured chunk set")
		}
		live = input.zipBudget.CurrentBytes()
		return executeVolumeOperation(ctx, captured, reporter)
	}, nil, input)
	if result.err != nil || !result.completed || result.cancelled || result.kept || result.deleteFailed || result.succeeded != 1 || removed != 2 {
		t.Fatalf("frozen-volume result=%+v removed=%d", result, removed)
	}
	got, err := os.ReadFile(input.outputFile)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("frozen plaintext changed: %q %v", got, err)
	}
	for path := range chunks {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("captured chunk remains: %s %v", path, err)
		}
	}
	if input.zipBudget.CurrentBytes() != 0 {
		t.Fatal("success retained manifest charge")
	}
}
