package fileops

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSplitAndRecombine tests the full cycle of splitting and recombining a file.
func TestSplitAndRecombine(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test file with known content
	testData := bytes.Repeat([]byte("Hello, Picocrypt! "), 1000) // ~18 KB
	inputPath := filepath.Join(tmpDir, "test.pcv")
	if err := os.WriteFile(inputPath, testData, 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	// Split into 5 KiB chunks
	chunks, err := Split(SplitOptions{
		InputPath: inputPath,
		ChunkSize: 5,
		Unit:      SplitUnitKiB,
	})
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// Verify we got multiple chunks
	if len(chunks) < 2 {
		t.Errorf("Expected multiple chunks, got %d", len(chunks))
	}

	// Verify chunks exist. The exact suffix naming is covered elsewhere; here we
	// care that every returned chunk is a real file backing the round-trip below.
	for i, chunk := range chunks {
		if _, err := os.Stat(chunk); err != nil {
			t.Errorf("Chunk %d does not exist: %v", i, err)
		}
	}

	t.Logf("Split into %d chunks", len(chunks))

	// Recombine
	recombinedPath := filepath.Join(tmpDir, "recombined.pcv")
	err = Recombine(RecombineOptions{
		InputBase:  inputPath,
		OutputPath: recombinedPath,
	})
	if err != nil {
		t.Fatalf("Recombine failed: %v", err)
	}

	// Verify recombined file matches original
	recombinedData, err := os.ReadFile(recombinedPath)
	if err != nil {
		t.Fatalf("Read recombined file: %v", err)
	}

	if !bytes.Equal(testData, recombinedData) {
		t.Error("Recombined data does not match original")
		t.Logf("Original length: %d, Recombined length: %d", len(testData), len(recombinedData))
	}

	t.Log("Split and recombine cycle successful")
}

// TestSplitUnits tests different split unit types.
func TestSplitUnits(t *testing.T) {
	testCases := []struct {
		name      string
		unit      SplitUnit
		chunkSize int
		dataSize  int
		minChunks int
		maxChunks int
	}{
		{"KiB", SplitUnitKiB, 1, 3 * 1024, 3, 3},         // 3 KiB into 1 KiB chunks = 3 chunks
		{"MiB", SplitUnitMiB, 1, 1024 * 1024, 1, 1},      // 1 MiB into 1 MiB chunks = 1 chunk
		{"Total_3parts", SplitUnitTotal, 3, 9000, 3, 3},  // 9000 bytes into 3 parts
		{"Total_5parts", SplitUnitTotal, 5, 10000, 5, 5}, // 10000 bytes into 5 parts
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Create test data
			testData := bytes.Repeat([]byte("X"), tc.dataSize)
			inputPath := filepath.Join(tmpDir, "test.dat")
			if err := os.WriteFile(inputPath, testData, 0o644); err != nil {
				t.Fatalf("Create test file: %v", err)
			}

			chunks, err := Split(SplitOptions{
				InputPath: inputPath,
				ChunkSize: tc.chunkSize,
				Unit:      tc.unit,
			})
			if err != nil {
				t.Fatalf("Split failed: %v", err)
			}

			if len(chunks) < tc.minChunks || len(chunks) > tc.maxChunks {
				t.Errorf("Expected %d-%d chunks, got %d", tc.minChunks, tc.maxChunks, len(chunks))
			}

			// Verify total size matches
			var totalChunkSize int64
			for _, chunk := range chunks {
				stat, err := os.Stat(chunk)
				if err != nil {
					t.Fatalf("Stat chunk: %v", err)
				}
				totalChunkSize += stat.Size()
			}

			if totalChunkSize != int64(tc.dataSize) {
				t.Errorf("Total chunk size %d != original size %d", totalChunkSize, tc.dataSize)
			}

			// Round-trip each subcase. Total-size equality alone is blind to
			// off-by-one boundary math that shuffles bytes across chunk edges
			// while preserving the byte count; recombining and comparing against
			// the original payload catches that corruption.
			recombinedPath := filepath.Join(tmpDir, "recombined.dat")
			if err := Recombine(RecombineOptions{
				InputBase:  inputPath,
				OutputPath: recombinedPath,
			}); err != nil {
				t.Fatalf("Recombine failed: %v", err)
			}
			got, err := os.ReadFile(recombinedPath)
			if err != nil {
				t.Fatalf("Read recombined file: %v", err)
			}
			if !bytes.Equal(got, testData) {
				t.Errorf("recombined data != original (len got %d, want %d)", len(got), len(testData))
			}

			t.Logf("Split %d bytes into %d chunks with unit %s", tc.dataSize, len(chunks), tc.name)
		})
	}
}

func TestSplitDoesNotDeleteSidecarFiles(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "archive.pcv")

	if err := os.WriteFile(inputPath, bytes.Repeat([]byte("A"), 32*1024), 0o644); err != nil {
		t.Fatalf("Create input file: %v", err)
	}
	if err := os.WriteFile(inputPath+".sig", []byte("sig"), 0o644); err != nil {
		t.Fatalf("Create signature sidecar: %v", err)
	}
	if err := os.WriteFile(inputPath+".backup", []byte("backup"), 0o644); err != nil {
		t.Fatalf("Create backup sidecar: %v", err)
	}
	if err := os.WriteFile(inputPath+".-1", []byte("signed"), 0o644); err != nil {
		t.Fatalf("Create signed sidecar: %v", err)
	}
	if err := os.WriteFile(inputPath+".+1.incomplete", []byte("signed incomplete"), 0o644); err != nil {
		t.Fatalf("Create signed incomplete sidecar: %v", err)
	}

	_, err := Split(SplitOptions{
		InputPath: inputPath,
		ChunkSize: 8,
		Unit:      SplitUnitKiB,
	})
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if _, err := os.Stat(inputPath + ".sig"); err != nil {
		t.Fatalf(".sig sidecar should remain: %v", err)
	}
	if _, err := os.Stat(inputPath + ".backup"); err != nil {
		t.Fatalf(".backup sidecar should remain: %v", err)
	}
	if _, err := os.Stat(inputPath + ".-1"); err != nil {
		t.Fatalf(".-1 sidecar should remain: %v", err)
	}
	if _, err := os.Stat(inputPath + ".+1.incomplete"); err != nil {
		t.Fatalf(".+1.incomplete sidecar should remain: %v", err)
	}
}

// TestSplitCancellation tests that split can be cancelled.
func TestSplitCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a larger test file
	testData := bytes.Repeat([]byte("Data"), 100000) // 400 KB
	inputPath := filepath.Join(tmpDir, "test.dat")
	if err := os.WriteFile(inputPath, testData, 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	// Cancel mid-stream rather than before the first byte: return true only AFTER
	// several invocations, by which point Split has created a random chunk stage.
	// This exercises the owned-stage cleanup path, not just the pre-loop guard.
	calls := 0
	observedRandomStage := false
	_, err := Split(SplitOptions{
		InputPath: inputPath,
		ChunkSize: 1,
		Unit:      SplitUnitKiB,
		Cancel: func() bool {
			calls++
			if calls <= 3 {
				return false
			}
			entries, readErr := os.ReadDir(tmpDir)
			if readErr != nil {
				t.Fatalf("read split directory during cancellation: %v", readErr)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".picocrypt-") {
					observedRandomStage = true
				}
			}
			return true
		},
	})

	if err == nil {
		t.Fatal("Expected cancellation error, got nil")
	}

	if err.Error() != "operation cancelled" {
		t.Errorf("Expected 'operation cancelled' error, got: %v", err)
	}
	if calls <= 3 {
		t.Fatalf("Cancel fired too early (%d calls); cancellation was not mid-stream", calls)
	}
	if !observedRandomStage {
		t.Error("Split did not use a random sibling stage for the in-progress chunk")
	}

	// Security/data-integrity outcome: no completed chunk or random stage may
	// leak after cancellation.
	chunks, _ := filepath.Glob(inputPath + ".*")
	if len(chunks) > 0 {
		t.Errorf("Expected no chunks after cancellation, found %v", chunks)
	}
	entries, readErr := os.ReadDir(tmpDir)
	if readErr != nil {
		t.Fatalf("read split directory after cancellation: %v", readErr)
	}
	for _, entry := range entries {
		if entry.Name() != filepath.Base(inputPath) {
			t.Errorf("unexpected split artifact after cancellation: %s", entry.Name())
		}
	}
}

// TestRecombineCancellation tests that recombine can be cancelled.
func TestRecombineCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create chunks manually
	for i := range 5 {
		chunkData := bytes.Repeat([]byte{byte(i)}, 1000)
		chunkPath := filepath.Join(tmpDir, "test.pcv."+string(rune('0'+i)))
		if err := os.WriteFile(chunkPath, chunkData, 0o644); err != nil {
			t.Fatalf("Create chunk: %v", err)
		}
	}

	// Cancel mid-stream: return true only AFTER several invocations, by which
	// point Recombine has created the output file and written at least one chunk
	// into it. This exercises the partial-output cleanup path, not the pre-loop
	// guard that fires before any bytes land.
	outputPath := filepath.Join(tmpDir, "output.pcv")
	calls := 0
	err := Recombine(RecombineOptions{
		InputBase:  filepath.Join(tmpDir, "test.pcv"),
		OutputPath: outputPath,
		Cancel: func() bool {
			calls++
			return calls > 3
		},
	})

	if err == nil {
		t.Fatal("Expected cancellation error, got nil")
	}

	if err.Error() != "operation cancelled" {
		t.Errorf("Expected 'operation cancelled' error, got: %v", err)
	}
	if calls <= 3 {
		t.Fatalf("Cancel fired too early (%d calls); cancellation was not mid-stream", calls)
	}

	// Security/data-integrity outcome: the partially-written output must be
	// removed. A mutation that skips cleanup on mid-stream cancel leaves a
	// truncated file the caller could mistake for a complete recombination.
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Errorf("Expected output file to be removed after cancellation, stat err = %v", statErr)
	}
}

// TestCountChunks tests the chunk counting function.
func TestCountChunks(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")

	// No chunks: must report the specific "no chunks found" sentinel and yield
	// the zero count/size. A mutation that returns a bogus success (e.g. count=1)
	// would let Recombine proceed against a non-existent chunk set.
	noCount, noSize, err := CountChunks(basePath)
	if err == nil {
		t.Fatal("Expected error for no chunks")
	}
	if !strings.Contains(err.Error(), "no chunks found") {
		t.Errorf("error = %v; want it to contain %q", err, "no chunks found")
	}
	if noCount != 0 || noSize != 0 {
		t.Errorf("CountChunks(empty) = (%d, %d); want (0, 0)", noCount, noSize)
	}

	// Create some chunks
	chunkSizes := []int{100, 200, 150}
	for i, sz := range chunkSizes {
		chunkPath := basePath + "." + string(rune('0'+i))
		if err := os.WriteFile(chunkPath, bytes.Repeat([]byte{0}, sz), 0o644); err != nil {
			t.Fatalf("Create chunk: %v", err)
		}
	}

	count, size, err := CountChunks(basePath)
	if err != nil {
		t.Fatalf("CountChunks failed: %v", err)
	}

	if count != 3 {
		t.Errorf("Expected 3 chunks, got %d", count)
	}

	expectedSize := int64(100 + 200 + 150)
	if size != expectedSize {
		t.Errorf("Expected total size %d, got %d", expectedSize, size)
	}

	t.Logf("CountChunks: found %d chunks, %d bytes total", count, size)
}

// TestRecombineOutputExists tests that recombine fails if output exists.
func TestRecombineOutputExists(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")
	outputPath := filepath.Join(tmpDir, "output.pcv")

	// Create a chunk
	if err := os.WriteFile(basePath+".0", []byte("chunk0"), 0o644); err != nil {
		t.Fatalf("Create chunk: %v", err)
	}

	// Create output file with sentinel content (a stand-in for a victim file the
	// user does not want clobbered).
	victim := []byte("existing")
	if err := os.WriteFile(outputPath, victim, 0o644); err != nil {
		t.Fatalf("Create output file: %v", err)
	}

	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})

	if err == nil {
		t.Fatal("Expected error for existing output file")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %v; want it to contain %q", err, "already exists")
	}

	// Security outcome: the pre-existing file must be untouched. If the
	// overwrite-refusal were dropped, Recombine would truncate/replace the victim.
	if got, readErr := os.ReadFile(outputPath); readErr != nil {
		t.Fatalf("pre-existing output should remain readable: %v", readErr)
	} else if !bytes.Equal(got, victim) {
		t.Errorf("pre-existing output was modified: got %q, want %q", got, victim)
	}
}

// TestSplitProgress tests that progress callback is called.
func TestSplitProgress(t *testing.T) {
	tmpDir := t.TempDir()

	testData := bytes.Repeat([]byte("X"), 10*1024) // 10 KiB
	inputPath := filepath.Join(tmpDir, "test.dat")
	if err := os.WriteFile(inputPath, testData, 0o644); err != nil {
		t.Fatalf("Create test file: %v", err)
	}

	progressCalls := 0
	statusCalls := 0
	var lastProgress float32

	_, err := Split(SplitOptions{
		InputPath: inputPath,
		ChunkSize: 1,
		Unit:      SplitUnitKiB,
		Progress: func(p float32, info string) {
			progressCalls++
			lastProgress = p
		},
		Status: func(s string) {
			statusCalls++
		},
	})
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	if progressCalls == 0 {
		t.Error("Progress callback was never called")
	}
	if statusCalls == 0 {
		t.Error("Status callback was never called")
	}

	// Progress must actually reach completion, mirroring TestRecombineProgress.
	// A mutation that stops reporting partway (or reports a stale fraction) would
	// leave the final value short of ~1.0 even though every byte was written.
	if lastProgress < 0.99 {
		t.Errorf("Last progress = %f; want ~1.0", lastProgress)
	}

	t.Logf("Progress called %d times, Status called %d times", progressCalls, statusCalls)
}

// TestRecombineProgress tests that progress callback is called during recombine.
func TestRecombineProgress(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")

	// Create chunks with enough data to trigger progress updates
	chunkData := bytes.Repeat([]byte("X"), 10*1024) // 10 KiB per chunk
	for i := range 3 {
		chunkPath := basePath + "." + string(rune('0'+i))
		if err := os.WriteFile(chunkPath, chunkData, 0o644); err != nil {
			t.Fatalf("Create chunk: %v", err)
		}
	}

	progressCalls := 0
	statusCalls := 0
	var lastProgress float32

	outputPath := filepath.Join(tmpDir, "output.pcv")
	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
		Progress: func(p float32, info string) {
			progressCalls++
			lastProgress = p
		},
		Status: func(s string) {
			statusCalls++
		},
	})
	if err != nil {
		t.Fatalf("Recombine failed: %v", err)
	}

	if progressCalls == 0 {
		t.Error("Progress callback was never called")
	}
	if statusCalls == 0 {
		t.Error("Status callback was never called")
	}

	// Last progress should be close to 1.0
	if lastProgress < 0.99 {
		t.Errorf("Last progress = %f; want ~1.0", lastProgress)
	}

	t.Logf("Progress called %d times, Status called %d times", progressCalls, statusCalls)
}

// TestRecombineRejectsMissingMiddleChunk tests error handling when a chunk is missing.
func TestRecombineRejectsMissingMiddleChunk(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")

	// Create only chunk 0, missing chunk 1
	if err := os.WriteFile(basePath+".0", []byte("chunk0"), 0o644); err != nil {
		t.Fatalf("Create chunk: %v", err)
	}
	// Create chunk 2 (skipping 1)
	if err := os.WriteFile(basePath+".2", []byte("chunk2"), 0o644); err != nil {
		t.Fatalf("Create chunk: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "output.pcv")
	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})

	if err == nil {
		t.Fatal("expected missing chunk error")
	}

	// Name the gap explicitly: chunks .0 and .2 exist but .1 is absent. If the
	// contiguity check were dropped, Recombine would either succeed silently or
	// fail on .1's open with a different message; "missing chunk 1" proves the
	// index-gap detection fired before any I/O.
	if !strings.Contains(err.Error(), "missing chunk 1") {
		t.Errorf("error = %v; want it to contain %q", err, "missing chunk 1")
	}

	// No partial/corrupt output must be left behind for the caller to mistake
	// for a complete recombination.
	if _, statErr := os.Stat(outputPath); !os.IsNotExist(statErr) {
		t.Errorf("output should not exist after rejection, stat err = %v", statErr)
	}
}

func TestRecombineRejectsSymlinkOutput(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")

	if err := os.WriteFile(basePath+".0", []byte("chunk0"), 0o644); err != nil {
		t.Fatalf("Create chunk: %v", err)
	}

	outsideDir := filepath.Join(tmpDir, "outside")
	if err := os.MkdirAll(outsideDir, 0o755); err != nil {
		t.Fatalf("Create outside dir: %v", err)
	}
	targetPath := filepath.Join(outsideDir, "owned.pcv")
	outputPath := filepath.Join(tmpDir, "output.pcv")
	if err := os.Symlink(targetPath, outputPath); err != nil {
		t.Skipf("Symlinks unavailable on this platform: %v", err)
	}

	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})
	if err == nil {
		t.Fatal("expected symlink rejection")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "symlink") {
		t.Errorf("error = %v; want it to mention a symlink rejection", err)
	}

	// Security outcome: the symlink must NOT have been followed. If Recombine
	// opened the link with O_CREATE-following semantics, it would have created
	// and written targetPath inside outsideDir (a write outside the intended dir).
	if _, statErr := os.Stat(targetPath); !os.IsNotExist(statErr) {
		t.Errorf("symlink target %q must not be created/written, stat err = %v", targetPath, statErr)
	}
}

func TestRecombineIgnoresSignedChunkLikeSuffixes(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")

	if err := os.WriteFile(basePath+".0", []byte("chunk0"), 0o644); err != nil {
		t.Fatalf("Create chunk 0: %v", err)
	}
	if err := os.WriteFile(basePath+".+1", []byte("plus1"), 0o644); err != nil {
		t.Fatalf("Create signed sidecar: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "output.pcv")
	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})
	if err != nil {
		t.Fatalf("Recombine should ignore signed suffix sidecar: %v", err)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Read output: %v", err)
	}
	if string(content) != "chunk0" {
		t.Fatalf("output = %q, want %q", string(content), "chunk0")
	}
}

func TestCountChunksHandlesLiteralGlobCharacters(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "file[1].pcv")

	if err := os.WriteFile(basePath+".0", []byte("chunk0"), 0o644); err != nil {
		t.Fatalf("Create chunk: %v", err)
	}

	count, total, err := CountChunks(basePath)
	if err != nil {
		t.Fatalf("CountChunks returned error: %v", err)
	}
	if count != 1 {
		t.Fatalf("CountChunks count = %d; want 1", count)
	}
	if total != int64(len("chunk0")) {
		t.Fatalf("CountChunks total = %d; want %d", total, len("chunk0"))
	}
}

func TestSplitRejectsNonPositiveChunkSize(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "invalid_split.pcv")
	content := []byte("content")
	if err := os.WriteFile(inputPath, content, 0o644); err != nil {
		t.Fatalf("Create input: %v", err)
	}

	_, err := Split(SplitOptions{
		InputPath: inputPath,
		ChunkSize: 0,
		Unit:      SplitUnitKiB,
	})
	if err == nil {
		t.Fatal("expected invalid chunk size error")
	}

	// Reject for the specific reason. If the guard is relaxed (e.g. <0 instead
	// of <=0), a ChunkSize of 0 would divide by zero / spin, so the precise
	// message proves the >0 guard fired.
	if !strings.Contains(err.Error(), "greater than zero") {
		t.Errorf("error = %v; want it to contain %q", err, "greater than zero")
	}

	// Security/data-loss outcome: no chunk artifacts created. volume.Encrypt
	// removes the source .pcv on a nil error from Split, so a silently-accepted
	// bad size that produced partial chunks could destroy data.
	chunks, _ := filepath.Glob(inputPath + ".*")
	if len(chunks) != 0 {
		t.Errorf("expected no chunks after rejection, found %v", chunks)
	}

	// Input must be left byte-for-byte intact for the caller to recover.
	if got, readErr := os.ReadFile(inputPath); readErr != nil {
		t.Fatalf("input should remain readable: %v", readErr)
	} else if !bytes.Equal(got, content) {
		t.Error("input file was modified despite the error")
	}
}

// TestSplitRejectsOverflowingChunkSize verifies that a chunk size which overflows
// int64 when scaled to bytes fails loudly instead of silently producing zero chunks.
//
// Silent failure is dangerous: volume.Encrypt treats a nil error from Split as success
// and then removes the just-written .pcv, so an unguarded overflow destroys the
// encrypted output (data loss). The conversion overflows when ChunkSize*unit exceeds
// math.MaxInt64; for TiB (2^40) that is any ChunkSize >= 2^23.
func TestSplitRejectsOverflowingChunkSize(t *testing.T) {
	cases := []struct {
		name      string
		chunkSize int
		unit      SplitUnit
	}{
		{"TiB_boundary", 1 << 23, SplitUnitTiB},    // 2^23 * 2^40 = 2^63, wraps to negative
		{"TiB_large", 1_000_000_000, SplitUnitTiB}, // far past the overflow threshold
		{"GiB_boundary", 1 << 33, SplitUnitGiB},    // 2^33 * 2^30 = 2^63, wraps to negative
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			inputPath := filepath.Join(tmpDir, "overflow.pcv")
			content := bytes.Repeat([]byte("Z"), 4096)
			if err := os.WriteFile(inputPath, content, 0o644); err != nil {
				t.Fatalf("Create input: %v", err)
			}

			chunks, err := Split(SplitOptions{
				InputPath: inputPath,
				ChunkSize: tc.chunkSize,
				Unit:      tc.unit,
			})
			if err == nil {
				t.Fatalf("expected overflow error, got nil (chunks=%v)", chunks)
			}
			if len(chunks) != 0 {
				t.Errorf("expected no chunks on error, got %d", len(chunks))
			}

			// The original input must be left intact so the caller can handle the error.
			if got, readErr := os.ReadFile(inputPath); readErr != nil {
				t.Fatalf("input file should remain readable: %v", readErr)
			} else if !bytes.Equal(got, content) {
				t.Error("input file was modified despite the error")
			}
		})
	}
}

// TestChunkSizeToBytes verifies the shared checked unit->bytes conversion: valid
// sizes scale correctly and overflowing sizes are rejected rather than wrapping.
func TestChunkSizeToBytes(t *testing.T) {
	cases := []struct {
		name      string
		chunkSize int
		unit      SplitUnit
		want      int64
		wantErr   bool
	}{
		{"KiB", 4, SplitUnitKiB, 4 << 10, false},
		{"MiB", 2, SplitUnitMiB, 2 << 20, false},
		{"GiB", 1, SplitUnitGiB, 1 << 30, false},
		{"TiB", 1, SplitUnitTiB, 1 << 40, false},
		{"Total_passthrough", 7, SplitUnitTotal, 7, false}, // size-relative: unscaled, cannot overflow
		{"TiB_overflow", 1 << 23, SplitUnitTiB, 0, true},   // 2^23 * 2^40 = 2^63 > MaxInt64
		{"GiB_overflow", 1 << 33, SplitUnitGiB, 0, true},   // 2^33 * 2^30 = 2^63 > MaxInt64
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ChunkSizeToBytes(tc.chunkSize, tc.unit)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ChunkSizeToBytes(%d, %v) = %d, nil; want error", tc.chunkSize, tc.unit, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ChunkSizeToBytes(%d, %v) unexpected error: %v", tc.chunkSize, tc.unit, err)
			}
			if got != tc.want {
				t.Errorf("ChunkSizeToBytes(%d, %v) = %d; want %d", tc.chunkSize, tc.unit, got, tc.want)
			}
		})
	}
}

// TestSplitRejectsOccupiedFinalDirectory asserts that a non-empty directory at
// a final chunk path is treated as foreign state and left untouched.
func TestSplitRejectsOccupiedFinalDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	inputPath := filepath.Join(tmpDir, "test.pcv")

	// Small file → exactly 1 final chunk path to check.
	if err := os.WriteFile(inputPath, bytes.Repeat([]byte("A"), 1024), 0o644); err != nil {
		t.Fatalf("create input: %v", err)
	}

	finalPath := inputPath + ".0"
	sentinelPath := filepath.Join(finalPath, "sentinel")
	if err := os.MkdirAll(sentinelPath, 0o755); err != nil {
		t.Fatalf("create blocking dir: %v", err)
	}

	_, err := Split(SplitOptions{
		InputPath: inputPath,
		ChunkSize: 4, // 4 KiB chunk — larger than the file, so 1 chunk
		Unit:      SplitUnitKiB,
	})
	if err == nil {
		t.Fatal("expected occupied-output error, got nil")
	}

	if info, statErr := os.Stat(sentinelPath); statErr != nil {
		t.Errorf("foreign directory was changed: %v", statErr)
	} else if !info.IsDir() {
		t.Errorf("foreign sentinel mode = %v, want directory", info.Mode())
	}
	entries, readErr := os.ReadDir(tmpDir)
	if readErr != nil {
		t.Fatalf("read split directory: %v", readErr)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-") {
			t.Errorf("leftover random stage after occupied-output rejection: %s", entry.Name())
		}
	}
}

// TestRecombineLargeChunks tests recombining larger chunks.
func TestRecombineLargeChunks(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")

	// Create chunks larger than the internal buffer (1 MiB)
	chunkData := bytes.Repeat([]byte("Y"), 2*1024*1024) // 2 MiB per chunk
	for i := range 2 {
		chunkPath := basePath + "." + string(rune('0'+i))
		if err := os.WriteFile(chunkPath, chunkData, 0o644); err != nil {
			t.Fatalf("Create chunk: %v", err)
		}
	}

	outputPath := filepath.Join(tmpDir, "output.pcv")
	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})
	if err != nil {
		t.Fatalf("Recombine failed: %v", err)
	}

	// Verify output size
	stat, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("Stat output: %v", err)
	}

	expectedSize := int64(2 * 2 * 1024 * 1024) // 2 chunks * 2 MiB
	if stat.Size() != expectedSize {
		t.Errorf("Output size = %d; want %d", stat.Size(), expectedSize)
	}
}

// TestRecombineSingleChunk tests recombining a single chunk.
func TestRecombineSingleChunk(t *testing.T) {
	tmpDir := t.TempDir()
	basePath := filepath.Join(tmpDir, "test.pcv")

	chunkData := []byte("single chunk content")
	if err := os.WriteFile(basePath+".0", chunkData, 0o644); err != nil {
		t.Fatalf("Create chunk: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "output.pcv")
	err := Recombine(RecombineOptions{
		InputBase:  basePath,
		OutputPath: outputPath,
	})
	if err != nil {
		t.Fatalf("Recombine failed: %v", err)
	}

	// Verify content
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Read output: %v", err)
	}

	if !bytes.Equal(content, chunkData) {
		t.Error("Recombined content does not match original chunk")
	}
}
