package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3operation"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"runtime/debug"
	"testing"
)

// BenchmarkEncryptProduction24MiB compares complete encryption operations with
// their fixed production KDFs. The shared, deterministic incompressible input
// models already-compressed data; it is unrelated to any user's document.
func BenchmarkEncryptProduction24MiB(b *testing.B) {
	// TestMain speeds up ordinary legacy tests. Performance comparisons must
	// restore the real legacy derivations as well as PCV3's production KDF.
	restore := useProductionTestKDF()
	defer restore()
	const inputBytes = 24 << 20
	inputPath := filepath.Join(b.TempDir(), "incompressible.bin")
	input, err := os.OpenFile(inputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		b.Fatal(err)
	}
	// io.CopyN generates the public fixture in bounded chunks. This PRNG is
	// only a reproducible benchmark-data source, never cryptographic randomness.
	_, copyErr := io.CopyN(input, rand.New(rand.NewSource(1)), inputBytes) //nolint:gosec // Public deterministic fixture.
	closeErr := input.Close()
	if copyErr != nil || closeErr != nil {
		b.Fatalf("prepare input: write=%v close=%v", copyErr, closeErr)
	}
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		b.Fatal(err)
	}

	for _, mode := range []struct {
		name        string
		pcv3        bool
		paranoid    bool
		deniability bool
	}{
		{"LegacyV2_Paranoid_Deniability_Compress", false, true, true},
		{"PCV3_Standard_Compress", true, false, false},
		{"PCV3_Paranoid_Compress", true, true, false},
		{"PCV3_Paranoid_D1_Compress", true, true, true},
	} {
		b.Run(mode.name, func(b *testing.B) {
			b.StopTimer()
			outputPath := filepath.Join(b.TempDir(), "encrypted.zip.pcv")
			b.SetBytes(inputBytes)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				b.StartTimer()
				result, err := EncryptWithResult(b.Context(), &EncryptRequest{
					InputFile: inputPath, OutputFile: outputPath,
					Password: []byte("public encryption benchmark password"),
					PCV3:     mode.pcv3, Paranoid: mode.paranoid,
					Deniability: mode.deniability, Compress: true, RSCodecs: rs,
				}, pcv3operation.ExecutionOptions{})
				// EncryptWithResult has already completed its real source,
				// temporary archive, and sensitive-memory cleanup before this stop.
				b.StopTimer()
				if err != nil {
					b.Fatalf("encrypt: %v", err)
				}
				if mode.pcv3 {
					if result == nil || result.CompletionClass() != pcv3operation.CompletionClean {
						b.Fatalf("PCV3 encryption did not complete cleanly: %v", result)
					}
				} else if result != nil {
					b.Fatalf("legacy encryption returned a PCV3 result: %v", result)
				}
				outputInfo, err := os.Stat(outputPath)
				if err != nil || !outputInfo.Mode().IsRegular() || outputInfo.Size() <= 0 {
					b.Fatalf("encryption did not publish a nonempty regular volume: %v", err)
				}
				inputInfo, err := os.Stat(inputPath)
				if err != nil || inputInfo.Size() != inputBytes {
					b.Fatalf("encryption removed or resized its input: %v", err)
				}
				if err := os.Remove(outputPath); err != nil {
					b.Fatalf("remove benchmark-owned output: %v", err)
				}
				// Keep previous production KDF allocations out of the next
				// iteration's resource-admission decision in every case.
				debug.FreeOSMemory()
			}
		})
	}
}
