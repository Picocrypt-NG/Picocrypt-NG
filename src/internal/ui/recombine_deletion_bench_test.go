package ui

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func BenchmarkCaptureRecombineDeletionManifest(b *testing.B) {
	for _, count := range []int{1, 128, 1024} {
		b.Run(fmt.Sprintf("N%d", count), func(b *testing.B) {
			b.StopTimer()
			base := filepath.Join(b.TempDir(), "input.pcv")
			for i := range count {
				if err := os.WriteFile(base+"."+strconv.Itoa(i), []byte{byte(i)}, 0o600); err != nil {
					b.Fatal(err)
				}
			}
			budget := fileops.NewZIPResourceBudget()
			input := operationInput{mode: "decrypt", inputFile: base + ".0", recombine: true, delete: true}
			b.ReportAllocs()
			for range b.N {
				b.StartTimer()
				manifest, err := captureOperationDeletionManifestWithBudget(context.Background(), input, budget)
				b.StopTimer()
				if err != nil {
					b.Fatal(err)
				}
				if manifest == nil || len(manifest.files) != count || budget.CurrentBytes() != manifest.charged || manifest.charged == 0 {
					b.Fatalf("capture lost sources or charge: manifest=%+v live=%d", manifest, budget.CurrentBytes())
				}
				for i, source := range manifest.files {
					if source.path != base+"."+strconv.Itoa(i) || source.info.Size() != 1 {
						b.Fatalf("capture changed source order or size: %+v", source)
					}
				}
				if !budget.Release(manifest.charged) || budget.CurrentBytes() != 0 {
					b.Fatal("capture charge did not retire")
				}
			}
			for i := range count {
				got, err := os.ReadFile(base + "." + strconv.Itoa(i))
				if err != nil || len(got) != 1 || got[0] != byte(i) {
					b.Fatalf("capture changed source %d: %v", i, err)
				}
			}
			entries, err := os.ReadDir(filepath.Dir(base))
			if err != nil || len(entries) != count {
				b.Fatalf("capture changed fixture tree: %v %v", entries, err)
			}
		})
	}
}
