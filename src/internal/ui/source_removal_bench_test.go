package ui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func BenchmarkOperationSourceCleanup(b *testing.B) {
	for _, count := range []int{1, 128, 1024} {
		for _, separate := range []bool{false, true} {
			parents := "shared"
			if separate {
				parents = "separate"
			}
			b.Run(fmt.Sprintf("%s/%d", parents, count), func(b *testing.B) {
				b.StopTimer()
				dir := b.TempDir()
				output := filepath.Join(dir, "ready-output")
				if err := os.WriteFile(output, []byte("ready output"), 0o600); err != nil {
					b.Fatal(err)
				}
				a := &App{}
				input := operationInput{mode: "decrypt", delete: true}
				b.ReportAllocs()
				for range b.N {
					sources := make([]deletionSource, 0, count)
					for n := range count {
						parent := dir
						if separate {
							parent = filepath.Join(dir, strconv.Itoa(n))
							if err := os.Mkdir(parent, 0o700); err != nil {
								b.Fatal(err)
							}
						}
						path := filepath.Join(parent, fmt.Sprintf("source-%d", n))
						if err := os.WriteFile(path, []byte("captured source"), 0o600); err != nil {
							b.Fatal(err)
						}
						source, err := captureDeletionSource(path, false)
						if err != nil {
							b.Fatal(err)
						}
						sources = append(sources, source)
					}
					manifest := &operationDeletionManifest{files: sources}
					// A completed legacy result isolates filesystem cleanup from KDF work.
					completed := operationResult{completed: true}
					b.StartTimer()
					result := a.cleanupOperationSources(context.Background(), input, manifest, completed)
					b.StopTimer()
					if result.err != nil || !result.completed || result.cancelled || result.deleteFailed {
						b.Fatalf("cleanup=%+v", result)
					}
					if body, err := os.ReadFile(output); err != nil || string(body) != "ready output" {
						b.Fatalf("output bytes=%q error=%v", body, err)
					}
					for _, source := range sources {
						if _, err := os.Lstat(source.path); !os.IsNotExist(err) {
							b.Fatalf("source remains: %v", err)
						}
						if separate {
							if err := os.Remove(filepath.Dir(source.path)); err != nil {
								b.Fatal(err)
							}
						}
					}
				}
			})
		}
	}
}
