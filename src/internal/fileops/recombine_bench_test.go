package fileops

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func BenchmarkRecombineExpectedInputs(b *testing.B) {
	const payloadBytes = 16 << 20
	for _, count := range []int{1, 16, 128} {
		for _, pinned := range []bool{false, true} {
			label := "nil"
			if pinned {
				label = "unchanged"
			}
			b.Run(fmt.Sprintf("N%d/%s", count, label), func(b *testing.B) {
				b.StopTimer()
				payload := make([]byte, payloadBytes)
				for i := range payload {
					payload[i] = byte(i*31 + 7)
				}
				base := filepath.Join(b.TempDir(), "input.pcv")
				expected := make([]os.FileInfo, count)
				chunkBytes := payloadBytes / count
				for i := range count {
					path := base + "." + strconv.Itoa(i)
					if err := os.WriteFile(path, payload[i*chunkBytes:(i+1)*chunkBytes], 0o600); err != nil {
						b.Fatal(err)
					}
					file, err := os.Open(path)
					if err != nil {
						b.Fatal(err)
					}
					expected[i], err = file.Stat()
					closeErr := file.Close()
					if err != nil || closeErr != nil {
						b.Fatalf("capture benchmark input: %v %v", err, closeErr)
					}
				}
				var inputs []os.FileInfo
				if pinned {
					inputs = expected
				}
				b.ReportAllocs()
				b.SetBytes(payloadBytes)
				for range b.N {
					opts := RecombineOptions{InputBase: base, OutputPath: base, ExpectedInputs: inputs}
					b.StartTimer()
					err := Recombine(opts)
					b.StopTimer()
					if err != nil {
						b.Fatal(err)
					}
					got, err := os.ReadFile(base)
					if err != nil || !bytes.Equal(got, payload) {
						b.Fatalf("recombined bytes changed: %v", err)
					}
					if err := os.Remove(base); err != nil {
						b.Fatal(err)
					}
				}
				for i := range count {
					path := base + "." + strconv.Itoa(i)
					got, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(got, payload[i*chunkBytes:(i+1)*chunkBytes]) {
						b.Fatalf("recombination changed source %d: %v", i, err)
					}
				}
				entries, err := os.ReadDir(filepath.Dir(base))
				if err != nil || len(entries) != count {
					b.Fatalf("recombination left residue: %v %v", entries, err)
				}
			})
		}
	}
}
