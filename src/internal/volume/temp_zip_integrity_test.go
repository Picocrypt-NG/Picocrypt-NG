package volume

import (
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type corruptPreparedZIPReporter struct {
	GoldenTestReporter
	directory string
	injected  bool
	t         *testing.T
}

func (r *corruptPreparedZIPReporter) SetStatus(status string) {
	if status != "Generating values..." || r.injected {
		return
	}
	entries, e := os.ReadDir(r.directory)
	if e != nil {
		r.t.Fatal(e)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-") {
			file, e := os.OpenFile(filepath.Join(r.directory, entry.Name()), os.O_RDWR, 0)
			if e != nil {
				r.t.Fatal(e)
			}
			var tag [1]byte
			info, e := file.Stat()
			if e != nil {
				file.Close()
				r.t.Fatal(e)
			}
			if _, e = file.ReadAt(tag[:], info.Size()-1); e != nil {
				file.Close()
				r.t.Fatal(e)
			}
			tag[0] ^= 1
			if _, e = file.WriteAt(tag[:], info.Size()-1); e != nil {
				file.Close()
				r.t.Fatal(e)
			}
			file.Close()
			r.injected = true
			return
		}
	}
	r.t.Fatal("preparation did not create encrypted stage")
}

// Corruption of an owned spool must fail before publication, including when
// legacy's payload loop normally accepts EOF with a final partial buffer.
func TestAuthenticatedTempZIPCorruptionNeverPublishesLegacyOutput(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	body := []byte("original remains intact when temporary tag is corrupted")
	if e := os.WriteFile(source, body, 0o600); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(source)
	if e != nil {
		t.Fatal(e)
	}
	codecs, e := encoding.NewRSCodecs()
	if e != nil {
		t.Fatal(e)
	}
	reporter := &corruptPreparedZIPReporter{directory: dir, t: t}
	e = Encrypt(context.Background(), &EncryptRequest{InputFile: source, OutputFile: filepath.Join(dir, "out.pcv"), Compress: true, Password: []byte("fixture password"), RSCodecs: codecs, Reporter: reporter})
	if e == nil || !reporter.injected {
		t.Fatalf("corrupt stage was accepted: injected=%t err=%v", reporter.injected, e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 || entries[0].Name() != "source" {
		t.Fatalf("failure published/retained output: %v %v", entries, e)
	}
	got, e := os.ReadFile(source)
	after, se := os.Stat(source)
	if e != nil || se != nil || !bytes.Equal(got, body) || !os.SameFile(info, after) {
		t.Fatal("original content or identity changed")
	}
}
