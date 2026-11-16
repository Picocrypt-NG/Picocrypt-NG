package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
)

func TestLegacyDropLabelsCommentsAsUnverifiedBeforeCredentials(t *testing.T) {
	resetLocalizationForTest(t)
	for _, version := range []string{"v1.33", "v2.00"} {
		t.Run(version, func(t *testing.T) {
			rs, err := encoding.NewRSCodecs()
			if err != nil {
				t.Fatal(err)
			}
			h := header.NewVolumeHeader(make([]byte, header.SaltSize), make([]byte, header.HKDFSaltSize), make([]byte, header.SerpentIVSize), make([]byte, header.NonceSize))
			h.Version, h.Comments = version, "unverified metadata"
			var data bytes.Buffer
			if _, err := header.NewWriter(&data, rs).WriteHeader(h); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "preview.pcv")
			if err := os.WriteFile(path, data.Bytes(), 0o600); err != nil {
				t.Fatal(err)
			}
			fyneApp := newTestFyneApp(t)
			a := createUIReadyDropTestApp(t, fyneApp)
			fyne.DoAndWait(func() { a.applyStartupPaths([]string{path}) })
			waitForDropProcessing(t, a)
			fyne.DoAndWait(func() {
				s := a.State.UISnapshot()
				if s.Mode != "decrypt" || s.Comments != h.Comments {
					t.Fatalf("preview not loaded: %+v", s.InputSummary)
				}
				if s.CommentsPreviewState != app.CommentsPreviewUnverified || a.commentsLabel.Text != "Comments (not verified):" {
					t.Fatalf("legacy preview conceals comment trust: state=%v label=%q", s.CommentsPreviewState, a.commentsLabel.Text)
				}
			})
		})
	}
}
