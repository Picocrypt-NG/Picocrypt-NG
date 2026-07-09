package ui

import (
	"path/filepath"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

func TestKeyfileDisplayLabelUsesSemanticState(t *testing.T) {
	tests := []struct {
		name       string
		required   bool
		count      int
		applicable bool
		want       string
	}{
		{name: "not applicable", applicable: false, want: tr("keyfiles.not_applicable", "Not applicable")},
		{name: "none selected", applicable: true, want: tr("keyfiles.none_selected", "None selected")},
		{name: "required", required: true, applicable: true, want: tr("keyfiles.required", "Keyfiles required")},
		{name: "one selected", count: 1, applicable: true, want: trn("keyfiles.count", "{{.Count}} keyfile", 1, map[string]any{"Count": 1})},
		{name: "many selected", count: 3, applicable: true, want: trn("keyfiles.count", "{{.Count}} keyfiles", 3, map[string]any{"Count": 3})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := keyfileDisplayLabel(tt.required, tt.count, tt.applicable); got != tt.want {
				t.Fatalf("keyfileDisplayLabel(%v, %d, %v) = %q; want %q", tt.required, tt.count, tt.applicable, got, tt.want)
			}
		})
	}
}

func TestKeyfileNameLabelTruncatesLongNames(t *testing.T) {
	name := strings.Repeat("very-long-keyfile-name-", 12) + ".bin"
	label := newKeyfileNameLabel(name)

	if label.Text != name {
		t.Fatalf("keyfile name label text = %q; want original name", label.Text)
	}
	if label.Truncation != fyne.TextTruncateEllipsis {
		t.Fatalf("keyfile name label truncation = %v; want ellipsis", label.Truncation)
	}
}

func TestKeyfileDialogKeepsLongNamesWithinFixedWindowWidth(t *testing.T) {
	fyneApp := newTestFyneApp(t)

	a := createUIReadyDropTestApp(t, fyneApp)
	a.State.Keyfiles = []string{
		filepath.Join(t.TempDir(), strings.Repeat("long-keyfile-name-", 18)+".bin"),
	}

	fyne.DoAndWait(func() {
		a.showKeyfileModal()
	})
	t.Cleanup(func() {
		fyne.DoAndWait(func() {
			if a.keyfileModal != nil {
				a.keyfileModal.Hide()
			}
		})
	})

	if a.keyfileListScroll == nil {
		t.Fatal("keyfile list scroll was not created")
	}
	if got := a.keyfileListScroll.MinSize().Width; got > keyfileDialogListWidth {
		t.Fatalf("keyfile list scroll MinSize width %.1f exceeds bound %.1f", got, float32(keyfileDialogListWidth))
	}
	if got := a.keyfileModal.MinSize().Width; got > windowWidth {
		t.Fatalf("keyfile dialog MinSize width %.1f exceeds fixed window width %.1f", got, float32(windowWidth))
	}
}
