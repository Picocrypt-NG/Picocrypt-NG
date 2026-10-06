package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

func TestZipAndEncryptDroppedSelectionRoundTrip(t *testing.T) {
	for _, deniable := range []bool{false, true} {
		name := "Normal"
		if deniable {
			name = "D1"
		}
		t.Run(name, func(t *testing.T) { testZipAndEncryptDroppedSelectionRoundTrip(t, deniable) })
	}
}

func testZipAndEncryptDroppedSelectionRoundTrip(t *testing.T, deniable bool) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	dir := t.TempDir()
	folder := filepath.Join(dir, "folder")
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"top.txt": "top-level content", "folder/inner.txt": "nested content"}
	var wantUnpackedBytes int64
	for name, content := range want {
		wantUnpackedBytes += int64(len(content))
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	keyDir := t.TempDir()
	keyPaths := []string{filepath.Join(keyDir, "second.factor"), filepath.Join(keyDir, "first.factor")}
	for index, keyPath := range keyPaths {
		if err := os.WriteFile(keyPath, []byte{byte(index), 0x37, 0xc4, 0x82}, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	fyne.DoAndWait(func() { a.onDrop([]string{filepath.Join(dir, "top.txt"), folder}) })
	waitForDropProcessing(t, a)
	var input operationInput
	var captureErr error
	fyne.DoAndWait(func() {
		a.State.Password = "public ZIP regression password"
		a.State.CPassword = a.State.Password
		a.State.Keyfiles = keyPaths
		a.State.Compress = true
		a.State.Deniability = deniable
		a.State.Paranoid = deniable
		a.State.KeyfileOrdered = deniable
		input, captureErr = a.captureOperationInput(a.State.Snapshot())
	})
	if captureErr != nil {
		t.Fatal(captureErr)
	}
	result := a.runCapturedOperation(context.Background(), executeVolumeOperation, nil, input)
	if result.err != nil || !result.completed || result.pcv3 == nil || result.pcv3.CompletionClass() != pcv3operation.CompletionClean {
		t.Fatalf("Zip and Encrypt from the dropped selection failed: %v", result.err)
	}

	ciphertext, err := os.ReadFile(input.outputFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		autoUnzip bool
		sameLevel bool
	}{
		{name: "KeepZIP"},
		{name: "AutoUnzip", autoUnzip: true},
		{name: "AutoUnzipSameLevel", autoUnzip: true, sameLevel: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outputParent := t.TempDir()
			readOutput := filepath.Join(outputParent, "decrypted.zip")
			const occupiedOutput = "existing destination must survive the refused operation"
			if !tc.autoUnzip {
				if err := os.WriteFile(readOutput, []byte(occupiedOutput), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			fyne.DoAndWait(func() { a.onDrop([]string{input.outputFile}) })
			waitForDropProcessing(t, a)
			fyne.DoAndWait(func() {
				if deniable {
					if !a.advancedOpen {
						test.Tap(a.advancedToggleBtn)
					}
					button := findPCV3Button(a.advancedContainer, tr("pcv3.format.d1_action", "Open as PCV3 D1"))
					if button == nil {
						t.Fatal("created D1 volume has no explicit open action")
					}
					test.Tap(button)
				}
				snap := a.State.UISnapshot()
				if snap.PCV3Route != app.PCV3RouteReady || snap.PCV3Action != app.PCV3ActionDecrypt || a.passwordEntry.Disabled() {
					t.Fatalf("created volume did not open ready for GUI decryption: %v/%v", snap.PCV3Route, snap.PCV3Action)
				}
				ticket, _, ready := a.State.PCV3ReadyOutputSelection()
				if !ready || !a.State.SetPCV3OutputForReady(ticket, readOutput) {
					t.Fatal("choose decrypted output")
				}
				a.passwordEntry.SetText("public ZIP regression password")
				test.Tap(a.keyfileEditBtn)
				a.onDrop(keyPaths)
				if a.keyfileOrderCheck.Checked != deniable {
					test.Tap(a.keyfileOrderCheck)
				}
				a.keyfileModal.Hide()
				a.State.ShowKeyfile = false
				if !a.advancedOpen {
					test.Tap(a.advancedToggleBtn)
				}
				if a.autoUnzipCheck == nil || a.autoUnzipCheck.Disabled() || a.sameLevelCheck == nil {
					t.Fatal("ordinary PCV3 decryption does not expose enabled archive options")
				}
				if a.autoUnzipCheck.Checked || a.sameLevelCheck.Checked || !a.sameLevelCheck.Disabled() {
					t.Fatal("opening an archive must default to keeping ZIP with Same level disabled")
				}
				if tc.autoUnzip {
					test.Tap(a.autoUnzipCheck)
					if a.sameLevelCheck.Disabled() {
						t.Fatal("Auto unzip did not enable Same level")
					}
					if tc.sameLevel {
						test.Tap(a.sameLevelCheck)
					}
				}
				if a.startButton.Disabled() {
					t.Fatal("GUI did not enable decryption after entering both factors")
				}
				if !tc.autoUnzip {
					test.Tap(a.startButton)
					if a.State.IsWorking() || a.State.UISnapshot().PCV3Route != app.PCV3RouteReady {
						t.Fatal("occupied destination started or consumed the operation")
					}
					if a.statusLabel.link.Text != tr("status.pcv3_output_exists", "PCV3 output already exists. Choose a different name.") ||
						!a.configurationForm.Visible() || !a.operationFooter.Visible() {
						t.Fatal("occupied destination did not leave a visible error and editable form")
					}
				}
			})
			if !tc.autoUnzip {
				if got, err := os.ReadFile(readOutput); err != nil || string(got) != occupiedOutput {
					t.Fatalf("refused operation changed the existing destination: %v", err)
				}
				// Retry the same destination after releasing the test-owned file.
				// A picker change would clear the stale status before this regression.
				if err := os.Remove(readOutput); err != nil {
					t.Fatal(err)
				}
			}
			fyne.DoAndWait(func() { test.Tap(a.startButton) })
			a.workers.wait()
			fyne.DoAndWait(func() {})
			read := a.pcv3Result
			if read == nil || read.CompletionClass() != pcv3operation.CompletionClean || read.ArchiveFollowUp() != nil {
				t.Fatalf("real GUI decryption did not complete the chosen archive action: %v", read)
			}
			fyne.DoAndWait(func() {
				if !a.pcv3Container.Visible() || a.configurationForm.Visible() || a.operationFooter.Visible() {
					t.Fatal("PCV3 result still shows inactive inputs or the stale preflight error footer")
				}
				if tc.autoUnzip {
					// The selected folder contributes its regular file; the ZIP
					// writer does not add a separate directory entry.
					summary := a.pcv3ArchiveSummary
					if summary == nil || summary.Files != 2 || summary.Directories != 0 || summary.UnpackedBytes != wantUnpackedBytes {
						t.Fatalf("real decryption did not review the authenticated archive's exact contents: %+v", summary)
					}
				} else if a.pcv3ArchiveSummary != nil {
					t.Fatalf("keeping ZIP unexpectedly requested archive extraction review: %+v", a.pcv3ArchiveSummary)
				}
			})
			recovered := make(map[string]string, len(want))
			if !tc.autoUnzip {
				archive, err := zip.OpenReader(readOutput)
				if err != nil {
					t.Fatalf("open authenticated ZIP: %v", err)
				}
				defer archive.Close()
				for _, entry := range archive.File {
					if entry.FileInfo().IsDir() {
						continue
					}
					reader, err := entry.Open()
					if err != nil {
						t.Fatal(err)
					}
					got, readErr := io.ReadAll(reader)
					closeErr := reader.Close()
					content, exists := want[entry.Name]
					_, duplicate := recovered[entry.Name]
					if readErr != nil || closeErr != nil || !exists || duplicate || string(got) != content {
						t.Fatalf("ZIP entry %q differs from the source or repeats", entry.Name)
					}
					recovered[entry.Name] = string(got)
				}
				entries, err := os.ReadDir(outputParent)
				if err != nil || len(entries) != 1 || entries[0].Name() != "decrypted.zip" {
					t.Fatalf("keep ZIP created extra plaintext or staging output: %v", err)
				}
			} else {
				extracted := outputParent
				if !tc.sameLevel {
					extracted = filepath.Join(outputParent, "decrypted")
					entries, err := os.ReadDir(outputParent)
					if err != nil || len(entries) != 1 || entries[0].Name() != "decrypted" || !entries[0].IsDir() {
						t.Fatalf("Auto unzip did not create only the requested extraction folder: %v", err)
					}
				}
				if _, err := os.Lstat(readOutput); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("automatic extraction left a published ZIP: %v", err)
				}
				if err := filepath.WalkDir(extracted, func(path string, entry fs.DirEntry, walkErr error) error {
					if walkErr != nil {
						return walkErr
					}
					if entry.IsDir() {
						return nil
					}
					if !entry.Type().IsRegular() {
						t.Fatalf("extraction created a non-regular file: %s", path)
					}
					name, err := filepath.Rel(extracted, path)
					if err != nil {
						return err
					}
					name = filepath.ToSlash(name)
					got, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					content, exists := want[name]
					if !exists || string(got) != content {
						t.Fatalf("extracted entry %q differs from the source", name)
					}
					recovered[name] = string(got)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			if len(recovered) != len(want) {
				t.Fatalf("recovered %d files; want %d", len(recovered), len(want))
			}
			for name, content := range want {
				got, err := os.ReadFile(filepath.Join(dir, name))
				if err != nil || string(got) != content || recovered[name] != content {
					t.Fatalf("original or recovered file %q changed", name)
				}
			}
			if got, err := os.ReadFile(input.outputFile); err != nil || !bytes.Equal(got, ciphertext) {
				t.Fatalf("archive operation changed or removed its ciphertext: %v", err)
			}
			if _, err := os.Stat(input.inputFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("proposed archive name must not become a plaintext temporary file: %v", err)
			}
			fyne.DoAndWait(func() {
				a.resetUI()
				if !a.configurationForm.Visible() || !a.operationFooter.Visible() || a.pcv3Container.Visible() {
					t.Fatal("reset did not restore the operation form and footer")
				}
			})
		})
	}
}
