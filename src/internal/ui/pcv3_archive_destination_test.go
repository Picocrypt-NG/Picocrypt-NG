package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"archive/zip"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"
)

type pcv3ArchiveNonFileURI struct{ fyne.ListableURI }

func (pcv3ArchiveNonFileURI) Scheme() string { return "https" }

func pcv3ArchiveDirectoryURI(t *testing.T, path string) fyne.ListableURI {
	t.Helper()
	uri, err := storage.ListerForURI(storage.NewFileURI(path))
	if err != nil {
		t.Fatal(err)
	}
	return uri
}

func logPCV3ArchiveDestinationMemory(t *testing.T) {
	t.Helper()
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	t.Logf("Go memory at archive failure: Alloc=%d HeapInuse=%d HeapReleased=%d Sys=%d NextGC=%d NumGC=%d", memory.Alloc, memory.HeapInuse, memory.HeapReleased, memory.Sys, memory.NextGC, memory.NumGC)
	cgroups, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Logf("cgroup memory evidence unavailable: %v", err)
		return
	}
	for _, line := range strings.Split(string(cgroups), "\n") {
		if !strings.HasPrefix(line, "0::/") {
			continue
		}
		for _, name := range []string{"memory.current", "memory.peak", "memory.max", "memory.swap.current", "memory.swap.max"} {
			value, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(line, "0::"), name))
			if err != nil {
				t.Logf("cgroup %s unavailable: %v", name, err)
				continue
			}
			t.Logf("cgroup %s at archive failure: %s", name, strings.TrimSpace(string(value)))
		}
		return
	}
}

func newPCV3AuthenticatedArchiveDestinationUI(t *testing.T) (*App, *pcv3operation.Result, uint64, string, string) {
	t.Helper()
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	fixture := filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "normal")
	ciphertext, err := os.ReadFile(filepath.Join(fixture, "volumes", "normal-standard-combined-ordered-archive-small.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	sourcePath := filepath.Join(base, "encrypted-source.pcv")
	if err := os.WriteFile(sourcePath, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	keyfiles := []string{filepath.Join(base, "red.key"), filepath.Join(base, "blue.key")}
	for i, value := range []string{"red", "blue"} {
		if err := os.WriteFile(keyfiles[i], []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	stageDirectory := t.TempDir()
	// The default facade retains the authenticated archive for the live chooser.
	// Credentials, KDF, verification, handoff, workers and extraction stay real.
	a.pcv3OperationExecutor = pcv3operation.Run
	fyne.DoAndWait(func() {
		if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, sourcePath, filepath.Join(stageDirectory, "pending.zip"), int64(len(ciphertext))) {
			t.Fatal("set authenticated archive selection")
		}
		a.State.Password = "mix"
		a.State.Keyfiles = keyfiles
		a.State.KeyfileOrdered = true
		a.State.SetPCV3Intent(app.PCV3ActionDecrypt, app.PCV3FactorPolicyCombined, app.PCV3KeyfileOrderSelected)
		a.updateUIState()
		a.startPCV3Work()
	})
	t.Cleanup(func() {
		a.stopCurrentOperation()
		a.workers.wait()
		fyne.DoAndWait(a.releasePCV3Result)
		got, err := os.ReadFile(sourcePath)
		if err != nil || !bytes.Equal(got, ciphertext) {
			t.Errorf("archive selection altered encrypted source: %v", err)
		}
	})
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		var done bool
		fyne.DoAndWait(func() { done = !a.State.IsWorking() })
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var result *pcv3operation.Result
	var generation uint64
	fyne.DoAndWait(func() {
		result, generation = a.pcv3Result, a.pcv3ResultGeneration
		if a.State.IsWorking() || result == nil || result.ArchiveFollowUp() == nil || !result.Presentation().ArchivePending() {
			logPCV3ArchiveDestinationMemory(t)
			t.Fatalf("real archive operation did not yield a live authenticated follow-up: %v (stage=%v diagnostic=%v warnings=%v)", result, result.Stage(), result.Diagnostic(), result.Warnings())
		}
	})
	return a, result, generation, stageDirectory, filepath.Join(fixture, "plaintext", "normal-standard-combined-ordered-archive-small.zip")
}

func pcv3ArchiveDestinationDialogText(a *App) string {
	var texts []string
	for _, object := range test.LaidOutObjects(a.Window.Canvas().Overlays().Top()) {
		if label, ok := object.(*widget.Label); ok {
			texts = append(texts, label.Text)
		}
	}
	return strings.Join(texts, "\n")
}

func dismissPCV3ArchiveDestinationDialog(t *testing.T, a *App) {
	t.Helper()
	for _, object := range test.LaidOutObjects(a.Window.Canvas().Overlays().Top()) {
		if button, ok := object.(*widget.Button); ok {
			test.Tap(button)
			return
		}
	}
	t.Fatal("archive destination error has no dismiss action")
}

func requirePCV3ArchiveDestinationEmpty(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("archive selection left plaintext or private staging in %q: %v, %v", path, entries, err)
	}
}

func requirePCV3ExtractedArchive(t *testing.T, directory, fixture string) {
	t.Helper()
	archive, err := zip.OpenReader(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	for _, entry := range archive.File {
		path := filepath.Join(directory, filepath.FromSlash(entry.Name))
		if entry.FileInfo().IsDir() {
			if info, err := os.Stat(path); err != nil || !info.IsDir() {
				t.Fatalf("retry did not extract directory %q: %v", entry.Name, err)
			}
			continue
		}
		reader, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		want, err := io.ReadAll(reader)
		closeErr := reader.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("read frozen plaintext archive: %v, %v", err, closeErr)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("retry extracted incorrect bytes for %q: %v", entry.Name, err)
		}
	}
}

func TestPCV3ArchiveDestinationErrorsPreserveRetryAndClose(t *testing.T) {
	resetLocalizationForTest(t)
	for _, action := range []string{"retry", "close"} {
		t.Run(action, func(t *testing.T) {
			a, result, generation, stageDirectory, plaintextFixture := newPCV3AuthenticatedArchiveDestinationUI(t)
			followUp := result.ArchiveFollowUp()
			destination := t.TempDir()
			validURI := pcv3ArchiveDirectoryURI(t, destination)
			removed := t.TempDir()
			removedURI := pcv3ArchiveDirectoryURI(t, removed)
			if err := os.Remove(removed); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(t.TempDir(), "destination-symlink")
			if err := os.Symlink(destination, link); err != nil {
				t.Fatal(err)
			}
			linkURI := pcv3ArchiveDirectoryURI(t, link)
			assertPending := func() {
				t.Helper()
				if a.pcv3Result != result || a.pcv3ResultGeneration != generation ||
					result.ArchiveFollowUp() != followUp || !a.State.UISnapshot().PCV3Result.ArchivePending() || a.State.IsWorking() {
					t.Fatal("folder selection error consumed or replaced the authenticated archive capability")
				}
				for _, key := range []string{"pcv3.archive.extract", "pcv3.archive.close"} {
					if button := findPCV3Button(a.pcv3Container, tr(key, "")); button == nil || button.Disabled() {
						t.Fatalf("folder selection lost enabled %q action", key)
					}
				}
				requirePCV3ArchiveDestinationEmpty(t, destination)
			}
			for _, language := range []struct {
				code                      LanguageCode
				picker, destination, body string
			}{
				{"en", "Cannot select folder", "Cannot open extraction folder", "Choose another folder or try again."},
				{"ru", "Не удалось выбрать папку", "Не удалось открыть папку для извлечения", "Выберите другую папку или повторите попытку."},
			} {
				fyne.DoAndWait(func() {
					if err := setActiveLanguage(language.code); err != nil {
						t.Fatal(err)
					}
					a.updateUIState()
					for _, selection := range []struct {
						name  string
						uri   fyne.ListableURI
						err   error
						title string
					}{
						{"removed folder", removedURI, nil, language.destination},
						{"symlink", linkURI, nil, language.destination},
						{"picker failure before cancellation", nil, errors.New("private-backend-error /private/sentinel"), language.picker},
						{"non-file destination", pcv3ArchiveNonFileURI{validURI}, nil, language.destination},
					} {
						a.handlePCV3ArchiveFolderSelection(result, generation, selection.uri, selection.err)
						text := pcv3ArchiveDestinationDialogText(a)
						if !strings.Contains(text, selection.title) || !strings.Contains(text, language.body) {
							t.Fatalf("%s %s error is not visibly actionable: %q", language.code, selection.name, text)
						}
						for _, secret := range []string{removed, link, "private-backend-error", "/private/sentinel"} {
							if strings.Contains(text, secret) {
								t.Fatalf("destination error disclosed backend detail %q", secret)
							}
						}
						assertPending()
						dismissPCV3ArchiveDestinationDialog(t, a)
					}
					for _, selection := range []struct {
						result     *pcv3operation.Result
						generation uint64
						uri        fyne.ListableURI
						err        error
					}{
						{result, generation, nil, nil},
						{nil, generation, validURI, errors.New("stale picker error")},
						{result, generation + 1, validURI, errors.New("stale generation error")},
					} {
						a.handlePCV3ArchiveFolderSelection(selection.result, selection.generation, selection.uri, selection.err)
						if a.Window.Canvas().Overlays().Top() != nil {
							t.Fatal("cancelled or stale chooser callback opened a dialog")
						}
						assertPending()
					}
					a.pcv3Result = nil
					a.handlePCV3ArchiveFolderSelection(result, generation, validURI, errors.New("retired result picker error"))
					if a.pcv3Result != nil || a.Window.Canvas().Overlays().Top() != nil || result.ArchiveFollowUp() != followUp {
						t.Fatal("retired result callback changed the current surface or consumed its old capability")
					}
					a.pcv3Result = result
					assertPending()
				})
			}
			fyne.DoAndWait(func() {
				if action == "retry" {
					a.handlePCV3ArchiveFolderSelection(result, generation, validURI, nil)
				} else {
					test.Tap(findPCV3Button(a.pcv3Container, tr("pcv3.archive.close", "")))
				}
			})
			a.workers.wait()
			fyne.DoAndWait(func() {
				if a.State.IsWorking() || a.pcv3Result == nil || a.pcv3Result == result ||
					a.State.UISnapshot().PCV3Result.ArchivePending() || result.ArchiveFollowUp() != nil {
					t.Fatalf("%s did not consume exactly the pending archive: %v", action, a.pcv3Result)
				}
				if action == "retry" {
					if a.pcv3Result.PublicationState() != pcv3publication.StatePublishedDurable {
						logPCV3ArchiveDestinationMemory(t)
						t.Fatalf("retry did not finish durable real extraction: %v (stage=%v diagnostic=%v warnings=%v)", a.pcv3Result, a.pcv3Result.Stage(), a.pcv3Result.Diagnostic(), a.pcv3Result.Warnings())
					}
				} else if a.pcv3Result.CompletionClass() != pcv3operation.CompletionNoOutput {
					t.Fatalf("close did not finish with no output: %v", a.pcv3Result)
				}
				// A late picker failure after consumption must not cover the final result.
				a.handlePCV3ArchiveFolderSelection(result, generation, nil, errors.New("late picker failure"))
				if a.Window.Canvas().Overlays().Top() != nil {
					t.Fatal("consumed archive callback covered terminal result")
				}
			})
			if action == "retry" {
				requirePCV3ExtractedArchive(t, destination, plaintextFixture)
			} else {
				requirePCV3ArchiveDestinationEmpty(t, destination)
			}
			requirePCV3ArchiveDestinationEmpty(t, stageDirectory)
		})
	}
}
