package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
)

// A valid first record must not let the desktop describe consented, damaged
// later records as merely missing. Keep the independent volume frozen.
func TestPCV3RecoveryTrustMessagesFromRealOperation(t *testing.T) {
	resetLocalizationForTest(t)
	if !nativeUIDirectorySyncSupported(t, t.TempDir()) {
		t.Skip("range inspection requires a durably published recovery artifact on this filesystem")
	}
	if runIsolatedPCV3FyneTest(t) {
		return
	}
	volume, err := os.ReadFile(filepath.Join("..", "pcv3operation", "internal", "pcv3", "testdata", "normal", "volumes", "normal-standard-combined-ordered-two-mib.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(volume)
	if hex.EncodeToString(digest[:]) != "5845cf7585fb85f5e48d20b9c0e2a075355190e2bb9445217f455bca31fcc9da" {
		t.Fatal("independent two-record volume changed")
	}
	// Frozen layout: 1112-byte header, two 1 MiB records with 48-byte
	// descriptors and 64-byte tags, then the final descriptor/tag.
	volume[2098424] ^= 1 // second data MAC only; recovered bytes are intact
	volume[2098536] ^= 1 // final MAC; completion is not authenticated
	dir := t.TempDir()
	sourcePath, output := filepath.Join(dir, "damaged.pcv"), filepath.Join(dir, "recovery.pcv3-recovery")
	if err := os.WriteFile(sourcePath, volume, 0o600); err != nil {
		t.Fatal(err)
	}
	red, blue := filepath.Join(dir, "red.key"), filepath.Join(dir, "blue.key")
	for path, data := range map[string]string{red: "red", blue: "blue"} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	var executed *pcv3operation.Result
	a.pcv3OperationExecutor = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
		executed = pcv3operation.Run(ctx, request)
		return executed
	}
	fyne.DoAndWait(func() {
		if !a.State.SetPCV3Ready(source, app.PCV3FormatNormal, sourcePath, output, int64(len(volume))) {
			t.Fatal("set PCV3 selection")
		}
		a.State.Password, a.State.Keyfiles, a.State.KeyfileOrdered = "mix", []string{red, blue}, true
		a.State.SetPCV3Intent(app.PCV3ActionForceUnverified, app.PCV3FactorPolicyCombined, app.PCV3KeyfileOrderSelected)
		a.refreshAdvanced()
		a.updateUIState()
		a.startPCV3Work()
	})
	waitForPCV3UI(t, func() bool { return a.Window.Canvas().Overlays().Top() != nil }, "consent overlay missing")
	fyne.DoAndWait(func() {
		radio, ack, confirm := pcv3PCV3ConsentControls(t, a.Window.Canvas().Overlays().Top())
		if radio == nil || ack == nil || confirm == nil {
			t.Fatal("live consent controls missing")
		}
		radio.SetSelected("Backup capsule")
		ack.SetChecked(true)
		if confirm.Disabled() {
			t.Fatal("role-bound consent unavailable")
		}
		confirm.OnTapped()
	})
	terminal := false
	for attempt := 0; attempt < 1200 && !terminal; attempt++ {
		fyne.DoAndWait(func() {
			terminal = !a.State.IsWorking() && a.State.UISnapshot().PCV3Result.CompletionClass() != pcv3operation.CompletionUnknown
		})
		if !terminal {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !terminal || executed == nil {
		t.Fatal("real recovery did not finish")
	}
	if executed.Outcome() != pcv3operation.OutcomeForcePartial || executed.SourceDeletionAllowed() || executed.ArchiveFollowUp() != nil || executed.Presentation().ArchivePending() {
		t.Fatalf("damaged output granted trusted plaintext authority: %v", executed)
	}
	inspection := executed.ArtifactInspection()
	if inspection == nil {
		t.Fatalf("durable artifact inspection missing: %v", executed)
	}
	metadata := inspection.Metadata()
	if metadata.Kind != pcv3operation.ArtifactStatePartial || metadata.Role != pcv3operation.ArtifactRoleBackup || metadata.Final != pcv3operation.ArtifactFinalUnverified || metadata.VerifiedRangeCount != 1 || metadata.UnverifiedRangeCount != 1 || metadata.MissingRangeCount != 0 {
		t.Fatalf("real recovery evidence = %#v", metadata)
	}
	ranges, ok := inspection.Page(0, 2)
	if !ok || len(ranges) != 2 || ranges[0].Start != 0 || ranges[0].End != 1048576 || ranges[0].Status != pcv3operation.ArtifactRangeVerified || ranges[1].Start != 1048576 || ranges[1].End != 2097152 || ranges[1].Status != pcv3operation.ArtifactRangeUnverified {
		t.Fatalf("real recovery ranges = %#v", ranges)
	}
	retained, err := os.ReadFile(sourcePath)
	if err != nil || !bytes.Equal(retained, volume) {
		t.Fatal("recovery changed the source")
	}
	artifact, err := os.ReadFile(output)
	if err != nil || len(artifact) == 2097152 || !bytes.HasPrefix(artifact, []byte("PICO-RECOVERY-3\x00")) {
		t.Fatalf("published output is not an explicit recovery artifact: bytes=%d err=%v", len(artifact), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 4 {
		t.Fatalf("desktop recovery left non-artifact output or private staging: %v, %v", entries, err)
	}
	text := pcv3RenderedText(a.pcv3Container)
	for _, want := range []string{"Partial recovery", "Not a fully verified file. Data may be missing or unverified."} {
		if !strings.Contains(text, want) {
			t.Errorf("real desktop warning %q lacks %q", text, want)
		}
	}
	if strings.Contains(text, "some are missing") || strings.Contains(text, "Extract archive") {
		t.Errorf("real desktop claims absent ranges or offers extraction: %q", text)
	}
}
