package volume

import (
	"Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// etaStatusReporter captures every status string so a test can assert that a
// streaming pass reported throughput and ETA at some point.
type etaStatusReporter struct {
	statuses []string
}

func (r *etaStatusReporter) SetStatus(text string)                  { r.statuses = append(r.statuses, text) }
func (r *etaStatusReporter) SetProgress(fraction float32, _ string) {}
func (r *etaStatusReporter) SetCanCancel(can bool)                  {}
func (r *etaStatusReporter) Update()                                {}
func (r *etaStatusReporter) IsCancelled() bool                      { return false }

// assertStreamingSpeedAndETA fails unless the captured statuses prove a real
// streaming progress pass for the named operation. It delegates to the pure
// streamingSpeedAndETAProblems so the accept/reject policy is unit-testable
// against captured real-world status batches (see
// TestStreamingSpeedAndETAAcceptsCoarseClockZeroSpeed).
func assertStreamingSpeedAndETA(t *testing.T, op string, statuses []string) {
	t.Helper()
	for _, p := range streamingSpeedAndETAProblems(statuses) {
		t.Errorf("%s: %s; statuses=%v", op, p, statuses)
	}
}

// streamingSpeedAndETAProblems returns one reason per way the captured statuses
// fail to prove a streaming throughput+ETA pass, or nil if they pass. It is
// mutation-sensitive against the production status format
// ("... at %.2f MiB/s (ETA: %s)"):
//   - (a) at least two statuses match the "MiB/s"+"ETA:" shape (a single sample
//     would mean no streaming loop, just one bookend report);
//   - (b) at least one sample carries a PARSEABLE speed token in the "%.2f MiB/s"
//     slot (a missing/garbled number means the speed math was dropped). The value
//     is deliberately NOT required to be > 0: util.Statify legitimately reports
//     0.00 MiB/s when elapsed<=0, which happens on low-resolution-clock platforms
//     (the go-legacy-win7 toolchain) where a small payload finishes inside one
//     timer tick. Pinning speed>0 here flaked the windows-legacy release runner;
//     the positive-speed math is pinned deterministically in util.TestStatify.
//   - (c) at least one sample carries a non-empty token after "ETA: " (a dropped
//     ETA field would leave the parenthesis empty).
func streamingSpeedAndETAProblems(statuses []string) []string {
	matches := 0
	sawParseableSpeed := false
	sawNonEmptyETA := false
	for _, s := range statuses {
		if !strings.Contains(s, "MiB/s") || !strings.Contains(s, "ETA:") {
			continue
		}
		matches++

		// Parse the float immediately preceding " MiB/s": take the text before that
		// marker and read the final whitespace-delimited token as the speed.
		if prefix, _, ok := strings.Cut(s, " MiB/s"); ok {
			fields := strings.Fields(prefix)
			if len(fields) > 0 {
				if speed, err := strconv.ParseFloat(fields[len(fields)-1], 64); err == nil && speed >= 0 {
					sawParseableSpeed = true
				}
			}
		}

		// Extract the ETA token between "ETA: " and the closing ")".
		if _, after, ok := strings.Cut(s, "ETA: "); ok {
			eta, _, _ := strings.Cut(after, ")")
			if strings.TrimSpace(eta) != "" {
				sawNonEmptyETA = true
			}
		}
	}

	var problems []string
	if matches < 2 {
		problems = append(problems, fmt.Sprintf("got %d speed+ETA statuses, want >=2 (streaming should report multiple samples)", matches))
	}
	if !sawParseableSpeed {
		problems = append(problems, `no status carried a parseable speed in the "%.2f MiB/s" slot`)
	}
	if !sawNonEmptyETA {
		problems = append(problems, "no status reported a non-empty ETA token")
	}
	return problems
}

// TestDeniabilityReportsSpeedAndETA verifies both deniability passes report a
// status with throughput and ETA while streaming, like the encrypt/decrypt
// payload passes — not just a bare percentage. The fast KDF stub installed by
// TestMain keeps the Argon2 derivation cheap.
func TestDeniabilityReportsSpeedAndETA(t *testing.T) {
	rs, err := encoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	tmpDir := t.TempDir()

	// AddDeniability encrypts whatever bytes it is given, so a plain 2 MiB blob
	// exercises its streaming progress reporting.
	addPath := filepath.Join(tmpDir, "add.bin")
	if err := os.WriteFile(addPath, bytes.Repeat([]byte("x"), 2*1024*1024), 0o644); err != nil {
		t.Fatalf("write add input: %v", err)
	}
	addRep := &etaStatusReporter{}
	if err := AddDeniability(addPath, []byte("pw"), addRep); err != nil {
		t.Fatalf("AddDeniability: %v", err)
	}
	assertStreamingSpeedAndETA(t, "AddDeniability", addRep.statuses)

	// RemoveDeniability now selects the password form by probing the inner
	// version field before streaming, so it must operate on a REAL deniable
	// volume to reach (and report on) the streaming pass. Build one: encrypt a
	// 2 MiB file, then wrap it.
	plainPath := filepath.Join(tmpDir, "pt.bin")
	if err := os.WriteFile(plainPath, bytes.Repeat([]byte("y"), 2*1024*1024), 0o644); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	volPath := filepath.Join(tmpDir, "vol.pcv")
	if err := Encrypt(context.Background(), &EncryptRequest{
		InputFile: plainPath, OutputFile: volPath, Password: []byte("pw"),
		Reporter: &GoldenTestReporter{}, RSCodecs: rs,
	}); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if err := AddDeniability(volPath, []byte("pw"), &etaStatusReporter{}); err != nil {
		t.Fatalf("AddDeniability(volume): %v", err)
	}

	remRep := &etaStatusReporter{}
	stage, err := RemoveDeniability(volPath, []byte("pw"), remRep, rs)
	if err != nil {
		t.Fatalf("RemoveDeniability: %v", err)
	}
	defer stage.Cleanup()
	assertStreamingSpeedAndETA(t, "RemoveDeniability", remRep.statuses)
}

// TestStreamingSpeedAndETAAcceptsCoarseClockZeroSpeed pins that a streaming pass
// whose every sample reads 0.00 MiB/s is still accepted as a real throughput+ETA
// report. This is the exact RemoveDeniability batch captured from the
// windows-legacy release runner (go-legacy-win7), where a 2 MiB payload finished
// inside one timer tick so util.Statify's elapsed<=0 guard reported 0.00 MiB/s on
// every sample. Requiring speed>0 here flaked that runner; reintroducing it would
// re-break this batch. The positive-speed math is pinned deterministically in
// util.TestStatify instead.
func TestStreamingSpeedAndETAAcceptsCoarseClockZeroSpeed(t *testing.T) {
	statuses := []string{
		"Removing deniability protection...",
		"Removing deniability at 0.00 MiB/s (ETA: 00:00:00)",
		"Removing deniability at 0.00 MiB/s (ETA: 00:00:00)",
		"Removing deniability at 0.00 MiB/s (ETA: 00:00:00)",
	}
	if problems := streamingSpeedAndETAProblems(statuses); len(problems) != 0 {
		t.Errorf("coarse-clock streaming batch wrongly rejected: %v; statuses=%v", problems, statuses)
	}
}
