package cli

import (
	"bufio"
	"bytes"
	"slices"
	"strings"
	"testing"

	"golang.org/x/term"
)

func TestReadPasswordFDLineKeepsSecretInSingleBoundedAllocation(t *testing.T) {
	want := bytes.Repeat([]byte{'x'}, 256)
	input := append(append([]byte(nil), want...), '\n')
	got, err := readPasswordFDLine(bytes.NewReader(input))
	if err != nil {
		t.Fatalf("readPasswordFDLine() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("readPasswordFDLine() length = %d; want exact %d-byte password", len(got), len(want))
	}
	if cap(got) != maximumCLIPasswordBytes+2 {
		t.Fatalf(
			"password backing capacity = %d; want one fixed bounded allocation of %d bytes",
			cap(got), maximumCLIPasswordBytes+2,
		)
	}
}

func TestNonASCIIPasswordNote(t *testing.T) {
	// Built from a code point so the literal cannot be silently re-normalized.
	nonASCII := "caf" + string([]rune{0x00E9})

	cases := []struct {
		name     string
		confirm  bool
		password string
		wantNote bool
	}{
		{"non-ascii encrypt", true, nonASCII, true},
		{"ascii encrypt", true, "plain-password", false},
		{"non-ascii decrypt (no confirm)", false, nonASCII, false},
		{"empty encrypt", true, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			note := nonASCIIPasswordNote(tc.confirm, []byte(tc.password))
			if got := note != ""; got != tc.wantNote {
				t.Errorf("nonASCIIPasswordNote(confirm=%v, %q) note=%q, want note present=%v",
					tc.confirm, tc.password, note, tc.wantNote)
			}
			if tc.wantNote && !strings.Contains(note, "non-ASCII") {
				t.Errorf("note should mention non-ASCII, got %q", note)
			}
		})
	}
}

func TestReadPasswordLine(t *testing.T) {
	testCases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "newline", input: "pw\n", want: "pw"},
		{name: "crlf", input: "pw\r\n", want: "pw"},
		{name: "eof without newline", input: "pw", want: "pw"},
		{name: "empty eof", input: "", want: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPasswordLine(bufio.NewReader(strings.NewReader(tc.input)))
			if err != nil {
				t.Fatalf("readPasswordLine() error = %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("readPasswordLine() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSignalRestoresTerminalState checks that a SIGINT during the interactive
// password prompt (before any operation reporter is stored) restores the saved
// terminal mode before the process exits. os.Exit skips term.ReadPassword's
// deferred restore, so the handler must restore explicitly and do so before
// exiting, or the shell is left with echo disabled. The call order is asserted
// because, with a real os.Exit, restoring after exit would never run.
func TestSignalRestoresTerminalState(t *testing.T) {
	globalReporter.Store(nil) // reproduces the pre-Store prompt window
	sentinel := &term.State{}
	savedTerminalState.Store(sentinel)

	var events []string
	var restored *term.State
	origRestore, origExit := restoreTerminalFn, exitFn
	t.Cleanup(func() {
		restoreTerminalFn, exitFn = origRestore, origExit
		savedTerminalState.Store(nil)
	})
	restoreTerminalFn = func(s *term.State) {
		restored = s
		events = append(events, "restore")
	}
	exitFn = func(int) { events = append(events, "exit") }

	handleSignal()

	if restored != sentinel {
		t.Fatalf("terminal state not restored on signal path: got %p want %p", restored, sentinel)
	}
	want := []string{"restore", "exit"}
	if !slices.Equal(events, want) {
		t.Fatalf("signal path order = %v, want %v (restore must run before exit)", events, want)
	}
}

// TestSignalWithReporterDoesNotExit pins the complementary contract: once an
// operation reporter is active, SIGINT must cancel the operation rather than
// exit the process.
func TestSignalWithReporterDoesNotExit(t *testing.T) {
	reporter := NewReporter(true)
	globalReporter.Store(reporter)
	origExit := exitFn
	t.Cleanup(func() {
		exitFn = origExit
		globalReporter.Store(nil)
	})
	exited := false
	exitFn = func(int) { exited = true }

	handleSignal()

	if exited {
		t.Fatalf("reporter active: signal path must cancel, not exit")
	}
	if !reporter.IsCancelled() {
		t.Fatalf("reporter active: signal path must cancel the operation")
	}
}
