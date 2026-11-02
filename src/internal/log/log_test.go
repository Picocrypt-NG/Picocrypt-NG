package log

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLevel(t *testing.T) {
	tests := []struct {
		level    Level
		expected string
	}{
		{LevelDebug, "DEBUG"},
		{LevelInfo, "INFO"},
		{LevelWarn, "WARN"},
		{LevelError, "ERROR"},
		{Level(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		if tt.level.String() != tt.expected {
			t.Errorf("Level(%d).String() = %q, want %q", tt.level, tt.level.String(), tt.expected)
		}
	}
}

// TestFieldCreators covers only the field constructors with non-trivial logic;
// the String/Int/Int64/Float64/Bool constructors merely wrap Field{} and re-asserting
// them tests nothing the type system doesn't already guarantee. The rows kept each
// pin a real transform:
//   - Err(err) must store err.Error() (the string), not the error object — a leak of
//     the raw error or a swap to .Value=err would change downstream %v formatting.
//   - Err(nil) must yield Value==nil (and not panic on err.Error()) — the nil guard.
//   - Duration must store value.String() ("5s"), not the raw time.Duration — dropping
//     the .String() call would print "5000000000" instead of "5s".
func TestFieldCreators(t *testing.T) {
	tests := []struct {
		name      string
		field     Field
		wantKey   string
		wantValue any
	}{
		{name: "Err with error", field: Err(errors.New("test error")), wantKey: "error", wantValue: "test error"},
		{name: "Err with nil", field: Err(nil), wantKey: "error", wantValue: nil},
		{name: "Duration stores String()", field: Duration("elapsed", 5*time.Second), wantKey: "elapsed", wantValue: "5s"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.field.Key != tt.wantKey || tt.field.Value != tt.wantValue {
				t.Errorf("field = %+v; want Key=%q Value=%#v", tt.field, tt.wantKey, tt.wantValue)
			}
		})
	}
}

func TestNullLogger(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	defer func() {
		os.Stdout, os.Stderr = stdout, stderr
		_ = w.Close()
		_ = r.Close()
	}()

	logger := &nullLogger{}
	logger.Debug("discarded debug")
	logger.Info("discarded info")
	logger.Warn("discarded warning")
	logger.Error("discarded error")
	logger.WithFields(String("key", "discarded field")).Info("discarded child message")

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = stdout, stderr
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) != 0 {
		t.Fatalf("disabled logging emitted output: %q", output)
	}
}

func TestSimpleLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelInfo)

	// Debug should be filtered out at Info level. Assert the MESSAGE is absent, not
	// merely Len==0: a mutation that drops the level token but still writes the
	// message would pass a Len check but leak "debug message". This pins that the
	// whole record (message included) is suppressed below the configured level.
	logger.Debug("debug message")
	if strings.Contains(buf.String(), "debug message") {
		t.Errorf("Debug message must be filtered at Info level; got %q", buf.String())
	}

	// Info should be logged. "key=value" is the documented field format (log.go
	// log() Fprintf "%s=%v"); asserting it pins the wire format, not just presence.
	logger.Info("info message", String("key", "value"))
	output := buf.String()
	if !strings.Contains(output, "INFO") {
		t.Error("Info message should contain INFO level")
	}
	if !strings.Contains(output, "info message") {
		t.Error("Info message should contain message")
	}
	if !strings.Contains(output, "key=value") {
		t.Error("Info message should contain field in key=value format")
	}

	buf.Reset()

	// Warn should be logged
	logger.Warn("warn message")
	if !strings.Contains(buf.String(), "WARN") {
		t.Error("Warn message should contain WARN level")
	}

	buf.Reset()

	// Error should be logged
	logger.Error("error message")
	if !strings.Contains(buf.String(), "ERROR") {
		t.Error("Error message should contain ERROR level")
	}

	// A logger constructed AT LevelDebug must emit DEBUG. This pins the direction of
	// the `level < s.level` comparison: inverting it would suppress debug here while
	// still passing the Info-level filter assertion above (which only proves SOME
	// suppression happens, not that the threshold points the right way).
	buf.Reset()
	debugLogger := NewSimpleLogger(&buf, LevelDebug)
	debugLogger.Debug("debug emitted")
	out := buf.String()
	if !strings.Contains(out, "DEBUG") {
		t.Errorf("LevelDebug logger should emit DEBUG level; got %q", out)
	}
	if !strings.Contains(out, "debug emitted") {
		t.Errorf("LevelDebug logger should emit the debug message; got %q", out)
	}
}

func TestSimpleLoggerWithFields(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelDebug)

	child := logger.WithFields(String("service", "test"))
	child.Info("message", String("extra", "field"))

	output := buf.String()
	if !strings.Contains(output, "service=test") {
		t.Error("Output should contain persistent field")
	}
	if !strings.Contains(output, "extra=field") {
		t.Error("Output should contain call-specific field")
	}
}

func TestDefaultLogger(t *testing.T) {
	// Default logger should be null logger
	logger := GetLogger()
	if _, ok := logger.(*nullLogger); !ok {
		t.Error("Default logger should be null logger")
	}

	// Test SetLogger with custom logger
	var buf bytes.Buffer
	customLogger := NewSimpleLogger(&buf, LevelDebug)
	SetLogger(customLogger)

	Info("test message")
	if !strings.Contains(buf.String(), "test message") {
		t.Error("Custom logger should receive messages")
	}

	// Reset to null logger
	SetLogger(nil)
	if _, ok := GetLogger().(*nullLogger); !ok {
		t.Error("SetLogger(nil) should set null logger")
	}
}

func TestPackageLevelFunctions(t *testing.T) {
	var buf bytes.Buffer
	SetLogger(NewSimpleLogger(&buf, LevelDebug))
	defer SetLogger(nil)

	Debug("debug")
	Info("info")
	Warn("warn")
	Error("error")

	output := buf.String()
	if !strings.Contains(output, "DEBUG") {
		t.Error("Debug function should work")
	}
	if !strings.Contains(output, "INFO") {
		t.Error("Info function should work")
	}
	if !strings.Contains(output, "WARN") {
		t.Error("Warn function should work")
	}
	if !strings.Contains(output, "ERROR") {
		t.Error("Error function should work")
	}
}
