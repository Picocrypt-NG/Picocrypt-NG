package log

import (
	"bytes"
	"errors"
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

func TestFieldCreators(t *testing.T) {
	// Test String field
	f := String("key", "value")
	if f.Key != "key" || f.Value != "value" {
		t.Errorf("String field incorrect: %+v", f)
	}

	// Test Int field
	f = Int("count", 42)
	if f.Key != "count" || f.Value != 42 {
		t.Errorf("Int field incorrect: %+v", f)
	}

	// Test Int64 field
	f = Int64("bytes", 1024)
	if f.Key != "bytes" || f.Value != int64(1024) {
		t.Errorf("Int64 field incorrect: %+v", f)
	}

	// Test Float64 field
	f = Float64("ratio", 3.14)
	if f.Key != "ratio" || f.Value != 3.14 {
		t.Errorf("Float64 field incorrect: %+v", f)
	}

	// Test Bool field
	f = Bool("enabled", true)
	if f.Key != "enabled" || f.Value != true {
		t.Errorf("Bool field incorrect: %+v", f)
	}

	// Test Err field with error
	err := errors.New("test error")
	f = Err(err)
	if f.Key != "error" || f.Value != "test error" {
		t.Errorf("Err field incorrect: %+v", f)
	}

	// Test Err field with nil
	f = Err(nil)
	if f.Key != "error" || f.Value != nil {
		t.Errorf("Err(nil) field incorrect: %+v", f)
	}

	// Test Duration field
	f = Duration("elapsed", 5*time.Second)
	if f.Key != "elapsed" || f.Value != "5s" {
		t.Errorf("Duration field incorrect: %+v", f)
	}
}

func TestNullLogger(t *testing.T) {
	logger := &nullLogger{}

	// These should all be no-ops
	logger.Debug("test")
	logger.Info("test")
	logger.Warn("test")
	logger.Error("test")

	// WithFields should return same null logger
	child := logger.WithFields(String("key", "value"))
	if child != logger {
		t.Error("nullLogger.WithFields should return same instance")
	}
}

func TestSimpleLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewSimpleLogger(&buf, LevelInfo)

	// Debug should be filtered out (level is Info)
	logger.Debug("debug message")
	if buf.Len() > 0 {
		t.Error("Debug message should be filtered at Info level")
	}

	// Info should be logged
	logger.Info("info message", String("key", "value"))
	output := buf.String()
	if !strings.Contains(output, "INFO") {
		t.Error("Info message should contain INFO level")
	}
	if !strings.Contains(output, "info message") {
		t.Error("Info message should contain message")
	}
	if !strings.Contains(output, "key=value") {
		t.Error("Info message should contain field")
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
