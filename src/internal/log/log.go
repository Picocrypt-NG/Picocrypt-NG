// Package log provides structured logging for Picocrypt operations.
// By default, logging is disabled (null logger) for zero overhead.
// Enable logging by calling SetLogger with a custom implementation.
package log

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level represents the logging level.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// Field represents a key-value pair for structured logging.
type Field struct {
	Key   string
	Value any
}

// String creates a string field.
func String(key, value string) Field {
	return Field{Key: key, Value: value}
}

// Int creates an integer field.
func Int(key string, value int) Field {
	return Field{Key: key, Value: value}
}

// Int64 creates an int64 field.
func Int64(key string, value int64) Field {
	return Field{Key: key, Value: value}
}

// Float64 creates a float64 field.
func Float64(key string, value float64) Field {
	return Field{Key: key, Value: value}
}

// Bool creates a boolean field.
func Bool(key string, value bool) Field {
	return Field{Key: key, Value: value}
}

// Err creates an error field.
func Err(err error) Field {
	if err == nil {
		return Field{Key: "error", Value: nil}
	}
	return Field{Key: "error", Value: err.Error()}
}

// Duration creates a duration field.
func Duration(key string, value time.Duration) Field {
	return Field{Key: key, Value: value.String()}
}

// Logger is the interface for structured logging.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	WithFields(fields ...Field) Logger
}

// nullLogger is a no-op logger that discards all output.
type nullLogger struct{}

func (n *nullLogger) Debug(msg string, fields ...Field) {}
func (n *nullLogger) Info(msg string, fields ...Field)  {}
func (n *nullLogger) Warn(msg string, fields ...Field)  {}
func (n *nullLogger) Error(msg string, fields ...Field) {}
func (n *nullLogger) WithFields(fields ...Field) Logger { return n }

// simpleLogger writes logs to an io.Writer.
type simpleLogger struct {
	mu     sync.Mutex
	out    io.Writer
	level  Level
	fields []Field
}

// NewSimpleLogger creates a simple logger that writes to the given writer.
func NewSimpleLogger(out io.Writer, level Level) Logger {
	return &simpleLogger{out: out, level: level}
}

func (s *simpleLogger) log(level Level, msg string, fields ...Field) {
	if level < s.level {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Format: timestamp level message field1=value1 field2=value2
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	fmt.Fprintf(s.out, "%s %s %s", timestamp, level.String(), msg)

	// Add persistent fields first
	for _, f := range s.fields {
		fmt.Fprintf(s.out, " %s=%v", f.Key, f.Value)
	}

	// Add call-specific fields
	for _, f := range fields {
		fmt.Fprintf(s.out, " %s=%v", f.Key, f.Value)
	}

	fmt.Fprintln(s.out)
}

func (s *simpleLogger) Debug(msg string, fields ...Field) {
	s.log(LevelDebug, msg, fields...)
}

func (s *simpleLogger) Info(msg string, fields ...Field) {
	s.log(LevelInfo, msg, fields...)
}

func (s *simpleLogger) Warn(msg string, fields ...Field) {
	s.log(LevelWarn, msg, fields...)
}

func (s *simpleLogger) Error(msg string, fields ...Field) {
	s.log(LevelError, msg, fields...)
}

func (s *simpleLogger) WithFields(fields ...Field) Logger {
	newFields := make([]Field, len(s.fields)+len(fields))
	copy(newFields, s.fields)
	copy(newFields[len(s.fields):], fields)
	return &simpleLogger{
		out:    s.out,
		level:  s.level,
		fields: newFields,
	}
}

// Package-level logger (null by default for zero overhead)
var (
	defaultLogger Logger = &nullLogger{}
	loggerMu      sync.RWMutex
)

// SetLogger sets the package-level logger.
// Call with nil to disable logging.
func SetLogger(l Logger) {
	loggerMu.Lock()
	defer loggerMu.Unlock()
	if l == nil {
		defaultLogger = &nullLogger{}
	} else {
		defaultLogger = l
	}
}

// GetLogger returns the current package-level logger.
func GetLogger() Logger {
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return defaultLogger
}

// EnableDebugLogging enables debug logging to stderr.
// This is a convenience function for development.
func EnableDebugLogging() {
	SetLogger(NewSimpleLogger(os.Stderr, LevelDebug))
}

// EnableFileLogging enables logging to a file.
func EnableFileLogging(path string, level Level) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	SetLogger(NewSimpleLogger(f, level))
	return nil
}

// Package-level logging functions that use the default logger

// Debug logs a debug message.
func Debug(msg string, fields ...Field) {
	GetLogger().Debug(msg, fields...)
}

// Info logs an info message.
func Info(msg string, fields ...Field) {
	GetLogger().Info(msg, fields...)
}

// Warn logs a warning message.
func Warn(msg string, fields ...Field) {
	GetLogger().Warn(msg, fields...)
}

// Error logs an error message.
func Error(msg string, fields ...Field) {
	GetLogger().Error(msg, fields...)
}
