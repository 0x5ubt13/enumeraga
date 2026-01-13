package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

// Logger provides structured logging with backward-compatible interface
// Maintains colored output while providing better control and testability
type Logger struct {
	quiet       bool
	verbose     bool
	output      io.Writer
	errorOutput io.Writer
	mu          sync.Mutex
}

// Global logger instance - initialised to maintain backward compatibility
var defaultLogger *Logger
var loggerOnce sync.Once

// InitLogger initialises the global logger (called once at startup)
func InitLogger(quiet, verbose bool) *Logger {
	loggerOnce.Do(func() {
		defaultLogger = &Logger{
			quiet:       quiet,
			verbose:     verbose,
			output:      os.Stdout,
			errorOutput: os.Stderr,
		}
	})
	return defaultLogger
}

// GetLogger returns the global logger instance, initializing if needed
func GetLogger() *Logger {
	if defaultLogger == nil {
		return InitLogger(false, false)
	}
	return defaultLogger
}

// SetQuiet enables/disables quiet mode
func (l *Logger) SetQuiet(quiet bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.quiet = quiet
}

// SetVerbose enables/disables verbose mode
func (l *Logger) SetVerbose(verbose bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.verbose = verbose
}

// Info logs an informational message (respects quiet mode)
func (l *Logger) Info(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.quiet {
		fmt.Fprintf(l.output, format, args...)
	}
}

// Infof logs an informational message with newline (respects quiet mode)
func (l *Logger) Infof(format string, args ...interface{}) {
	l.Info(format+"\n", args...)
}

// Print logs a message without quiet mode filtering (for important messages)
func (l *Logger) Print(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.output, format, args...)
}

// Printf logs a message with newline without quiet mode filtering
func (l *Logger) Printf(format string, args ...interface{}) {
	l.Print(format+"\n", args...)
}

// Error logs an error message (always shown, regardless of quiet mode)
func (l *Logger) Error(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.errorOutput, "%s %s\n", Red("[-] Error detected:"), msg)
}

// Success logs a success message (respects quiet mode)
func (l *Logger) Success(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.quiet {
		fmt.Fprintf(l.output, format, args...)
	}
}

// Successf logs a success message with newline (respects quiet mode)
func (l *Logger) Successf(format string, args ...interface{}) {
	l.Success(format+"\n", args...)
}

// Debug logs a debug message (only in verbose mode)
func (l *Logger) Debug(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.verbose {
		fmt.Fprintf(l.output, format, args...)
	}
}

// Debugf logs a debug message with newline (only in verbose mode)
func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Debug(format+"\n", args...)
}

// ColoredMsg logs a colored message using the existing color functions
// This maintains backward compatibility with PrintCustomBiColourMsg
func (l *Logger) ColoredMsg(color1, color2 string, parts ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.quiet && !isImportantMessage(parts) {
		return
	}

	// Use existing PrintCustomBiColourMsg logic
	PrintCustomBiColourMsg(color1, color2, parts...)
}

// isImportantMessage determines if a message should bypass quiet mode
// Error messages and critical notifications are always shown
func isImportantMessage(parts []string) bool {
	if len(parts) == 0 {
		return false
	}

	// Check for error/warning indicators
	first := parts[0]
	return first == "[-]" || first == "[!]" || first == "[+]"
}

// SetOutput allows redirecting output for testing
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// SetErrorOutput allows redirecting error output for testing
func (l *Logger) SetErrorOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errorOutput = w
}

// Package-level convenience functions for backward compatibility
// These maintain the existing API while using the logger internally

// LogInfo logs an info message using the global logger
func LogInfo(format string, args ...interface{}) {
	GetLogger().Info(format, args...)
}

// LogError logs an error message using the global logger
func LogError(format string, args ...interface{}) {
	GetLogger().Error(format, args...)
}

// LogSuccess logs a success message using the global logger
func LogSuccess(format string, args ...interface{}) {
	GetLogger().Success(format, args...)
}

// LogDebug logs a debug message using the global logger
func LogDebug(format string, args ...interface{}) {
	GetLogger().Debug(format, args...)
}

// StandardLogger returns a Go standard library logger backed by our logger
// Useful for integrating with libraries that expect *log.Logger
func (l *Logger) StandardLogger() *log.Logger {
	return log.New(l.output, "", 0)
}
