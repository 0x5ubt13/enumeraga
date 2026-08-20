package context

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/utils/output"
)

// Global context for graceful shutdown - allows cancellation of all running tools
var (
	globalCtx    context.Context
	globalCancel context.CancelFunc

	// deadlineCancel releases the wall-clock timer installed by SetRunDeadline.
	// It is held for the process lifetime rather than invoked; releasing it
	// early would cancel the run, and the timer is reclaimed on process exit
	// regardless. Kept as a field (not discarded with "_") so the intent behind
	// leaving it uncalled is documented rather than implicit.
	//nolint:unused // deliberately write-only; see comment above
	deadlineCancel context.CancelFunc

	// ctxMu guards globalCtx, which is written twice — once at start-up and once
	// when a wall-clock budget is installed — and read from every tool goroutine.
	ctxMu sync.RWMutex

	shutdownOnce    sync.Once
	shutdownStarted bool
	shutdownMu      sync.RWMutex
)

// InitGlobalContext initialises the global context with signal handling.
// Call this once at program startup (in main.go).
func InitGlobalContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())

	ctxMu.Lock()
	globalCtx, globalCancel = ctx, cancel
	ctxMu.Unlock()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigChan
		shutdownMu.Lock()
		shutdownStarted = true
		shutdownMu.Unlock()

		output.PrintCustomBiColourMsg("yellow", "red", "\n[!] Received signal ", sig.String(), ", initiating graceful shutdown...")
		output.PrintCustomBiColourMsg("cyan", "yellow", "[*] Waiting for running tools to terminate (press Ctrl+C again to force exit)...")

		// Cancel all contexts
		globalCancel()

		// Listen for second signal to force exit
		go func() {
			<-sigChan
			output.PrintCustomBiColourMsg("red", "yellow", "\n[!] Force exit requested. Terminating immediately...")
			os.Exit(1)
		}()
	}()

	return ctx
}

// GetGlobalContext returns the global context for use in tool execution.
// Returns a background context if InitGlobalContext hasn't been called.
func GetGlobalContext() context.Context {
	ctxMu.RLock()
	defer ctxMu.RUnlock()
	if globalCtx == nil {
		return context.Background()
	}
	return globalCtx
}

// SetRunDeadline bounds the already-initialised global context to d.
//
// The deadline arrives separately from initialisation because signal handling
// must be in place from process start, while the wall-clock budget only becomes
// known once the CLI flags have been parsed. Call this once, before any scanning
// begins. A zero or negative d leaves the context unbounded.
func SetRunDeadline(d time.Duration) {
	if d <= 0 {
		return
	}

	ctxMu.Lock()
	defer ctxMu.Unlock()
	if globalCtx == nil {
		return
	}
	globalCtx, deadlineCancel = context.WithTimeout(globalCtx, d)
}

// RunDeadlineExceeded reports whether the run's wall-clock budget expired, as
// distinct from a user interrupt. The caller uses this to exit with a code that
// says "bounded and stopped, the partial results are valid" rather than "failed".
func RunDeadlineExceeded() bool {
	ctxMu.RLock()
	defer ctxMu.RUnlock()
	if globalCtx == nil {
		return false
	}
	return errors.Is(globalCtx.Err(), context.DeadlineExceeded)
}

// IsShuttingDown returns true if a shutdown has been initiated.
func IsShuttingDown() bool {
	shutdownMu.RLock()
	defer shutdownMu.RUnlock()
	return shutdownStarted
}

// CancelGlobalContext cancels the global context, signaling all tools to stop.
func CancelGlobalContext() {
	shutdownOnce.Do(func() {
		if globalCancel != nil {
			globalCancel()
		}
	})
}
