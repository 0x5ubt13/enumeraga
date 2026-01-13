package context

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/0x5ubt13/enumeraga/internal/utils/output"
)

// Global context for graceful shutdown - allows cancellation of all running tools
var (
	globalCtx       context.Context
	globalCancel    context.CancelFunc
	shutdownOnce    sync.Once
	shutdownStarted bool
	shutdownMu      sync.RWMutex
)

// InitGlobalContext initialises the global context with signal handling.
// Call this once at program startup (in main.go).
func InitGlobalContext() context.Context {
	globalCtx, globalCancel = context.WithCancel(context.Background())

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

	return globalCtx
}

// GetGlobalContext returns the global context for use in tool execution.
// Returns a background context if InitGlobalContext hasn't been called.
func GetGlobalContext() context.Context {
	if globalCtx == nil {
		return context.Background()
	}
	return globalCtx
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
