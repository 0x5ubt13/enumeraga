package context

import (
	"sync"
	"testing"
	"time"
)

// TestSetRunDeadlineBoundsTheGlobalContext verifies the wall-clock budget is
// applied to the context every tool derives from.
func TestSetRunDeadlineBoundsTheGlobalContext(t *testing.T) {
	resetGlobalContextForTest()

	InitGlobalContext()
	SetRunDeadline(2 * time.Second)

	deadline, ok := GetGlobalContext().Deadline()
	if !ok {
		t.Fatal("global context has no deadline after SetRunDeadline")
	}
	if remaining := time.Until(deadline); remaining <= 0 || remaining > 2*time.Second+time.Second {
		t.Errorf("deadline in %v, want ~2s", remaining)
	}
}

// TestSetRunDeadlineIgnoresZero verifies an unset budget leaves the context
// unbounded, so an ordinary run is unaffected.
func TestSetRunDeadlineIgnoresZero(t *testing.T) {
	resetGlobalContextForTest()

	InitGlobalContext()
	SetRunDeadline(0)

	if _, ok := GetGlobalContext().Deadline(); ok {
		t.Error("global context gained a deadline from a zero budget")
	}
}

// TestRunDeadlineExceeded verifies an expired budget is distinguishable from a
// user interrupt, which is what lets the caller tell a bounded stop from a failure.
func TestRunDeadlineExceeded(t *testing.T) {
	resetGlobalContextForTest()

	InitGlobalContext()
	SetRunDeadline(50 * time.Millisecond)

	if RunDeadlineExceeded() {
		t.Error("RunDeadlineExceeded() true before the budget expired")
	}

	<-GetGlobalContext().Done()

	if !RunDeadlineExceeded() {
		t.Error("RunDeadlineExceeded() false after the budget expired")
	}
}

// TestRunDeadlineExceededFalseOnCancel verifies a cancellation is not reported
// as a deadline, so Ctrl+C does not produce a timeout exit code.
func TestRunDeadlineExceededFalseOnCancel(t *testing.T) {
	resetGlobalContextForTest()

	InitGlobalContext()
	CancelGlobalContext()
	<-GetGlobalContext().Done()

	if RunDeadlineExceeded() {
		t.Error("RunDeadlineExceeded() true after a plain cancellation")
	}
}

// resetGlobalContextForTest clears the package state between tests. The global
// context is process-wide by design, so tests must reset it explicitly.
func resetGlobalContextForTest() {
	ctxMu.Lock()
	globalCtx = nil
	ctxMu.Unlock()

	globalCancel = nil
	deadlineCancel = nil
	shutdownOnce = sync.Once{}

	shutdownMu.Lock()
	shutdownStarted = false
	shutdownMu.Unlock()
}
