package commands

import (
	"context"
	"testing"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// TestToolContextAppliesDeadline verifies that toolContext derives a context
// with a wall-clock deadline of ToolTimeout minutes from the parent context.
func TestToolContextAppliesDeadline(t *testing.T) {
	originalTimeout := utils.ToolTimeout
	defer func() { utils.ToolTimeout = originalTimeout }()

	utils.ToolTimeout = 10
	ctx, cancel := toolContext(context.Background())
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("toolContext() returned a context with no deadline")
	}

	remaining := time.Until(deadline)
	// Expect ~10 minutes; allow a generous window for scheduling slack.
	if remaining < 9*time.Minute || remaining > 10*time.Minute+time.Second {
		t.Errorf("toolContext() deadline in %v, want ~10m", remaining)
	}
}

// TestToolContextPropagatesParentCancel verifies that cancelling the parent
// context (e.g. Ctrl+C via the global context) also cancels the tool context,
// preserving graceful-shutdown behaviour.
func TestToolContextPropagatesParentCancel(t *testing.T) {
	originalTimeout := utils.ToolTimeout
	defer func() { utils.ToolTimeout = originalTimeout }()

	utils.ToolTimeout = 10
	parent, parentCancel := context.WithCancel(context.Background())
	ctx, cancel := toolContext(parent)
	defer cancel()

	parentCancel()

	select {
	case <-ctx.Done():
		if ctx.Err() != context.Canceled {
			t.Errorf("tool context Err() = %v, want context.Canceled", ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("cancelling parent did not cancel the tool context")
	}
}

func TestGetTimeoutSeconds(t *testing.T) {
	// Save original value to restore later
	originalTimeout := utils.ToolTimeout
	defer func() {
		utils.ToolTimeout = originalTimeout
	}()

	tests := []struct {
		name           string
		timeoutInput   int
		expectedOutput string
	}{
		{"default 10 mins", 10, "600"},
		{"5 mins", 5, "300"},
		{"1 hour", 60, "3600"},
		{"0 mins", 0, "0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			utils.ToolTimeout = tt.timeoutInput
			got := getTimeoutSeconds()
			if got != tt.expectedOutput {
				t.Errorf("getTimeoutSeconds() = %v, want %v", got, tt.expectedOutput)
			}
		})
	}
}
