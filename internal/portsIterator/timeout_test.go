package portsIterator

import (
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/utils"
)

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
