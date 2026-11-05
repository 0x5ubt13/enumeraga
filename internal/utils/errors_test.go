package utils

import (
	"errors"
	"fmt"
	"testing"
)

func TestRunExitCode(t *testing.T) {
	tests := []struct {
		name        string
		deadlineHit bool
		interrupted bool
		want        int
	}{
		{"completed", false, false, 0},
		{"wall-clock deadline", true, false, 124},
		{"stopped by a signal", false, true, 130},
		{"deadline expired before a later signal", true, true, 124},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RunExitCode(tt.deadlineHit, tt.interrupted); got != tt.want {
				t.Errorf("RunExitCode(%v, %v) = %d, want %d", tt.deadlineHit, tt.interrupted, got, tt.want)
			}
		})
	}
}

func TestExitCodeForError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"help", ErrHelpRequested, 0},
		{"install", ErrInstallComplete, 0},
		{"cloud complete", ErrCloudComplete, 0},
		{"cloud complete wrapped", fmt.Errorf("cloud: %w", ErrCloudComplete), 0},
		{"cloud interrupted", ErrCloudInterrupted, 130},
		{"cloud interrupted wrapped", fmt.Errorf("cloud: %w", ErrCloudInterrupted), 130},
		{"other failure", errors.New("boom"), 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCodeForError(tt.err); got != tt.want {
				t.Errorf("ExitCodeForError(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}

func TestCloudInterruptedIsNotSuccess(t *testing.T) {
	if IsExitSuccess(ErrCloudInterrupted) {
		t.Error("an interrupted cloud scan must not be reported as a successful exit")
	}
}
