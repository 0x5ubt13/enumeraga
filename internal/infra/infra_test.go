package infra

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCheckFive tests target validation
func TestCheckFive(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{
			name:    "valid target",
			target:  "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "empty target",
			target:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkFive(&tt.target)
			if tt.wantErr && err == nil {
				t.Errorf("checkFive() expected error for empty target, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("checkFive() unexpected error: %v", err)
			}
		})
	}
}

// TestCheckSix tests output directory creation
func TestCheckSix(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name   string
		output string
	}{
		{
			name:   "valid directory",
			output: filepath.Join(tmpDir, "test_output"),
		},
		{
			name:   "nested directory",
			output: filepath.Join(tmpDir, "test", "nested", "output"),
		},
	}

	quiet := true
	verbose := false

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkSix(&tt.output, &quiet, &verbose)

			// Verify directory was created
			if _, err := os.Stat(tt.output); os.IsNotExist(err) {
				t.Errorf("checkSix() did not create directory %s", tt.output)
			}
		})
	}
}

// TestCheckSeven tests target type detection (single vs multi-target)
func TestCheckSeven(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a test targets file
	targetsFile := filepath.Join(tmpDir, "targets.txt")
	targetsContent := "192.168.1.1\n10.0.0.1\n172.16.0.1\n"
	if err := os.WriteFile(targetsFile, []byte(targetsContent), 0644); err != nil {
		t.Fatalf("Failed to create test targets file: %v", err)
	}

	tests := []struct {
		name       string
		target     string
		wantLines  int
		shouldFail bool
	}{
		{
			name:      "single IP address",
			target:    "192.168.1.1",
			wantLines: 0,
		},
		{
			name:      "IPv6 address",
			target:    "::1",
			wantLines: 0,
		},
		{
			name:      "resolvable hostname",
			target:    "localhost",
			wantLines: 0,
		},
		{
			name:      "multi-target file",
			target:    targetsFile,
			wantLines: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldFail {
				t.Skip("Skipping test that calls os.Exit()")
			}

			targetCopy := tt.target
			result, err := checkSeven(&targetCopy)
			if err != nil {
				t.Errorf("checkSeven() returned unexpected error: %v", err)
				return
			}

			if result != tt.wantLines {
				t.Errorf("checkSeven() = %d, want %d", result, tt.wantLines)
			}

			// For hostname resolution tests, verify the target was updated to IP
			if tt.name == "resolvable hostname" {
				if targetCopy == tt.target {
					t.Errorf("checkSeven() did not update target from hostname to IP")
				}
			}
		})
	}
}

// TestCheckSevenInvalidCases tests error cases for checkSeven
func TestCheckSevenInvalidCases(t *testing.T) {
	tests := []struct {
		name   string
		target string
	}{
		{
			name:   "non-existent file",
			target: "/tmp/nonexistent_targets_file_12345.txt",
		},
		{
			name:   "invalid hostname",
			target: "this-hostname-definitely-does-not-exist-12345.invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetCopy := tt.target
			_, err := checkSeven(&targetCopy)
			if err == nil {
				t.Errorf("checkSeven() expected error for invalid target %q, got nil", tt.target)
			}
		})
	}
}

// TestPrintInfraUsage tests that usage function doesn't panic
func TestPrintInfraUsage(t *testing.T) {
	// Redirect stdout to suppress output during test
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w
	defer func() {
		os.Stdout = old
	}()

	// Just verify it doesn't panic
	printInfraUsage()
}

// Integration test to verify the flow works end-to-end
func TestInfraFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")

	// Note: OutputDir is set through checkSix function, not directly

	tests := []struct {
		name   string
		target string
		output string
	}{
		{
			name:   "single target flow",
			target: "127.0.0.1",
			output: outputDir,
		},
	}

	quiet := true
	verbose := false

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test checkFive
			checkFive(&tt.target)

			// Test checkSix
			checkSix(&tt.output, &quiet, &verbose)

			// Verify output directory exists
			if _, err := os.Stat(tt.output); os.IsNotExist(err) {
				t.Errorf("Output directory %s was not created", tt.output)
			}

			// Test checkSeven
			lines, err := checkSeven(&tt.target)
			if err != nil {
				t.Errorf("checkSeven() returned unexpected error: %v", err)
			}
			if lines != 0 {
				t.Errorf("checkSeven() for single target returned %d, want 0", lines)
			}
		})
	}
}
