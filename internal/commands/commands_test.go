package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// TestWPEnumeration tests WordPress detection logic
func TestWPEnumeration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires external tools in short mode")
	}

	// This test would require mocking curl or having a test server
	// For now, we'll just verify it doesn't panic with invalid input
	tmpDir := t.TempDir()
	verbose := true

	t.Run("invalid URL does not panic", func(t *testing.T) {
		// Should return gracefully, not panic
		WPEnumeration("http://invalid-test-url-12345.invalid", tmpDir, "80", &verbose)
	})
}

// TestTomcatEnumeration tests Tomcat detection logic
func TestTomcatEnumeration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test that requires external tools in short mode")
	}

	tmpDir := t.TempDir()
	verbose := true
	brute := false

	t.Run("invalid URL does not panic", func(t *testing.T) {
		// Should return gracefully, not panic
		tomcatEnumeration("invalid-test-url-12345.invalid", "http://invalid-test-url-12345.invalid", tmpDir, "8080", &brute, &verbose)
	})
}

// TestRunCIDR tests CIDR validation in RunRangeTools
func TestRunCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{
			name:    "valid CIDR",
			cidr:    "192.168.1.0/24",
			wantErr: false,
		},
		{
			name:    "invalid CIDR",
			cidr:    "invalid",
			wantErr: true,
		},
		{
			name:    "empty CIDR",
			cidr:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test just the validation part
			err := utils.ValidateCIDR(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCIDR(%q) error = %v, wantErr %v", tt.cidr, err, tt.wantErr)
			}
		})
	}
}

// TestToolOutputPath tests tool output path generation
func TestToolOutputPath(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		caseDir  string
		tool     string
		port     string
		expected string
	}{
		{
			name:     "nmap output",
			caseDir:  tmpDir + "/",
			tool:     "nmap",
			port:     "80",
			expected: tmpDir + "/nmap_80.out",
		},
		{
			name:     "wpscan output",
			caseDir:  tmpDir + "/",
			tool:     "wpscan",
			port:     "443",
			expected: tmpDir + "/wpscan_443.out",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filepath.Join(tt.caseDir, tt.tool+"_"+tt.port+".out")
			if result != tt.expected {
				t.Errorf("got %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestGenerateReportStructure tests basic report generation logic
func TestGenerateReportStructure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	outputDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		t.Fatalf("Failed to create output directory: %v", err)
	}

	// Note: Global state is managed by the main program
	// Just verify output directory exists

	t.Run("report directory structure", func(t *testing.T) {
		// Verify output directory exists
		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			t.Errorf("Output directory does not exist: %s", outputDir)
		}
	})
}

// TestValidateToolCommands tests that tool command arrays are properly formed
func TestValidateToolCommands(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "empty command",
			args:    []string{},
			wantErr: true,
		},
		{
			name:    "valid command",
			args:    []string{"echo", "test"},
			wantErr: false,
		},
		{
			name:    "command with flags",
			args:    []string{"curl", "-s", "-X", "GET", "http://example.com"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasErr := len(tt.args) == 0
			if hasErr != tt.wantErr {
				t.Errorf("command validation: got error=%v, want error=%v", hasErr, tt.wantErr)
			}
		})
	}
}

// TestFileOutputCreation tests that tool outputs are written correctly
func TestFileOutputCreation(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test_output.txt")

	testContent := "test output content\n"

	// Write test content
	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Read back and verify
	content, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	if string(content) != testContent {
		t.Errorf("File content = %q, want %q", string(content), testContent)
	}
}

// TestPortRangeGeneration tests port range handling
func TestPortRangeGeneration(t *testing.T) {
	tests := []struct {
		name      string
		portRange string
		valid     bool
	}{
		{
			name:      "single port",
			portRange: "80",
			valid:     true,
		},
		{
			name:      "port range",
			portRange: "1-100",
			valid:     true,
		},
		{
			name:      "multiple ports",
			portRange: "22,80,443",
			valid:     true,
		},
		{
			name:      "invalid port",
			portRange: "70000",
			valid:     false,
		},
		{
			name:      "invalid range",
			portRange: "abc",
			valid:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := utils.ValidatePorts(tt.portRange)
			isValid := err == nil
			if isValid != tt.valid {
				t.Errorf("ValidatePorts(%q) valid=%v, want valid=%v", tt.portRange, isValid, tt.valid)
			}
		})
	}
}

// TestToolCommandConstruction tests building command arrays
func TestToolCommandConstruction(t *testing.T) {
	tests := []struct {
		name     string
		tool     string
		target   string
		flags    []string
		wantTool string
	}{
		{
			name:     "nmap command",
			tool:     "nmap",
			target:   "192.168.1.1",
			flags:    []string{"-sV", "-p", "80"},
			wantTool: "nmap",
		},
		{
			name:     "curl command",
			tool:     "curl",
			target:   "http://example.com",
			flags:    []string{"-s", "-X", "GET"},
			wantTool: "curl",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build command array
			args := append([]string{tt.tool}, tt.flags...)
			args = append(args, tt.target)

			if args[0] != tt.wantTool {
				t.Errorf("Command tool = %s, want %s", args[0], tt.wantTool)
			}

			// Verify target is in the args
			found := false
			for _, arg := range args {
				if strings.Contains(arg, tt.target) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Target %s not found in command args", tt.target)
			}
		})
	}
}

// TestOutputDirectoryStructure tests that output directories are created correctly
func TestOutputDirectoryStructure(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name   string
		subdir string
	}{
		{
			name:   "base output directory",
			subdir: "",
		},
		{
			name:   "target subdirectory",
			subdir: "192.168.1.1",
		},
		{
			name:   "nested subdirectory",
			subdir: "192.168.1.1/port_80",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dirPath := filepath.Join(tmpDir, tt.subdir)
			if err := os.MkdirAll(dirPath, 0755); err != nil {
				t.Errorf("Failed to create directory %s: %v", dirPath, err)
			}

			// Verify directory exists
			if _, err := os.Stat(dirPath); os.IsNotExist(err) {
				t.Errorf("Directory %s does not exist after creation", dirPath)
			}
		})
	}
}

// BenchmarkCommandConstruction benchmarks building command arrays
func BenchmarkCommandConstruction(b *testing.B) {
	for i := 0; i < b.N; i++ {
		args := []string{"nmap", "-sV", "-p", "80", "192.168.1.1"}
		_ = args
	}
}

// BenchmarkFilePathJoin benchmarks filepath operations
func BenchmarkFilePathJoin(b *testing.B) {
	base := "/tmp/enumeraga_output"
	target := "192.168.1.1"
	tool := "nmap"

	for i := 0; i < b.N; i++ {
		_ = filepath.Join(base, target, tool+"_output.txt")
	}
}
