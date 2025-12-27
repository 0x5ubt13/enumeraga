package utils

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestValidateIP tests IP address validation
func TestValidateIP(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{"valid IPv4", "192.168.1.1", false},
		{"valid IPv4 localhost", "127.0.0.1", false},
		{"valid IPv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", false},
		{"valid IPv6 short", "::1", false},
		{"invalid empty", "", true},
		{"invalid hostname", "example.com", true},
		{"invalid format", "256.256.256.256", true},
		{"invalid text", "not-an-ip", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateIP(tt.ip)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateIP(%q) error = %v, wantErr %v", tt.ip, err, tt.wantErr)
			}
		})
	}
}

// TestResolveHostToIP tests hostname to IP resolution
func TestResolveHostToIP(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		wantErr bool
		checkIP bool // If true, verify result is a valid IP
	}{
		{"valid IP address", "8.8.8.8", false, true},
		{"valid IPv6", "::1", false, true},
		{"localhost", "localhost", false, true},
		{"URL with http", "http://8.8.8.8", false, true},
		{"URL with https", "https://192.168.1.1", false, true},
		{"URL with path", "http://8.8.8.8/test/path", false, true},
		{"URL with port", "http://8.8.8.8:8080", false, true},
		{"invalid hostname", "this-hostname-should-not-exist-12345.invalid", true, false},
		{"empty string", "", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ResolveHostToIP(tt.host)
			if (err != nil) != tt.wantErr {
				t.Errorf("ResolveHostToIP(%q) error = %v, wantErr %v", tt.host, err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.checkIP {
				if net.ParseIP(result) == nil {
					t.Errorf("ResolveHostToIP(%q) = %q, expected valid IP", tt.host, result)
				}
			}
		})
	}
}

// TestValidateCIDR tests CIDR notation validation
func TestValidateCIDR(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		wantErr bool
	}{
		{"valid CIDR /24", "192.168.1.0/24", false},
		{"valid CIDR /16", "10.0.0.0/16", false},
		{"valid CIDR /32", "192.168.1.1/32", false},
		{"valid IPv6 CIDR", "2001:db8::/32", false},
		{"invalid no mask", "192.168.1.0", true},
		{"invalid mask too large", "192.168.1.0/33", true},
		{"invalid IP in CIDR", "256.256.256.256/24", true},
		{"invalid format", "not-a-cidr", true},
		{"empty string", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCIDR(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCIDR(%q) error = %v, wantErr %v", tt.cidr, err, tt.wantErr)
			}
		})
	}
}

// TestValidatePort tests single port validation
func TestValidatePort(t *testing.T) {
	tests := []struct {
		name    string
		port    string
		wantErr bool
	}{
		{"valid port 80", "80", false},
		{"valid port 443", "443", false},
		{"valid port 1", "1", false},
		{"valid port 65535", "65535", false},
		{"invalid port 0", "0", true},
		{"invalid port 65536", "65536", true},
		{"invalid negative", "-1", true},
		{"invalid text", "abc", true},
		{"invalid empty", "", true},
		{"invalid float", "80.5", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePort(tt.port)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePort(%q) error = %v, wantErr %v", tt.port, err, tt.wantErr)
			}
		})
	}
}

// TestValidatePorts tests comma-separated port list validation
func TestValidatePorts(t *testing.T) {
	tests := []struct {
		name    string
		ports   string
		wantErr bool
	}{
		{"single port", "80", false},
		{"multiple ports", "80,443,8080", false},
		{"port range", "1-100", false},
		{"mixed ports and ranges", "22,80,443,8000-9000", false},
		{"ports with spaces", "80, 443, 8080", false},
		{"invalid port in list", "80,99999,443", true},
		{"invalid range format", "80-90-100", true},
		{"invalid range values", "100-50", true}, // Should error when start > end
		{"empty string", "", false},              // Empty is technically valid (no invalid ports)
		{"just comma", ",", false},
		{"text in list", "80,abc,443", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePorts(tt.ports)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePorts(%q) error = %v, wantErr %v", tt.ports, err, tt.wantErr)
			}
		})
	}
}

// TestValidateFilePath tests file path validation
func TestValidateFilePath(t *testing.T) {
	// Create a temporary file for testing
	tmpDir := t.TempDir()
	validFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(validFile, []byte("test"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"valid file", validFile, false},
		{"non-existent file", filepath.Join(tmpDir, "nonexistent.txt"), true},
		{"empty path", "", true},
		{"directory instead of file", tmpDir, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFilePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFilePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}
}

// TestReadTargetsFile tests reading targets from a file
func TestReadTargetsFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name        string
		content     string
		wantTargets int
		wantErr     bool
	}{
		{
			name:        "single target",
			content:     "192.168.1.1\n",
			wantTargets: 1,
			wantErr:     false,
		},
		{
			name:        "multiple targets",
			content:     "192.168.1.1\n10.0.0.1\n172.16.0.1\n",
			wantTargets: 3,
			wantErr:     false,
		},
		{
			name:        "targets with empty lines",
			content:     "192.168.1.1\n\n10.0.0.1\n\n",
			wantTargets: 2,
			wantErr:     false,
		},
		{
			name:        "targets with whitespace",
			content:     "  192.168.1.1  \n  10.0.0.1  \n",
			wantTargets: 2,
			wantErr:     false,
		},
		{
			name:        "empty file",
			content:     "",
			wantTargets: 0,
			wantErr:     false,
		},
		{
			name:        "only whitespace",
			content:     "   \n  \n\n",
			wantTargets: 0,
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test file
			testFile := filepath.Join(tmpDir, tt.name+".txt")
			if err := os.WriteFile(testFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			targets, count := ReadTargetsFile(&testFile)
			if (targets == nil) != tt.wantErr {
				t.Errorf("ReadTargetsFile() error = %v, wantErr %v", targets == nil, tt.wantErr)
				return
			}
			if count != tt.wantTargets {
				t.Errorf("ReadTargetsFile() got %d targets, want %d", count, tt.wantTargets)
			}
			if !tt.wantErr && len(targets) != tt.wantTargets {
				t.Errorf("ReadTargetsFile() slice length = %d, want %d", len(targets), tt.wantTargets)
			}
		})
	}

	// Test non-existent file
	t.Run("non-existent file", func(t *testing.T) {
		nonExistentPath := filepath.Join(tmpDir, "nonexistent.txt")
		targets, count := ReadTargetsFile(&nonExistentPath)
		if targets != nil {
			t.Error("ReadTargetsFile() should return nil for non-existent file")
		}
		if count != 0 {
			t.Errorf("ReadTargetsFile() count = %d, want 0 for non-existent file", count)
		}
	})
}

// TestRemoveDuplicates tests duplicate removal from comma-separated strings
func TestRemoveDuplicates(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string // Expected unique values (order may vary)
	}{
		{
			name:  "no duplicates",
			input: "80,443,8080",
			want:  []string{"80", "443", "8080"},
		},
		{
			name:  "with duplicates",
			input: "80,443,80,8080,443",
			want:  []string{"80", "443", "8080"},
		},
		{
			name:  "single value",
			input: "80",
			want:  []string{"80"},
		},
		{
			name:  "empty string",
			input: "",
			want:  []string{},
		},
		{
			name:  "all same values",
			input: "80,80,80,80",
			want:  []string{"80"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveDuplicates(tt.input)

			// Parse result back into slice for comparison
			var resultSlice []string
			if result != "" {
				resultSlice = strings.Split(result, ",")
			}

			// Check count
			if len(resultSlice) != len(tt.want) {
				t.Errorf("RemoveDuplicates(%q) returned %d items, want %d", tt.input, len(resultSlice), len(tt.want))
				return
			}

			// Check all expected values are present (order-agnostic)
			resultMap := make(map[string]bool)
			for _, v := range resultSlice {
				resultMap[v] = true
			}

			for _, expected := range tt.want {
				if !resultMap[expected] {
					t.Errorf("RemoveDuplicates(%q) missing expected value %q", tt.input, expected)
				}
			}
		})
	}
}

// TestWriteTextToFile tests writing text to files
func TestWriteTextToFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		text     string
		filename string
		wantErr  bool
	}{
		{
			name:     "simple text",
			text:     "Hello, World!",
			filename: "test1.txt",
			wantErr:  false,
		},
		{
			name:     "multiline text",
			text:     "Line 1\nLine 2\nLine 3",
			filename: "test2.txt",
			wantErr:  false,
		},
		{
			name:     "empty text",
			text:     "",
			filename: "test3.txt",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filepath := filepath.Join(tmpDir, tt.filename)
			err := WriteTextToFile(filepath, tt.text)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteTextToFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify file contents (note: fmt.Fprintln adds a newline)
				content, err := os.ReadFile(filepath)
				if err != nil {
					t.Fatalf("Failed to read file: %v", err)
				}
				expectedContent := tt.text + "\n"
				if string(content) != expectedContent {
					t.Errorf("File content = %q, want %q", string(content), expectedContent)
				}
			}
		})
	}

	// Test writing to invalid path
	t.Run("invalid path", func(t *testing.T) {
		err := WriteTextToFile("/invalid/path/that/does/not/exist/file.txt", "test")
		if err == nil {
			t.Error("WriteTextToFile() should return error for invalid path")
		}
	})
}

// TestWritePortsToFile tests writing ports to file
func TestWritePortsToFile(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		ports    string
		target   string
		wantErr  bool
		wantFile bool
	}{
		{
			name:     "single port",
			ports:    "80",
			target:   "192.168.1.1",
			wantErr:  false,
			wantFile: true,
		},
		{
			name:     "multiple ports",
			ports:    "22,80,443,8080",
			target:   "10.0.0.1",
			wantErr:  false,
			wantFile: true,
		},
		{
			name:     "empty ports",
			ports:    "",
			target:   "192.168.1.1",
			wantErr:  false,
			wantFile: false, // Should not create file if no ports
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// WritePortsToFile expects a base path, adds "open_ports.txt" suffix
			basePath := filepath.Join(tmpDir, tt.target+"_")
			returnedPorts, err := WritePortsToFile(basePath, tt.ports, tt.target)
			if (err != nil) != tt.wantErr {
				t.Errorf("WritePortsToFile() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && tt.wantFile {
				// Verify file exists and contains correct data
				// The function creates a file named: basePath + "open_ports.txt"
				expectedFile := basePath + "open_ports.txt"
				if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
					t.Errorf("WritePortsToFile() did not create file at %q", expectedFile)
					return
				}

				content, err := os.ReadFile(expectedFile)
				if err != nil {
					t.Fatalf("Failed to read file: %v", err)
				}

				// Content should match the ports string (with added newline from Fprintln)
				if strings.TrimSpace(string(content)) != tt.ports {
					t.Errorf("File content = %q, want %q", string(content), tt.ports)
				}

				// Verify the return value is the ports string
				if returnedPorts != tt.ports {
					t.Errorf("WritePortsToFile() returned %q, want %q", returnedPorts, tt.ports)
				}
			}
		})
	}
}

// BenchmarkValidateIP benchmarks IP validation
func BenchmarkValidateIP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateIP("192.168.1.1")
	}
}

// BenchmarkResolveHostToIP benchmarks hostname resolution
func BenchmarkResolveHostToIP(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ResolveHostToIP("127.0.0.1")
	}
}

// BenchmarkValidateCIDR benchmarks CIDR validation
func BenchmarkValidateCIDR(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ValidateCIDR("192.168.1.0/24")
	}
}

// BenchmarkRemoveDuplicates benchmarks duplicate removal
func BenchmarkRemoveDuplicates(b *testing.B) {
	input := "80,443,80,8080,443,22,80,3389,443"
	for i := 0; i < b.N; i++ {
		RemoveDuplicates(input)
	}
}

// TestVisitedStateBasicFlow tests the basic visited state tracking flow
func TestVisitedStateBasicFlow(t *testing.T) {
	// Reset visited flags before test
	ResetVisitedFlags()

	// First check should mark as visited and return false (wasn't visited before)
	if IsVisited("http") {
		t.Error("HTTP should not be visited initially")
	}

	// Second check should return true (already visited)
	if !IsVisited("http") {
		t.Error("HTTP should be marked as visited after first call")
	}

	// Different protocol should not be affected
	if IsVisited("smb") {
		t.Error("SMB should not be visited initially")
	}

	// Reset should clear all flags
	ResetVisitedFlags()
	if IsVisited("http") {
		t.Error("HTTP should not be visited after reset")
	}
}

// TestVisitedStateConcurrency tests concurrent access to visited state
func TestVisitedStateConcurrency(t *testing.T) {
	ResetVisitedFlags()

	// Use the correct protocol names as defined in VisitedState switch cases
	protocols := []string{"http", "smb", "ldap", "ftp", "smtp", "imap", "snmp", "rsvc", "winrm"}
	done := make(chan bool, len(protocols))

	// Concurrently mark all protocols as visited
	for _, p := range protocols {
		go func(protocol string) {
			_ = IsVisited(protocol)
			done <- true
		}(p)
	}

	// Wait for all to complete
	for i := 0; i < len(protocols); i++ {
		<-done
	}

	// Now verify all are marked as visited (sequential check is fine here)
	for _, p := range protocols {
		if !IsVisited(p) {
			t.Errorf("Protocol %s should be visited after first access", p)
		}
	}
}

// TestWorkerPoolBasic tests basic worker pool operations
func TestWorkerPoolBasic(t *testing.T) {
	// Initialize pool with small size for testing
	InitWorkerPool(3)
	pool := GetWorkerPool()

	if pool.GetMaxWorkers() != 3 {
		t.Errorf("Expected max workers to be 3, got %d", pool.GetMaxWorkers())
	}

	// Acquire workers
	if !pool.Acquire() {
		t.Error("First acquire should succeed")
	}
	if pool.GetActiveWorkers() != 1 {
		t.Errorf("Expected 1 active worker, got %d", pool.GetActiveWorkers())
	}

	if !pool.Acquire() {
		t.Error("Second acquire should succeed")
	}
	if pool.GetActiveWorkers() != 2 {
		t.Errorf("Expected 2 active workers, got %d", pool.GetActiveWorkers())
	}

	if !pool.Acquire() {
		t.Error("Third acquire should succeed")
	}
	if pool.GetActiveWorkers() != 3 {
		t.Errorf("Expected 3 active workers, got %d", pool.GetActiveWorkers())
	}

	// Release one worker
	pool.Release()
	if pool.GetActiveWorkers() != 2 {
		t.Errorf("Expected 2 active workers after release, got %d", pool.GetActiveWorkers())
	}

	// Release remaining workers
	pool.Release()
	pool.Release()
	if pool.GetActiveWorkers() != 0 {
		t.Errorf("Expected 0 active workers after all releases, got %d", pool.GetActiveWorkers())
	}
}

// TestWorkerPoolConcurrency tests concurrent worker pool operations
func TestWorkerPoolConcurrency(t *testing.T) {
	InitWorkerPool(5)
	pool := GetWorkerPool()

	// Drain any existing workers from previous tests
	for pool.GetActiveWorkers() > 0 {
		pool.Release()
	}

	done := make(chan bool, 5)

	// Launch exactly 5 goroutines (matches pool size) that acquire, do work, then release
	for i := 0; i < 5; i++ {
		go func() {
			if pool.Acquire() {
				// Simulate work
				pool.Release()
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 5; i++ {
		<-done
	}

	// Verify pool is back to empty state
	if pool.GetActiveWorkers() != 0 {
		t.Errorf("Expected 0 active workers after all complete, got %d", pool.GetActiveWorkers())
	}
}

// TestWorkerPoolGetPool tests that GetWorkerPool returns a valid pool
func TestWorkerPoolGetPool(t *testing.T) {
	pool := GetWorkerPool()
	if pool == nil {
		t.Error("GetWorkerPool should return a non-nil pool")
	}
	// Pool should have a positive max workers count
	if pool.GetMaxWorkers() <= 0 {
		t.Errorf("Expected positive max workers, got %d", pool.GetMaxWorkers())
	}
}
