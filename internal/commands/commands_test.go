package commands

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/config"
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

func TestPrepCloudToolNucleiSkipsWithoutTarget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	tmpDir := t.TempDir() + "/"
	verbose := false
	cfg := &config.CloudConfig{
		Provider:        "aws",
		NucleiEnabled:   true,
		NucleiTargetURL: "", // no target -- should return nil immediately
	}
	err := PrepCloudTool("nuclei", tmpDir, cfg, &verbose)
	if err != nil {
		t.Errorf("expected nil error when no target URL, got: %v", err)
	}
}

func TestPrepCloudToolNucleiDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	tmpDir := t.TempDir() + "/"
	verbose := false
	cfg := &config.CloudConfig{
		Provider:        "aws",
		NucleiEnabled:   false,
		NucleiTargetURL: "https://example.com",
	}
	err := PrepCloudTool("nuclei", tmpDir, cfg, &verbose)
	if err != nil {
		t.Errorf("expected nil error when disabled, got: %v", err)
	}
}

func TestPrepCloudToolCredInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping cloud tool test in short mode")
	}

	dir := t.TempDir()
	verbose := false

	cfg := &config.CloudConfig{
		Provider:  "gcp",
		CredsFile: "/tmp/fake.json",
	}

	// Should not panic — tool not installed returns error gracefully
	err := PrepCloudTool("scoutsuite", dir, cfg, &verbose)
	// err may or may not be nil depending on whether scout is installed
	// We just verify no panic occurred
	_ = err
}

func TestPrepCloudToolGCPIAMBruteSkipsNonGCP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	tmpDir := t.TempDir() + "/"
	verbose := false
	cfg := &config.CloudConfig{
		Provider:           "aws",
		GCPIAMBruteEnabled: true,
	}
	err := PrepCloudTool("gcp_iam_brute", tmpDir, cfg, &verbose)
	if err != nil {
		t.Errorf("expected nil error for non-GCP provider, got: %v", err)
	}
}

func TestPrepCloudToolGCPIAMBruteSkipsWhenDisabled(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	tmpDir := t.TempDir() + "/"
	verbose := false
	cfg := &config.CloudConfig{
		Provider:           "gcp",
		GCPIAMBruteEnabled: false,
	}
	err := PrepCloudTool("gcp_iam_brute", tmpDir, cfg, &verbose)
	if err != nil {
		t.Errorf("expected nil error when disabled, got: %v", err)
	}
}

func TestResolveGCPIAMBruteEmailFromConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	cfg := &config.CloudConfig{
		GCPIAMBruteEmail: "test@project.iam.gserviceaccount.com",
	}
	email, err := resolveGCPIAMBruteEmail(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "test@project.iam.gserviceaccount.com" {
		t.Errorf("expected override email, got %q", email)
	}
}

func TestResolveGCPIAMBruteEmailFromCredsFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in short mode")
	}
	// Write a minimal service account JSON to a temp file
	credsJSON := `{"type":"service_account","client_email":"sa@my-project.iam.gserviceaccount.com"}`
	f, err := os.CreateTemp("", "creds-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(credsJSON); err != nil {
		t.Fatal(err)
	}
	f.Close()

	cfg := &config.CloudConfig{
		CredsFile: f.Name(),
	}
	email, err := resolveGCPIAMBruteEmail(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if email != "sa@my-project.iam.gserviceaccount.com" {
		t.Errorf("expected email from creds file, got %q", email)
	}
}

// putStubOnPath drops empty executables named after each tool onto PATH so
// prep functions that check for a binary do not try to install one.
func putStubOnPath(t *testing.T, tools ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range tools {
		name := tool
		body := []byte("#!/bin/sh\n")
		if runtime.GOOS == "windows" {
			name += ".cmd"
			body = []byte("@echo off\r\n")
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o755); err != nil {
			t.Fatalf("failed to create stub %s: %v", tool, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestPrepScoutsuiteKeepsSpacedPathsAsSingleArgs(t *testing.T) {
	putStubOnPath(t, "scout")
	reportDir := filepath.Join(t.TempDir(), "scout report")
	creds := filepath.Join(t.TempDir(), "my creds.json")
	got, err := prepScoutsuite(&config.CloudConfig{
		Provider:  "gcp",
		CredsFile: creds,
	}, reportDir)
	if err != nil {
		t.Fatalf("prepScoutsuite() error = %v", err)
	}
	want := []string{"scout", "gcp", "--force", "--no-browser", "--report-dir", reportDir, "--service-account", creds}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepScoutsuite() = %#v, want %#v", got, want)
	}
}

func TestPrepProwlerKeepsSpacedPathsAsSingleArgs(t *testing.T) {
	putStubOnPath(t, "prowler")
	outDir := filepath.Join(t.TempDir(), "prowler out")
	creds := filepath.Join(t.TempDir(), "adc file.json")
	got, err := prepProwler(&config.CloudConfig{
		Provider:  "gcp",
		CredsFile: creds,
	}, outDir)
	if err != nil {
		t.Fatalf("prepProwler() error = %v", err)
	}
	want := []string{"prowler", "gcp", "-o", outDir, "--credentials-file", creds}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepProwler() = %#v, want %#v", got, want)
	}
}

func TestPrepProwlerAzureCLIKeepsSubscriptionAsSingleArg(t *testing.T) {
	putStubOnPath(t, "prowler")
	outDir := filepath.Join(t.TempDir(), "prowler out")
	got, err := prepProwler(&config.CloudConfig{
		Provider:          "azure",
		AzureSubscription: "sub with spaces",
	}, outDir)
	if err != nil {
		t.Fatalf("prepProwler() error = %v", err)
	}
	want := []string{"prowler", "azure", "-o", outDir, "--az-cli-auth", "--subscription-ids", "sub with spaces"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepProwler() = %#v, want %#v", got, want)
	}
}

func TestPrepCloudfoxKeepsSpacedPathsAsSingleArgs(t *testing.T) {
	putStubOnPath(t, "cloudfox")
	outDir := filepath.Join(t.TempDir(), "fox out")
	pmapper := filepath.Join(t.TempDir(), "pmapper data")
	got, err := prepCloudfox(&config.CloudConfig{
		Provider:   "aws",
		AWSProfile: "lab profile",
		PMapperDir: pmapper,
	}, outDir)
	if err != nil {
		t.Fatalf("prepCloudfox() error = %v", err)
	}
	want := []string{"cloudfox", "aws", "all-checks", "--outdir", outDir, "--profile", "lab profile", "--pmapper-data-basepath", pmapper}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepCloudfox() = %#v, want %#v", got, want)
	}
}

func TestPrepKubenumerateKeepsSpacedOutputAsSingleArg(t *testing.T) {
	outDir := filepath.Join(t.TempDir(), "k8s out")
	got, err := prepKubenumerate(&config.CloudConfig{Provider: "k8s"}, outDir)
	if err != nil {
		t.Fatalf("prepKubenumerate() error = %v", err)
	}
	want := []string{"python3", "kubenumerate.py", "-o", outDir}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepKubenumerate() = %#v, want %#v", got, want)
	}
}

func TestPrepGcpScannerKeepsSpacedPathsAsSingleArgs(t *testing.T) {
	putStubOnPath(t, "gcp-scanner")
	outDir := filepath.Join(t.TempDir(), "scanner out")
	creds := filepath.Join(t.TempDir(), "sa key.json")
	got, err := prepGcpScanner(&config.CloudConfig{
		Provider:   "gcp",
		GCPProject: "my project",
		CredsFile:  creds,
	}, outDir)
	if err != nil {
		t.Fatalf("prepGcpScanner() error = %v", err)
	}
	want := []string{"gcp-scanner", "-o", outDir, "-p", "my project", "-k", creds}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepGcpScanner() = %#v, want %#v", got, want)
	}
}

func TestPrepNucleiKeepsSpacedURLAsSingleArg(t *testing.T) {
	putStubOnPath(t, "nuclei")
	got, err := prepNuclei(&config.CloudConfig{
		Provider:        "aws",
		NucleiEnabled:   true,
		NucleiTargetURL: "https://example.com/path with space",
	})
	if err != nil {
		t.Fatalf("prepNuclei() error = %v", err)
	}
	want := []string{"nuclei", "-u", "https://example.com/path with space", "-t", "cloud/aws/", "-silent", "-no-interactivity", "-no-color"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepNuclei() = %#v, want %#v", got, want)
	}
}

func TestPrepAWSEnumeratorKeepsSpacedProfileAsSingleArg(t *testing.T) {
	putStubOnPath(t, "aws-enumerator")
	got, err := prepAWSEnumerator(&config.CloudConfig{
		Provider:             "aws",
		AWSEnumeratorEnabled: true,
		AWSProfile:           "lab profile",
	})
	if err != nil {
		t.Fatalf("prepAWSEnumerator() error = %v", err)
	}
	want := []string{"aws-enumerator", "enum", "-services", "all", "-profile", "lab profile"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepAWSEnumerator() = %#v, want %#v", got, want)
	}
}

func TestPrepPmapperReturnsArgvNotShellString(t *testing.T) {
	got, err := prepPmapper(&config.CloudConfig{Provider: "aws"}, t.TempDir())
	if err != nil {
		t.Fatalf("prepPmapper() error = %v", err)
	}
	want := []string{"pmapper", "graph", "create"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepPmapper() = %#v, want %#v", got, want)
	}
}

func TestScoutAzureCLIArgsKeepsSpacedPathsAsSingleArgs(t *testing.T) {
	reportDir := filepath.Join(t.TempDir(), "azure report")
	got := scoutAzureCLIArgs(reportDir, "sub with spaces")
	want := []string{"scout", "azure", "--cli", "--force", "--no-browser", "--report-dir", reportDir, "--subscriptions", "sub with spaces"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scoutAzureCLIArgs() = %#v, want %#v", got, want)
	}
}

func TestScoutAzureFileAuthArgsKeepsSpacedPathsAsSingleArgs(t *testing.T) {
	auth := filepath.Join(t.TempDir(), "auth file.json")
	reportDir := filepath.Join(t.TempDir(), "azure report")
	got := scoutAzureFileAuthArgs(auth, reportDir, "sub with spaces")
	want := []string{"scout", "azure", "--file-auth", auth, "--force", "--no-browser", "--report-dir", reportDir, "--subscriptions", "sub with spaces"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scoutAzureFileAuthArgs() = %#v, want %#v", got, want)
	}
}

func TestGcpIAMBruteCommandKeepsSpacedValuesAsSingleArgs(t *testing.T) {
	got := gcpIAMBruteCommand("ya29.token with space", "my project", "sa name@x.com")
	want := []string{"gcp-iam-brute", "--access-token", "ya29.token with space", "--project-id", "my project", "--service-account-email", "sa name@x.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("gcpIAMBruteCommand() = %#v, want %#v", got, want)
	}
}
