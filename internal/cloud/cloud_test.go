package cloud

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/config"
)

func TestValidateCredsFile(t *testing.T) {
	t.Run("empty credsFile is a no-op", func(t *testing.T) {
		err := validateCredsFile("gcp", "")
		if err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
	})

	t.Run("non-gcp provider with creds prints warning and returns nil", func(t *testing.T) {
		// warning is printed to stdout; we just check no error is returned
		err := validateCredsFile("aws", "/some/file.json")
		if err != nil {
			t.Fatalf("expected nil for non-gcp provider, got %v", err)
		}
	})

	t.Run("path with spaces is rejected", func(t *testing.T) {
		err := validateCredsFile("gcp", "/home/user/my keys/sa.json")
		if err == nil {
			t.Fatal("expected error for path with spaces, got nil")
		}
	})

	t.Run("file not found is rejected", func(t *testing.T) {
		err := validateCredsFile("gcp", "/nonexistent/path/sa.json")
		if err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})

	t.Run("invalid JSON is rejected", func(t *testing.T) {
		f, _ := os.CreateTemp(t.TempDir(), "creds*.json")
		f.WriteString("not json at all")
		f.Close()
		err := validateCredsFile("gcp", f.Name())
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil")
		}
	})

	t.Run("valid JSON sets GOOGLE_APPLICATION_CREDENTIALS", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "sa.json")
		os.WriteFile(path, []byte(`{"type":"service_account"}`), 0600)
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "") // clear before test
		err := validateCredsFile("gcp", path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); got != path {
			t.Fatalf("expected GOOGLE_APPLICATION_CREDENTIALS=%s, got %s", path, got)
		}
	})
}

func TestExtractProviderArg(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantProvider string
		wantFiltered []string
	}{
		{
			name:         "provider after flags",
			args:         []string{"enumeraga", "--creds", "/path/sa.json", "gcp"},
			wantProvider: "gcp",
			wantFiltered: []string{"enumeraga", "--creds", "/path/sa.json"},
		},
		{
			name:         "provider before flags",
			args:         []string{"enumeraga", "gcp", "--creds", "/path/sa.json"},
			wantProvider: "gcp",
			wantFiltered: []string{"enumeraga", "--creds", "/path/sa.json"},
		},
		{
			name:         "provider alias",
			args:         []string{"enumeraga", "aws"},
			wantProvider: "aws",
			wantFiltered: []string{"enumeraga"},
		},
		{
			name:         "no provider",
			args:         []string{"enumeraga", "--help"},
			wantProvider: "",
			wantFiltered: []string{"enumeraga", "--help"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotProvider, gotFiltered := extractProviderArg(tt.args)
			if gotProvider != tt.wantProvider {
				t.Errorf("provider: got %q, want %q", gotProvider, tt.wantProvider)
			}
			if len(gotFiltered) != len(tt.wantFiltered) {
				t.Errorf("filtered len: got %d, want %d: %v", len(gotFiltered), len(tt.wantFiltered), gotFiltered)
				return
			}
			for i := range gotFiltered {
				if gotFiltered[i] != tt.wantFiltered[i] {
					t.Errorf("filtered[%d]: got %q, want %q", i, gotFiltered[i], tt.wantFiltered[i])
				}
			}
		})
	}
}

func TestGcpAuthPreflight(t *testing.T) {
	t.Run("success string in output returns nil and writes log", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "gcloud_auth_login.log")
		successOutput := []byte("Activated service account credentials for: [test@proj.iam.gserviceaccount.com]")

		err := checkGcpAuthOutput(successOutput, nil, logPath)
		if err != nil {
			t.Fatalf("expected nil, got %v", err)
		}
		content, _ := os.ReadFile(logPath)
		if string(content) != string(successOutput) {
			t.Fatal("log file content mismatch")
		}
	})

	t.Run("non-zero exit returns error and writes log", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "gcloud_auth_login.log")
		output := []byte("ERROR: invalid credentials")
		err := checkGcpAuthOutput(output, fmt.Errorf("exit status 1"), logPath)
		if err == nil {
			t.Fatal("expected error for non-zero exit")
		}
		content, readErr := os.ReadFile(logPath)
		if readErr != nil {
			t.Fatalf("expected log file to be written, got read error: %v", readErr)
		}
		if string(content) != string(output) {
			t.Fatal("log file content mismatch on failure path")
		}
	})

	t.Run("zero exit but missing success string returns error", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, "gcloud_auth_login.log")
		err := checkGcpAuthOutput([]byte("some unexpected output"), nil, logPath)
		if err == nil {
			t.Fatal("expected error when success string absent")
		}
	})
}

func TestCloudConfigNucleiDefaults(t *testing.T) {
	cfg := config.NewCloudConfig()
	if !cfg.NucleiEnabled {
		t.Error("expected NucleiEnabled to default to true")
	}
	if cfg.NucleiTargetURL != "" {
		t.Errorf("expected NucleiTargetURL to default to empty, got %q", cfg.NucleiTargetURL)
	}
}
