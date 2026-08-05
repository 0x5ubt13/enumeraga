package installer

import (
	"os"
	"path/filepath"
	"testing"
)

// isToolPresent must treat a tool as present when EITHER the apt package is
// registered with dpkg OR the binary is resolvable on PATH. Tools installed
// out-of-band (the Docker image fetches nuclei as a pre-built binary into
// /usr/local/bin, and creates /usr/share/seclists with mkdir) are invisible to
// dpkg, so a dpkg-only check wrongly prompts to install tools that are present.
func TestIsToolPresentAcceptsEitherSource(t *testing.T) {
	tests := []struct {
		name    string
		dpkg    bool
		binary  bool
		present bool
	}{
		{name: "registered with dpkg only", dpkg: true, binary: false, present: true},
		{name: "on PATH only", dpkg: false, binary: true, present: true},
		{name: "both sources", dpkg: true, binary: true, present: true},
		{name: "neither source", dpkg: false, binary: false, present: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isToolPresentWith(
				"some-tool",
				func(string) bool { return tc.dpkg },
				func(string) bool { return tc.binary },
			)
			if got != tc.present {
				t.Errorf("isToolPresentWith(dpkg=%v, binary=%v) = %v, want %v",
					tc.dpkg, tc.binary, got, tc.present)
			}
		})
	}
}

// A package name such as ldap-utils has no binary of that name, so it can only
// ever be detected via dpkg. Guard that the OR-check keeps these working.
func TestIsToolPresentPackageOnlyNames(t *testing.T) {
	packageOnly := []string{
		"ldap-utils",
		"nfs-client",
		"snmp",
		"python3-impacket",
		"metasploit-framework",
	}

	for _, pkg := range packageOnly {
		t.Run(pkg, func(t *testing.T) {
			got := isToolPresentWith(
				pkg,
				func(string) bool { return true },  // dpkg knows it
				func(string) bool { return false }, // no such binary
			)
			if !got {
				t.Errorf("isToolPresentWith(%q) = false, want true when dpkg reports it installed", pkg)
			}
		})
	}
}

// CheckToolExists special-cases seclists to a directory check rather than a
// PATH lookup. Verify that path is intact, since the container relies on it.
func TestCheckToolExistsSeclistsUsesDirectory(t *testing.T) {
	if _, err := os.Stat("/usr/share/seclists"); err == nil {
		if !CheckToolExists("seclists") {
			t.Error("CheckToolExists(\"seclists\") = false, want true when /usr/share/seclists exists")
		}
		return
	}
	if CheckToolExists("seclists") {
		t.Error("CheckToolExists(\"seclists\") = true, want false when /usr/share/seclists is absent")
	}
}

// The tool list drives installation prompts. A name that is neither an apt
// package nor a binary can never be satisfied, so it would prompt on every run.
func TestKeyToolsAreNonEmptyAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range getKeyTools() {
		if tool == "" {
			t.Fatal("getKeyTools() contains an empty entry")
		}
		if seen[tool] {
			t.Errorf("getKeyTools() contains duplicate entry %q", tool)
		}
		seen[tool] = true
	}

	// Tools the Dockerfile must provide; regression guard for the three that
	// were missing from the image entirely (gowitness, rsync, cmseek).
	for _, required := range []string{"gowitness", "rsync", "cmseek", "nuclei", "seclists"} {
		if !seen[required] {
			t.Errorf("getKeyTools() missing expected tool %q", required)
		}
	}
}

// Under `docker run` without -it, stdin is a pipe rather than a character
// device. Consent must decline without blocking or appearing to prompt.
func TestConsentDeclinesWhenStdinNotATTY(t *testing.T) {
	original := os.Stdin
	t.Cleanup(func() { os.Stdin = original })

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	t.Cleanup(func() {
		read.Close()
		write.Close()
	})
	write.Close() // closed pipe mirrors docker's empty, non-TTY stdin
	os.Stdin = read

	if stdinIsInteractive() {
		t.Fatal("stdinIsInteractive() = true for a pipe, want false")
	}

	if got := Consent("some-tool"); got != 'n' {
		t.Errorf("Consent() = %q, want 'n' when stdin is not a TTY", got)
	}
}

// CheckToolExists resolves real binaries via PATH. Use a binary guaranteed to
// exist in any environment this test runs in.
func TestCheckToolExistsFindsBinaryOnPath(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "enumeraga-test-tool")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("failed to create test binary: %v", err)
	}
	t.Setenv("PATH", dir)

	if !CheckToolExists("enumeraga-test-tool") {
		t.Error("CheckToolExists() = false, want true for an executable on PATH")
	}
	if CheckToolExists("enumeraga-definitely-absent-tool") {
		t.Error("CheckToolExists() = true, want false for a tool absent from PATH")
	}
}
