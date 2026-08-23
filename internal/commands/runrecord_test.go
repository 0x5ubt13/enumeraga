package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/runrecord"
)

func recordedEntries(t *testing.T, dir string) []runrecord.Entry {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, runrecord.FileName))
	if err != nil {
		t.Fatalf("reading record: %v", err)
	}
	var out []runrecord.Entry
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var e runrecord.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// A tool held back by a bound is recorded as skipped, with its reason and no exit
// code, because nothing ran.
func TestASkippedToolIsRecordedWithItsReasonAndNoExitCode(t *testing.T) {
	dir := t.TempDir()
	originalRecorder, originalBounds := runrecord.Active, bounds.Active
	t.Cleanup(func() { runrecord.Active, bounds.Active = originalRecorder, originalBounds })

	b, err := bounds.Validate(bounds.Config{Rate: 5})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	bounds.Active = b
	runrecord.Active = runrecord.Open(dir)

	// cmseek has no throttle, so a rate cap skips it.
	_ = runToolAs("cmseek on port 80", []string{"cmseek", "-u", "http://example.invalid"},
		filepath.Join(dir, "cmseek.out"), "80", &falseFlag)
	runrecord.Active.Close()

	entries := recordedEntries(t, dir)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Kind != runrecord.KindTool {
		t.Errorf("kind = %q, want tool", e.Kind)
	}
	if e.Status != runrecord.StatusSkipped {
		t.Errorf("status = %q, want skipped", e.Status)
	}
	if e.SkipReason == "" {
		t.Error("skip_reason empty; the reason is the point of recording a skip")
	}
	if e.ExitCode != nil {
		t.Errorf("exit_code = %d, want absent: nothing ran", *e.ExitCode)
	}
	if len(e.Argv) == 0 || e.Argv[0] != "cmseek" {
		t.Errorf("argv = %v, want the verbatim vector", e.Argv)
	}
}

// The exact status, not a boolean. `false` exits 1 on every Unix.
func TestAFailingToolRecordsItsRealExitCode(t *testing.T) {
	dir := t.TempDir()
	original := runrecord.Active
	t.Cleanup(func() { runrecord.Active = original })
	runrecord.Active = runrecord.Open(dir)

	_ = runToolAs("false on port 0", []string{"false"}, filepath.Join(dir, "false.out"), "0", &falseFlag)
	runrecord.Active.Close()

	e := recordedEntries(t, dir)[0]
	if e.ExitCode == nil {
		t.Fatal("exit_code absent for a tool that ran")
	}
	if *e.ExitCode != 1 {
		t.Errorf("exit_code = %d, want 1", *e.ExitCode)
	}
	if e.Status != runrecord.StatusFailed {
		t.Errorf("status = %q, want failed", e.Status)
	}
}

// Status and exit code may legitimately disagree, and the record must not force
// them into agreement. runToolAs returns nil for these three tools because they
// do not exit cleanly, so the tracker calls them completed; the real exit status
// is still information and is recorded as it was.
func TestToleratedNonZeroExitsRecordBothTruthfully(t *testing.T) {
	dir := t.TempDir()
	original := runrecord.Active
	t.Cleanup(func() { runrecord.Active = original })
	runrecord.Active = runrecord.Open(dir)

	// fping is one of the three tolerated tools. An unresolvable target makes it
	// exit non-zero without that being a failure enumeraga cares about.
	_ = runToolAs("fping on port 0", []string{"fping", "-c1", "no.such.host.invalid"},
		filepath.Join(dir, "fping.out"), "0", &falseFlag)
	runrecord.Active.Close()

	entries := recordedEntries(t, dir)
	if len(entries) != 1 {
		t.Skip("fping is not installed in this environment")
	}
	e := entries[0]
	if e.ExitCode == nil {
		t.Skip("fping is not installed in this environment")
	}
	if e.Status != runrecord.StatusCompleted {
		t.Errorf("status = %q, want completed: enumeraga tolerates fping's exit status", e.Status)
	}
	if *e.ExitCode == 0 {
		t.Errorf("exit_code = %v, want the real non-zero status", e.ExitCode)
	}
}

var falseFlag = false
