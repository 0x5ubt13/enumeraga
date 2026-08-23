package runrecord

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func readLines(t *testing.T, dir string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("reading record: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line is not valid JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func TestEachEntryIsOneJSONLine(t *testing.T) {
	dir := t.TempDir()
	r := Open(dir)
	r.Write(Entry{Kind: KindTool, Name: "nmap on port 80", Argv: []string{"nmap", "-p", "80"}})
	r.Write(Entry{Kind: KindProbe, Name: "http probe on port 80", URL: "http://x:80"})
	r.Close()

	lines := readLines(t, dir)
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2", len(lines))
	}
	if lines[0]["kind"] != "tool" || lines[1]["kind"] != "probe" {
		t.Errorf("kinds = %v, %v", lines[0]["kind"], lines[1]["kind"])
	}
}

// A probe has no command line. The explicit null is the point: a consumer can see
// the action had no argument vector rather than inferring a gap.
func TestProbeArgvIsExplicitlyNull(t *testing.T) {
	dir := t.TempDir()
	r := Open(dir)
	r.Write(Entry{Kind: KindProbe, Name: "https probe on port 443", URL: "https://x:443"})
	r.Close()

	line := readLines(t, dir)[0]
	v, present := line["argv"]
	if !present {
		t.Fatal("argv key absent; it must be present and null for a probe")
	}
	if v != nil {
		t.Errorf("argv = %v, want null", v)
	}
}

// A skip records no exit code, because nothing ran.
func TestSkipOmitsExitCode(t *testing.T) {
	dir := t.TempDir()
	r := Open(dir)
	r.Write(Entry{Kind: KindTool, Name: "cmseek on port 80", Status: StatusSkipped, SkipReason: "no throttle available"})
	r.Close()

	line := readLines(t, dir)[0]
	if _, present := line["exit_code"]; present {
		t.Errorf("exit_code present on a skip: %v", line["exit_code"])
	}
	if line["skip_reason"] != "no throttle available" {
		t.Errorf("skip_reason = %v", line["skip_reason"])
	}
}

// Exit code zero is meaningful and must survive, so the field cannot be omitempty.
func TestExitCodeZeroIsRecorded(t *testing.T) {
	dir := t.TempDir()
	r := Open(dir)
	code := 0
	r.Write(Entry{Kind: KindTool, Name: "nmap on port 80", Status: StatusCompleted, ExitCode: &code})
	r.Close()

	line := readLines(t, dir)[0]
	v, present := line["exit_code"]
	if !present {
		t.Fatal("exit_code absent for a completed tool")
	}
	if v.(float64) != 0 {
		t.Errorf("exit_code = %v, want 0", v)
	}
}

func TestConcurrentWritesProduceWholeLines(t *testing.T) {
	dir := t.TempDir()
	r := Open(dir)

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			r.Write(Entry{Kind: KindTool, Name: "tool", Argv: []string{"x", strings.Repeat("y", 200)}})
		}(i)
	}
	wg.Wait()
	r.Close()

	if got := len(readLines(t, dir)); got != 200 {
		t.Errorf("lines = %d, want 200 with none interleaved or lost", got)
	}
}

// An unwritable directory must disable recording, not fail the scan.
func TestAnUnwritableDirectoryDisablesRecordingSilently(t *testing.T) {
	r := Open(filepath.Join(t.TempDir(), "does", "not", "exist"))
	r.Write(Entry{Kind: KindTool, Name: "nmap on port 80"})
	r.Close()
	if r.Enabled() {
		t.Error("recorder reports enabled despite an unopenable path")
	}
}

// Every call site relies on this rather than guarding.
func TestANilRecorderIsSafe(t *testing.T) {
	var r *Recorder
	r.Write(Entry{Kind: KindTool, Name: "nmap on port 80"})
	r.Close()
	if r.Enabled() {
		t.Error("a nil recorder must not report enabled")
	}
}

func TestTimestampsAreRFC3339(t *testing.T) {
	dir := t.TempDir()
	r := Open(dir)
	start := time.Now()
	r.Write(Entry{Kind: KindTool, Name: "nmap on port 80", StartedAt: &start})
	r.Close()

	line := readLines(t, dir)[0]
	if _, err := time.Parse(time.RFC3339, line["started_at"].(string)); err != nil {
		t.Errorf("started_at = %v, not RFC 3339: %v", line["started_at"], err)
	}
}

// A half-written line costs the last entry, not the whole record. This is the
// property that motivated JSON Lines, so it is tested rather than assumed.
func TestATruncatedFinalLineCostsOnlyThatLine(t *testing.T) {
	dir := t.TempDir()
	r := Open(dir)
	for i := 0; i < 3; i++ {
		r.Write(Entry{Kind: KindTool, Name: "nmap on port 80", Argv: []string{"nmap"}})
	}
	r.Close()

	path := filepath.Join(dir, FileName)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading record: %v", err)
	}
	// Lop off the last line mid-way, as a kill during a write would.
	cut := len(data) - 12
	if cut <= 0 {
		t.Fatal("record too short to truncate meaningfully")
	}
	if err := os.WriteFile(path, data[:cut], 0o644); err != nil {
		t.Fatalf("truncating: %v", err)
	}

	var recovered int
	for _, line := range strings.Split(string(data[:cut]), "\n") {
		if line == "" {
			continue
		}
		var e Entry
		if json.Unmarshal([]byte(line), &e) == nil {
			recovered++
		}
	}
	if recovered != 2 {
		t.Errorf("recovered %d entries from a truncated record, want 2", recovered)
	}
}
