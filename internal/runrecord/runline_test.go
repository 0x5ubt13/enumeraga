package runrecord

import (
	"strings"
	"testing"
	"time"
)

// The opening line is what a caller hashes against its approved request, so the
// bounds must survive verbatim -- including the T:/U: prefixes, which are the
// difference between authorising a port over TCP and over UDP.
func TestOpeningRunLineCarriesTheBoundsVerbatim(t *testing.T) {
	dir := t.TempDir()
	r := Open(dir)
	start := time.Now()
	r.Write(Entry{
		Kind:      KindRun,
		Version:   "dev",
		Target:    "192.0.2.1",
		Bounds:    "ports=80,U:53 rate=5 concurrency=2 max-runtime=15m0s",
		StartedAt: &start,
	})
	r.Close()

	lines := readLines(t, dir)
	if lines[0]["kind"] != "run" {
		t.Fatalf("first line kind = %v, want run", lines[0]["kind"])
	}
	got, _ := lines[0]["bounds"].(string)
	if !strings.Contains(got, "U:53") {
		t.Errorf("bounds = %q, lost the U: prefix", got)
	}
	if lines[0]["version"] != "dev" {
		t.Errorf("version = %v", lines[0]["version"])
	}
}

// A wall-clock stop is not a failure, and the closing line must say which it was.
func TestClosingRunLineRecordsTheDisposition(t *testing.T) {
	dir := t.TempDir()
	r := Open(dir)
	end := time.Now()
	hit, code := true, 124
	r.Write(Entry{Kind: KindRun, EndedAt: &end, DeadlineHit: &hit, ProcessExit: &code})
	r.Close()

	line := readLines(t, dir)[0]
	if line["deadline_exceeded"] != true {
		t.Errorf("deadline_exceeded = %v, want true", line["deadline_exceeded"])
	}
	if line["process_exit_code"].(float64) != 124 {
		t.Errorf("process_exit_code = %v, want 124", line["process_exit_code"])
	}
}
