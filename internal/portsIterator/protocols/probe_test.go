package protocols

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/runrecord"
)

// A probe spawns no process, so it appears nowhere in the process table and
// nowhere in a packet capture that only records what crossed a mediator. Without
// an entry it is the one action reaching the target that leaves no trace at all.
func TestProbesAreRecordedWithANullArgv(t *testing.T) {
	dir := t.TempDir()
	original := runrecord.Active
	t.Cleanup(func() { runrecord.Active = original })
	runrecord.Active = runrecord.Open(dir)

	// A closed port on the loopback: the probe is refused immediately rather than
	// waiting out its timeout three times, and the outcome is recorded as not found.
	_ = IsHTTPService("http://127.0.0.1:1/")
	_ = IsHTTPSService("https://127.0.0.1:1/")
	runrecord.Active.Close()

	data, err := os.ReadFile(filepath.Join(dir, runrecord.FileName))
	if err != nil {
		t.Fatalf("reading record: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("entries = %d, want 2 (one per probe call, not per attempt)", len(lines))
	}

	for _, line := range lines {
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatalf("bad line: %v", err)
		}
		if raw["kind"] != "probe" {
			t.Errorf("kind = %v, want probe", raw["kind"])
		}
		v, present := raw["argv"]
		if !present || v != nil {
			t.Errorf("argv = %v (present=%v), want an explicit null", v, present)
		}
		if raw["url"] == "" || raw["url"] == nil {
			t.Error("url absent; it is the only record of what was reached")
		}
		if raw["attempts"] == nil {
			t.Error("attempts absent; a probe retries and the count is part of what it did")
		}
	}
}
