package progress

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func readSnapshot(t *testing.T, dir string) Snapshot {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatalf("reading progress file: %v", err)
	}
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("unmarshalling progress file: %v\n%s", err, data)
	}
	return s
}

func TestOpenWritesInitialSnapshot(t *testing.T) {
	tests := []struct {
		name       string
		maxRuntime time.Duration
		want       *int
	}{
		{"one hour", time.Hour, intPtr(3600)},
		{"no limit", 0, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			w := Open(dir, Meta{Kind: "infra", Target: "10.0.0.1", MaxRuntime: tc.maxRuntime})
			defer w.Finish(0, false)

			s := readSnapshot(t, dir)
			if s.Schema != 1 || s.Phase != PhaseDiscovery || !s.TotalIsProvisional {
				t.Errorf("unexpected initial snapshot: %+v", s)
			}
			if s.Running == nil || len(s.Running) != 0 {
				t.Errorf("running = %#v, want empty non-nil", s.Running)
			}
			if s.ProcessExitCode != nil {
				t.Errorf("process_exit_code = %v, want nil", *s.ProcessExitCode)
			}
			if (s.MaxRuntimeS == nil) != (tc.want == nil) || (tc.want != nil && *s.MaxRuntimeS != *tc.want) {
				t.Errorf("max_runtime_s = %v, want %v", s.MaxRuntimeS, tc.want)
			}
			if s.Kind != "infra" || s.Target != "10.0.0.1" {
				t.Errorf("kind/target = %q/%q", s.Kind, s.Target)
			}
		})
	}
}

func TestRunningIsNeverNull(t *testing.T) {
	dir := t.TempDir()
	w := Open(dir, Meta{Kind: "infra"})
	w.Finish(0, false)
	data, _ := os.ReadFile(filepath.Join(dir, FileName))
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["running"]) != "[]" {
		t.Errorf("running = %s, want []", raw["running"])
	}
}

func TestUpdateCountsAndFinish(t *testing.T) {
	dir := t.TempDir()
	w := Open(dir, Meta{Kind: "infra", Target: "t"})
	w.Update(Counts{Completed: 16, Failed: 1, Skipped: 2, Total: 20, Running: []string{"nikto on port 443"}})
	w.DiscoveryDone()
	w.Finish(0, false)

	s := readSnapshot(t, dir)
	if s.Completed != 16 || s.Failed != 1 || s.Skipped != 2 || s.Total != 20 {
		t.Errorf("counts wrong: %+v", s)
	}
	if s.TotalIsProvisional {
		t.Error("total should no longer be provisional")
	}
	if s.Phase != PhaseFinished {
		t.Errorf("phase = %q", s.Phase)
	}
	if s.ProcessExitCode == nil || *s.ProcessExitCode != 0 {
		t.Errorf("process_exit_code = %v", s.ProcessExitCode)
	}
	if len(s.Running) != 1 || s.Running[0] != "nikto on port 443" {
		t.Errorf("running = %v", s.Running)
	}
}

func TestFlushShowsIntermediateRunningPhase(t *testing.T) {
	dir := t.TempDir()
	w := Open(dir, Meta{Kind: "infra"})
	defer w.Finish(0, false)
	w.Update(Counts{Total: 3})
	w.DiscoveryDone()
	w.flush()
	s := readSnapshot(t, dir)
	if s.Phase != PhaseRunning || s.TotalIsProvisional || s.Total != 3 {
		t.Errorf("unexpected intermediate snapshot: %+v", s)
	}
}

func TestFinishPhaseFromExitCode(t *testing.T) {
	tests := []struct {
		name         string
		exit         int
		deadlineHit  bool
		wantPhase    Phase
		wantDeadline bool
	}{
		{"clean", 0, false, PhaseFinished, false},
		{"deadline", 124, true, PhaseFinished, true},
		{"failure", 1, false, PhaseFailed, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			w := Open(dir, Meta{Kind: "infra"})
			w.Finish(tc.exit, tc.deadlineHit)
			s := readSnapshot(t, dir)
			if s.Phase != tc.wantPhase || s.DeadlineExceeded != tc.wantDeadline {
				t.Errorf("phase=%q deadline=%v", s.Phase, s.DeadlineExceeded)
			}
			if s.ProcessExitCode == nil || *s.ProcessExitCode != tc.exit {
				t.Errorf("exit code = %v", s.ProcessExitCode)
			}
		})
	}
}

func TestAtomicReplace(t *testing.T) {
	dir := t.TempDir()
	w := Open(dir, Meta{Kind: "infra"})

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := os.ReadFile(filepath.Join(dir, FileName))
			if err != nil {
				t.Errorf("read: %v", err)
				return
			}
			var s Snapshot
			if err := json.Unmarshal(data, &s); err != nil {
				t.Errorf("torn read: %v: %q", err, data)
				return
			}
		}
	}()

	for i := 0; i < 2000; i++ {
		w.Update(Counts{Completed: i, Total: 2000, Running: []string{"x"}})
	}
	w.Finish(0, false)
	close(stop)
	wg.Wait()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != FileName {
		t.Errorf("directory contents = %v, want only %s", entries, FileName)
	}
}

func TestUpdateAfterFinishIgnored(t *testing.T) {
	dir := t.TempDir()
	w := Open(dir, Meta{Kind: "infra"})
	w.Update(Counts{Completed: 5, Total: 5})
	w.Finish(0, false)
	w.Update(Counts{Completed: 99, Total: 99})
	w.flush()
	if s := readSnapshot(t, dir); s.Completed != 5 || s.Total != 5 {
		t.Errorf("counts changed after Finish: %+v", s)
	}
	w.Finish(1, false) // idempotent
	if s := readSnapshot(t, dir); s.Phase != PhaseFinished {
		t.Errorf("second Finish changed phase to %q", s.Phase)
	}
}

func TestProgressFileIsWorldReadable(t *testing.T) {
	dir := t.TempDir()
	w := Open(dir, Meta{Kind: "infra"})
	w.Finish(0, false)
	fi, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("mode = %v, want 0644", fi.Mode().Perm())
	}
}

func TestUnwritableDirDisables(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	w := Open(notDir, Meta{Kind: "infra"})
	if w.Enabled() {
		t.Error("writer should be disabled")
	}
	w.Update(Counts{Total: 1})
	w.DiscoveryDone()
	w.Finish(0, false)

	var nilW *Writer
	nilW.Update(Counts{})
	nilW.DiscoveryDone()
	nilW.Finish(0, false)
	if nilW.Enabled() {
		t.Error("nil writer reports enabled")
	}
}

func TestWriteErrorMidRunDisables(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions are not enforced for root")
	}
	dir := t.TempDir()
	w := Open(dir, Meta{Kind: "infra"})
	if !w.Enabled() {
		t.Fatal("writer should start enabled")
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	w.Update(Counts{Total: 1})
	w.Finish(0, false)
	if w.Enabled() {
		t.Error("writer should be disabled after a write error")
	}
}

func TestConcurrentFinishWaitsForFinalWrite(t *testing.T) {
	for round := 0; round < 20; round++ {
		dir := t.TempDir()
		w := Open(dir, Meta{Kind: "infra"})
		w.Update(Counts{Completed: 1, Total: 2})

		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.Finish(0, false)
				data, err := os.ReadFile(filepath.Join(dir, FileName))
				if err != nil {
					t.Errorf("read: %v", err)
					return
				}
				var s Snapshot
				if err := json.Unmarshal(data, &s); err != nil {
					t.Errorf("unmarshal: %v", err)
					return
				}
				if s.Phase != PhaseFinished || s.ProcessExitCode == nil {
					t.Errorf("Finish returned before the final snapshot: %+v", s)
				}
			}()
		}
		wg.Wait()
	}
}

func TestSubSecondMaxRuntimeRoundsUp(t *testing.T) {
	dir := t.TempDir()
	w := Open(dir, Meta{Kind: "infra", MaxRuntime: 500 * time.Millisecond})
	defer w.Finish(0, false)
	if s := readSnapshot(t, dir); s.MaxRuntimeS == nil || *s.MaxRuntimeS != 1 {
		t.Errorf("max_runtime_s = %v, want 1", s.MaxRuntimeS)
	}
}

func intPtr(i int) *int { return &i }
