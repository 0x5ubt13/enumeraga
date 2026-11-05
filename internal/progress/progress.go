// Package progress keeps a small progress.json snapshot in the scan output root,
// so that something outside the process can report how far a scan has got
// without reading logs.
//
// It is evidence of progress, not a record: each write replaces the previous
// snapshot, and nothing here is a history of what ran (that is runrecord's job).
//
// The package imports only the standard library. The tool tracker in utils feeds
// it, so importing utils from here would create an import cycle.
package progress

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// FileName is the snapshot's name inside the output root.
	FileName = "progress.json"
	// SchemaVersion is bumped whenever the snapshot's shape changes incompatibly.
	SchemaVersion = 1
)

// Phase is where the scan is in its life.
type Phase string

const (
	PhaseDiscovery Phase = "discovery"
	PhaseRunning   Phase = "running"
	PhaseFinished  Phase = "finished"
	PhaseFailed    Phase = "failed"
)

// Counts is the tracker's view of the tools at one instant. Completed counts
// every terminal tool, failed and skipped included.
type Counts struct {
	Completed, Failed, Skipped, Total int
	Running                           []string
}

// Meta describes the run and does not change once it has started.
type Meta struct {
	Kind, Target string
	MaxRuntime   time.Duration
}

// Snapshot is the JSON written to FileName.
type Snapshot struct {
	Schema             int      `json:"schema"`
	Kind               string   `json:"kind"`
	Target             string   `json:"target"`
	StartedAt          string   `json:"started_at"`
	UpdatedAt          string   `json:"updated_at"`
	Phase              Phase    `json:"phase"`
	Completed          int      `json:"completed"`
	Failed             int      `json:"failed"`
	Skipped            int      `json:"skipped"`
	Total              int      `json:"total"`
	TotalIsProvisional bool     `json:"total_is_provisional"`
	Running            []string `json:"running"`
	MaxRuntimeS        *int     `json:"max_runtime_s"`
	DeadlineExceeded   bool     `json:"deadline_exceeded"`
	ProcessExitCode    *int     `json:"process_exit_code"`
}

// Active is the writer the whole run reports to. It is nil until main opens one,
// and every method tolerates that, so no call site needs a guard.
var Active *Writer

// Writer replaces the snapshot through a single goroutine.
//
// Update is called while the caller holds its own lock, so it only stores state
// and signals; it never does I/O and never calls out. mu guards the stored state
// and is never held across a write or a callback. writeMu serialises writes, so
// the writer goroutine and a synchronous flush cannot interleave.
type Writer struct {
	dir     string
	meta    Meta
	started time.Time

	enabled  atomic.Bool
	warnOnce sync.Once

	kick chan struct{}
	stop chan struct{}
	done chan struct{}

	// finishOnce makes every concurrent Finish caller wait for the final write.
	finishOnce sync.Once

	writeMu sync.Mutex

	mu          sync.Mutex
	counts      Counts
	phase       Phase
	provisional bool
	exitCode    *int
	deadline    bool
	finished    bool
}

// Open writes the first snapshot and starts the writer goroutine.
//
// A directory that cannot be written yields a disabled writer rather than an
// error: a scan abandoned because a status file could not be written is worse
// than a scan without one.
func Open(dir string, m Meta) *Writer {
	w := &Writer{
		dir:         dir,
		meta:        m,
		started:     time.Now().UTC(),
		kick:        make(chan struct{}, 1),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		phase:       PhaseDiscovery,
		provisional: true,
	}
	w.enabled.Store(true)

	w.flush()
	if !w.enabled.Load() {
		close(w.done)
		return w
	}
	go w.run()
	return w
}

func (w *Writer) run() {
	defer close(w.done)
	for {
		select {
		case <-w.kick:
			w.flush()
		case <-w.stop:
			return
		}
	}
}

// Enabled reports whether snapshots are being written.
func (w *Writer) Enabled() bool {
	return w != nil && w.enabled.Load()
}

// Update stores the latest counts and asks the writer goroutine to write them.
// It is safe on a nil or disabled writer, never blocks on I/O, and is ignored
// once Finish has been called.
func (w *Writer) Update(c Counts) {
	if w == nil {
		return
	}
	c.Running = append([]string(nil), c.Running...)

	w.mu.Lock()
	if w.finished {
		w.mu.Unlock()
		return
	}
	w.counts = c
	w.mu.Unlock()

	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// DiscoveryDone moves the scan out of discovery: the total is now final.
func (w *Writer) DiscoveryDone() {
	if w == nil {
		return
	}
	w.mu.Lock()
	if w.finished {
		w.mu.Unlock()
		return
	}
	w.phase = PhaseRunning
	w.provisional = false
	w.mu.Unlock()

	select {
	case w.kick <- struct{}{}:
	default:
	}
}

// Finish stops the writer goroutine and writes the final snapshot before it
// returns, so the last state is on disk before the process exits. It is
// idempotent: the wall-clock path and the deferred call in main may both reach it.
func (w *Writer) Finish(exitCode int, deadlineHit bool) {
	if w == nil {
		return
	}
	// Do blocks concurrent callers until the first has returned, so none of them
	// can return before the final snapshot is on disk.
	w.finishOnce.Do(func() {
		w.mu.Lock()
		w.finished = true
		w.provisional = false
		w.deadline = deadlineHit
		w.exitCode = &exitCode
		if exitCode == 0 || exitCode == 124 {
			w.phase = PhaseFinished
		} else {
			w.phase = PhaseFailed
		}
		w.mu.Unlock()

		close(w.stop)
		<-w.done
		w.flush()
	})
}

// snapshot copies the state under mu. The caller holds writeMu; mu is never held
// across I/O.
func (w *Writer) snapshot() Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()

	running := append([]string{}, w.counts.Running...)
	s := Snapshot{
		Schema:             SchemaVersion,
		Kind:               w.meta.Kind,
		Target:             w.meta.Target,
		StartedAt:          w.started.Format(time.RFC3339),
		UpdatedAt:          time.Now().UTC().Format(time.RFC3339),
		Phase:              w.phase,
		Completed:          w.counts.Completed,
		Failed:             w.counts.Failed,
		Skipped:            w.counts.Skipped,
		Total:              w.counts.Total,
		TotalIsProvisional: w.provisional,
		Running:            running,
		DeadlineExceeded:   w.deadline,
	}
	if w.meta.MaxRuntime > 0 {
		secs := int((w.meta.MaxRuntime + time.Second - 1) / time.Second) // round up: never report a limit as 0
		s.MaxRuntimeS = &secs
	}
	if w.exitCode != nil {
		code := *w.exitCode
		s.ProcessExitCode = &code
	}
	return s
}

// flush writes the current state synchronously. The first failure warns once and
// disables the writer, since retrying on every update would only repeat the error.
func (w *Writer) flush() {
	if !w.enabled.Load() {
		return
	}

	// Snapshot inside writeMu, so a snapshot taken earlier can never be written
	// after a later one.
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	if !w.enabled.Load() {
		return
	}
	s := w.snapshot()
	if err := w.write(s); err != nil {
		w.warnOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "[!] Progress file disabled: %v\n", err)
		})
		w.enabled.Store(false)
	}
}

// write replaces FileName atomically, so a reader sees either the previous
// snapshot or the new one and never a torn file.
func (w *Writer) write(s Snapshot) (err error) {
	tmp, err := os.CreateTemp(w.dir, ".progress-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()

	if err = json.NewEncoder(tmp).Encode(s); err != nil {
		return err
	}
	// CreateTemp makes the file 0600; the snapshot is not a secret.
	if err = tmp.Chmod(0o644); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, filepath.Join(w.dir, FileName))
}
