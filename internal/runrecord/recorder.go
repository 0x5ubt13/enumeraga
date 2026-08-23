package runrecord

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// Active is the recorder the whole run writes to. It is nil until main opens
// one, and every method tolerates that, so no call site needs a guard.
var Active *Recorder

// channelDepth is generous because a producer blocking is preferable to an entry
// being dropped: a dropped entry is a silent hole in the evidence, which is the
// one failure this package exists to prevent.
const channelDepth = 512

// Recorder appends entries to the record through a single writer goroutine.
//
// Serialising through one goroutine is what stops concurrent tool goroutines
// interleaving a partial line, and means no producer ever waits on file I/O
// beyond handing over the entry.
//
// The lock guards the channel's lifetime, nothing else. Producers hold it for
// reading, so they still hand over concurrently, and Close holds it for writing,
// so it cannot close the channel underneath a send in progress. Without that, a
// producer that passed the enabled check an instant before Close would send on a
// closed channel and take the whole scan down with it -- most likely on the
// wall-clock path, where tool goroutines are still live when main gives up.
//
// enabled is atomic rather than lock-guarded because the writer goroutine sets it
// when a write fails. Were that to need the lock, a producer blocked on a full
// channel while holding it would leave nothing draining, and the two would wait
// on each other.
type Recorder struct {
	entries chan Entry
	done    chan struct{}

	enabled atomic.Bool

	mu     sync.RWMutex
	closed bool
}

// Open starts a recorder writing to FileName inside dir.
//
// A directory that cannot be written yields a disabled recorder rather than an
// error: enumeraga's job is to scan, and a scan abandoned because a log file
// could not be opened is a worse outcome than a scan with no log. A caller that
// requires the record can detect its absence.
func Open(dir string) *Recorder {
	r := &Recorder{entries: make(chan Entry, channelDepth), done: make(chan struct{})}

	path := filepath.Join(dir, FileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644) //nolint:gosec // the record is world-readable evidence, not a secret
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Run record disabled: cannot open %s: %v\n", path, err)
		close(r.done)
		return r
	}

	r.enabled.Store(true)
	go r.run(f)
	return r
}

func (r *Recorder) run(f *os.File) {
	defer close(r.done)
	defer func() { _ = f.Close() }()

	encoder := json.NewEncoder(f)
	for entry := range r.entries {
		if err := encoder.Encode(entry); err != nil {
			// Warn once and stop writing. Retrying per line would turn a full
			// disk into a slow scan.
			fmt.Fprintf(os.Stderr, "[!] Run record disabled after a write error: %v\n", err)
			r.enabled.Store(false)
			for range r.entries {
				// Drain so producers are never blocked by a dead writer.
			}
			return
		}
	}
}

// Enabled reports whether entries are being written.
func (r *Recorder) Enabled() bool {
	return r != nil && r.enabled.Load()
}

// Write appends an entry. It is safe on a nil or disabled recorder.
func (r *Recorder) Write(e Entry) {
	if r == nil {
		return
	}
	if e.EndedAt == nil && e.Kind != KindRun {
		now := time.Now()
		e.EndedAt = &now
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed || !r.enabled.Load() {
		return
	}
	r.entries <- e
}

// Close stops the writer and waits for the queue to drain, so the last entry is
// on disk before the process exits. It is idempotent, because the wall-clock path
// calls it explicitly and the deferred call in main then runs again.
func (r *Recorder) Close() {
	if r == nil {
		return
	}

	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	close(r.entries)
	r.mu.Unlock()

	<-r.done
	r.enabled.Store(false)
}
