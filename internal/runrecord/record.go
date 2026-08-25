// Package runrecord writes a machine-readable account of what a scan did.
//
// It is evidence, not enforcement: nothing here decides whether a scan is
// permitted. That belongs to the caller holding the scope manifest.
//
// The package deliberately imports only the standard library. It is called from
// commands, scans, portsIterator and main, so any dependency of its own risks an
// import cycle with one of them.
package runrecord

import "time"

// FileName is the record's name inside the output root.
const FileName = "run.jsonl"

// Kind distinguishes the run itself from the things it did, and an external
// command from an in-process probe.
type Kind string

const (
	// KindRun appears exactly twice: once before any tool starts, carrying the
	// bounds a caller hashes against its approved request, and once at the end
	// carrying the disposition. Two lines rather than one mutable line is what
	// an append-only format costs.
	KindRun Kind = "run"
	// KindTool is one external command launch.
	KindTool Kind = "tool"
	// KindProbe is a connection enumeraga makes itself, with no command line.
	KindProbe Kind = "probe"
)

// Status mirrors the tool tracker's terminal states.
type Status string

const (
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusSkipped   Status = "skipped"
)

// Entry is one line of the record.
//
// Argv has no omitempty: a probe records an explicit null so a consumer can see
// the action had no command line rather than inferring a gap. ExitCode is a
// pointer for the same reason inverted -- zero is a meaningful exit status, so it
// must survive, while a skip must omit the field because nothing ran.
type Entry struct {
	Kind Kind   `json:"kind"`
	Name string `json:"name,omitempty"`

	Argv []string `json:"argv"`

	Target   string `json:"target,omitempty"`
	Ports    string `json:"ports,omitempty"`
	Protocol string `json:"protocol,omitempty"`
	URL      string `json:"url,omitempty"`
	Artefact string `json:"artefact,omitempty"`

	StartedAt *time.Time `json:"started_at,omitempty"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`

	Status     Status `json:"status,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	Signal     string `json:"signal,omitempty"`
	SkipReason string `json:"skip_reason,omitempty"`
	// Error carries why a launch failed when there is no exit status to carry it:
	// a refused exec, a pipe that could not be opened. A failed status with no
	// exit code beside it means nothing ran, and this says what stopped it.
	Error      string `json:"error,omitempty"`
	RateNote   string `json:"rate_note,omitempty"`
	Attempts   int    `json:"attempts,omitempty"`
	Found      *bool  `json:"found,omitempty"`

	// Run-line fields.
	Version     string `json:"version,omitempty"`
	Bounds      string `json:"bounds,omitempty"`
	DeadlineHit *bool  `json:"deadline_exceeded,omitempty"`
	ProcessExit *int   `json:"process_exit_code,omitempty"`
}
