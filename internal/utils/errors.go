package utils

import "errors"

// Sentinel errors for special exit conditions
var (
	// ErrHelpRequested indicates user requested help (-h flag)
	// Programs should print usage and exit with code 0
	ErrHelpRequested = errors.New("help requested")

	// ErrInstallComplete indicates tool installation completed successfully
	// Programs should exit with code 0
	ErrInstallComplete = errors.New("installation complete")

	// ErrCloudComplete indicates cloud scanning completed successfully
	// Programs should exit with code 0
	ErrCloudComplete = errors.New("cloud scanning complete")

	// ErrCloudInterrupted indicates a cloud scan was stopped by a signal
	// (Ctrl+C, docker stop). The results written so far are partial.
	// Programs should exit with ExitInterrupted.
	ErrCloudInterrupted = errors.New("cloud scanning interrupted")
)

// Process exit codes for a run that did not simply complete.
const (
	// ExitDeadline is the code for a run stopped by its own wall-clock budget.
	// It follows the GNU timeout convention; the results so far are valid.
	ExitDeadline = 124
	// ExitInterrupted is the code for a run stopped by a signal. It follows the
	// shell convention of 128 + SIGINT; the results so far are partial.
	ExitInterrupted = 130
)

// IsExitSuccess returns true if the error represents a successful exit condition
func IsExitSuccess(err error) bool {
	return errors.Is(err, ErrHelpRequested) ||
		errors.Is(err, ErrInstallComplete) ||
		errors.Is(err, ErrCloudComplete)
}

// RunExitCode picks the process exit code for a run that has reached its end.
// The deadline takes precedence: once the run's context has expired, a later
// signal does not change that it was stopped by its own budget, and
// RunDeadlineExceeded keeps reporting true. A signal that arrived first cancels
// the context, so the deadline is never reported as hit in that case.
func RunExitCode(deadlineHit, interrupted bool) int {
	switch {
	case deadlineHit:
		return ExitDeadline
	case interrupted:
		return ExitInterrupted
	default:
		return 0
	}
}

// ExitCodeForError maps an error returned before the infra flow starts to the
// process exit code: 0 for the success sentinels, ExitInterrupted for a cloud
// scan stopped by a signal, and 1 for anything else.
func ExitCodeForError(err error) int {
	switch {
	case err == nil, IsExitSuccess(err):
		return 0
	case errors.Is(err, ErrCloudInterrupted):
		return ExitInterrupted
	default:
		return 1
	}
}
