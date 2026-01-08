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
)

// IsExitSuccess returns true if the error represents a successful exit condition
func IsExitSuccess(err error) bool {
	return errors.Is(err, ErrHelpRequested) ||
		errors.Is(err, ErrInstallComplete) ||
		errors.Is(err, ErrCloudComplete)
}
