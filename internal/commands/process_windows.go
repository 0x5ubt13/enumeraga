//go:build windows

package commands

import "os/exec"

// setProcessGroup is a no-op on Windows, which has no process groups in the
// POSIX sense. Containing a process tree there needs a job object, which is
// beyond what this scanner requires.
func setProcessGroup(_ *exec.Cmd) {}

// killProcessGroup kills the child process. Grandchildren are not reachable
// without a job object, so this matches what CommandContext already does.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
}
