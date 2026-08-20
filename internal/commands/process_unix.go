//go:build !windows

package commands

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the child into its own process group so the whole tree
// can be signalled at once. Without it, killing the child leaves grandchildren
// running: msfconsole, dirsearch and wpscan all spawn helpers that would keep
// sending traffic after a timeout had already returned.
//
// Must be called before cmd.Start().
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup kills the child's entire process group.
//
// SIGKILL is sent directly rather than after a SIGTERM grace period: these are
// scanning tools with no cleanup obligations, and the guarantee being kept is
// that traffic stops when the budget does.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	// A negative PID addresses the whole process group.
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
