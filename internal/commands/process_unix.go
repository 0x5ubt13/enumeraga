//go:build !windows

package commands

import (
	"os/exec"
	"syscall"
	"time"
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

// killProcessGroup starts graceful-to-forceful termination for the child's
// entire process group. It returns immediately so os/exec can reap the process
// while the escalation goroutine gives descendants time to exit as well.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	terminateProcessGroup(cmd.Process.Pid, 30*time.Second, 30*time.Second)
}

func terminateProcessGroup(pid int, interruptGrace, terminateGrace time.Duration) {
	if !signalProcessGroup(pid, syscall.SIGINT) {
		return
	}

	go func() {
		if waitForProcessGroupExit(pid, interruptGrace) {
			return
		}
		if !signalProcessGroup(pid, syscall.SIGTERM) {
			return
		}
		if waitForProcessGroupExit(pid, terminateGrace) {
			return
		}
		// A negative PID addresses the whole process group.
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}()
}

func signalProcessGroup(pid int, signal syscall.Signal) bool {
	err := syscall.Kill(-pid, signal)
	return err == nil || err == syscall.EPERM
}

func waitForProcessGroupExit(pid int, grace time.Duration) bool {
	deadline := time.NewTimer(grace)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()

	for {
		if syscall.Kill(-pid, 0) == syscall.ESRCH {
			return true
		}
		select {
		case <-deadline.C:
			return false
		case <-ticker.C:
		}
	}
}
