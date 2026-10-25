//go:build !windows

package commands

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTerminateProcessGroupEscalatesINTTERMThenKILL(t *testing.T) {
	signalDir := t.TempDir()
	signalLog := filepath.Join(signalDir, "signals.log")
	readyFile := filepath.Join(signalDir, "ready.pid")
	script := "trap 'echo INT >> " + signalLog + "' INT; trap 'echo TERM >> " + signalLog + "' TERM; echo $$ > " + readyFile + "; while :; do :; done"
	cmd := exec.Command("sh", "-c", script)
	setProcessGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting command: %v", err)
	}
	waitForPID(t, readyFile)

	terminateProcessGroup(cmd.Process.Pid, 25*time.Millisecond, 25*time.Millisecond)
	if err := cmd.Wait(); err == nil {
		t.Fatal("process exited successfully; expected escalation to SIGKILL")
	}

	data, err := os.ReadFile(signalLog)
	if err != nil {
		t.Fatalf("reading signal log: %v", err)
	}
	if got, want := strings.TrimSpace(string(data)), "INT\nTERM"; got != want {
		t.Fatalf("received signals = %q, want %q before SIGKILL", got, want)
	}
}

// TestKillProcessGroupKillsGrandchildren verifies that cancelling a tool kills
// the processes it spawned, not just the process enumeraga started directly.
// Without this, a timed-out scan would keep sending traffic.
func TestKillProcessGroupKillsGrandchildren(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that spawns real processes")
	}

	pidFile, err := os.CreateTemp(t.TempDir(), "grandchild-*.pid")
	if err != nil {
		t.Fatalf("creating temp file: %v", err)
	}
	pidPath := pidFile.Name()
	if closeErr := pidFile.Close(); closeErr != nil {
		t.Fatalf("closing temp file: %v", closeErr)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The shell backgrounds a long sleep, records its PID, then waits. Killing
	// only the shell would leave the sleep running.
	script := "sleep 120 & echo $! > " + pidPath + "; wait"
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	setProcessGroup(cmd)

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting command: %v", err)
	}

	grandchildPID := waitForPID(t, pidPath)

	terminateProcessGroup(cmd.Process.Pid, 50*time.Millisecond, 50*time.Millisecond)
	_ = cmd.Wait()

	// Give the kernel a moment to reap the group.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(grandchildPID) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Clean up so a failing test does not leave a stray process behind.
	_ = syscall.Kill(grandchildPID, syscall.SIGKILL)
	t.Fatalf("grandchild %d survived killProcessGroup", grandchildPID)
}

// waitForPID polls until the backgrounded process has written its PID.
func waitForPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path) //nolint:gosec // path is from t.TempDir()
		if err == nil {
			if pid, convErr := strconv.Atoi(strings.TrimSpace(string(data))); convErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("timed out waiting for the grandchild to record its PID")
	return 0
}

// processAlive reports whether a PID is still running. Signal 0 performs the
// permission and existence checks without actually sending anything.
func processAlive(pid int) bool {
	if stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		if end := strings.LastIndex(string(stat), ")"); end >= 0 && end+2 < len(stat) {
			state := stat[end+2]
			if state == 'Z' || state == 'X' {
				return false
			}
		}
	}
	return syscall.Kill(pid, 0) == nil
}
