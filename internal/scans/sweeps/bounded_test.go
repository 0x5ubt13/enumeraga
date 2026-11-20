package sweeps

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

// TestBoundedPortSweepRequiresPorts verifies the sweep refuses to run with no
// ports at all, rather than silently falling back to a default list.
func TestBoundedPortSweepRequiresPorts(t *testing.T) {
	optVVerbose := false
	_, _, err := BoundedPortSweep("127.0.0.1", "", "", &optVVerbose)
	if err == nil {
		t.Fatal("BoundedPortSweep accepted an empty port specification")
	}
}

// TestBoundedPortSweepSkipsUDPWhenNotRequested verifies no UDP scan runs when
// the caller asked for TCP ports only. The standard UdpPortSweep probes its own
// hardcoded list, which would be traffic outside the caller's port list.
func TestBoundedPortSweepSkipsUDPWhenNotRequested(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test that runs nmap")
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap is not installed")
	}
	// The sweep runs nmap with --privileged, as it does in the scan container (root
	// with NET_RAW). Elsewhere, as a normal user, nmap refuses the raw-socket scan
	// and exits 1, which says nothing about the code under test.
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		t.Skip("needs root: the sweep runs nmap with --privileged")
	}

	optVVerbose := false
	_, udpHosts, err := BoundedPortSweep("127.0.0.1", "22", "", &optVVerbose)
	if err != nil {
		t.Fatalf("BoundedPortSweep returned an error: %v", err)
	}
	if udpHosts != nil {
		t.Errorf("udpHosts = %v, want nil when no UDP ports were requested", udpHosts)
	}
}
