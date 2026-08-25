package sweeps

import "testing"

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

	optVVerbose := false
	_, udpHosts, err := BoundedPortSweep("127.0.0.1", "22", "", &optVVerbose)
	if err != nil {
		t.Fatalf("BoundedPortSweep returned an error: %v", err)
	}
	if udpHosts != nil {
		t.Errorf("udpHosts = %v, want nil when no UDP ports were requested", udpHosts)
	}
}
