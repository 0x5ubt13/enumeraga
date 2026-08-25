package protocols

import (
	"testing"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// setBounds installs a validated Bounds for the duration of a test.
func setBounds(t *testing.T, cfg bounds.Config) {
	t.Helper()
	original := bounds.Active
	t.Cleanup(func() { bounds.Active = original })

	b, err := bounds.Validate(cfg)
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b
}

// TestDefaultHandlerLaunchesNothingForAUDPOnlyPort is the regression test for the
// last ungated actively-probing launch. DEFAULT is the handler every unrecognised
// port reaches, and its nuclei invocation is an automatic scan over TCP, so with
// --ports U:9999 and 9999 open on UDP enumeraga used to decline to SYN-scan TCP
// 9999 and then immediately probe TCP 9999 with nuclei anyway.
//
// The tracker is the seam: both CallIndividualPortScannerWithNSEScripts and
// CallRunTool register their tool synchronously before spawning a goroutine, so a
// launch that was suppressed leaves the registry empty.
func TestDefaultHandlerLaunchesNothingForAUDPOnlyPort(t *testing.T) {
	setBounds(t, bounds.Config{Ports: "U:9999"})

	utils.ToolRegistry = utils.NewToolTracker()
	utils.BaseDir = t.TempDir() + "/"

	DEFAULT("9999")
	utils.Wg.Wait()

	if got := utils.ToolRegistry.GetTotal(); got != 0 {
		t.Errorf("registered tools = %d, want 0: nothing may be launched against a port authorised only over UDP", got)
	}
}

// TestDefaultHandlerLaunchesForATCPAuthorisedPort is the positive control for the
// test above, which would otherwise pass even if DEFAULT did nothing at all.
//
// It has to prevent the two tools actually executing, so it borrows the mechanism
// a wall-clock stop uses: with the worker pool full and the run's budget already
// expired, each tool registers itself and is then refused a slot, which records a
// skip without ever spawning a process.
func TestDefaultHandlerLaunchesForATCPAuthorisedPort(t *testing.T) {
	setBounds(t, bounds.Config{Ports: "9999", MaxRuntimeSeconds: 1})

	utils.ToolRegistry = utils.NewToolTracker()
	utils.BaseDir = t.TempDir() + "/"

	pool := utils.GetWorkerPool()
	slots := pool.GetMaxWorkers()
	for i := 0; i < slots; i++ {
		if !pool.Acquire() {
			t.Fatalf("could not fill the worker pool at slot %d of %d", i, slots)
		}
	}
	defer func() {
		for i := 0; i < slots; i++ {
			pool.Release()
		}
	}()

	utils.InitGlobalContext()
	defer utils.InitGlobalContext()
	utils.SetRunDeadline(time.Nanosecond)

	giveUp := time.Now().Add(2 * time.Second)
	for !utils.RunDeadlineExceeded() {
		if time.Now().After(giveUp) {
			t.Fatal("the wall-clock deadline never registered as exceeded")
		}
		time.Sleep(time.Millisecond)
	}

	DEFAULT("9999")
	utils.Wg.Wait()

	// The nmap NSE scan and nuclei: both reach the tracker when TCP 9999 is in scope.
	if got := utils.ToolRegistry.GetTotal(); got != 2 {
		t.Errorf("registered tools = %d, want 2 (nmap NSE and nuclei): the gate must open for an authorised TCP port", got)
	}
	if got := utils.ToolRegistry.CountByStatus(utils.ToolCompleted); got != 0 {
		t.Errorf("completed count = %d, want 0: no tool should have executed in this test", got)
	}
}

// TestNucleiGateMatchesTheProtocolItSpeaks pins the predicate every gate added in
// this wave uses, in both directions. Nuclei, ODAT and the HTTP/HTTPS detection
// probes are TCP whatever protocol the port was discovered over, so they consult
// the authorised TCP set specifically.
func TestNucleiGateMatchesTheProtocolItSpeaks(t *testing.T) {
	tests := []struct {
		name  string
		ports string
		port  string
		want  bool
	}{
		{name: "UDP-only authorisation blocks a TCP tool", ports: "U:9999", port: "9999", want: false},
		{name: "TCP authorisation permits it", ports: "9999", port: "9999", want: true},
		{name: "both protocols authorised", ports: "9999,U:9999", port: "9999", want: true},
		{name: "a different port does not authorise it", ports: "80", port: "9999", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setBounds(t, bounds.Config{Ports: tt.ports})
			if got := bounds.Active.PortInScope(tt.port, false); got != tt.want {
				t.Errorf("PortInScope(%q, false) = %v, want %v", tt.port, got, tt.want)
			}
		})
	}
}

// TestNoBoundsLeavesEveryGateOpen is the inertness assertion: a caller who passes
// no bounds must see none of these gates close.
func TestNoBoundsLeavesEveryGateOpen(t *testing.T) {
	setBounds(t, bounds.Config{})

	for _, port := range []string{"22", "3306", "9999", "1521"} {
		if !bounds.Active.PortInScope(port, false) {
			t.Errorf("PortInScope(%q, false) = false with no bounds, want true", port)
		}
	}
}
