package common

import (
	"testing"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/checks"
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

// enableBrute turns brute mode on for the duration of a test. Every RunHydraBrute
// path is behind it, so without this the tests would pass on the wrong branch.
func enableBrute(t *testing.T) {
	t.Helper()
	original := *checks.OptBrute
	t.Cleanup(func() { *checks.OptBrute = original })
	*checks.OptBrute = true
}

// TestHydraIsNotLaunchedForAUDPOnlyPort is the regression test for the gate.
//
// hydra brute-forces over TCP for every service enumeraga passes it, but the
// handlers that call it are dispatched on the port number alone, with no regard
// for which sweep found it. rdp and mysql both have UDP transports, so before the
// gate existed a caller passing --ports U:3389 -b would have TCP 3389
// brute-forced despite never authorising it.
//
// The tracker is the seam: CallRunTool registers its tool synchronously before
// spawning a goroutine, so a suppressed launch leaves the registry empty.
func TestHydraIsNotLaunchedForAUDPOnlyPort(t *testing.T) {
	enableBrute(t)

	for _, tc := range []struct{ service, port, ports string }{
		{service: "rdp", port: "3389", ports: "U:3389"},
		{service: "mysql", port: "3306", ports: "U:3306"},
		{service: "ssh", port: "22", ports: "U:22"},
		{service: "ftp", port: "21", ports: "20"},
	} {
		t.Run(tc.service, func(t *testing.T) {
			setBounds(t, bounds.Config{Ports: tc.ports})
			utils.ToolRegistry = utils.NewToolTracker()

			RunHydraBrute(tc.service, tc.port, t.TempDir()+"/")
			utils.Wg.Wait()

			if got := utils.ToolRegistry.GetTotal(); got != 0 {
				t.Errorf("registered tools = %d, want 0: hydra must not brute-force port %s when --ports is %q",
					got, tc.port, tc.ports)
			}
		})
	}
}

// TestHydraIsLaunchedForATCPAuthorisedPort is the positive control for the test
// above, which would otherwise pass even if RunHydraBrute did nothing at all.
//
// It has to stop hydra actually executing, so it borrows the mechanism a
// wall-clock stop uses: with the worker pool full and the run's budget already
// expired, the tool registers itself and is then refused a slot, which records the
// attempt without ever spawning a process.
func TestHydraIsLaunchedForATCPAuthorisedPort(t *testing.T) {
	enableBrute(t)
	setBounds(t, bounds.Config{Ports: "3389", MaxRuntimeSeconds: 1})

	utils.ToolRegistry = utils.NewToolTracker()

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

	RunHydraBrute("rdp", "3389", t.TempDir()+"/")
	utils.Wg.Wait()

	if got := utils.ToolRegistry.GetTotal(); got != 1 {
		t.Errorf("registered tools = %d, want 1: the gate must open for an authorised TCP port", got)
	}
	if got := utils.ToolRegistry.CountByStatus(utils.ToolCompleted); got != 0 {
		t.Errorf("completed count = %d, want 0: hydra should not have executed in this test", got)
	}
}

// TestHydraGateIsInertWithoutBounds is the inertness assertion: a caller who
// passes no port list must see the gate stay open for every service, exactly as
// before it existed.
func TestHydraGateIsInertWithoutBounds(t *testing.T) {
	setBounds(t, bounds.Config{})

	for _, port := range []string{"21", "22", "23", "3306", "3389"} {
		if !bounds.Active.PortInScope(port, false) {
			t.Errorf("PortInScope(%q, false) = false with no bounds in force, want true", port)
		}
	}
}

// TestHydraIsNotLaunchedWithoutBruteMode pins the pre-existing guard, so a future
// change to the new scope check cannot accidentally start brute-forcing by default.
func TestHydraIsNotLaunchedWithoutBruteMode(t *testing.T) {
	original := *checks.OptBrute
	defer func() { *checks.OptBrute = original }()
	*checks.OptBrute = false

	setBounds(t, bounds.Config{Ports: "3389"})
	utils.ToolRegistry = utils.NewToolTracker()

	RunHydraBrute("rdp", "3389", t.TempDir()+"/")
	utils.Wg.Wait()

	if got := utils.ToolRegistry.GetTotal(); got != 0 {
		t.Errorf("registered tools = %d, want 0: hydra must never run without -b", got)
	}
}
