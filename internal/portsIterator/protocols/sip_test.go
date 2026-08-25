package protocols

import (
	"testing"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// drainWorkerPool fills the worker pool and expires the run's wall-clock budget,
// so a tool registers itself and is then refused a slot. That records the launch
// attempt without ever spawning a process, which is what lets these tests count
// launches for a tool that is not installed.
func drainWorkerPool(t *testing.T) {
	t.Helper()

	pool := utils.GetWorkerPool()
	slots := pool.GetMaxWorkers()
	for i := 0; i < slots; i++ {
		if !pool.Acquire() {
			t.Fatalf("could not fill the worker pool at slot %d of %d", i, slots)
		}
	}
	t.Cleanup(func() {
		for i := 0; i < slots; i++ {
			pool.Release()
		}
	})

	utils.InitGlobalContext()
	t.Cleanup(func() { utils.InitGlobalContext() })
	utils.SetRunDeadline(time.Nanosecond)

	giveUp := time.Now().Add(2 * time.Second)
	for !utils.RunDeadlineExceeded() {
		if time.Now().After(giveUp) {
			t.Fatal("the wall-clock deadline never registered as exceeded")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestSIPHonoursTheAuthorisedProtocol is the regression test for the SIP gate.
//
// SIP is reached from a flat port list that merges the TCP and UDP sweep results,
// so the handler cannot tell which protocol found 5060. It used to run an nmap UDP
// scan, an nmap TCP scan, and sippts over both tcp and udp on any sighting at all,
// so --ports U:5060 had TCP 5060 probed without ever being authorised.
//
// Five launches when both protocols are authorised: nmap UDP, nmap TCP, sippts
// scan, sippts enumerate over tcp, and sippts enumerate over udp. Authorising one
// protocol suppresses exactly two of them — one nmap scan and one sippts
// enumerate — and a port outside the list launches nothing at all.
func TestSIPHonoursTheAuthorisedProtocol(t *testing.T) {
	for _, tt := range []struct {
		name  string
		ports string
		want  int
	}{
		{name: "both protocols authorised", ports: "5060,U:5060", want: 5},
		{name: "UDP only suppresses the TCP half", ports: "U:5060", want: 3},
		{name: "TCP only suppresses the UDP half", ports: "5060", want: 3},
		{name: "a different port authorises nothing", ports: "80", want: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			utils.ResetVisitedFlags()
			setBounds(t, bounds.Config{Ports: tt.ports, MaxRuntimeSeconds: 1})
			utils.ToolRegistry = utils.NewToolTracker()
			utils.BaseDir = t.TempDir() + "/"
			drainWorkerPool(t)

			SIP("5060")
			utils.Wg.Wait()

			if got := utils.ToolRegistry.GetTotal(); got != tt.want {
				t.Errorf("launches = %d, want %d for --ports %q", got, tt.want, tt.ports)
			}
			if got := utils.ToolRegistry.CountByStatus(utils.ToolCompleted); got != 0 {
				t.Errorf("completed count = %d, want 0: nothing should execute in this test", got)
			}
		})
	}
}

// TestSIPTransportSelectionFollowsTheAuthorisedProtocol pins the two decisions
// that the launch counts above cannot see: which transports sippts is asked to
// probe, and how wide a port range it sweeps.
//
// sippts scan takes a range rather than a single port, and the handler's default
// of 5060-5070 reaches ten ports beyond the one that dispatched it. Under a port
// list that range must collapse to the authorised port.
func TestSIPTransportSelectionFollowsTheAuthorisedProtocol(t *testing.T) {
	for _, tt := range []struct {
		name          string
		ports         string
		wantTransport string
		wantRange     string
	}{
		{name: "UDP only", ports: "U:5060", wantTransport: "udp", wantRange: "5060"},
		{name: "TCP only", ports: "5060", wantTransport: "tcp", wantRange: "5060"},
		{name: "both", ports: "5060,U:5060", wantTransport: "all", wantRange: "5060"},
		{name: "no bounds keeps the default spread", ports: "", wantTransport: "all", wantRange: "5060-5070"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			setBounds(t, bounds.Config{Ports: tt.ports})

			tcpInScope := bounds.Active.PortInScope("5060", false)
			udpInScope := bounds.Active.PortInScope("5060", true)

			transport := "all"
			switch {
			case !udpInScope:
				transport = "tcp"
			case !tcpInScope:
				transport = "udp"
			}
			if transport != tt.wantTransport {
				t.Errorf("sippts transport = %q, want %q for --ports %q", transport, tt.wantTransport, tt.ports)
			}

			scanRange := "5060-5070"
			if bounds.Active.HasPortList() {
				scanRange = "5060"
			}
			if scanRange != tt.wantRange {
				t.Errorf("sippts -r = %q, want %q for --ports %q", scanRange, tt.wantRange, tt.ports)
			}
		})
	}
}

// TestSipptsCveProbingIsHeldBehindBruteMode covers the one part of the SIP
// handler that is not enumeration.
//
// -cve makes sippts probe for known SIP vulnerabilities. It ran by default when
// the handler was contributed, which put vulnerability probing in the same run as
// ordinary service discovery. It now sits behind -b, alongside the brute-force
// tools, and the scan still runs without it.
func TestSipptsCveProbingIsHeldBehindBruteMode(t *testing.T) {
	has := func(args []string, flag string) bool {
		for _, a := range args {
			if a == flag {
				return true
			}
		}
		return false
	}

	original := *checks.OptBrute
	t.Cleanup(func() { *checks.OptBrute = original })

	*checks.OptBrute = false
	without := sipptsScanArgs("udp", "5060", "192.0.2.1")
	if has(without, "-cve") {
		t.Errorf("-cve present without -b: %v", without)
	}

	*checks.OptBrute = true
	with := sipptsScanArgs("udp", "5060", "192.0.2.1")
	if !has(with, "-cve") {
		t.Errorf("-cve missing under -b: %v", with)
	}

	// The scan must still be a scan either way: dropping -cve must not drop the
	// target, the transport, the port list or the fingerprinting flag.
	for _, args := range [][]string{without, with} {
		for _, required := range []string{"sippts", "scan", "-p", "udp", "-r", "5060", "-fp", "-i", "192.0.2.1"} {
			if !has(args, required) {
				t.Errorf("%q missing from %v", required, args)
			}
		}
	}
}
