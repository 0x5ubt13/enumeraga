package bounds

import (
	"strings"
	"testing"
	"time"
)

func TestParsePortSpec(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantTCP string
		wantUDP string
		wantErr bool
	}{
		{name: "two tcp ports", spec: "80,443", wantTCP: "80,443"},
		{name: "explicit tcp prefix", spec: "T:80,T:443", wantTCP: "80,443"},
		{name: "mixed tcp and udp", spec: "80,U:53", wantTCP: "80", wantUDP: "53"},
		{name: "udp only", spec: "U:53,U:161", wantUDP: "53,161"},
		{name: "tcp range", spec: "T:8000-8010", wantTCP: "8000-8010"},
		{name: "lowercase prefix", spec: "u:53", wantUDP: "53"},
		{name: "single port", spec: "22", wantTCP: "22"},
		{name: "boundary ports", spec: "1,65535", wantTCP: "1,65535"},

		{name: "empty spec", spec: "", wantErr: true},
		{name: "empty entry", spec: "80,,443", wantErr: true},
		{name: "trailing comma", spec: "80,", wantErr: true},
		{name: "semicolon separator", spec: "80;443", wantErr: true},
		{name: "wildcard", spec: "*", wantErr: true},
		{name: "whitespace inside", spec: "80, 443", wantErr: true},
		{name: "port zero", spec: "0", wantErr: true},
		{name: "port too high", spec: "70000", wantErr: true},
		{name: "descending range", spec: "443-80", wantErr: true},
		{name: "equal range", spec: "80-80", wantErr: true},
		{name: "triple range", spec: "1-2-3", wantErr: true},
		{name: "unknown protocol prefix", spec: "X:80", wantErr: true},
		{name: "signed port", spec: "+80", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePortSpec(tt.spec)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ParsePortSpec(%q) = %+v, want error", tt.spec, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePortSpec(%q) returned unexpected error: %v", tt.spec, err)
			}
			if got.TCP != tt.wantTCP {
				t.Errorf("ParsePortSpec(%q).TCP = %q, want %q", tt.spec, got.TCP, tt.wantTCP)
			}
			if got.UDP != tt.wantUDP {
				t.Errorf("ParsePortSpec(%q).UDP = %q, want %q", tt.spec, got.UDP, tt.wantUDP)
			}
		})
	}
}

func TestSetFlagValueDoesNotMutateInput(t *testing.T) {
	original := []string{"ffuf", "-w", "list.txt"}
	got := SetFlagValue(original, "-rate", "5")

	if len(original) != 3 {
		t.Errorf("SetFlagValue mutated its input: %v", original)
	}
	want := []string{"ffuf", "-w", "list.txt", "-rate", "5"}
	if len(got) != len(want) {
		t.Fatalf("SetFlagValue() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SetFlagValue() = %v, want %v", got, want)
		}
	}
}

func TestSetFlagValueReplacesExisting(t *testing.T) {
	got := SetFlagValue([]string{"ffuf", "-rate", "500", "-w", "list.txt"}, "-rate", "5")
	if got[2] != "5" {
		t.Errorf("SetFlagValue() did not replace existing value: %v", got)
	}
	if len(got) != 5 {
		t.Errorf("SetFlagValue() appended instead of replacing: %v", got)
	}
}

func TestHasPortList(t *testing.T) {
	if (&Bounds{}).HasPortList() {
		t.Error("empty Bounds reports a port list")
	}
	if !(&Bounds{TCPPorts: "80"}).HasPortList() {
		t.Error("Bounds with TCP ports reports no port list")
	}
	if !(&Bounds{UDPPorts: "53"}).HasPortList() {
		t.Error("Bounds with UDP ports only reports no port list")
	}
}

func TestValidateMutualExclusion(t *testing.T) {
	_, err := Validate(Config{Ports: "80,443", TopPorts: "100"})
	if err == nil {
		t.Fatal("Validate accepted --ports together with --top-ports")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should explain the conflict, got: %v", err)
	}
}

func TestValidateImpliesBounded(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "explicit flag", cfg: Config{Bounded: true}},
		{name: "ports implies", cfg: Config{Ports: "80"}},
		{name: "rate implies", cfg: Config{Rate: 5}},
		{name: "concurrency implies", cfg: Config{Concurrency: 2}},
		{name: "max runtime implies", cfg: Config{MaxRuntimeSeconds: 900}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := Validate(tt.cfg)
			if err != nil {
				t.Fatalf("Validate returned an error: %v", err)
			}
			if !b.Enabled {
				t.Error("Enabled = false, want true")
			}
		})
	}
}

func TestValidateStaysInertWithNoBounds(t *testing.T) {
	// The whole point of the mode flag: an existing invocation must be unaffected.
	b, err := Validate(Config{Target: "10.0.0.1"})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	if b.Enabled {
		t.Error("Enabled = true with no bound flags passed")
	}
}

func TestValidateRejectsNegativeValues(t *testing.T) {
	for _, cfg := range []Config{
		{Rate: -1},
		{Concurrency: -1},
		{MaxRuntimeSeconds: -1},
	} {
		if _, err := Validate(cfg); err == nil {
			t.Errorf("Validate accepted a negative value in %+v", cfg)
		}
	}
}

func TestValidateRefusesRangeWhenBounded(t *testing.T) {
	_, err := Validate(Config{Bounded: true, Range: "10.0.0.0/24"})
	if err == nil {
		t.Fatal("Validate accepted --range under --bounded")
	}
	if !strings.Contains(err.Error(), "--allow-multi-target") {
		t.Errorf("error should name the flag that permits it, got: %v", err)
	}

	if _, err := Validate(Config{Bounded: true, Range: "10.0.0.0/24", AllowMultiTarget: true}); err != nil {
		t.Errorf("Validate refused --range despite --allow-multi-target: %v", err)
	}
}

func TestValidatePropagatesPortSpec(t *testing.T) {
	b, err := Validate(Config{Ports: "80,U:53"})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	if b.TCPPorts != "80" || b.UDPPorts != "53" {
		t.Errorf("TCPPorts=%q UDPPorts=%q, want 80 and 53", b.TCPPorts, b.UDPPorts)
	}

	if _, err := Validate(Config{Ports: "80;443"}); err == nil {
		t.Error("Validate accepted a malformed port specification")
	}
}

func TestValidateConvertsMaxRuntime(t *testing.T) {
	b, err := Validate(Config{MaxRuntimeSeconds: 900})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	if b.MaxRuntime != 15*time.Minute {
		t.Errorf("MaxRuntime = %v, want 15m", b.MaxRuntime)
	}
}

func TestValidateRejectsGentleWithRate(t *testing.T) {
	_, err := Validate(Config{Gentle: true, Rate: 5})
	if err == nil {
		t.Fatal("Validate accepted --gentle together with --rate")
	}
	if !strings.Contains(err.Error(), "--gentle") || !strings.Contains(err.Error(), "--rate") {
		t.Errorf("error should name both --gentle and --rate, got: %v", err)
	}
}

func TestValidateRejectsGentleWithConcurrency(t *testing.T) {
	_, err := Validate(Config{Gentle: true, Concurrency: 2})
	if err == nil {
		t.Fatal("Validate accepted --gentle together with --concurrency")
	}
	if !strings.Contains(err.Error(), "--gentle") || !strings.Contains(err.Error(), "--concurrency") {
		t.Errorf("error should name both --gentle and --concurrency, got: %v", err)
	}
}

func TestValidateAcceptsGentleAlone(t *testing.T) {
	// Gentle on its own must not flip on the bounded contract: a long-standing
	// --gentle user has never supplied a port list, a rate or a concurrency cap,
	// and must not suddenly have multi-target input refused or discovery scope
	// narrowed just because gentle mode happens to be active.
	b, err := Validate(Config{Gentle: true})
	if err != nil {
		t.Fatalf("Validate rejected --gentle on its own: %v", err)
	}
	if b.Enabled {
		t.Error("Enabled = true for --gentle alone, want false")
	}
}

func TestValidateAcceptsRateWithoutGentle(t *testing.T) {
	b, err := Validate(Config{Rate: 5})
	if err != nil {
		t.Fatalf("Validate rejected --rate without --gentle: %v", err)
	}
	if b.Rate != 5 {
		t.Errorf("Rate = %d, want 5", b.Rate)
	}
}

func TestSummaryLine(t *testing.T) {
	b, err := Validate(Config{Ports: "80,443", Rate: 5, Concurrency: 2, MaxRuntimeSeconds: 900})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	got := b.SummaryLine()
	for _, want := range []string{"ports=80,443", "rate=5/s", "concurrency=2", "max-runtime=15m0s"} {
		if !strings.Contains(got, want) {
			t.Errorf("SummaryLine() = %q, missing %q", got, want)
		}
	}

	if (&Bounds{}).SummaryLine() != "" {
		t.Error("SummaryLine() should be empty when no bounds are in force")
	}
}

// TestPortsInScopeInertWithoutPortList is the most important test here: a filter
// bug that suppressed scans for every existing, unbounded user would be a silent
// regression, not a safety improvement.
func TestPortsInScopeInertWithoutPortList(t *testing.T) {
	b := &Bounds{}
	got := b.PortsInScope("137,138,139,445", false)
	if got != "137,138,139,445" {
		t.Errorf("PortsInScope() = %q, want the candidate unchanged when no port list is in force", got)
	}
}

func TestPortsInScopeFiltersClusterToAuthorisedMember(t *testing.T) {
	b := &Bounds{TCPPorts: "445"}
	got := b.PortsInScope("137,138,139,445", false)
	if got != "445" {
		t.Errorf("PortsInScope() = %q, want %q", got, "445")
	}
}

func TestPortsInScopeReturnsEmptyWhenNothingAuthorised(t *testing.T) {
	b := &Bounds{TCPPorts: "80"}
	got := b.PortsInScope("137,138,139,445", false)
	if got != "" {
		t.Errorf("PortsInScope() = %q, want empty string", got)
	}
}

func TestPortsInScopeRespectsRangesInCallerList(t *testing.T) {
	b := &Bounds{TCPPorts: "8000-8010"}
	got := b.PortsInScope("8005,9000", false)
	if got != "8005" {
		t.Errorf("PortsInScope() = %q, want %q", got, "8005")
	}
}

func TestPortsInScopeKeepsTCPAndUDPListsSeparate(t *testing.T) {
	b := &Bounds{TCPPorts: "445", UDPPorts: "137"}

	if got := b.PortsInScope("137,138,139,445", true); got != "137" {
		t.Errorf("UDP PortsInScope() = %q, want %q (must not draw from the TCP list)", got, "137")
	}
	if got := b.PortsInScope("137", false); got != "" {
		t.Errorf("TCP PortsInScope() = %q, want empty (must not draw from the UDP list)", got)
	}
}

func TestPortsInScopePreservesCandidateOrder(t *testing.T) {
	b := &Bounds{TCPPorts: "135,593"}
	got := b.PortsInScope("593,135", false)
	if got != "593,135" {
		t.Errorf("PortsInScope() = %q, want %q (candidate order preserved)", got, "593,135")
	}
}

func TestPortInScopeSingleWithoutPortList(t *testing.T) {
	b := &Bounds{}
	if !b.PortInScope("135", false) {
		t.Error("PortInScope() = false, want true when no port list is in force")
	}
}

func TestPortInScopeSingleAuthorised(t *testing.T) {
	b := &Bounds{TCPPorts: "135,593"}
	if !b.PortInScope("135", false) {
		t.Error("PortInScope(\"135\") = false, want true")
	}
	if !b.PortInScope("593", false) {
		t.Error("PortInScope(\"593\") = false, want true")
	}
}

func TestPortInScopeSingleUnauthorised(t *testing.T) {
	b := &Bounds{TCPPorts: "135"}
	if b.PortInScope("593", false) {
		t.Error("PortInScope(\"593\") = true, want false: 593 was never authorised")
	}
}
