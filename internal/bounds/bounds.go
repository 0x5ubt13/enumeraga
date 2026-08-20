// Package bounds carries the explicit limits a caller has placed on a scan and
// applies them to the tools enumeraga launches.
//
// It deliberately imports nothing from the rest of the codebase. Keeping it free
// of internal dependencies means it can be tested in isolation, and lets both
// internal/utils and internal/scans/common import it without an import cycle.
package bounds

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Bounds carries the explicit limits placed on a run. The zero value means
// unbounded, which is the behaviour enumeraga has always had: nothing changes
// unless the caller asks for it.
type Bounds struct {
	// Enabled reports whether the strict bounded contract is in force. It
	// suppresses the scope-widening enumeraga otherwise performs on its own
	// initiative: the extra fingerprinting port, the second re-sweep, and
	// multi-target input.
	Enabled bool

	// TCPPorts and UDPPorts are nmap-ready port strings derived from --ports.
	// An empty string means that protocol was not requested at all.
	TCPPorts string
	UDPPorts string

	// Rate caps requests per second for HTTP-layer tools, and packets per second
	// for nmap. Zero means uncapped.
	Rate int

	// Concurrency caps simultaneous tool processes. Zero means use the existing
	// mode-derived default.
	Concurrency int

	// MaxRuntime bounds the whole run. Zero means unbounded.
	MaxRuntime time.Duration

	// AllowMultiTarget permits a targets file or a CIDR range under Enabled.
	AllowMultiTarget bool

	// AllowUnthrottledTools runs tools that cannot honour Rate rather than
	// skipping them.
	AllowUnthrottledTools bool

	// toolOverrides reproduces a preset's exact per-tool arguments as flag/value
	// pairs. Gentle mode uses this to keep its long-standing values rather than
	// having them re-derived from a rate, which would silently change what
	// gentle mode does.
	toolOverrides map[string][]string
}

// Active holds the bounds for the current run. It is replaced once during
// start-up, before any scanning begins, and only read thereafter.
var Active = &Bounds{}

// HasPortList reports whether the caller supplied an explicit port list.
func (b *Bounds) HasPortList() bool {
	return b.TCPPorts != "" || b.UDPPorts != ""
}

// PortsInScope filters a candidate nmap port specification down to the ports the
// caller authorised via --ports. It returns candidate unchanged when no explicit
// port list is in force, and "" when none of the candidates are in scope.
//
// Protocol handlers scan hardcoded port clusters — SMB probes 137,138,139,445 as
// a group — so without this a caller who named one member of a cluster would have
// the rest touched too, breaking the guarantee that --ports is the complete list
// of ports this run may reach. A candidate range entry is kept only if every port
// it implies is authorised: partially honouring a range would still touch a port
// outside the list.
func (b *Bounds) PortsInScope(candidate string, udp bool) string {
	if !b.HasPortList() {
		return candidate
	}

	allowed := b.allowedPortSet(udp)

	var kept []string
	for _, entry := range strings.Split(candidate, ",") {
		if entry == "" {
			continue
		}
		if portEntryFullyIn(entry, allowed) {
			kept = append(kept, entry)
		}
	}
	return strings.Join(kept, ",")
}

// PortInScope reports whether a single port may be touched. It exists for tools
// that take a port as a literal argument rather than as part of a scan
// specification, such as impacket-rpcdump, where there is no nmap port string to
// filter and the port either gets passed to the tool or it does not run at all.
func (b *Bounds) PortInScope(port string, udp bool) bool {
	if !b.HasPortList() {
		return true
	}
	return portEntryFullyIn(port, b.allowedPortSet(udp))
}

// allowedPortSet expands the caller's authorised TCP or UDP port list into the
// set of individual port numbers it covers, resolving any low-high ranges.
func (b *Bounds) allowedPortSet(udp bool) map[int]bool {
	spec := b.TCPPorts
	if udp {
		spec = b.UDPPorts
	}
	set := make(map[int]bool)
	if spec == "" {
		return set
	}
	for _, entry := range strings.Split(spec, ",") {
		for _, port := range expandPortEntry(entry) {
			set[port] = true
		}
	}
	return set
}

// portEntryFullyIn reports whether every port implied by entry (a single port or
// a low-high range) is present in allowed. An entry that fails to parse is never
// in scope, since a candidate this package did not itself validate must not be
// treated as authorised by default.
func portEntryFullyIn(entry string, allowed map[int]bool) bool {
	ports := expandPortEntry(entry)
	if len(ports) == 0 {
		return false
	}
	for _, port := range ports {
		if !allowed[port] {
			return false
		}
	}
	return true
}

// expandPortEntry parses a single port or low-high range into the individual
// port numbers it covers. It returns nil for anything it cannot parse.
func expandPortEntry(entry string) []int {
	parts := strings.Split(entry, "-")
	switch len(parts) {
	case 1:
		port, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil
		}
		return []int{port}
	case 2:
		low, errLow := strconv.Atoi(parts[0])
		high, errHigh := strconv.Atoi(parts[1])
		if errLow != nil || errHigh != nil || high < low {
			return nil
		}
		ports := make([]int, 0, high-low+1)
		for port := low; port <= high; port++ {
			ports = append(ports, port)
		}
		return ports
	default:
		return nil
	}
}

// PortSpec is the validated result of parsing a --ports value, split into the
// two nmap port strings the TCP and UDP scans need.
type PortSpec struct {
	TCP string
	UDP string
}

// ParsePortSpec validates a --ports value and splits it into nmap-ready TCP and
// UDP port strings.
//
// Entries are comma separated. Each is optionally prefixed "T:" or "U:" (TCP is
// the default) and is either a single port or a low-high range. Anything else is
// rejected outright: the entire point of an explicit port list is that the caller
// can guarantee nothing outside it is touched, so a value that cannot be
// understood must fail rather than be reinterpreted.
func ParsePortSpec(spec string) (PortSpec, error) {
	if spec == "" {
		return PortSpec{}, fmt.Errorf("empty port specification")
	}

	var tcp, udp []string
	for _, entry := range strings.Split(spec, ",") {
		if entry == "" {
			return PortSpec{}, fmt.Errorf("empty port entry in %q", spec)
		}

		proto, body := 'T', entry
		if len(entry) > 2 && entry[1] == ':' {
			switch entry[0] {
			case 'T', 't':
				proto, body = 'T', entry[2:]
			case 'U', 'u':
				proto, body = 'U', entry[2:]
			default:
				return PortSpec{}, fmt.Errorf("unknown protocol prefix %q in port entry %q (expected T: or U:)", string(entry[0]), entry)
			}
		}

		if err := validatePortBody(body); err != nil {
			return PortSpec{}, err
		}

		if proto == 'U' {
			udp = append(udp, body)
		} else {
			tcp = append(tcp, body)
		}
	}

	return PortSpec{TCP: strings.Join(tcp, ","), UDP: strings.Join(udp, ",")}, nil
}

// validatePortBody checks a single port or low-high range. Every character is
// checked explicitly rather than relying on strconv alone, which would otherwise
// accept values such as "+80"; nothing reaches nmap without passing through here.
func validatePortBody(body string) error {
	if body == "" {
		return fmt.Errorf("empty port entry")
	}
	for _, r := range body {
		if (r < '0' || r > '9') && r != '-' {
			return fmt.Errorf("invalid character %q in port specification %q", string(r), body)
		}
	}

	parts := strings.Split(body, "-")
	if len(parts) > 2 {
		return fmt.Errorf("malformed port range %q", body)
	}

	previous := 0
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("invalid port %q in %q", p, body)
		}
		if n < 1 || n > 65535 {
			return fmt.Errorf("port %d out of range 1-65535", n)
		}
		if i == 1 && n <= previous {
			return fmt.Errorf("port range %q does not ascend", body)
		}
		previous = n
	}
	return nil
}

// SetFlagValue returns a copy of args with flag set to value, replacing an
// existing occurrence or appending a new one.
//
// The input slice is never modified. Tool argument slices are built once and
// may be shared, so mutating in place would leak one run's throttle into another.
func SetFlagValue(args []string, flag, value string) []string {
	out := make([]string, len(args))
	copy(out, args)
	for i := 0; i < len(out)-1; i++ {
		if out[i] == flag {
			out[i+1] = value
			return out
		}
	}
	return append(out, flag, value)
}

// Config carries raw flag values into validation. It exists so this package does
// not have to import the flag definitions, which would create an import cycle.
type Config struct {
	Bounded               bool
	Ports                 string
	TopPorts              string
	Rate                  int
	Concurrency           int
	MaxRuntimeSeconds     int
	AllowMultiTarget      bool
	AllowUnthrottledTools bool
	Gentle                bool
	Range                 string
	Target                string
}

// Validate turns raw flag values into a Bounds, or returns the first violation.
//
// Every failure is a startup error rather than a silent reinterpretation. A
// silently ignored cap produces a run the caller must afterwards treat as
// unbounded, which is a worse outcome than refusing to start.
func Validate(c Config) (*Bounds, error) {
	if c.Ports != "" && c.TopPorts != "" {
		return nil, fmt.Errorf("--ports and --top-ports are mutually exclusive: --ports names exact ports, --top-ports asks for a count of common ones")
	}
	if c.Gentle && (c.Rate > 0 || c.Concurrency > 0) {
		return nil, fmt.Errorf("--gentle is a rate and concurrency preset, so it cannot be combined with --rate or --concurrency; pass either the preset or explicit values, not both")
	}
	// Zero is valid throughout and means the bound was not supplied, so the rule
	// enforced here is "must not be negative" rather than "must be positive";
	// the messages say so, so a caller is not told to raise a value it never set.
	if c.Rate < 0 {
		return nil, fmt.Errorf("--rate must not be negative, got %d (omit it, or pass 0, to leave the rate uncapped)", c.Rate)
	}
	if c.Concurrency < 0 {
		return nil, fmt.Errorf("--concurrency must not be negative, got %d (omit it, or pass 0, to use the mode-derived default)", c.Concurrency)
	}
	if c.MaxRuntimeSeconds < 0 {
		return nil, fmt.Errorf("--max-runtime must not be negative, got %d (omit it, or pass 0, to leave the run unbounded)", c.MaxRuntimeSeconds)
	}

	b := &Bounds{
		Enabled: c.Bounded || c.Ports != "" || c.Rate > 0 ||
			c.Concurrency > 0 || c.MaxRuntimeSeconds > 0,
		Rate:                  c.Rate,
		Concurrency:           c.Concurrency,
		MaxRuntime:            time.Duration(c.MaxRuntimeSeconds) * time.Second,
		AllowMultiTarget:      c.AllowMultiTarget,
		AllowUnthrottledTools: c.AllowUnthrottledTools,
	}

	if c.Ports != "" {
		spec, err := ParsePortSpec(c.Ports)
		if err != nil {
			return nil, fmt.Errorf("--ports: %w", err)
		}
		b.TCPPorts, b.UDPPorts = spec.TCP, spec.UDP
	}

	if b.Enabled && !b.AllowMultiTarget && c.Range != "" {
		return nil, fmt.Errorf("--range expands the scan to a whole subnet, which a bounded run refuses; pass --allow-multi-target to permit it")
	}

	return b, nil
}

// SummaryLine renders the bounds actually in force, for the end-of-run summary.
// It returns an empty string when nothing was bounded, so an ordinary run prints
// no extra noise.
func (b *Bounds) SummaryLine() string {
	var parts []string
	if b.HasPortList() {
		ports := b.TCPPorts
		if b.UDPPorts != "" {
			if ports != "" {
				ports += ","
			}
			ports += "U:" + b.UDPPorts
		}
		parts = append(parts, "ports="+ports)
	}
	if b.Rate > 0 {
		parts = append(parts, "rate="+strconv.Itoa(b.Rate)+"/s")
	}
	if b.Concurrency > 0 {
		parts = append(parts, "concurrency="+strconv.Itoa(b.Concurrency))
	}
	if b.MaxRuntime > 0 {
		parts = append(parts, "max-runtime="+b.MaxRuntime.String())
	}
	return strings.Join(parts, "  ")
}
