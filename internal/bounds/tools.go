package bounds

import (
	"math"
	"strconv"
)

// RateClass describes how — or whether — a tool can honour a requests-per-second cap.
type RateClass int

const (
	// RateFlagged is a true rate or inter-request delay control that a rate cap
	// maps onto directly.
	RateFlagged RateClass = iota

	// RateThreadsOnly is a thread or concurrency count with no rate control. It
	// is capped at min(rate, concurrency) and reported as concurrency-capped,
	// never as rate-capped: N threads can issue far more than N requests per
	// second, so presenting it as an honoured rate cap would be a silent
	// violation of the caller's limit.
	RateThreadsOnly

	// RateSingleRequest makes roughly one request per invocation and is therefore
	// inherently under any sane cap. It runs unmodified.
	RateSingleRequest

	// RateUnthrottled makes many requests with no throttle available. It is
	// skipped under a rate cap unless the caller opts in explicitly.
	RateUnthrottled

	// RateUnclassified means no class was determined because there was nothing
	// to classify — an empty argument vector. It is deliberately not the zero
	// value: RateFlagged occupies that, so a result returned without ever
	// consulting the table would otherwise be reported as rate-capped.
	RateUnclassified RateClass = -1
)

// Note returns the short label used to group tools in the run summary, so the
// caller can see which of its traffic was genuinely rate-capped and which was
// only held to a thread count. RateUnclassified returns an empty string, which
// callers treat as "record no note".
func (c RateClass) Note() string {
	switch c {
	case RateFlagged:
		return "rate-capped"
	case RateThreadsOnly:
		return "concurrency-capped only, not rate-capped"
	case RateSingleRequest:
		return "ran without a cap (single-request)"
	case RateUnthrottled:
		return "unthrottled"
	default:
		return ""
	}
}

// unitKind describes the units a tool's throttle flag expects.
type unitKind int

const (
	unitNone         unitKind = iota
	unitRate                  // the rate itself
	unitDelaySeconds          // seconds between requests
	unitDelayMillis           // milliseconds between requests
	unitThreads               // a thread count
)

// ToolRate is a tool's entry in the capability table.
type ToolRate struct {
	Class RateClass
	Flag  string // empty for RateSingleRequest and RateUnthrottled
	Unit  unitKind
}

// toolRates classifies every external tool enumeraga launches. A tool is
// classified pessimistically where its request volume is uncertain: wafw00f, for
// instance, fires a series of fingerprinting payloads with no throttle available,
// so it is unthrottled rather than single-request.
var toolRates = map[string]ToolRate{
	// True rate or inter-request delay controls.
	"nmap":        {Class: RateFlagged, Flag: "--max-rate", Unit: unitRate},
	"ffuf":        {Class: RateFlagged, Flag: "-rate", Unit: unitRate},
	"nuclei":      {Class: RateFlagged, Flag: "-rate-limit", Unit: unitRate},
	"nikto":       {Class: RateFlagged, Flag: "-Pause", Unit: unitDelaySeconds},
	"onesixtyone": {Class: RateFlagged, Flag: "-w", Unit: unitDelayMillis},
	"fping":       {Class: RateFlagged, Flag: "-i", Unit: unitDelayMillis},

	// Thread counts only: a concurrency knob, not a rate.
	"gobuster":     {Class: RateThreadsOnly, Flag: "-t", Unit: unitThreads},
	"dirsearch":    {Class: RateThreadsOnly, Flag: "-t", Unit: unitThreads},
	"hydra":        {Class: RateThreadsOnly, Flag: "-t", Unit: unitThreads},
	"wpscan":       {Class: RateThreadsOnly, Flag: "--max-threads", Unit: unitThreads},
	"whatweb":      {Class: RateThreadsOnly, Flag: "--max-threads", Unit: unitThreads},
	"netexec":      {Class: RateThreadsOnly, Flag: "--threads", Unit: unitThreads},
	"crackmapexec": {Class: RateThreadsOnly, Flag: "--threads", Unit: unitThreads},
	"gowitness":    {Class: RateThreadsOnly, Flag: "--threads", Unit: unitThreads},

	// Roughly one request or connection each.
	"ldapsearch":       {Class: RateSingleRequest},
	"showmount":        {Class: RateSingleRequest},
	"nmblookup":        {Class: RateSingleRequest},
	"nc":               {Class: RateSingleRequest},
	"openssl":          {Class: RateSingleRequest},
	"impacket-rpcdump": {Class: RateSingleRequest},
	"ssh-audit":        {Class: RateSingleRequest},
	"rusers":           {Class: RateSingleRequest},
	"rwho":             {Class: RateSingleRequest},
	"ident-user-enum":  {Class: RateSingleRequest},

	// Many requests, no throttle available.
	// testssl.sh performs a full protocol, cipher and vulnerability sweep, which
	// is many hundreds of TLS handshakes, and exposes no rate or delay control to
	// hold them to a cap. Both spellings are listed because the Kali package
	// installs the binary as 'testssl.sh' while a manual install commonly names
	// it 'testssl', and the launch site picks whichever exists.
	"testssl":             {Class: RateUnthrottled},
	"testssl.sh":          {Class: RateUnthrottled},
	"cmseek":              {Class: RateUnthrottled},
	"braa":                {Class: RateUnthrottled},
	"snmpwalk":            {Class: RateUnthrottled},
	"smbmap":              {Class: RateUnthrottled},
	"enum4linux-ng":       {Class: RateUnthrottled},
	"odat":                {Class: RateUnthrottled},
	"cewl":                {Class: RateUnthrottled},
	"wafw00f":             {Class: RateUnthrottled},
	"msfconsole":          {Class: RateUnthrottled},
	"nbtscan-unixwiz":     {Class: RateUnthrottled},
	"responder-RunFinger": {Class: RateUnthrottled},
}

// RateFor returns the capability entry for a tool. An unknown tool is treated as
// unthrottled: failing closed means a newly added tool is skipped and reported
// under a rate cap rather than quietly running uncapped, and the resulting skip
// message is what prompts someone to classify it.
func RateFor(tool string) ToolRate {
	if r, ok := toolRates[tool]; ok {
		return r
	}
	return ToolRate{Class: RateUnthrottled}
}

// IsClassified reports whether a tool has an explicit table entry, as distinct
// from having been defaulted to unthrottled.
func IsClassified(tool string) bool {
	_, ok := toolRates[tool]
	return ok
}

// ApplyResult is the outcome of applying the bounds to a tool's arguments.
type ApplyResult struct {
	// Args is the argument vector to execute. Unchanged when no cap applies.
	Args []string
	// Skip is true when the tool cannot honour the rate cap and the caller has
	// not opted into running it anyway.
	Skip bool
	// Reason explains a skip, for the run summary.
	Reason string
	// Class is the tool's capability class, used to group the summary output.
	Class RateClass
}

// ApplyRate returns the argument vector to run, with the tool's own throttle set
// from the bounds where one exists.
func (b *Bounds) ApplyRate(args []string) ApplyResult {
	if len(args) == 0 {
		return ApplyResult{Args: args, Class: RateUnclassified}
	}
	tool := args[0]
	entry := RateFor(tool)

	// A preset's explicit values win over anything derived from a rate, so
	// switching gentle mode onto this code path changes none of its behaviour.
	if override, ok := b.toolOverrides[tool]; ok {
		return ApplyResult{Args: applyOverrides(args, override), Class: entry.Class}
	}

	if b.Rate <= 0 {
		return ApplyResult{Args: args, Class: entry.Class}
	}

	switch entry.Class {
	case RateSingleRequest:
		return ApplyResult{Args: args, Class: entry.Class}

	case RateUnthrottled:
		if b.AllowUnthrottledTools {
			return ApplyResult{Args: args, Class: entry.Class}
		}
		return ApplyResult{
			Args:   args,
			Skip:   true,
			Reason: "no throttle available and a rate cap is in force",
			Class:  entry.Class,
		}

	default:
		return ApplyResult{Args: SetFlagValue(args, entry.Flag, b.flagValue(entry, args)), Class: entry.Class}
	}
}

// flagValue converts the rate into the units a tool's throttle flag expects,
// never loosening a throttle the argument vector already carries.
//
// A cap is a ceiling, not a target. Where a launch site already passes a gentler
// value than the cap implies — dirsearch -t 10 under --rate 50, or onesixtyone
// -w 100 (ten packets a second) under --rate 50 — raising it to the cap would
// make a bounded run more aggressive than an unbounded one, which is the exact
// opposite of what the caller asked for. The gentler of the two always wins.
//
// Which direction is gentler depends on the unit: for rates and thread counts
// the smaller number, for inter-request delays the larger one. A value already
// present that does not parse as an integer is ignored, since it cannot be
// compared; the derived value is applied in its place.
func (b *Bounds) flagValue(entry ToolRate, args []string) string {
	derived := b.derivedFlagValue(entry)

	existing, ok := existingIntFlag(args, entry.Flag)
	if !ok {
		return derived
	}

	derivedInt, err := strconv.Atoi(derived)
	if err != nil {
		return derived
	}

	switch entry.Unit {
	case unitDelaySeconds, unitDelayMillis:
		if existing > derivedInt {
			return strconv.Itoa(existing)
		}
	default:
		if existing < derivedInt {
			return strconv.Itoa(existing)
		}
	}
	return derived
}

// existingIntFlag returns the integer value already present for flag in args.
// It reports false when the flag is absent, has no value after it, or carries a
// value that is not an integer.
func existingIntFlag(args []string, flag string) (int, bool) {
	if flag == "" {
		return 0, false
	}
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return 0, false
			}
			return n, true
		}
	}
	return 0, false
}

// derivedFlagValue converts the rate into the units a tool's throttle flag
// expects, without reference to what the argument vector already carries.
func (b *Bounds) derivedFlagValue(entry ToolRate) string {
	switch entry.Unit {
	case unitDelaySeconds:
		// A delay between requests, not a rate: 1/rate rounded up, floored at the
		// smallest value the tool accepts. For any rate of 1 or more this yields
		// one second, so at most one request per second — below the cap rather
		// than above it, which is the safe direction to err.
		secs := int(math.Ceil(1 / float64(b.Rate)))
		if secs < 1 {
			secs = 1
		}
		return strconv.Itoa(secs)

	case unitDelayMillis:
		ms := int(math.Ceil(1000 / float64(b.Rate)))
		if ms < 1 {
			ms = 1
		}
		return strconv.Itoa(ms)

	case unitThreads:
		// The lower of the two ceilings: a caller asking for a concurrency of 2
		// must not get 5 concurrent connections because the rate happened to be 5.
		threads := b.Rate
		if b.Concurrency > 0 && b.Concurrency < threads {
			threads = b.Concurrency
		}
		if threads < 1 {
			threads = 1
		}
		return strconv.Itoa(threads)

	default:
		return strconv.Itoa(b.Rate)
	}
}

// applyOverrides sets each flag/value pair from a preset onto args.
func applyOverrides(args, override []string) []string {
	out := args
	for i := 0; i+1 < len(override); i += 2 {
		out = SetFlagValue(out, override[i], override[i+1])
	}
	return out
}

// GentlePreset returns the Bounds that reproduce gentle mode exactly. The values
// are the ones gentle mode has always used and are pinned here rather than
// re-derived from a rate, so moving gentle mode onto the shared code path changes
// nothing about what it does.
func GentlePreset() *Bounds {
	return &Bounds{
		Concurrency: 2,
		toolOverrides: map[string][]string{
			"ffuf":      {"-rate", "50", "-t", "2"},
			"dirsearch": {"-t", "2"},
			"gobuster":  {"-t", "5"},
			"hydra":     {"-t", "2"},
			"wpscan":    {"--max-threads", "1"},
			"whatweb":   {"-a", "1"},
		},
	}
}
