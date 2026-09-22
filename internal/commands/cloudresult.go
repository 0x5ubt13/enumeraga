package commands

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/runrecord"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// CloudToolOutcome says how a cloud tool finished, at a finer grain than the
// process exit code alone can express.
//
// The distinction that matters is between a scanner that ran and found
// something and a scanner that never ran at all. Both exit non-zero, and
// treating them alike turns a complete scan into a reported failure and, worse,
// lets a broken invocation pass as a clean one.
type CloudToolOutcome string

const (
	// OutcomeCompleted is a clean run with nothing withheld.
	OutcomeCompleted CloudToolOutcome = "completed"
	// OutcomeFindings is a completed run whose non-zero exit means the scanner
	// found failing checks. Its reports are valid and must be kept.
	OutcomeFindings CloudToolOutcome = "completed_with_findings"
	// OutcomePartial is a completed run whose coverage was limited, typically by
	// the assessment identity lacking a read permission. The reports are valid
	// but do not cover everything that was asked for.
	OutcomePartial CloudToolOutcome = "completed_partial_coverage"
	// OutcomeInvalidInvocation is a tool that rejected the argument vector it was
	// given. Nothing was scanned.
	OutcomeInvalidInvocation CloudToolOutcome = "invalid_invocation"
	// OutcomeUnavailable is a binary that could not be executed at all.
	OutcomeUnavailable CloudToolOutcome = "unavailable"
	// OutcomeNotApplicable is a tool deliberately not run: it does not support
	// this provider, or the scope it requires was not supplied.
	OutcomeNotApplicable CloudToolOutcome = "not_applicable"
	// OutcomeFailed is a genuine execution failure: a crash, a kill, or a run
	// that ended before producing its report.
	OutcomeFailed CloudToolOutcome = "failed"
)

// Exit statuses that mean "this scanner finished its work", read from the
// versions installed by internal/cloud/Dockerfile rather than assumed.
const (
	// prowlerFindingsExit is Prowler's exit code when checks completed and at
	// least one failed. See prowler/__main__.py: "If there are failed findings
	// exit code 3". The reports are already written by that point.
	prowlerFindingsExit = 3
	// scoutHandledErrorsExit is ScoutSuite's exit code when it completed and
	// saved its HTML report but handled errors while collecting. See
	// ScoutSuite/__main__.py: "if ERRORS_LIST: return 200", which is reached
	// after report.save(). Azure permission denials land here.
	scoutHandledErrorsExit = 200
	// scoutPostProcessingExit and scoutReportExit are genuine failures: the run
	// did not get as far as a usable report.
	scoutPostProcessingExit = 108
	scoutReportExit         = 109
)

// invalidInvocationMarkers are what a cloud tool prints when it rejects its own
// command line.
//
// A marker check is needed because cloudfox exits 0 after refusing to run: on
// exit status alone a rejected command line is indistinguishable from a clean
// scan, which is exactly how a broken Azure inventory call went unnoticed.
var invalidInvocationMarkers = []string{
	"Please enter a valid input with a valid flag",
	"Error: unknown flag:",
	"Error: unknown command",
	"Error: unknown shorthand flag:",
	"Error: invalid argument",
	"Error: required flag",
}

// hasInvalidInvocationMarker reports whether output carries a tool's own
// complaint about the argument vector it was handed.
func hasInvalidInvocationMarker(output string) bool {
	for _, marker := range invalidInvocationMarkers {
		if strings.Contains(output, marker) {
			return true
		}
	}
	return false
}

// toolKey reduces an argv[0] to the tool's name. cloudfox may be launched by
// absolute path when it was downloaded at runtime, so matching the raw string
// would miss it.
func toolKey(binary string) string {
	return strings.TrimSuffix(filepath.Base(binary), ".exe")
}

// classifyCloudToolExit turns a tool's exit status and output into an outcome
// and a human-readable reason.
//
// exitCode is -1 when no process status was available, which means the tool
// never reached a clean exit rather than that it exited zero.
func classifyCloudToolExit(binary string, exitCode int, output string) (CloudToolOutcome, string) {
	// A rejected command line is decided by the tool's own message, because the
	// exit code cannot be trusted to carry it.
	if hasInvalidInvocationMarker(output) {
		return OutcomeInvalidInvocation, "the tool rejected its command line, so nothing was scanned"
	}

	switch exitCode {
	case 126:
		return OutcomeUnavailable, "the binary could not be executed"
	case 127:
		return OutcomeUnavailable, "the binary was not found on PATH"
	}

	switch toolKey(binary) {
	case "prowler":
		if exitCode == prowlerFindingsExit {
			return OutcomeFindings, fmt.Sprintf(
				"completed and generated its reports, exiting %d because checks failed", prowlerFindingsExit)
		}
	case "scout":
		switch exitCode {
		case scoutHandledErrorsExit:
			return OutcomePartial, fmt.Sprintf(
				"completed and saved its report, exiting %d because errors were handled during collection "+
					"(commonly the assessment identity lacking a read permission)", scoutHandledErrorsExit)
		case scoutPostProcessingExit:
			return OutcomeFailed, "failed while running its post-processing engine, so no usable report was produced"
		case scoutReportExit:
			return OutcomeFailed, "failed while generating its HTML report"
		}
	}

	if exitCode == 0 {
		return OutcomeCompleted, "completed"
	}
	if exitCode < 0 {
		return OutcomeFailed, "did not return an exit status"
	}
	return OutcomeFailed, fmt.Sprintf("exited %d", exitCode)
}

// CloudToolResult is one cloud tool's disposition within a run.
type CloudToolResult struct {
	Tool     string
	Outcome  CloudToolOutcome
	ExitCode int // -1 when no process status was available
	Detail   string
	Artefact string
}

// FullCoverage reports whether this tool delivered everything it was asked for.
// A run with findings is still full coverage; a permission-limited one is not.
func (r CloudToolResult) FullCoverage() bool {
	return r.Outcome == OutcomeCompleted || r.Outcome == OutcomeFindings
}

// cloudResults collects every cloud tool's disposition so the end of the run can
// state plainly what was and was not covered. Tools run sequentially, but the
// lock costs nothing and keeps the collector safe if that ever changes.
var cloudResults struct {
	mu      sync.Mutex
	results []CloudToolResult
}

// recordCloudResult appends one tool's disposition to the run.
func recordCloudResult(r CloudToolResult) {
	cloudResults.mu.Lock()
	defer cloudResults.mu.Unlock()
	cloudResults.results = append(cloudResults.results, r)
}

// RecordCloudSkip notes a tool that was deliberately not run, with the reason.
// A skip is evidence too: it is the difference between a check that passed and a
// check that was never made.
func RecordCloudSkip(tool, reason string) {
	recordCloudResult(CloudToolResult{
		Tool:     toolKey(tool),
		Outcome:  OutcomeNotApplicable,
		ExitCode: -1,
		Detail:   reason,
	})
}

// CloudResults returns the dispositions collected so far.
func CloudResults() []CloudToolResult {
	cloudResults.mu.Lock()
	defer cloudResults.mu.Unlock()
	out := make([]CloudToolResult, len(cloudResults.results))
	copy(out, cloudResults.results)
	return out
}

// ResetCloudResults clears the collector. It exists for tests; a process runs one
// cloud scan.
func ResetCloudResults() {
	cloudResults.mu.Lock()
	defer cloudResults.mu.Unlock()
	cloudResults.results = nil
}

// CloudCoverageSummary renders the end-of-run account of what each tool did.
//
// It returns the text rather than printing it so the wording can be asserted in
// a test. The leading line states coverage plainly: a scan that produced some
// results and lost others is not a successful scan, and must not read as one.
func CloudCoverageSummary(results []CloudToolResult) string {
	if len(results) == 0 {
		return ""
	}

	var incomplete []CloudToolResult
	for _, r := range results {
		if !r.FullCoverage() {
			incomplete = append(incomplete, r)
		}
	}

	var b strings.Builder
	b.WriteString("\n[*] Cloud tool coverage\n")
	for _, r := range results {
		marker := "+"
		if !r.FullCoverage() {
			marker = "!"
		}
		fmt.Fprintf(&b, "    [%s] %-16s %-26s %s\n", marker, r.Tool, r.Outcome, r.Detail)
	}

	if len(incomplete) == 0 {
		b.WriteString("\n[+] Full coverage: every tool completed.\n")
		return b.String()
	}

	names := make([]string, 0, len(incomplete))
	for _, r := range incomplete {
		names = append(names, r.Tool)
	}
	fmt.Fprintf(&b, "\n[!] PARTIAL COVERAGE: %s did not deliver complete results.\n",
		strings.Join(names, ", "))
	b.WriteString("    Results from the other tools are valid and have been kept.\n")
	return b.String()
}

// PrintCloudCoverageSummary writes the coverage account to the terminal.
func PrintCloudCoverageSummary() {
	summary := CloudCoverageSummary(CloudResults())
	if summary == "" {
		return
	}
	utils.PrintSafe("%s", summary)
}

// captureLimit bounds how much tool output is held for classification.
//
// Only the tool's own complaints about its command line need to be seen, and
// those appear early. gcp-iam-brute alone emits thousands of lines, so an
// unbounded buffer would hold a scan's entire output in memory for no gain.
const captureLimit = 64 << 10

// cloudOutputCapture keeps the first captureLimit bytes a tool writes, across
// both streams, so the run can be classified from what the tool actually said.
type cloudOutputCapture struct {
	mu  sync.Mutex
	buf []byte
}

func newCloudOutputCapture() *cloudOutputCapture {
	return &cloudOutputCapture{buf: make([]byte, 0, 4096)}
}

// Write is an io.Writer that never fails and never blocks the tool. Output past
// the limit is dropped rather than buffered: reporting the write as short would
// make io.Copy stop draining the pipe and stall the tool.
func (c *cloudOutputCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if remaining := captureLimit - len(c.buf); remaining > 0 {
		if len(p) <= remaining {
			c.buf = append(c.buf, p...)
		} else {
			c.buf = append(c.buf, p[:remaining]...)
		}
	}
	return len(p), nil
}

func (c *cloudOutputCapture) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.buf)
}

// writeCloudRunRecord adds one cloud tool to the run record.
//
// The record is the repository's existing account of what a scan did, so cloud
// tools belong in it rather than in a second status system. The exit code is
// carried verbatim, including zero, and the outcome is carried alongside it
// because the code alone cannot say whether a scanner found problems, was denied
// a permission, or never ran.
func writeCloudRunRecord(result CloudToolResult, argv []string, startedAt time.Time) {
	entry := runrecord.Entry{
		Kind:      runrecord.KindTool,
		Name:      result.Tool,
		Argv:      argv,
		Artefact:  result.Artefact,
		StartedAt: &startedAt,
		Outcome:   string(result.Outcome),
	}

	switch result.Outcome {
	case OutcomeCompleted, OutcomeFindings, OutcomePartial:
		entry.Status = runrecord.StatusCompleted
	case OutcomeNotApplicable:
		entry.Status = runrecord.StatusSkipped
		entry.SkipReason = result.Detail
	default:
		entry.Status = runrecord.StatusFailed
		entry.Error = result.Detail
	}

	// A skip records no exit code because nothing ran; -1 means the process never
	// returned a status, which is not the same as exiting zero.
	if result.ExitCode >= 0 {
		code := result.ExitCode
		entry.ExitCode = &code
	}

	runrecord.Active.Write(entry)
}

// cloudSkipAlreadyRecorded reports whether this tool already has a skip on the
// record, so a prep function that explained its own reason is not overwritten by
// the generic one.
func cloudSkipAlreadyRecorded(tool string) bool {
	key := toolKey(tool)
	for _, r := range CloudResults() {
		if r.Tool == key && r.Outcome == OutcomeNotApplicable {
			return true
		}
	}
	return false
}
