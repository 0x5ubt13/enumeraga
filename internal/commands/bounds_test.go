package commands

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

func TestRegistryName(t *testing.T) {
	if got := registryName("nikto", "443"); got != "nikto on port 443" {
		t.Errorf("registryName() = %q, want %q", got, "nikto on port 443")
	}
	if got := registryName("fping", ""); got != "fping" {
		t.Errorf("registryName() = %q, want %q", got, "fping")
	}
}

// TestRunToolSkipsUnthrottledToolUnderRateCap verifies that a tool with no
// throttle is not executed when a rate cap is in force, and is recorded as
// skipped rather than silently disappearing.
func TestRunToolSkipsUnthrottledToolUnderRateCap(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	b, err := bounds.Validate(bounds.Config{Rate: 5})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	utils.ToolRegistry = utils.NewToolTracker()
	name := registryName("cmseek", "443")
	utils.ToolRegistry.RegisterTool(name)

	// /nonexistent is never created: if runTool executed the tool it would fail
	// trying to write there, so the sentinel error proves it returned before
	// running rather than having failed partway through.
	err = runTool([]string{"cmseek", "-u", "http://example.invalid"},
		"/nonexistent/cmseek_443.out", "443", boolPtr(false))
	if !errors.Is(err, errToolSkipped) {
		t.Fatalf("runTool() error = %v, want errToolSkipped", err)
	}

	if got := utils.ToolRegistry.CountByStatus(utils.ToolSkipped); got != 1 {
		t.Errorf("skipped count = %d, want 1", got)
	}
}

// TestRunToolRecordsRateNote verifies the class note is recorded so the summary
// can distinguish rate-capped tools from merely thread-capped ones.
func TestRunToolRecordsRateNote(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	b, err := bounds.Validate(bounds.Config{Rate: 5})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	utils.ToolRegistry = utils.NewToolTracker()
	name := registryName("cmseek", "443")
	utils.ToolRegistry.RegisterTool(name)

	_ = runTool([]string{"cmseek", "-u", "http://example.invalid"},
		"/nonexistent/cmseek_443.out", "443", boolPtr(false))

	if got := utils.ToolRegistry.RateNoteFor(name); got != bounds.RateUnthrottled.Note() {
		t.Errorf("RateNoteFor() = %q, want %q", got, bounds.RateUnthrottled.Note())
	}
}

// TestCallRunToolSkipIsNotReportedAsSuccess is a regression test for a defect
// where CallRunTool called CompleteTool unconditionally after runTool
// returned, overwriting a recorded skip with ToolCompleted and printing a
// success message for a tool that never ran. It exercises CallRunTool itself
// (not runTool directly), since that overwrite only happened on this path.
func TestCallRunToolSkipIsNotReportedAsSuccess(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	b, err := bounds.Validate(bounds.Config{Rate: 5})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	utils.ToolRegistry = utils.NewToolTracker()
	utils.InitWorkerPool(3)

	verbose := boolPtr(false)
	CallRunTool([]string{"cmseek", "-u", "http://example.invalid"},
		"/nonexistent/cmseek_443.out", verbose)
	utils.Wg.Wait()

	name := registryName("cmseek", "443")
	if got := utils.ToolRegistry.RateNoteFor(name); got != bounds.RateUnthrottled.Note() {
		t.Errorf("RateNoteFor() = %q, want %q", got, bounds.RateUnthrottled.Note())
	}
	if got := utils.ToolRegistry.CountByStatus(utils.ToolSkipped); got != 1 {
		t.Errorf("skipped count = %d, want 1: a skip must survive CallRunTool's completion bookkeeping", got)
	}
	if got := utils.ToolRegistry.CountByStatus(utils.ToolCompleted); got != 0 {
		t.Errorf("completed count = %d, want 0: a skipped tool must never be reported as completed", got)
	}
}

func boolPtr(b bool) *bool { return &b }

// TestAggressiveScanOmits1337WhenBounded verifies the extra fingerprinting port
// is not probed under a bounded run. It is the one place enumeraga would
// otherwise touch a port the caller never authorised.
func TestAggressiveScanOmits1337WhenBounded(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	b, err := bounds.Validate(bounds.Config{Ports: "80,443"})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	if got := aggressiveScanPorts("80,443"); got != "80,443" {
		t.Errorf("aggressiveScanPorts() = %q, want exactly the open set %q", got, "80,443")
	}
}

// TestAggressiveScanKeeps1337WhenUnbounded verifies the long-standing OS
// fingerprinting behaviour is untouched for callers who pass no bounds.
func TestAggressiveScanKeeps1337WhenUnbounded(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	b, err := bounds.Validate(bounds.Config{})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	if got := aggressiveScanPorts("80,443"); got != "80,443,1337" {
		t.Errorf("aggressiveScanPorts() = %q, want %q", got, "80,443,1337")
	}
}

// TestAggressiveScanExcludesUDPOnlyPorts is a regression test for the worst
// defect in this feature: the open-port list handed to the aggressive scan merges
// the TCP and UDP sweep results with no protocol tag, and the scan itself is TCP,
// so --ports 80,U:53 with UDP 53 open used to SYN-probe TCP 53 — a port and
// protocol pair the caller never authorised.
func TestAggressiveScanExcludesUDPOnlyPorts(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	b, err := bounds.Validate(bounds.Config{Ports: "80,U:53"})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	// "80,53" is what GetOpenPortsSlice produces from TCP 80 plus UDP 53.
	if got := aggressiveScanPorts("80,53"); got != "80" {
		t.Errorf("aggressiveScanPorts(%q) = %q, want %q: UDP 53 must not be scanned over TCP", "80,53", got, "80")
	}
}

// TestAggressiveScanEmptyForUDPOnlyPortList verifies the correct outcome for a
// port list with no TCP entries at all: no TCP aggressive scan exists to run, so
// the port string is empty and CallFullAggressiveScan records a skip rather than
// handing nmap an empty -p and letting it choose its own ports.
func TestAggressiveScanEmptyForUDPOnlyPortList(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	b, err := bounds.Validate(bounds.Config{Ports: "U:53"})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	if got := aggressiveScanPorts("53"); got != "" {
		t.Errorf("aggressiveScanPorts(%q) = %q, want an empty string", "53", got)
	}

	utils.ToolRegistry = utils.NewToolTracker()
	CallFullAggressiveScan("example.invalid", "53", filepath.Join(t.TempDir(), "aggressive"), boolPtr(false))
	utils.Wg.Wait()

	if got := utils.ToolRegistry.CountByStatus(utils.ToolSkipped); got != 1 {
		t.Errorf("skipped count = %d, want 1: the omitted scan must be reported, not dropped silently", got)
	}
	if got := utils.ToolRegistry.CountByStatus(utils.ToolCompleted); got != 0 {
		t.Errorf("completed count = %d, want 0: a scan that never ran must not be reported as having run", got)
	}
}

// TestDirsearchThreadsAreNotRaisedByAHighRate covers the direction existing tests
// missed: every rate in them was low enough that min(rate, concurrency) happened
// to be below the value dirsearch already carries. At --rate 50 the cap is higher,
// and applying it outright turned the launch site's -t 10 into -t 50, making a
// bounded run more aggressive than an unbounded one.
func TestDirsearchThreadsAreNotRaisedByAHighRate(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	b, err := bounds.Validate(bounds.Config{Rate: 50})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	// The real launch site from internal/portsIterator/protocols/web.go.
	args := []string{"dirsearch", "-t", "10", "-u", "https://example.invalid:443",
		"-o", "/tmp/dirsearch_443.out", "--max-time", "600", "--quiet"}

	result := activeBounds().ApplyRate(args)
	if result.Skip {
		t.Fatalf("dirsearch skipped unexpectedly: %s", result.Reason)
	}

	for i := 0; i < len(result.Args)-1; i++ {
		if result.Args[i] == "-t" {
			if result.Args[i+1] != "10" {
				t.Fatalf("dirsearch -t = %q under --rate 50, want it left at %q", result.Args[i+1], "10")
			}
			return
		}
	}
	t.Fatalf("-t not present in %v", result.Args)
}

// TestRunToolDoesNotInventTrackerEntries is a regression test for a defect that
// bit callers passing no bounds at all. runTool annotated every tool it ran with
// a rate note, and NoteRate registered any name it did not recognise; the three
// call sites that reach runTool without RegisterTool (cewl and ffuf under -b,
// msfconsole under -r) therefore each produced a tracker entry with no terminal
// status, which buildSummary counts as a successful tool and which inflates the
// total so progress can never reach 100%.
func TestRunToolDoesNotInventTrackerEntries(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	// A rate cap is in force, so the note would be recorded if it were going to be.
	b, err := bounds.Validate(bounds.Config{Rate: 5})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	utils.ToolRegistry = utils.NewToolTracker()

	// ffuf is rate-flagged, so it is not skipped; the unwritable output path is
	// what stops it before anything is executed.
	_ = runTool([]string{"ffuf", "-u", "http://example.invalid/FUZZ", "-w", "/dev/null"},
		"/nonexistent/ffuf_keywords_80.out", "80", boolPtr(false))

	if got := utils.ToolRegistry.GetTotal(); got != 0 {
		t.Errorf("GetTotal() = %d, want 0: runTool must not invent an entry for a tool nobody registered", got)
	}
}

// TestUnboundedRunFiguresAreUnaffected is the inertness assertion for the summary
// figures: with no bounds at all, the unregistered cewl and ffuf calls made by
// the -b path must leave the totals of the tools that were registered alone.
func TestUnboundedRunFiguresAreUnaffected(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	b, err := bounds.Validate(bounds.Config{})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	utils.ToolRegistry = utils.NewToolTracker()
	utils.ToolRegistry.RegisterTool("nmap on port 80")
	utils.ToolRegistry.RegisterTool("nikto on port 80")
	utils.ToolRegistry.CompleteTool("nmap on port 80", true)
	utils.ToolRegistry.CompleteTool("nikto on port 80", true)

	// The two unregistered launches from runCewlAndFfuf, exactly as the -b path
	// makes them.
	_ = runTool([]string{"cewl", "-m7", "--lowercase", "-w", "/dev/null", "http://example.invalid"},
		"/nonexistent/cewl_80.out", "80", boolPtr(false))
	_ = runTool([]string{"ffuf", "-w", "/dev/null", "-u", "http://example.invalid/FUZZ"},
		"/nonexistent/ffuf_keywords_80.out", "80", boolPtr(false))

	if got := utils.ToolRegistry.GetTotal(); got != 2 {
		t.Errorf("GetTotal() = %d, want 2: an unbounded run's total must count only the registered tools", got)
	}
	if got := utils.ToolRegistry.CountByStatus(utils.ToolCompleted); got != 2 {
		t.Errorf("completed count = %d, want 2", got)
	}
	completed, total := utils.ToolRegistry.GetProgress()
	if completed != 2 || total != 2 {
		t.Errorf("GetProgress() = (%d, %d), want (2, 2): phantom entries stop progress reaching 100%%", completed, total)
	}
	// successful, as PrintFinalSummary computes it: total - failed - skipped.
	successful := total - utils.ToolRegistry.CountByStatus(utils.ToolFailed) -
		utils.ToolRegistry.CountByStatus(utils.ToolSkipped)
	if successful != 2 {
		t.Errorf("successful = %d, want 2", successful)
	}
}

// TestBudgetExpiryRecordsSkipsNotFailures verifies that a wall-clock stop reports
// the tools it prevented from starting as skipped. The deadline does not set the
// shutdown flag, so runTool's skip-on-shutdown path never fires on a timeout;
// instead the worker pool refuses a slot, and both branches that handle that used
// to record a failure. A clean --max-runtime stop then printed a long list of
// failures immediately above "results are partial but valid".
func TestBudgetExpiryRecordsSkipsNotFailures(t *testing.T) {
	originalBounds := bounds.Active
	defer func() { bounds.Active = originalBounds }()
	b, err := bounds.Validate(bounds.Config{MaxRuntimeSeconds: 1})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	utils.ToolRegistry = utils.NewToolTracker()

	// Fill the pool so the next Acquire has no slot to take and has to consult the
	// global context, which is how a stopped run refuses work.
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

	// A budget that has already expired. The deferred re-initialisation restores an
	// unexpired global context for the rest of the package's tests.
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

	verbose := boolPtr(false)
	CallRunTool([]string{"nikto", "-host", "http://example.invalid"},
		filepath.Join(t.TempDir(), "nikto_80.out"), verbose)
	CallIndividualPortScanner("example.invalid", "80",
		filepath.Join(t.TempDir(), "nmap_scan_80"), verbose)
	utils.Wg.Wait()

	if got := utils.ToolRegistry.CountByStatus(utils.ToolSkipped); got != 2 {
		t.Errorf("skipped count = %d, want 2 (one per branch: CallRunTool and runNmapScanAsync)", got)
	}
	if got := utils.ToolRegistry.CountByStatus(utils.ToolFailed); got != 0 {
		t.Errorf("failed count = %d, want 0: a clean stop at the wall-clock budget is not a failure", got)
	}
}

// TestNoRateNoteWithoutARateCap verifies the summary does not claim a cap that was
// never asked for. runTool recorded the class note for every tool it ran, and
// PrintFinalSummary prints the note lines whenever any bound is in force, so
// --ports 80,443 on its own produced "rate-capped: ffuf on port 80" when no rate
// had been requested and none had been applied.
func TestNoRateNoteWithoutARateCap(t *testing.T) {
	original := bounds.Active
	defer func() { bounds.Active = original }()

	// A bounded run, but bounded by ports only.
	b, err := bounds.Validate(bounds.Config{Ports: "80,443"})
	if err != nil {
		t.Fatalf("Validate returned an error: %v", err)
	}
	bounds.Active = b

	utils.ToolRegistry = utils.NewToolTracker()
	name := registryName("ffuf", "80")
	utils.ToolRegistry.RegisterTool(name)

	_ = runTool([]string{"ffuf", "-u", "http://example.invalid/FUZZ", "-w", "/dev/null"},
		"/nonexistent/ffuf_80.out", "80", boolPtr(false))

	if got := utils.ToolRegistry.RateNoteFor(name); got != "" {
		t.Errorf("RateNoteFor() = %q, want an empty string: no --rate was supplied, so nothing was rate-capped", got)
	}
}
