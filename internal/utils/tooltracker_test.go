package utils

import (
	"strings"
	"testing"
)

// TestToolTrackerBasicFlow tests the basic tool tracking flow
func TestToolTrackerBasicFlow(t *testing.T) {
	tracker := NewToolTracker()

	// Register a few tools
	tracker.RegisterTool("nmap on port 80")
	tracker.RegisterTool("nikto on port 80")
	tracker.RegisterTool("wpscan on port 443")

	// Check total count
	if total := tracker.GetTotal(); total != 3 {
		t.Errorf("Expected 3 total tools, got %d", total)
	}

	// Check progress before any start
	completed, total := tracker.GetProgress()
	if completed != 0 || total != 3 {
		t.Errorf("Expected 0/3 progress, got %d/%d", completed, total)
	}

	// Start first tool
	tracker.StartTool("nmap on port 80")
	running := tracker.GetRunningTools()
	if len(running) != 1 || running[0] != "nmap on port 80" {
		t.Errorf("Expected 1 running tool 'nmap on port 80', got %v", running)
	}

	// Start second tool
	tracker.StartTool("nikto on port 80")
	running = tracker.GetRunningTools()
	if len(running) != 2 {
		t.Errorf("Expected 2 running tools, got %d", len(running))
	}

	// Complete first tool successfully
	tracker.CompleteTool("nmap on port 80", true)
	completed, total = tracker.GetProgress()
	if completed != 1 || total != 3 {
		t.Errorf("Expected 1/3 progress, got %d/%d", completed, total)
	}

	// Complete second tool with failure
	tracker.CompleteTool("nikto on port 80", false)
	completed, total = tracker.GetProgress()
	if completed != 2 || total != 3 {
		t.Errorf("Expected 2/3 progress, got %d/%d", completed, total)
	}

	// Start and complete third tool
	tracker.StartTool("wpscan on port 443")
	tracker.CompleteTool("wpscan on port 443", true)

	completed, total = tracker.GetProgress()
	if completed != 3 || total != 3 {
		t.Errorf("Expected 3/3 progress, got %d/%d", completed, total)
	}

	// Check no tools are running
	running = tracker.GetRunningTools()
	if len(running) != 0 {
		t.Errorf("Expected 0 running tools, got %d: %v", len(running), running)
	}

	// Check failed count
	if got := tracker.CountByStatus(ToolFailed); got != 1 {
		t.Errorf("Expected 1 failed tool, got %d", got)
	}
}

// TestToolTrackerGetRunningTools tests that running tools are returned in alphabetical order
func TestToolTrackerGetRunningTools(t *testing.T) {
	tracker := NewToolTracker()

	tools := []string{
		"zebra",
		"alpha",
		"charlie",
		"bravo",
	}

	for _, tool := range tools {
		tracker.RegisterTool(tool)
		tracker.StartTool(tool)
	}

	running := tracker.GetRunningTools()
	expected := []string{"alpha", "bravo", "charlie", "zebra"}

	if len(running) != len(expected) {
		t.Fatalf("Expected %d running tools, got %d", len(expected), len(running))
	}

	for i := range running {
		if running[i] != expected[i] {
			t.Errorf("Expected tool at position %d to be '%s', got '%s'", i, expected[i], running[i])
		}
	}
}

// TestToolTrackerConcurrency tests concurrent access to the tracker
func TestToolTrackerConcurrency(t *testing.T) {
	tracker := NewToolTracker()

	// Register multiple tools
	for i := 0; i < 10; i++ {
		tracker.RegisterTool(string(rune('A' + i)))
	}

	// Start all tools concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			tracker.StartTool(string(rune('A' + idx)))
			done <- true
		}(i)
	}

	// Wait for all to start
	for i := 0; i < 10; i++ {
		<-done
	}

	// Complete all tools concurrently
	for i := 0; i < 10; i++ {
		go func(idx int) {
			tracker.CompleteTool(string(rune('A'+idx)), true)
			done <- true
		}(i)
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify final state
	completed, total := tracker.GetProgress()
	if completed != 10 || total != 10 {
		t.Errorf("Expected 10/10 progress after concurrent operations, got %d/%d", completed, total)
	}
}

// TestToolTrackerStatuses tests that tool statuses are tracked correctly
func TestToolTrackerStatuses(t *testing.T) {
	tracker := NewToolTracker()

	tracker.RegisterTool("tool1")
	tracker.RegisterTool("tool2")
	tracker.RegisterTool("tool3")

	// Check pending status
	if tracker.tools["tool1"].Status != ToolPending {
		t.Errorf("Expected tool1 to be pending, got %s", tracker.tools["tool1"].Status)
	}

	// Check running status
	tracker.StartTool("tool1")
	if tracker.tools["tool1"].Status != ToolRunning {
		t.Errorf("Expected tool1 to be running, got %s", tracker.tools["tool1"].Status)
	}

	// Check completed status
	tracker.StartTool("tool2")
	tracker.CompleteTool("tool2", true)
	if tracker.tools["tool2"].Status != ToolCompleted {
		t.Errorf("Expected tool2 to be completed, got %s", tracker.tools["tool2"].Status)
	}

	// Check failed status
	tracker.StartTool("tool3")
	tracker.CompleteTool("tool3", false)
	if tracker.tools["tool3"].Status != ToolFailed {
		t.Errorf("Expected tool3 to be failed, got %s", tracker.tools["tool3"].Status)
	}
}

// TestToolTrackerSkip verifies a skipped tool is recorded with its reason,
// counts as finished for progress, and is not counted as a failure.
func TestToolTrackerSkip(t *testing.T) {
	tracker := NewToolTracker()
	tracker.RegisterTool("cmseek on port 443")
	tracker.RegisterTool("nmap on port 80")

	tracker.SkipTool("cmseek on port 443", "no throttle available")

	completed, total := tracker.GetProgress()
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if completed != 1 {
		t.Errorf("completed = %d, want 1 (a skipped tool is finished)", completed)
	}

	if got := tracker.CountByStatus(ToolSkipped); got != 1 {
		t.Errorf("skipped count = %d, want 1", got)
	}
	if got := tracker.CountByStatus(ToolFailed); got != 0 {
		t.Errorf("failed count = %d, want 0 (a skip is not a failure)", got)
	}
}

// TestToolTrackerCompleteToolDoesNotOverwriteSkip verifies that a completion
// reported after a skip cannot erase it. A caller that runs SkipTool and then
// unconditionally calls CompleteTool (as CallRunTool used to) must not be able
// to turn a skipped tool into a completed one.
func TestToolTrackerCompleteToolDoesNotOverwriteSkip(t *testing.T) {
	tracker := NewToolTracker()
	tracker.RegisterTool("cmseek on port 443")
	tracker.SkipTool("cmseek on port 443", "no throttle available")

	completed, total := tracker.CompleteTool("cmseek on port 443", true)

	if got := tracker.CountByStatus(ToolSkipped); got != 1 {
		t.Errorf("skipped count = %d, want 1: CompleteTool must not overwrite a skip", got)
	}
	if got := tracker.CountByStatus(ToolCompleted); got != 0 {
		t.Errorf("completed count = %d, want 0: CompleteTool must not overwrite a skip", got)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if completed != 1 {
		t.Errorf("completed = %d, want 1 (the skipped tool still counts as finished)", completed)
	}
}

// TestToolTrackerSkipRegistersUnknownTool verifies a tool skipped before it was
// ever registered is still recorded, so counts stay right for the tools that
// bypass CallRunTool.
func TestToolTrackerSkipRegistersUnknownTool(t *testing.T) {
	tracker := NewToolTracker()
	tracker.SkipTool("braa on port 161", "no throttle available")

	if got := tracker.GetTotal(); got != 1 {
		t.Errorf("total = %d, want 1", got)
	}
	if got := tracker.CountByStatus(ToolSkipped); got != 1 {
		t.Errorf("skipped count = %d, want 1", got)
	}
}

// TestToolTrackerSkipDoesNotAppearAsRunning verifies a skipped tool never shows
// up in the "still running" list.
func TestToolTrackerSkipDoesNotAppearAsRunning(t *testing.T) {
	tracker := NewToolTracker()
	tracker.RegisterTool("cewl on port 80")
	tracker.StartTool("cewl on port 80")
	tracker.SkipTool("cewl on port 80", "no throttle available")

	if running := tracker.GetRunningTools(); len(running) != 0 {
		t.Errorf("running = %v, want empty", running)
	}
}

// TestToolTrackerNoteRate verifies rate notes are recorded against the tool.
func TestToolTrackerNoteRate(t *testing.T) {
	tracker := NewToolTracker()
	tracker.RegisterTool("ffuf on port 80")
	tracker.NoteRate("ffuf on port 80", "rate-capped")

	if got := tracker.RateNoteFor("ffuf on port 80"); got != "rate-capped" {
		t.Errorf("RateNoteFor() = %q, want %q", got, "rate-capped")
	}
}

// TestToolTrackerSummarySeparatesSkipReasons verifies that tools skipped for
// different reasons are reported under their own line, each naming only the
// tools that hit that reason. Before this test, PrintFinalSummary hardcoded a
// single label ("no throttle available") for every skip, so a tool skipped
// for a shutdown was misreported as though it lacked a rate cap.
func TestToolTrackerSummarySeparatesSkipReasons(t *testing.T) {
	tracker := NewToolTracker()
	tracker.RegisterTool("cmseek on port 443")
	tracker.RegisterTool("nikto on port 80")

	tracker.SkipTool("cmseek on port 443", "no throttle available")
	tracker.SkipTool("nikto on port 80", "scan shutting down before this tool could start")

	c := tracker.buildSummary()

	if c.skipped != 2 {
		t.Fatalf("skipped = %d, want 2", c.skipped)
	}
	if len(c.skipLines) != 2 {
		t.Fatalf("skipLines = %v, want 2 distinct lines", c.skipLines)
	}

	wantThrottle := "Skipped (no throttle available): cmseek on port 443"
	wantShutdown := "Skipped (scan shutting down before this tool could start): nikto on port 80"

	foundThrottle, foundShutdown := false, false
	for _, line := range c.skipLines {
		switch line {
		case wantThrottle:
			foundThrottle = true
		case wantShutdown:
			foundShutdown = true
		default:
			t.Errorf("unexpected skip line: %q", line)
		}
	}
	if !foundThrottle {
		t.Errorf("skipLines = %v, missing %q", c.skipLines, wantThrottle)
	}
	if !foundShutdown {
		t.Errorf("skipLines = %v, missing %q", c.skipLines, wantShutdown)
	}

	// The two reasons must not bleed into each other's line.
	for _, line := range c.skipLines {
		if strings.Contains(line, "cmseek") && strings.Contains(line, "nikto") {
			t.Errorf("a single skip line named both tools: %q", line)
		}
	}
}

// TestToolTrackerSummaryFallsBackForEmptySkipReason verifies a skip recorded
// with no reason string is still reported, rather than silently dropped from
// the grouped output.
func TestToolTrackerSummaryFallsBackForEmptySkipReason(t *testing.T) {
	tracker := NewToolTracker()
	tracker.RegisterTool("responder on port 445")
	tracker.SkipTool("responder on port 445", "")

	c := tracker.buildSummary()

	if len(c.skipLines) != 1 {
		t.Fatalf("skipLines = %v, want 1 line", c.skipLines)
	}
	if !strings.Contains(c.skipLines[0], "responder on port 445") {
		t.Errorf("skipLines[0] = %q, want it to name the tool", c.skipLines[0])
	}
}

// BenchmarkToolTrackerOperations benchmarks common tracker operations
func BenchmarkToolTrackerOperations(b *testing.B) {
	tracker := NewToolTracker()

	// Pre-register some tools
	for i := 0; i < 100; i++ {
		tracker.RegisterTool(string(rune('A' + (i % 26))))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tracker.GetProgress()
		tracker.GetRunningTools()
		tracker.GetTotal()
	}
}

// TestToolTrackerNoteRateIgnoresUnknownTools verifies NoteRate is annotate-only.
// It used to register any name it did not recognise, creating a ToolInfo with no
// status at all: buildSummary counts such an entry as neither failed nor skipped,
// so "successful = total - failed - skipped" reported a tool that never ran as a
// success, while the inflated total stopped progress ever reaching 100%.
func TestToolTrackerNoteRateIgnoresUnknownTools(t *testing.T) {
	tracker := NewToolTracker()
	tracker.NoteRate("cewl on port 80", "unthrottled")

	if got := tracker.GetTotal(); got != 0 {
		t.Errorf("GetTotal() = %d, want 0: a rate note must not invent a tool", got)
	}
	if got := tracker.RateNoteFor("cewl on port 80"); got != "" {
		t.Errorf("RateNoteFor() = %q, want an empty string", got)
	}

	c := tracker.buildSummary()
	successful := c.total - c.failed - c.skipped
	if successful != 0 {
		t.Errorf("successful = %d, want 0: an unregistered tool must not appear as a success", successful)
	}
}

// TestToolTrackerSkipStillRegistersUnknownTools guards the deliberate asymmetry
// with NoteRate: a skip is a fact about the run and must be counted even for the
// tools that are launched without going through CallRunTool.
func TestToolTrackerSkipStillRegistersUnknownTools(t *testing.T) {
	tracker := NewToolTracker()
	tracker.SkipTool("msfconsole on port 445", "no throttle available")

	if got := tracker.GetTotal(); got != 1 {
		t.Errorf("GetTotal() = %d, want 1: a skip must be counted even for an unregistered tool", got)
	}
	if got := tracker.CountByStatus(ToolSkipped); got != 1 {
		t.Errorf("skipped count = %d, want 1", got)
	}
}
