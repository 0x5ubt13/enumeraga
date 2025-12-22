package utils

import (
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
	if tracker.failed != 1 {
		t.Errorf("Expected 1 failed tool, got %d", tracker.failed)
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
