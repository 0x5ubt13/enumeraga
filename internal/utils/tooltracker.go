package utils

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type ToolStatus string

const (
	ToolPending   ToolStatus = "pending"
	ToolRunning   ToolStatus = "running"
	ToolCompleted ToolStatus = "completed"
	ToolFailed    ToolStatus = "failed"

	// ToolSkipped marks a tool that was deliberately not run, for example
	// because it has no way to honour a rate cap. It is finished but not failed.
	ToolSkipped ToolStatus = "skipped"
)

type ToolInfo struct {
	Name      string
	Status    ToolStatus
	StartTime time.Time
	EndTime   time.Time

	// SkipReason explains why a tool was not run. Set only when Status is ToolSkipped.
	SkipReason string

	// RateNote records how a rate cap applied to this tool, so the summary can
	// distinguish traffic that was genuinely rate-capped from traffic that was
	// only held to a thread count.
	RateNote string
}

type ToolTracker struct {
	mu    sync.RWMutex
	tools map[string]*ToolInfo
}

func NewToolTracker() *ToolTracker {
	return &ToolTracker{
		tools: make(map[string]*ToolInfo),
	}
}

func (t *ToolTracker) RegisterTool(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tools[name] = &ToolInfo{
		Name:   name,
		Status: ToolPending,
	}
}

func (t *ToolTracker) StartTool(name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tool, exists := t.tools[name]; exists {
		tool.Status = ToolRunning
		tool.StartTime = time.Now()
	}
}

// isFinished reports whether a tool has reached a terminal state. A skipped tool
// is finished: it will not run, so leaving it pending would stall progress at
// less than 100% for the rest of the scan.
func isFinished(status ToolStatus) bool {
	return status == ToolCompleted || status == ToolFailed || status == ToolSkipped
}

func (t *ToolTracker) CompleteTool(name string, success bool) (completed, total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tool, exists := t.tools[name]; exists {
		// A skip is terminal: never let a completion overwrite it. Without this,
		// a caller that reports success after a skipped tool returned would
		// erase the skip and claim coverage that never happened.
		if tool.Status == ToolSkipped {
			return t.progressLocked()
		}
		if success {
			tool.Status = ToolCompleted
		} else {
			tool.Status = ToolFailed
		}
		tool.EndTime = time.Now()
	}

	return t.progressLocked()
}

// progressLocked counts finished and total tools. Callers must hold t.mu.
func (t *ToolTracker) progressLocked() (completed, total int) {
	total = len(t.tools)
	for _, tool := range t.tools {
		if isFinished(tool.Status) {
			completed++
		}
	}
	return completed, total
}

// SkipTool records that a tool was deliberately not run, with the reason.
// The tool is registered if it was not already: some tools are launched without
// going through CallRunTool, and their skips must still be counted.
func (t *ToolTracker) SkipTool(name, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tool, exists := t.tools[name]
	if !exists {
		tool = &ToolInfo{Name: name}
		t.tools[name] = tool
	}
	tool.Status = ToolSkipped
	tool.SkipReason = reason
	tool.EndTime = time.Now()
}

// NoteRate records how a rate cap applied to a tool, for the summary block.
//
// It is annotate-only: an unknown name is ignored rather than registered. This
// is the opposite of SkipTool, deliberately. A skip is a fact about the run that
// must be counted even for the tools launched outside CallRunTool, whereas a
// rate note is only an annotation on a tool the tracker already knows about.
// Creating an entry here would invent a tool with no terminal status, which
// buildSummary counts as neither failed nor skipped and therefore reports as a
// successful tool that never ran — while also inflating the total so progress
// could never reach 100%.
func (t *ToolTracker) NoteRate(name, note string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if tool, exists := t.tools[name]; exists {
		tool.RateNote = note
	}
}

// RateNoteFor returns the rate note recorded for a tool, or an empty string.
func (t *ToolTracker) RateNoteFor(name string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if tool, exists := t.tools[name]; exists {
		return tool.RateNote
	}
	return ""
}

// CountByStatus returns how many tools are in the given status.
func (t *ToolTracker) CountByStatus(status ToolStatus) int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := 0
	for _, tool := range t.tools {
		if tool.Status == status {
			n++
		}
	}
	return n
}

func (t *ToolTracker) GetProgress() (completed, total int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	total = len(t.tools)
	for _, tool := range t.tools {
		if isFinished(tool.Status) {
			completed++
		}
	}
	return
}

func (t *ToolTracker) GetRunningTools() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	running := []string{}
	for _, tool := range t.tools {
		if tool.Status == ToolRunning {
			running = append(running, tool.Name)
		}
	}
	sort.Strings(running)
	return running
}

func (t *ToolTracker) GetTotal() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.tools)
}

// unreasonedSkip labels a skip recorded with no reason string, so the summary
// still reports it rather than dropping it from the grouping silently.
const unreasonedSkip = "no reason recorded"

// groupedLines turns a label-to-names map into deterministic "label: names"
// lines: labels sorted, and names sorted within each label. This is the one
// grouping path the summary uses, for both the rate-note block and the
// skip-reason block, so the two stay in step rather than drifting apart.
func groupedLines(groups map[string][]string, format string) []string {
	labels := make([]string, 0, len(groups))
	for label := range groups {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	lines := make([]string, 0, len(labels))
	for _, label := range labels {
		names := append([]string(nil), groups[label]...)
		sort.Strings(names)
		lines = append(lines, fmt.Sprintf(format, label, strings.Join(names, ", ")))
	}
	return lines
}

// summaryCounts holds the figures and grouped lines PrintFinalSummary renders,
// gathered under a single lock so the report reflects one consistent snapshot.
type summaryCounts struct {
	total, failed, skipped int
	noteLines, skipLines   []string
}

// buildSummary gathers the counts and grouped lines for the final summary. It
// is kept separate from PrintFinalSummary so the line-building logic can be
// tested directly, without capturing stdout.
func (t *ToolTracker) buildSummary() summaryCounts {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var c summaryCounts
	c.total = len(t.tools)

	notes := make(map[string][]string)
	skipGroups := make(map[string][]string)

	for _, tool := range t.tools {
		switch tool.Status {
		case ToolFailed:
			c.failed++
		case ToolSkipped:
			c.skipped++
			reason := tool.SkipReason
			if reason == "" {
				reason = unreasonedSkip
			}
			skipGroups[reason] = append(skipGroups[reason], tool.Name)
		}
		if tool.RateNote != "" && tool.Status != ToolSkipped {
			notes[tool.RateNote] = append(notes[tool.RateNote], tool.Name)
		}
	}

	c.noteLines = groupedLines(notes, "%s: %s")
	c.skipLines = groupedLines(skipGroups, "Skipped (%s): %s")

	return c
}

// PrintFinalSummary prints the run summary.
//
// boundsLine, when non-empty, is printed as the bounds block. It arrives
// pre-formatted so this package need not import the bounds package.
func (t *ToolTracker) PrintFinalSummary(boundsLine string) {
	c := t.buildSummary()
	successful := c.total - c.failed - c.skipped

	PrintCustomBiColourMsg("green", "cyan",
		fmt.Sprintf("\n[✓] All enumeration tools completed: %d total", c.total))
	PrintCustomBiColourMsg("green", "white",
		fmt.Sprintf("    Successful: %d | Failed: %d | Skipped: %d", successful, c.failed, c.skipped))

	if boundsLine == "" {
		return
	}
	PrintCustomBiColourMsg("cyan", "white", "    Bounds honoured: "+boundsLine)

	for _, line := range c.noteLines {
		PrintCustomBiColourMsg("cyan", "white", "    "+line)
	}
	for _, line := range c.skipLines {
		PrintCustomBiColourMsg("yellow", "white", "    "+line)
	}
}
