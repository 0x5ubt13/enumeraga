package utils

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

type ToolStatus string

const (
	ToolPending   ToolStatus = "pending"
	ToolRunning   ToolStatus = "running"
	ToolCompleted ToolStatus = "completed"
	ToolFailed    ToolStatus = "failed"
)

type ToolInfo struct {
	Name      string
	Status    ToolStatus
	StartTime time.Time
	EndTime   time.Time
}

type ToolTracker struct {
	mu     sync.RWMutex
	tools  map[string]*ToolInfo
	failed int
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

func (t *ToolTracker) CompleteTool(name string, success bool) (completed, total int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tool, exists := t.tools[name]; exists {
		if success {
			tool.Status = ToolCompleted
		} else {
			tool.Status = ToolFailed
			t.failed++
		}
		tool.EndTime = time.Now()
	}

	total = len(t.tools)
	for _, tool := range t.tools {
		if tool.Status == ToolCompleted || tool.Status == ToolFailed {
			completed++
		}
	}
	return completed, total
}

func (t *ToolTracker) GetProgress() (completed, total int) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	total = len(t.tools)
	for _, tool := range t.tools {
		if tool.Status == ToolCompleted || tool.Status == ToolFailed {
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

func (t *ToolTracker) PrintFinalSummary() {
	t.mu.RLock()
	defer t.mu.RUnlock()
	total := len(t.tools)
	successful := total - t.failed
	PrintCustomBiColourMsg("green", "cyan",
		fmt.Sprintf("\n[✓] All enumeration tools completed: %d total", total))
	PrintCustomBiColourMsg("green", "white",
		fmt.Sprintf("    Successful: %d | Failed: %d", successful, t.failed))
}
