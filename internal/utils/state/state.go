package state

import "sync"

// VisitedState provides thread-safe access to protocol visited flags.
// This prevents duplicate tool execution for the same protocol across different ports.
type VisitedState struct {
	mu      sync.RWMutex
	visited map[string]bool
}

// NewVisitedState creates a new VisitedState instance
func NewVisitedState() *VisitedState {
	return &VisitedState{
		visited: make(map[string]bool),
	}
}

// CheckAndMarkVisited atomically checks if a protocol was visited and marks it if not.
// Returns true if the protocol was already visited (caller should skip), false if this is the first visit.
func (v *VisitedState) CheckAndMarkVisited(protocol string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.visited[protocol] {
		return true
	}
	v.visited[protocol] = true
	return false
}

// Reset clears all visited flags (call between targets in multi-target mode)
func (v *VisitedState) Reset() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.visited = make(map[string]bool)
}

// IsVisited checks if a protocol has been visited (read-only)
func (v *VisitedState) IsVisited(protocol string) bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.visited[protocol]
}

// Global instance for backward compatibility
var globalVisitedState = NewVisitedState()

// IsVisited provides thread-safe access to check and mark protocol visited status
func IsVisited(protocol string) bool {
	return globalVisitedState.CheckAndMarkVisited(protocol)
}

// ResetVisitedFlags resets all visited flags (call between targets in multi-target mode)
func ResetVisitedFlags() {
	globalVisitedState.Reset()
}

// Deprecated: Legacy global variables for backwards compatibility
// These are maintained for compatibility but should use IsVisited() instead
var (
	VisitedSMTP  bool // Deprecated: use IsVisited("smtp")
	VisitedHTTP  bool // Deprecated: use IsVisited("http")
	VisitedIMAP  bool // Deprecated: use IsVisited("imap")
	VisitedSMB   bool // Deprecated: use IsVisited("smb")
	VisitedSNMP  bool // Deprecated: use IsVisited("snmp")
	VisitedLDAP  bool // Deprecated: use IsVisited("ldap")
	VisitedRsvc  bool // Deprecated: use IsVisited("rsvc")
	VisitedWinRM bool // Deprecated: use IsVisited("winrm")
	VisitedFTP   bool // Deprecated: use IsVisited("ftp")
)
