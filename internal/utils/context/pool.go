package context

import "sync"

// WorkerPool provides a semaphore-based limiter for concurrent tool execution.
// This prevents unbounded goroutine creation when scanning targets with many open ports.
type WorkerPool struct {
	sem chan struct{} // Semaphore to limit concurrency
	max int           // Maximum concurrent workers
}

// Global worker pool instance
var (
	workerPool     *WorkerPool
	workerPoolOnce sync.Once
)

// DefaultMaxWorkers is the default maximum concurrent tools (sensible for most systems)
const DefaultMaxWorkers = 20

// InitWorkerPool initialises the global worker pool with the specified max workers.
// If maxWorkers <= 0, uses DefaultMaxWorkers. Safe to call multiple times (only first call takes effect).
func InitWorkerPool(maxWorkers int) {
	workerPoolOnce.Do(func() {
		if maxWorkers <= 0 {
			maxWorkers = DefaultMaxWorkers
		}
		workerPool = &WorkerPool{
			sem: make(chan struct{}, maxWorkers),
			max: maxWorkers,
		}
	})
}

// GetWorkerPool returns the global worker pool, initializing with defaults if needed.
func GetWorkerPool() *WorkerPool {
	if workerPool == nil {
		InitWorkerPool(DefaultMaxWorkers)
	}
	return workerPool
}

// Acquire blocks until a worker slot is available, or returns false if shutdown is in progress.
func (wp *WorkerPool) Acquire() bool {
	if IsShuttingDown() {
		return false
	}
	select {
	case wp.sem <- struct{}{}:
		return true
	case <-GetGlobalContext().Done():
		return false
	}
}

// Release frees a worker slot. Must be called after Acquire() returns true.
func (wp *WorkerPool) Release() {
	<-wp.sem
}

// GetMaxWorkers returns the maximum number of concurrent workers configured.
func (wp *WorkerPool) GetMaxWorkers() int {
	return wp.max
}

// GetActiveWorkers returns the number of currently active workers.
func (wp *WorkerPool) GetActiveWorkers() int {
	return len(wp.sem)
}
