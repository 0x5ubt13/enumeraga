package common

import (
	"fmt"
	"strconv"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// ProgressTracker manages scan progress reporting with tickers
type ProgressTracker struct {
	ticker   *time.Ticker
	done     chan bool
	interval time.Duration
}

// NewProgressTracker creates a new progress tracker
func NewProgressTracker(interval time.Duration) *ProgressTracker {
	return &ProgressTracker{
		ticker:   time.NewTicker(interval),
		done:     make(chan bool, 1), // Buffered to prevent leak
		interval: interval,
	}
}

// start is the core loop: calls buildMsg on each tick and prints it.
// When done is signalled, the goroutine exits.
func (pt *ProgressTracker) start(buildMsg func(t time.Time) string, optVVerbose *bool) {
	go func() {
		for {
			select {
			case t := <-pt.ticker.C:
				utils.PrintCustomBiColourMsg("cyan", "yellow", buildMsg(t))
				if *optVVerbose {
					fmt.Println(utils.Debug(t))
				}
			case <-pt.done:
				return
			}
		}
	}()
}

// startWithCounter is like start but passes a monotonically increasing tick
// count to buildMsg, useful for minute-elapsed displays.
func (pt *ProgressTracker) startWithCounter(buildMsg func(lapsed int) string, optVVerbose *bool) {
	lapsed := 0
	go func() {
		for {
			select {
			case t := <-pt.ticker.C:
				if *optVVerbose {
					fmt.Println(utils.Debug("Very verbose - ticker.C contents:", t))
				}
				lapsed++
				utils.PrintCustomBiColourMsg("cyan", "yellow", buildMsg(lapsed))
			case <-pt.done:
				return
			}
		}
	}()
}

// minutePhrase returns "1 minute" or "N minutes" for a given tick count.
func minutePhrase(lapsed int) (string, string) {
	if lapsed == 1 {
		return "1", "minute"
	}
	return strconv.Itoa(lapsed), "minutes"
}

// StartNSEProgress starts progress reporting for NSE scans
func (pt *ProgressTracker) StartNSEProgress(target, port string, optVVerbose *bool) {
	pt.start(func(_ time.Time) string {
		return fmt.Sprintf("[*] Individual protocol nmap scan with NSE Scripts still running against port(s) '%s' on target '%s'. Please wait...", port, target)
	}, optVVerbose)
}

// StartNSEArgsProgress starts progress reporting for NSE scans with args
func (pt *ProgressTracker) StartNSEArgsProgress(target, port string, optVVerbose *bool) {
	pt.start(func(_ time.Time) string {
		return fmt.Sprintf("[*] Individual protocol nmap scan with NSE scripts and args still running against port(s) '%s' on target '%s'. Please wait...", port, target)
	}, optVVerbose)
}

// StartUDPNSEProgress starts progress reporting for UDP NSE scans
func (pt *ProgressTracker) StartUDPNSEProgress(target, port string, optVVerbose *bool) {
	pt.start(func(_ time.Time) string {
		return fmt.Sprintf("[*] Individual protocol nmap scan on UDP with NSE scripts still running against port(s) '%s' on target '%s'. Please wait...", port, target)
	}, optVVerbose)
}

// StartMinuteProgress starts progress reporting with minute counter
func (pt *ProgressTracker) StartMinuteProgress(target, port string, optVVerbose *bool, messagePrefix string) {
	pt.startWithCounter(func(lapsed int) string {
		n, unit := minutePhrase(lapsed)
		return fmt.Sprintf("[*] %s still running against port(s) '%s' on target '%s'. Time lapsed: '%s' %s. Please wait...", messagePrefix, port, target, n, unit)
	}, optVVerbose)
}

// StartAggressiveProgress starts progress for aggressive scans
func (pt *ProgressTracker) StartAggressiveProgress(target string, optVVerbose *bool) {
	pt.startWithCounter(func(lapsed int) string {
		n, unit := minutePhrase(lapsed)
		return fmt.Sprintf("[*] Main nmap scan still running against all open ports on target '%s'. Time lapsed: '%s' %s. Please wait...", target, n, unit)
	}, optVVerbose)
}

// Stop stops the progress tracker
func (pt *ProgressTracker) Stop() {
	pt.ticker.Stop()
	select {
	case pt.done <- true:
	default:
		// Goroutine already exited
	}
}
