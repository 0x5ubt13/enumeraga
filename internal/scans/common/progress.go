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

// StartNSEProgress starts progress reporting for NSE scans
func (pt *ProgressTracker) StartNSEProgress(target, port string, optVVerbose *bool) {
	go func() {
		for {
			select {
			case t := <-pt.ticker.C:
				utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan with NSE Scripts still running against port(s) '", port, "' on target '", target, "'. Please wait...")
				if *optVVerbose {
					fmt.Println(utils.Debug(t))
				}
			case <-pt.done:
				return
			}
		}
	}()
}

// StartNSEArgsProgress starts progress reporting for NSE scans with args
func (pt *ProgressTracker) StartNSEArgsProgress(target, port string, optVVerbose *bool) {
	go func() {
		for {
			select {
			case t := <-pt.ticker.C:
				utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan with NSE scripts and args still running against port(s) '", port, "' on target '", target, "'. Please wait...")
				if *optVVerbose {
					fmt.Println(utils.Debug(t))
				}
			case <-pt.done:
				return
			}
		}
	}()
}

// StartUDPNSEProgress starts progress reporting for UDP NSE scans
func (pt *ProgressTracker) StartUDPNSEProgress(target, port string, optVVerbose *bool) {
	go func() {
		for {
			select {
			case t := <-pt.ticker.C:
				utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan on UDP with NSE scripts still running against port(s) '", port, "' on target '", target, "'. Please wait...")
				if *optVVerbose {
					fmt.Println(utils.Debug(t))
				}
			case <-pt.done:
				return
			}
		}
	}()
}

// StartMinuteProgress starts progress reporting with minute counter
func (pt *ProgressTracker) StartMinuteProgress(target, port string, optVVerbose *bool, messagePrefix string) {
	lapsed := 0
	go func() {
		for {
			select {
			case t := <-pt.ticker.C:
				if *optVVerbose {
					fmt.Println(utils.Debug("Very verbose - ticker.C contents:", t))
				}

				lapsed++
				timeStr := "1"
				unit := "minute"
				if lapsed > 1 {
					timeStr = strconv.Itoa(lapsed)
					unit = "minutes"
				}

				utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] "+messagePrefix+" still running against port(s) '", port, "' on target '", target, "'. Time lapsed: '", timeStr, "' "+unit+". Please wait...")
			case <-pt.done:
				return
			}
		}
	}()
}

// StartAggressiveProgress starts progress for aggressive scans
func (pt *ProgressTracker) StartAggressiveProgress(target string, optVVerbose *bool) {
	lapsed := 0
	go func() {
		for {
			select {
			case t := <-pt.ticker.C:
				if *optVVerbose {
					fmt.Println(utils.Debug("Very verbose - ticker.C contents:", t))
				}

				lapsed++
				timeStr := "1"
				unit := "minute"
				if lapsed > 1 {
					timeStr = strconv.Itoa(lapsed)
					unit = "minutes"
				}

				utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Main nmap scan still running against all open ports on target '", target, "'. Time lapsed: '", timeStr, "' "+unit+". Please wait...")
			case <-pt.done:
				return
			}
		}
	}()
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
