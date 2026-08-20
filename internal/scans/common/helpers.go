package common

import (
	"context"
	"strings"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/Ullaakut/nmap/v3"
)

// ScanDefaults holds common scan configuration
const (
	DefaultTimeout  = 15 * time.Minute
	DefaultMinRate  = 500
	FastMinRate     = 2000
	GentleScanDelay = 400 * time.Millisecond
)

// HandleScanResult processes nmap scan results and warnings
func HandleScanResult(result *nmap.Run, warnings *[]string, err error, optVVerbose *bool) error {
	if len(*warnings) > 0 {
		if *optVVerbose {
			utils.PrintCustomBiColourMsg("red", "yellow", "[!] Nmap scan finished with warnings: ", strings.Join(*warnings,"\n"))
		}
	}
	return err
}

// CreateContext creates a scan context bounded both by the default scan timeout
// and by the run's global context.
//
// Deriving from the global context is what makes Ctrl+C and a wall-clock budget
// actually reach nmap. This previously used context.Background(), so a running
// port sweep ignored both.
func CreateContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(utils.GetGlobalContext(), DefaultTimeout)
}

// GentleTimingOptions returns nmap timing options for gentle mode.
func GentleTimingOptions() []nmap.Option {
	if !utils.GentleMode {
		return nil
	}
	return []nmap.Option{
		nmap.WithTimingTemplate(nmap.TimingPolite),
		nmap.WithScanDelay(GentleScanDelay),
	}
}

// RateOptions returns the nmap timing options implied by the active bounds,
// falling back to fallbackMinRate when no rate cap is in force.
//
// Under a rate cap the minimum-rate option is deliberately omitted: a minimum
// rate and a maximum rate are contradictory instructions, and keeping both would
// let nmap exceed the cap the caller asked for.
//
// Gentle mode and explicit bounds (--rate, --concurrency) are mutually exclusive
// by validation, so this short-circuit to gentle timing cannot discard a caller's bound.
func RateOptions(fallbackMinRate int) []nmap.Option {
	if utils.GentleMode {
		return GentleTimingOptions()
	}

	var options []nmap.Option
	if rate := bounds.Active.Rate; rate > 0 {
		options = append(options, nmap.WithMaxRate(rate))
	} else {
		options = append(options, nmap.WithMinRate(fallbackMinRate))
	}
	// A concurrency cap must also reach nmap: capping tool processes at two while
	// a single nmap opens a hundred parallel probes is not the cap that was asked for.
	if concurrency := bounds.Active.Concurrency; concurrency > 0 {
		options = append(options, nmap.WithMaxParallelism(concurrency))
	}
	return options
}

// PrintScanStart prints scan start message
func PrintScanStart(target, port string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")
}

// PrintScanComplete prints scan completion message
func PrintScanComplete(target, port, outFile string) {
	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	utils.PrintCustomBiColourMsg("yellow", "cyan", "    Shortcut: less -R '", outFile+".nmap", "'")
}

// PrintUDPScanStart prints UDP scan start message
func PrintUDPScanStart(target, port string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting UDP scan against port(s) '", port, "' on target '", target, "' and sending it to the background")
}

// PrintUDPScanComplete prints UDP scan completion message
func PrintUDPScanComplete(target, port, outFile string) {
	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! UDP scan against port(s) '", port, "' on target '", target, "' finished successfully")
	utils.PrintCustomBiColourMsg("yellow", "cyan", "    Shortcut: less -R '", outFile+".nmap", "'")
}
