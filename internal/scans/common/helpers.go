package common

import (
	"context"
	"fmt"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/Ullaakut/nmap/v3"
)

// ScanDefaults holds common scan configuration
const (
	DefaultTimeout = 15 * time.Minute
	DefaultMinRate = 500
	FastMinRate    = 2000
)

// HandleScanResult processes nmap scan results and warnings
func HandleScanResult(result *nmap.Run, warnings *[]string, err error, optVVerbose *bool) error {
	if len(*warnings) > 0 {
		if *optVVerbose {
			fmt.Printf("run finished with warnings: %s\n", *warnings)
		}
	}
	return err
}

// CreateContext creates a context with the default timeout
func CreateContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultTimeout)
}

// PrintScanStart prints scan start message
func PrintScanStart(target, port string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")
}

// PrintScanComplete prints scan completion message
func PrintScanComplete(target, port, outFile string) {
	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	utils.PrintCustomBiColourMsg("yellow", "cyan", "\tShortcut: less -R '", outFile+".nmap", "'")
}

// PrintUDPScanStart prints UDP scan start message
func PrintUDPScanStart(target, port string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting UDP scan against port(s) '", port, "' on target '", target, "' and sending it to the background")
}

// PrintUDPScanComplete prints UDP scan completion message
func PrintUDPScanComplete(target, port, outFile string) {
	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! UDP scan against port(s) '", port, "' on target '", target, "' finished successfully")
	utils.PrintCustomBiColourMsg("yellow", "cyan", "\tShortcut: less -R '", outFile+".nmap", "'")
}
