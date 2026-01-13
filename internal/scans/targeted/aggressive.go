package targeted

import (
	"fmt"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/scans/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/Ullaakut/nmap/v3"
)

// IndividualPortScanner runs a simple Nmap scan
func IndividualPortScanner(target, port, outFile string, optVVerbose *bool) error {
	ctx, cancel := common.CreateContext()
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts(port),
		nmap.WithPrivileged(),
		nmap.WithMinRate(common.DefaultMinRate),
		nmap.WithDisabledDNSResolution(),
		nmap.WithDefaultScript(),
		nmap.WithServiceInfo(),
		nmap.WithNmapOutput(outFile+".nmap"),
		nmap.WithGrepOutput(outFile+".grep"),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	)
	if err != nil {
		return fmt.Errorf("unable to create nmap scanner individualPortScanner: %s %s %s %w", target, port, outFile, err)
	}

	tracker := common.NewProgressTracker(1 * time.Minute)
	tracker.StartMinuteProgress(target, port, optVVerbose, "Individual protocol nmap scan")
	defer tracker.Stop()

	_, _, err = scanner.Run()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("unable to run nmap scan individualPortScanner: %s %s %s %v", target, port, outFile, err))
	}

	return nil
}

// FullAggressiveScan runs main aggressive scan for all open ports on the target
func FullAggressiveScan(target, ports, outFile string, optVVerbose *bool) error {
	ctx, cancel := common.CreateContext()
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts(ports),
		nmap.WithPrivileged(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithNmapOutput(outFile+".nmap"),
		nmap.WithOSDetection(),
		nmap.WithServiceInfo(),
		nmap.WithDefaultScript(),
		nmap.WithGrepOutput(outFile+".grep"),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	)
	if err != nil {
		return fmt.Errorf("unable to create nmap scanner fullAggressiveScan: %w", err)
	}

	tracker := common.NewProgressTracker(1 * time.Minute)
	tracker.StartAggressiveProgress(target, optVVerbose)
	defer tracker.Stop()

	_, _, err = scanner.Run()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("unable to run nmap scan fullAggressiveScan: %s %s %s %v", target, ports, outFile, err))
	}

	return nil
}
