package targeted

import (
	"fmt"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/scans/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/Ullaakut/nmap/v3"
)

// IndividualPortScanner runs a simple Nmap scan
func IndividualPortScanner(target, port, outFile string, OptVVerbose *bool) error {
	ctx, cancel := common.CreateContext()
	defer cancel()

	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithPorts(port),
		nmap.WithPrivileged(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithDefaultScript(),
		nmap.WithServiceInfo(),
		nmap.WithNmapOutput(outFile + ".nmap"),
		nmap.WithGrepOutput(outFile + ".grep"),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	}
	options = append(options, common.RateOptions(common.DefaultMinRate)...)
	startedAt := time.Now()
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return fmt.Errorf("unable to create nmap scanner individualPortScanner: %s %s %s %w", target, port, outFile, err)
	}

	if *OptVVerbose {
		tracker := common.NewProgressTracker(1 * time.Minute)
		tracker.StartMinuteProgress(target, port, OptVVerbose, "Individual protocol nmap scan")
		defer tracker.Stop()
	}

	result, warnings, err := scanner.Run()
	// The error is deliberately swallowed here, as it always has been; the call
	// is for the warning output and the run record.
	_ = common.HandleScanResult(common.ScanRecord{
		Name:      "nmap on port " + port,
		Target:    target,
		Ports:     port,
		Artefact:  outFile,
		StartedAt: startedAt,
		Scanner:   scanner,
	}, result, warnings, err, OptVVerbose)
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("unable to run nmap scan individualPortScanner: %s %s %s %v", target, port, outFile, err))
	}

	return nil
}

// FullAggressiveScan runs main aggressive scan for all open ports on the target
func FullAggressiveScan(target, ports, outFile string, OptVVerbose *bool) error {
	ctx, cancel := common.CreateContext()
	defer cancel()

	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithPorts(ports),
		nmap.WithPrivileged(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithNmapOutput(outFile + ".nmap"),
		nmap.WithOSDetection(),
		nmap.WithServiceInfo(),
		nmap.WithDefaultScript(),
		nmap.WithGrepOutput(outFile + ".grep"),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	}
	options = append(options, common.RateOptions(common.DefaultMinRate)...)
	startedAt := time.Now()
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return fmt.Errorf("unable to create nmap scanner fullAggressiveScan: %w", err)
	}

	if *OptVVerbose {
		tracker := common.NewProgressTracker(1 * time.Minute)
		tracker.StartAggressiveProgress(target, OptVVerbose)
		defer tracker.Stop()
	}

	result, warnings, err := scanner.Run()
	// The error is deliberately swallowed here, as it always has been; the call
	// is for the warning output and the run record.
	_ = common.HandleScanResult(common.ScanRecord{
		Name:      "nmap aggressive scan",
		Target:    target,
		Ports:     ports,
		Artefact:  outFile,
		StartedAt: startedAt,
		Scanner:   scanner,
	}, result, warnings, err, OptVVerbose)
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("unable to run nmap scan fullAggressiveScan: %s %s %s %v", target, ports, outFile, err))
	}

	return nil
}
