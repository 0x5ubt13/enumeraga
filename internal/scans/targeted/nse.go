package targeted

import (
	"fmt"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/scans/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/Ullaakut/nmap/v3"
)

// IndividualPortScannerWithNSEScripts runs Nmap scan with NSE scripts
func IndividualPortScannerWithNSEScripts(target, port, outFile, scripts string, optVVerbose *bool) error {
	common.PrintScanStart(target, port)

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
		nmap.WithScripts(scripts),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	}
	if utils.GentleMode {
		options = append(options, common.GentleTimingOptions()...)
	} else {
		options = append(options, nmap.WithMinRate(common.DefaultMinRate))
	}
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return fmt.Errorf("unable to create nmap scanner individualPortScannerWithNSEScripts: %s %s %s %w", target, port, outFile, err)
	}

	tracker := common.NewProgressTracker(2 * time.Minute)
	tracker.StartNSEProgress(target, port, optVVerbose)
	defer tracker.Stop()

	_, warnings, err := scanner.Run()
	if err := common.HandleScanResult(nil, warnings, err, optVVerbose); err != nil {
		utils.ErrorMsg(fmt.Sprintf("unable to run nmap scan individualPortScannerWithNSEScripts: %s %s %s %v", target, port, outFile, err))
	}

	common.PrintScanComplete(target, port, outFile)
	return nil
}

// IndividualPortScannerWithNSEScriptsAndScriptArgs runs Nmap scan with NSE scripts and NSE script arguments
func IndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string, optVVerbose *bool) error {
	common.PrintScanStart(target, port)

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
		nmap.WithScripts(scripts),
		nmap.WithScriptArguments(scriptArgs),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	}
	if utils.GentleMode {
		options = append(options, common.GentleTimingOptions()...)
	} else {
		options = append(options, nmap.WithMinRate(common.DefaultMinRate))
	}
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return fmt.Errorf("unable to create nmap scanner individualPortScannerWithNSEScriptsAndScriptArgs: %s %s %s %w", target, port, outFile, err)
	}

	tracker := common.NewProgressTracker(2 * time.Minute)
	tracker.StartNSEArgsProgress(target, port, optVVerbose)
	defer tracker.Stop()

	_, warnings, err := scanner.Run()
	if err := common.HandleScanResult(nil, warnings, err, optVVerbose); err != nil {
		utils.ErrorMsg(fmt.Sprintf("unable to run nmap scan individualPortScannerWithNSEScriptsAndScriptArgs: %s %s %s %v", target, port, outFile, err))
	}

	common.PrintScanComplete(target, port, outFile)
	return nil
}

// IndividualUDPPortScannerWithNSEScripts runs a UDP Nmap scan with NSE scripts
func IndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string, optVVerbose *bool) error {
	common.PrintUDPScanStart(target, port)

	ctx, cancel := common.CreateContext()
	defer cancel()

	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithUDPScan(),
		nmap.WithPorts(port),
		nmap.WithPrivileged(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithDefaultScript(),
		nmap.WithServiceInfo(),
		nmap.WithNmapOutput(outFile + ".nmap"),
		nmap.WithGrepOutput(outFile + ".grep"),
		nmap.WithScripts(scripts),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	}
	if utils.GentleMode {
		options = append(options, common.GentleTimingOptions()...)
	} else {
		options = append(options, nmap.WithMinRate(common.DefaultMinRate))
	}
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return fmt.Errorf("unable to create nmap scanner individualUDPPortScannerWithNSEScripts: %s %s %s %w", target, port, outFile, err)
	}

	tracker := common.NewProgressTracker(2 * time.Minute)
	tracker.StartUDPNSEProgress(target, port, optVVerbose)
	defer tracker.Stop()

	_, warnings, err := scanner.Run()
	if err := common.HandleScanResult(nil, warnings, err, optVVerbose); err != nil {
		utils.ErrorMsg(fmt.Sprintf("unable to run nmap scan individualUDPPortScannerWithNSEScripts: %s %s %s %v", target, port, outFile, err))
	}

	common.PrintUDPScanComplete(target, port, outFile)
	return nil
}
