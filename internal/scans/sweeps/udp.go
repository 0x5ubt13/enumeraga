package sweeps

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/scans/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/Ullaakut/nmap/v3"
)

// UdpPortSweep runs a quick port sweep on UDP
func UdpPortSweep(target string, optVVerbose *bool) ([]nmap.Host, error) {
	ctx, cancel := common.CreateContext()
	defer cancel()

	// Equivalent to `nmap -sU -p111,161,162,10161,10162,623 --min-rate=2000 --privileged <target>`
	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithUDPScan(),
		nmap.WithPorts("111,161,162,10161,10162,623"),
		nmap.WithPrivileged(),
	}
	if utils.GentleMode {
		options = append(options, common.GentleTimingOptions()...)
	} else {
		options = append(options, nmap.WithMinRate(common.FastMinRate))
	}
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner udpPortSweep: %s %w", target, err)
	}

	result, warnings, err := scanner.Run()
	if err := common.HandleScanResult(result, warnings, err, optVVerbose); err != nil {
		return nil, fmt.Errorf("unable to run nmap scan udpPortSweep: %w", err)
	}

	return result.Hosts, nil
}

// SlowerUdpPortSweep runs a slower port sweep on UDP
func SlowerUdpPortSweep(target string, optVVerbose *bool) ([]nmap.Host, error) {
	ctx, cancel := common.CreateContext()
	defer cancel()

	// Equivalent to `nmap -sU -p111,161,162,10161,10162,623 --min-rate=500 --privileged <target>`
	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithUDPScan(),
		nmap.WithPorts("111,161,162,10161,10162,623"),
		nmap.WithPrivileged(),
	}
	if utils.GentleMode {
		options = append(options, common.GentleTimingOptions()...)
	} else {
		options = append(options, nmap.WithMinRate(common.DefaultMinRate))
	}
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner udpPortSweep: %s %w", target, err)
	}

	result, warnings, err := scanner.Run()
	if err := common.HandleScanResult(result, warnings, err, optVVerbose); err != nil {
		return nil, fmt.Errorf("unable to run nmap scan udpPortSweep: %w", err)
	}

	return result.Hosts, nil
}
