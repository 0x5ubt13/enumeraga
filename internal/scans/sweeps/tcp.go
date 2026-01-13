package sweeps

import (
	"fmt"
	"strconv"

	"github.com/0x5ubt13/enumeraga/internal/scans/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/Ullaakut/nmap/v3"
)

// TcpPortSweep runs a quick port sweep on TCP
func TcpPortSweep(target string, optVVerbose *bool) ([]nmap.Host, error) {
	ctx, cancel := common.CreateContext()
	defer cancel()

	// Equivalent to `nmap -p1-65535 --min-rate=2000 --privileged <target>` with 15-min timeout
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts("1-65535"),
		nmap.WithMinRate(common.FastMinRate),
		nmap.WithPrivileged(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %w", err)
	}

	result, warnings, err := scanner.Run()
	if err := common.HandleScanResult(result, warnings, err, optVVerbose); err != nil {
		return nil, fmt.Errorf("unable to run nmap scan: %w", err)
	}

	utils.TimesSwept += 1
	return result.Hosts, nil
}

// SlowerTcpPortSweep runs a comprehensive TCP port sweep on all 65535 ports
func SlowerTcpPortSweep(target string, optVVerbose *bool) ([]nmap.Host, error) {
	ctx, cancel := common.CreateContext()
	defer cancel()

	// Equivalent to `nmap -p1-65535 --min-rate=500 --privileged <target>` with 15-min timeout
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts("1-65535"),
		nmap.WithMinRate(common.DefaultMinRate),
		nmap.WithPrivileged(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %w", err)
	}

	result, warnings, err := scanner.Run()
	if err := common.HandleScanResult(result, warnings, err, optVVerbose); err != nil {
		return nil, fmt.Errorf("unable to run nmap scan: %w", err)
	}

	return result.Hosts, nil
}

// TcpPortSweepWithTopPorts runs the quickest port sweep on TCP
func TcpPortSweepWithTopPorts(target string, optTopPorts *string, optVVerbose *bool) ([]nmap.Host, error) {
	ctx, cancel := common.CreateContext()
	defer cancel()

	topPorts, err := strconv.Atoi(*optTopPorts)
	if err != nil {
		return nil, fmt.Errorf("unable to convert top ports var: %w", err)
	}

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithMostCommonPorts(topPorts),
		nmap.WithTargets(target),
		nmap.WithMinRate(common.FastMinRate),
		nmap.WithPrivileged(),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %w", err)
	}

	result, warnings, err := scanner.Run()
	if err := common.HandleScanResult(result, warnings, err, optVVerbose); err != nil {
		return nil, fmt.Errorf("unable to run nmap scan: %w", err)
	}

	return result.Hosts, nil
}
