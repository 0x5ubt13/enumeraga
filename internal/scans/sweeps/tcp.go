package sweeps

import (
	"fmt"
	"strconv"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/scans/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/Ullaakut/nmap/v3"
)

// allTcpPorts is the full TCP range both unbounded sweeps ask for. It is named so
// the run record reports what was actually requested rather than a second copy of
// the string that can drift from it.
const allTcpPorts = "1-65535"

// TcpPortSweep runs a quick port sweep on TCP
func TcpPortSweep(target string, optVVerbose *bool) ([]nmap.Host, error) {
	ctx, cancel := common.CreateContext()
	defer cancel()

	// Equivalent to `nmap -p1-65535 --min-rate=2000 --privileged <target>` with 15-min timeout
	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithPorts(allTcpPorts),
		nmap.WithPrivileged(),
	}
	options = append(options, common.RateOptions(common.FastMinRate)...)
	startedAt := time.Now()
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %w", err)
	}

	result, warnings, err := scanner.Run()
	if err := common.HandleScanResult(common.ScanRecord{
		Name:      "nmap TCP sweep",
		Target:    target,
		Ports:     allTcpPorts,
		StartedAt: startedAt,
		Scanner:   scanner,
	}, result, warnings, err, optVVerbose); err != nil {
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
	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithPorts(allTcpPorts),
		nmap.WithPrivileged(),
	}
	options = append(options, common.RateOptions(common.DefaultMinRate)...)
	startedAt := time.Now()
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %w", err)
	}

	result, warnings, err := scanner.Run()
	if err := common.HandleScanResult(common.ScanRecord{
		Name:      "nmap slower TCP sweep",
		Target:    target,
		Ports:     allTcpPorts,
		StartedAt: startedAt,
		Scanner:   scanner,
	}, result, warnings, err, optVVerbose); err != nil {
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

	options := []nmap.Option{
		nmap.WithMostCommonPorts(topPorts),
		nmap.WithTargets(target),
		nmap.WithPrivileged(),
	}
	options = append(options, common.RateOptions(common.FastMinRate)...)
	startedAt := time.Now()
	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %w", err)
	}

	result, warnings, err := scanner.Run()
	if err := common.HandleScanResult(common.ScanRecord{
		Name:      "nmap TCP sweep, top ports",
		Target:    target,
		Ports:     fmt.Sprintf("top-%d", topPorts),
		StartedAt: startedAt,
		Scanner:   scanner,
	}, result, warnings, err, optVVerbose); err != nil {
		return nil, fmt.Errorf("unable to run nmap scan: %w", err)
	}

	return result.Hosts, nil
}
