package sweeps

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/scans/common"
	"github.com/Ullaakut/nmap/v3"
)

// BoundedPortSweep scans exactly the ports requested and nothing else.
//
// A UDP scan runs only when udpPorts is non-empty. This matters: the standard
// UdpPortSweep probes its own hardcoded list regardless of what was asked for,
// which under an explicit port list would be precisely the out-of-scope traffic
// the list exists to prevent. There is also no second, slower re-sweep here —
// widening the scan on our own initiative is what a bounded run rules out.
func BoundedPortSweep(target, tcpPorts, udpPorts string, optVVerbose *bool) ([]nmap.Host, []nmap.Host, error) {
	if tcpPorts == "" && udpPorts == "" {
		return nil, nil, fmt.Errorf("bounded sweep requires at least one port")
	}

	var tcpHosts, udpHosts []nmap.Host

	if tcpPorts != "" {
		hosts, err := boundedScan(target, tcpPorts, false, optVVerbose)
		if err != nil {
			return nil, nil, fmt.Errorf("bounded TCP sweep of %s: %w", tcpPorts, err)
		}
		tcpHosts = hosts
	}

	if udpPorts != "" {
		hosts, err := boundedScan(target, udpPorts, true, optVVerbose)
		if err != nil {
			return tcpHosts, nil, fmt.Errorf("bounded UDP sweep of %s: %w", udpPorts, err)
		}
		udpHosts = hosts
	}

	return tcpHosts, udpHosts, nil
}

// boundedScan runs a single nmap scan against exactly the ports given.
func boundedScan(target, ports string, udp bool, optVVerbose *bool) ([]nmap.Host, error) {
	ctx, cancel := common.CreateContext()
	defer cancel()

	options := []nmap.Option{
		nmap.WithTargets(target),
		nmap.WithPorts(ports),
		nmap.WithPrivileged(),
	}
	if udp {
		options = append(options, nmap.WithUDPScan())
	}
	options = append(options, common.RateOptions(common.FastMinRate)...)

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("unable to create nmap scanner: %w", err)
	}

	result, warnings, err := scanner.Run()
	if err := common.HandleScanResult(result, warnings, err, optVVerbose); err != nil {
		return nil, fmt.Errorf("unable to run nmap scan: %w", err)
	}

	return result.Hosts, nil
}
