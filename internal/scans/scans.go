package scans

import (
	"github.com/0x5ubt13/enumeraga/internal/scans/sweeps"
	"github.com/0x5ubt13/enumeraga/internal/scans/targeted"
	"github.com/Ullaakut/nmap/v3"
)

// TCP Port Sweeps - delegating to sweeps package

// TcpPortSweep runs a quick port sweep on TCP
func TcpPortSweep(target string, optVVerbose *bool) ([]nmap.Host, error) {
	return sweeps.TcpPortSweep(target, optVVerbose)
}

// SlowerTcpPortSweep runs a comprehensive TCP port sweep on all 65535 ports
func SlowerTcpPortSweep(target string, optVVerbose *bool) ([]nmap.Host, error) {
	return sweeps.SlowerTcpPortSweep(target, optVVerbose)
}

// TcpPortSweepWithTopPorts runs the quickest port sweep on TCP
func TcpPortSweepWithTopPorts(target string, optTopPorts *string, optVVerbose *bool) ([]nmap.Host, error) {
	return sweeps.TcpPortSweepWithTopPorts(target, optTopPorts, optVVerbose)
}

// UDP Port Sweeps - delegating to sweeps package

// UdpPortSweep runs a quick port sweep on UDP
func UdpPortSweep(target string, optVVerbose *bool) ([]nmap.Host, error) {
	return sweeps.UdpPortSweep(target, optVVerbose)
}

// SlowerUdpPortSweep runs a slower port sweep on UDP
func SlowerUdpPortSweep(target string, optVVerbose *bool) ([]nmap.Host, error) {
	return sweeps.SlowerUdpPortSweep(target, optVVerbose)
}

// Targeted Scans - delegating to targeted package

// IndividualPortScannerWithNSEScripts runs Nmap scan with NSE scripts
func IndividualPortScannerWithNSEScripts(target, port, outFile, scripts string, optVVerbose *bool) error {
	return targeted.IndividualPortScannerWithNSEScripts(target, port, outFile, scripts, optVVerbose)
}

// IndividualPortScannerWithNSEScriptsAndScriptArgs runs Nmap scan with NSE scripts and NSE script arguments
func IndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string, optVVerbose *bool) error {
	return targeted.IndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts, scriptArgs, optVVerbose)
}

// IndividualUDPPortScannerWithNSEScripts runs a UDP Nmap scan with NSE scripts
func IndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string, optVVerbose *bool) error {
	return targeted.IndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts, optVVerbose)
}

// IndividualPortScanner runs a simple Nmap scan
func IndividualPortScanner(target, port, outFile string, optVVerbose *bool) error {
	return targeted.IndividualPortScanner(target, port, outFile, optVVerbose)
}

// FullAggressiveScan runs main aggressive scan for all open ports on the target
func FullAggressiveScan(target, ports, outFile string, optVVerbose *bool) error {
	return targeted.FullAggressiveScan(target, ports, outFile, optVVerbose)
}
