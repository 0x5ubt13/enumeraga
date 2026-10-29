package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// MODBUS enumerates Modbus protocol (502/TCP)
func MODBUS(port string) {
	dir := utils.ProtocolDetected2("MODBUS", port, utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "modbus_scan"
	nmapNSEScripts := "modbus-discover"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)

	// Metasploit
	if !safeMsfRHost(utils.Target) {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Skipping msfconsole for MODBUS: unsafe target value ", utils.Target)
		return
	}
	msfArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/scada/modbus_findunitid; set rhosts %s; set rport %s; run; exit", utils.Target, port)}
	msfPath := fmt.Sprintf("%smsf_scanner.out", dir)
	commands.CallRunTool(msfArgs, msfPath, checks.OptVVerbose)
}

// S7 enumerates Siemens S7 protocol (102/TCP)
func S7(port string) {
	dir := utils.ProtocolDetected2("S7", port, utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "s7_scan"
	nmapNSEScripts := "s7-info"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)
}

// PROFINET enumerates PROFINET devices (34964/UDP)
func PROFINET(port string) {
	dir := utils.ProtocolDetected2("PROFINET", port, utils.BaseDir)

	// profinet-cm-lookup is a UDP script (PNIO-CM on 34964/UDP), while the
	// dispatching port may have been found open on TCP, so the scope check is
	// against the authorised UDP ports.
	if !bounds.Active.PortInScope(port, true) {
		return
	}

	// Nmap
	nmapOutputFile := dir + "profinet_scan"
	nmapNSEScripts := "profinet-cm-lookup"
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, port, nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)
}
