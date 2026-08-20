package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// SNMP enumerates Simple Network Management Protocol (161-162,10161-10162/UDP)
func SNMP(port string) {
	if utils.IsVisited("snmp") {
		return
	}
	dir := utils.ProtocolDetected2("SNMP", port, utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "snmp_scan"
	nmapNSEScripts := "snmp* and not snmp-brute"

	// SNMP is dispatched on any one of 161,162,10161,10162, so a caller who named
	// only one of them via --ports must not have the rest of the cluster touched too.
	if udpPorts := bounds.Active.PortsInScope("161,162,10161,10162", true); udpPorts != "" {
		commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, udpPorts, nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)
	}

	// SNMPWalk
	snmpWalkArgs := []string{"snmpwalk", "-v2c", "-c", "public", utils.Target}
	snmpWalkPath := fmt.Sprintf("%ssnmpwalk_v2c_public.out", dir)
	commands.CallRunTool(snmpWalkArgs, snmpWalkPath, checks.OptVVerbose)

	// OneSixtyOne
	oneSixtyOneArgs := []string{"onesixtyone", "-c", utils.SnmpList, utils.Target}
	oneSixtyOnePath := fmt.Sprintf("%sonesixtyone.out", dir)
	commands.CallRunTool(oneSixtyOneArgs, oneSixtyOnePath, checks.OptVVerbose)

	// Braa
	braaArgs := []string{"braa", fmt.Sprintf("public@%s:.1.3.6.*", utils.Target)}
	braaPath := fmt.Sprintf("%sbraa_public.out", dir)
	commands.CallRunTool(braaArgs, braaPath, checks.OptVVerbose)
}

// NTP enumerates Network Time Protocol (123/UDP)
func NTP(port string) {
	dir := utils.ProtocolDetected2("NTP", port, utils.BaseDir)

	// The scan is UDP while the dispatching port may have been found open on TCP,
	// so the scope check is against the authorised UDP ports.
	if !bounds.Active.PortInScope(port, true) {
		return
	}
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, port, dir+"ntp_scan", "ntp-*", checks.OptVVerbose)
}

// IPSEC enumerates IPsec protocol (500/UDP)
func IPSEC(port string) {
	dir := utils.ProtocolDetected2("VPN", port, utils.BaseDir)

	// As with NTP: a UDP scan, so it is the authorised UDP ports that decide.
	if !bounds.Active.PortInScope(port, true) {
		return
	}
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, port, dir+"ntp_scan", "ike-version", checks.OptVVerbose)
}


