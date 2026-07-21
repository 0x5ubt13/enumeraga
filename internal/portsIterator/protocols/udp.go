package protocols

import (
	"fmt"

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
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, "161,162,10161,10162", nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)

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
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, port, dir+"ntp_scan", "ntp-*", checks.OptVVerbose)
}

// IPSEC enumerates IPsec protocol (500/UDP)
func IPSEC(port string) {
	dir := utils.ProtocolDetected2("VPN", port, utils.BaseDir)
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, port, dir+"ntp_scan", "ike-version", checks.OptVVerbose)
}


