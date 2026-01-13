package protocols

import (
	"fmt"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// DNS enumerates Domain Name System (53/TCP)
func DNS() {
	dir := utils.ProtocolDetected("DNS", utils.BaseDir)
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "53", dir+"dns_scan", "*dns*", checks.OptVVerbose)
}

// Finger enumerates Finger (79/TCP)
func Finger() {
	dir := utils.ProtocolDetected("Finger", utils.BaseDir)
	commands.CallIndividualPortScanner(utils.Target, "79", dir+"finger_scan", checks.OptVVerbose)

	msfArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/finger/finger_users;set rhost %s;run;exit", utils.Target)}
	commands.CallRunTool(msfArgs, common.BuildOutputPath(dir, "msfconsole"), checks.OptVVerbose)
}

// RPC enumerates Remote Procedure Call Protocol (111/TCP)
func RPC() {
	dir := utils.ProtocolDetected("RPC", utils.BaseDir)
	nmapOutputFile := dir + "rpc_scan"
	commands.CallIndividualPortScanner(utils.Target, "111", nmapOutputFile, checks.OptVVerbose)
}

// Ident enumerates Ident Protocol (113/TCP)
func Ident(openPortsSlice []string) {
	dir := utils.ProtocolDetected("Ident", utils.BaseDir)
	nmapOutputFile := dir + "ident_scan"
	commands.CallIndividualPortScanner(utils.Target, "113", nmapOutputFile, checks.OptVVerbose)

	// ident-user-enum
	spacedPorts := strings.Join(openPortsSlice, " ")
	identUserEnumArgs := []string{"ident-user-enum", utils.Target, spacedPorts}
	identUserEnumPath := fmt.Sprintf("%sident-user-enum.out", dir)
	commands.CallRunTool(identUserEnumArgs, identUserEnumPath, checks.OptVVerbose)
}

// MSRPC enumerates Microsoft's Remote Procedure Call Protocol (135,593/TCP)
func MSRPC() {
	dir := utils.ProtocolDetected("MSRPC", utils.BaseDir)
	nmapOutputFile := dir + "msrpc_scan"
	commands.CallIndividualPortScanner(utils.Target, "135,593", nmapOutputFile, checks.OptVVerbose)

	rpcDump135Args := []string{"impacket-rpcdump", "135"}
	rpcDump135Path := fmt.Sprintf("%srpcdump_135.out", dir)
	commands.CallRunTool(rpcDump135Args, rpcDump135Path, checks.OptVVerbose)

	rpcDump593Args := []string{"impacket-rpcdump", "593"}
	rpcDump593Path := fmt.Sprintf("%srpcdump_593.out", dir)
	commands.CallRunTool(rpcDump593Args, rpcDump593Path, checks.OptVVerbose)
}

// SNMP enumerates Simple Network Management Protocol (161-162,10161-10162/UDP)
func SNMP() {
	if utils.IsVisited("snmp") {
		return
	}
	dir := utils.ProtocolDetected("SNMP", utils.BaseDir)

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
	oneSixtyOnePath := fmt.Sprintf("%snblookup.out", dir)
	commands.CallRunTool(oneSixtyOneArgs, oneSixtyOnePath, checks.OptVVerbose)

	// Braa
	braaArgs := []string{"braa", fmt.Sprintf("public@%s:.1.3.6.*", utils.Target)}
	braaPath := fmt.Sprintf("%sbraa_public.out", dir)
	commands.CallRunTool(braaArgs, braaPath, checks.OptVVerbose)
}

// RServices enumerates Berkeley R-services (512-514/TCP)
func RServices() {
	if utils.IsVisited("rsvc") {
		return
	}
	dir := utils.ProtocolDetected("RServices", utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "rservices_scan"
	commands.CallIndividualPortScanner(utils.Target, "512,513,514", nmapOutputFile, checks.OptVVerbose)

	// Rwho
	rwhoArgs := []string{"rwho", "-a", utils.Target}
	rwhoPath := fmt.Sprintf("%srwho.out", dir)
	commands.CallRunTool(rwhoArgs, rwhoPath, checks.OptVVerbose)

	// Rusers
	rusersArgs := []string{"rusers", "-la", utils.Target}
	rusersPath := fmt.Sprintf("%srusers.out", dir)
	commands.CallRunTool(rusersArgs, rusersPath, checks.OptVVerbose)

	filePath := dir + "next_step_tip.txt"
	message := `
	Tip: Enumerate NFS, etc on the utils.Target server for /home/user/.rhosts and /etc/hosts.equiv files to use with rlogin, rsh and rexec.
	If found, use the following command:
	rlogin "utils.Target" -l "found_user"`
	if err := utils.WriteTextToFile(filePath, message); err != nil {
		utils.ErrorMsg(fmt.Sprintf("Failed to write r-services enumeration tips file: %v", err))
	}
}

// IPMI enumerates Intelligent Platform Management Interface Protocol (623/TCP)
func IPMI() {
	dir := utils.ProtocolDetected("IPMI", utils.BaseDir)
	nmapOutputFile := dir + "ipmi_scan"

	// Nmap
	nmapNSEScripts := "ipmi*"
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, "623", nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)

	// Metasploit
	msfArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/ipmi/ipmi_dumphashes; set rhosts %s; set output_john_file %sipmi_hashes.john; run; exit", utils.Target, dir)}
	msfPath := fmt.Sprintf("%smsf_scanner.out", dir)
	commands.CallRunTool(msfArgs, msfPath, checks.OptVVerbose)
}

// Port10000 enumerates port 10000/TCP - commonly Webmin or NDMP
func Port10000() {
	dir := utils.ProtocolDetected("port_10000", utils.BaseDir)
	nmapOutputFile := dir + "port_10000_scan"
	// Use service version detection to identify Webmin vs NDMP vs other
	commands.CallIndividualPortScanner(utils.Target, "10000", nmapOutputFile, checks.OptVVerbose)
}
