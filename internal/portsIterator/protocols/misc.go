package protocols

import (
	"fmt"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// safeMsfRHost reports whether target is safe to interpolate into an msfconsole -x RC
// script. The -x value is a ';'-separated sequence of Metasploit commands, so a target
// containing ';', whitespace, or shell/quote metacharacters (for example an unvalidated
// line read from a targets file) could inject extra RC commands. Literal IPs and hostnames
// contain none of these; anything that does is rejected rather than executed.
func safeMsfRHost(target string) bool {
	return target != "" && !strings.ContainsAny(target, " \t\r\n;&|$`'\"\\")
}

// DNS enumerates Domain Name System (53/TCP)
func DNS(port string) {
	dir := utils.ProtocolDetected2("DNS", port, utils.BaseDir)
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "53", dir+"dns_scan", "*dns*", checks.OptVVerbose)
}

// Finger enumerates Finger (79/TCP)
func Finger(port string) {
	dir := utils.ProtocolDetected2("Finger", port, utils.BaseDir)
	commands.CallIndividualPortScanner(utils.Target, "79", dir+"finger_scan", checks.OptVVerbose)

	if !safeMsfRHost(utils.Target) {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Skipping msfconsole for Finger: unsafe target value ", utils.Target)
		return
	}
	msfArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/finger/finger_users;set rhost %s;run;exit", utils.Target)}
	commands.CallRunTool(msfArgs, common.BuildOutputPath(dir, "msfconsole"), checks.OptVVerbose)
}

// RPC enumerates Remote Procedure Call Protocol (111/TCP)
func RPC(port string) {
	dir := utils.ProtocolDetected2("RPC", port, utils.BaseDir)
	nmapOutputFile := dir + "rpc_scan"
	commands.CallIndividualPortScanner(utils.Target, "111", nmapOutputFile, checks.OptVVerbose)
}

// Ident enumerates Ident Protocol (113/TCP)
func Ident(port string, openPortsSlice []string) {
	dir := utils.ProtocolDetected2("Ident", port, utils.BaseDir)
	nmapOutputFile := dir + "ident_scan"
	commands.CallIndividualPortScanner(utils.Target, "113", nmapOutputFile, checks.OptVVerbose)

	// ident-user-enum
	spacedPorts := strings.Join(openPortsSlice, " ")
	identUserEnumArgs := []string{"ident-user-enum", utils.Target, spacedPorts}
	identUserEnumPath := fmt.Sprintf("%sident-user-enum.out", dir)
	commands.CallRunTool(identUserEnumArgs, identUserEnumPath, checks.OptVVerbose)
}

// MSRPC enumerates Microsoft's Remote Procedure Call Protocol (135,593/TCP)
func MSRPC(port string) {
	dir := utils.ProtocolDetected2("MSRPC", port, utils.BaseDir)
	nmapOutputFile := dir + "msrpc_scan"
	commands.CallIndividualPortScanner(utils.Target, "135,593", nmapOutputFile, checks.OptVVerbose)

	rpcDump135Args := []string{"impacket-rpcdump", "135"}
	rpcDump135Path := fmt.Sprintf("%srpcdump_135.out", dir)
	commands.CallRunTool(rpcDump135Args, rpcDump135Path, checks.OptVVerbose)

	rpcDump593Args := []string{"impacket-rpcdump", "593"}
	rpcDump593Path := fmt.Sprintf("%srpcdump_593.out", dir)
	commands.CallRunTool(rpcDump593Args, rpcDump593Path, checks.OptVVerbose)
}

// RServices enumerates Berkeley R-services (512-514/TCP)
func RServices(port string) {
	if utils.IsVisited("rsvc") {
		return
	}
	dir := utils.ProtocolDetected2("RServices", port, utils.BaseDir)

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
func IPMI(port string) {
	dir := utils.ProtocolDetected2("IPMI", port, utils.BaseDir)
	nmapOutputFile := dir + "ipmi_scan"

	// Nmap
	nmapNSEScripts := "ipmi*"
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, "623", nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)

	// Metasploit
	if !safeMsfRHost(utils.Target) {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Skipping msfconsole for IPMI: unsafe target value ", utils.Target)
		return
	}
	msfArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use auxiliary/scanner/ipmi/ipmi_dumphashes; set rhosts %s; set output_john_file %sipmi_hashes.john; run; exit", utils.Target, dir)}
	msfPath := fmt.Sprintf("%smsf_scanner.out", dir)
	commands.CallRunTool(msfArgs, msfPath, checks.OptVVerbose)
}

// Port10000 enumerates port 10000/TCP - commonly Webmin or NDMP
func Port10000(port string) {
	dir := utils.ProtocolDetected2("port_10000", port, utils.BaseDir)
	nmapOutputFile := dir + "port_10000_scan"
	// Use service version detection to identify Webmin vs NDMP vs other
	commands.CallIndividualPortScanner(utils.Target, "10000", nmapOutputFile, checks.OptVVerbose)
}

// SIP enumerates Session Initiation Protocol (5060/TCP, 5060/UDP)
func SIP(port string) {

	if utils.IsVisited("sip") {
		return
	}
	dir := utils.ProtocolDetected2("SIP", port, utils.BaseDir)
	nmapNSEScripts := "sip-methods,sip-enum-users"

	// Nmap
	nmapOutputFile := dir + "sip_scan_5060_udp"
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, "5060", nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)
	nmapOutputFile = dir + "sip_scan_5060_tcp"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "5060", nmapOutputFile, nmapNSEScripts, checks.OptVVerbose)

	// sippts scan
        sipptsArgs1 := []string{"sippts", "scan", "-p", "all", "-r", "5060-5070", "-fp", "-cve", "-i",  utils.Target}
        sipptsPath1 := fmt.Sprintf("%ssippts_scan.out", dir)
        commands.CallRunTool(sipptsArgs1, sipptsPath1, checks.OptVVerbose)

	// sippts enum
        sipptsArgs2 := []string{"sippts", "enumerate", "-p", "tcp", "-r", "5060", "-i",  utils.Target}
        sipptsPath2 := fmt.Sprintf("%ssippts_enumerate_tcp.out", dir)
        commands.CallRunTool(sipptsArgs2, sipptsPath2, checks.OptVVerbose)

	sipptsArgs3 := []string{"sippts", "enumerate", "-p", "udp", "-r", "5060", "-i",  utils.Target}
        sipptsPath3 := fmt.Sprintf("%ssippts_enumerate_udp.out", dir)
        commands.CallRunTool(sipptsArgs3, sipptsPath3, checks.OptVVerbose)

}

