package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// SSH enumerates Secure Shell Protocol (22/TCP)
func SSH(port string) {
	dir := utils.ProtocolDetected2("SSH", port, utils.BaseDir)

	// nmap with nse
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, dir+"ssh_scan_"+port, "ssh-* and not brute", checks.OptVVerbose)
	// ssh-audit
	sshAuditPath := fmt.Sprintf("%sssh_audit_%s.out", dir, port)
	sshAuditArgs := []string{"ssh-audit", utils.Target}
	commands.CallRunTool(sshAuditArgs, sshAuditPath, checks.OptVVerbose)

	// hydra
	common.RunHydraBrute("ssh", dir)
}

// RDP enumerates Remote Desktop Protocol (3389/TCP)
func RDP(port string) {
	dir := utils.ProtocolDetected2("RDP", port, utils.BaseDir)
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, dir+"rdp_scan_"+port, "rdp*", checks.OptVVerbose)
	common.RunHydraBrute("rdp", dir)
}

// WinRM enumerates Windows Remote Management Protocol (5985-5986/TCP)
func WinRM(port string) {
	if utils.IsVisited("winrm") {
		return
	}

	dir := utils.ProtocolDetected2("WinRM", port, utils.BaseDir)
	nmapOutputFile := dir + "winrm_scan_" + port 
	commands.CallIndividualPortScanner(utils.Target, port, nmapOutputFile, checks.OptVVerbose)
}
