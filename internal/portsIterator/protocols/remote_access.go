package protocols

import (
	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// SSH enumerates Secure Shell Protocol (22/TCP)
func SSH() {
	dir := utils.ProtocolDetected("SSH", utils.BaseDir)
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "22", dir+"ssh_scan", "ssh-* and not brute", checks.OptVVerbose)
	common.RunHydraBrute("ssh", dir)
}

// RDP enumerates Remote Desktop Protocol (3389/TCP)
func RDP() {
	dir := utils.ProtocolDetected("RDP", utils.BaseDir)
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "3389", dir+"rdp_scan", "rdp*", checks.OptVVerbose)
	common.RunHydraBrute("rdp", dir)
}

// WinRM enumerates Windows Remote Management Protocol (5985-5986/TCP)
func WinRM() {
	if utils.IsVisited("winrm") {
		return
	}

	dir := utils.ProtocolDetected("WinRM", utils.BaseDir)
	nmapOutputFile := dir + "winrm_scan"
	commands.CallIndividualPortScanner(utils.Target, "5985,5986", nmapOutputFile, checks.OptVVerbose)
}
