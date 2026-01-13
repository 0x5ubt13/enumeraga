package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// SMB enumerates NetBIOS / Server Message Block Protocol (137-139,445/TCP - 137/UDP)
func SMB() {
	if utils.IsVisited("smb") {
		return
	}
	dir := utils.ProtocolDetected("NetBIOS-SMB", utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "nb_smb_scan"
	nmapUDPOutputFile := dir + "nb_smb_UDP_scan"
	nmapNSEScripts := "smb* and not brute"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "137,138,139,445", nmapOutputFile, nmapNSEScripts, checks.OptVVerbose) // TCP
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, "137", nmapUDPOutputFile, "nbstat.nse", checks.OptVVerbose)         // UDP

	// CME
	cmeArgs := []string{"crackmapexec", "smb", "-u", "''", "-p", "''", utils.Target}
	cmePath := fmt.Sprintf("%scme_anon.out", dir)
	commands.CallRunTool(cmeArgs, cmePath, checks.OptVVerbose)

	if *checks.OptBrute {
		// CME BruteForcing
		cmeBfArgs := []string{"crackmapexec", "smb", "-u", utils.UsersList, "-p", utils.DarkwebTop1000, "--shares", "--sessions", "--disks", "--loggedon-users", "--users", "--groups", "--computers", "--local-groups", "--pass-pol", "--rid-brute", utils.Target}
		cmeBfPath := fmt.Sprintf("%scme_bf.out", dir)
		commands.CallRunTool(cmeBfArgs, cmeBfPath, checks.OptVVerbose)
	}

	// SMBMap
	smbMapArgs := []string{"smbmap", "-H", utils.Target}
	smbMapPath := fmt.Sprintf("%ssmbmap.out", dir)
	commands.CallRunTool(smbMapArgs, smbMapPath, checks.OptVVerbose)

	// NMBLookup
	nmbLookupArgs := []string{"nmblookup", "-A", utils.Target}
	nmbLookupPath := fmt.Sprintf("%snmblookup.out", dir)
	commands.CallRunTool(nmbLookupArgs, nmbLookupPath, checks.OptVVerbose)

	// Enum4linux-ng
	enum4linuxNgArgs := []string{"enum4linux-ng", "-A", "-C", utils.Target}
	enum4linuxNgPath := fmt.Sprintf("%senum4linux_ng.out", dir)
	commands.CallRunTool(enum4linuxNgArgs, enum4linuxNgPath, checks.OptVVerbose)
}
