package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// SMB enumerates NetBIOS / Server Message Block Protocol (137-139,445/TCP - 137/UDP)
func SMB(port string) {
	if utils.IsVisited("smb") {
		return
	}
	dir := utils.ProtocolDetected2("SMB", port, utils.BaseDir)

	// Nmap
	nmapOutputFile := dir + "nmap_tcp_scan"
	nmapUDPOutputFile := dir + "nmap_udp_scan"
	nmapNSEScripts := "smb* and not brute"
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "137,138,139,445", nmapOutputFile, nmapNSEScripts, checks.OptVVerbose) // TCP
	commands.CallIndividualUDPPortScannerWithNSEScripts(utils.Target, "137", nmapUDPOutputFile, "nbstat.nse", checks.OptVVerbose)         // UDP
 
	// netexec
	cmeArgs := []string{"netexec", "smb", utils.Target, "--shares", "--pass-pol"}
	cmePath := fmt.Sprintf("%snetexec_anon.out", dir)
	commands.CallRunTool(cmeArgs, cmePath, checks.OptVVerbose)

	// SMBMap
	smbMapArgs := []string{"smbmap", "-H", utils.Target, "--no-update"}
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

        // Nuclei
        nucleiArgs := []string{
                "nuclei",
                "-target", fmt.Sprintf("%s:445", utils.Target),
                "-tags", "smb",
                "-timeout", common.GetTimeoutSeconds(),
        }
        nucleiPath := fmt.Sprintf("%snuclei.out", dir)
        commands.CallRunTool(nucleiArgs, nucleiPath, checks.OptVVerbose)

	// netexec BruteForcing
	if *checks.OptBrute {
		cmeBfArgs := []string{"netexec", "smb", utils.Target, "-u", utils.UsersList, "-p", utils.DarkwebTop1000, "--shares", "--sessions", "--disks", "--loggedon-users", "--users", "--groups", "--computers", "--local-groups", "--pass-pol", "--rid-brute"}
		cmeBfPath := fmt.Sprintf("%snetexec_bf.out", dir)
		commands.CallRunTool(cmeBfArgs, cmeBfPath, checks.OptVVerbose)
	}

}
