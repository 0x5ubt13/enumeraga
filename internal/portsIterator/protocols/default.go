package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// DEFAULT tries to get as much info as can about given TCP port 
func DEFAULT(port string) {
	dir := utils.ProtocolDetected2("unknown", port, utils.BaseDir)

	// nmap
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, dir+"nmap_scan_"+port, "(default and version and discovery) and not (broadcast) ", checks.OptVVerbose)

	// Nuclei speaks TCP whatever protocol the port turned out to be, and this is the
	// handler every unrecognised port reaches, so an automatic scan here would probe
	// TCP on a port the caller may have authorised only over UDP.
	if bounds.Active.PortInScope(port, false) {
        // Nuclei
        nucleiArgs := []string{
                "nuclei",
                "-target", fmt.Sprintf("%s:%s", utils.Target, port),
		"-automatic-scan",
		"-timeout", common.GetTimeoutSeconds(),
        }
        nucleiPath := fmt.Sprintf("%snuclei_%s.out", dir,port)
        commands.CallRunTool(nucleiArgs, nucleiPath, checks.OptVVerbose)
	}

}


