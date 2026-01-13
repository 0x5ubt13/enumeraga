package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// SMTP enumerates Simple Mail Transfer Protocol (25,465,587/TCP)
func SMTP() {
	if utils.IsVisited("smtp") {
		return
	}

	smtpDir := utils.ProtocolDetected("SMTP", utils.BaseDir)
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, "25,465,587", smtpDir+"smtp_scan", "smtp-commands,smtp-enum-users,smtp-open-relay", checks.OptVVerbose)
}

// IMAP enumerates Internet Message Access Protocol (110,143,993,995/TCP)
func IMAP() {
	if utils.IsVisited("imap") {
		return
	}

	dir := utils.ProtocolDetected("IMAP-POP3", utils.BaseDir)
	nmapOutputFile := dir + "imap_pop3_scan"
	commands.CallIndividualPortScanner(utils.Target, "110,143,993,995", nmapOutputFile, checks.OptVVerbose)

	// Openssl
	openSSLArgs := []string{"openssl", "s_client", "-connect", fmt.Sprintf("%s:imaps", utils.Target)}
	openSSLPath := fmt.Sprintf("%sopenssl_imap.out", dir)
	commands.CallRunTool(openSSLArgs, openSSLPath, checks.OptVVerbose)

	// NC banner grabbing
	ports := []string{"110", "143", "993", "995"}
	for port := range ports {
		ncArgs := []string{"nc", "-nv", utils.Target, ports[port]}
		ncPath := fmt.Sprintf("%s%s_banner_grab.out", dir, ports[port])
		commands.CallRunTool(ncArgs, ncPath, checks.OptVVerbose)
	}
}
