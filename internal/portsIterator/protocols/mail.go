package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// SMTP enumerates Simple Mail Transfer Protocol 
func SMTP(port string) {
	if utils.IsVisited("smtp") {
		return
	}
	smtpDir := utils.ProtocolDetected2("SMTP", port, utils.BaseDir)

	// Namap with NSE
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, smtpDir+"smtp_scan_"+port, "smtp-commands,smtp-enum-users,smtp-ntlm-info,ssl-cert,ssl-date,smtp-open-relay", checks.OptVVerbose)
}

// IMAP enumerates Internet Message Access Protocol 
func IMAP(port string) {
	if utils.IsVisited("imap") {
		return
	}
	dir := utils.ProtocolDetected2("IMAP", port, utils.BaseDir)

	// Namap with NSE
	nmapOutputFile := dir + "imap_scan_" + port 
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, nmapOutputFile, "imap-ntlm-info,imap-capabilities,ssl-cert,ssl-date", checks.OptVVerbose)

	// NC banner grabbing
	ncArgs := []string{"nc", "-nv", utils.Target, port}
	ncPath := fmt.Sprintf("%simap_banner_%s.out", dir, port)
	commands.CallRunTool(ncArgs, ncPath, checks.OptVVerbose)
}


// POP3 Enumerate Post Office Protocol
func POP3(port string) {
	if utils.IsVisited("pop3") {
		return
	}
	dir := utils.ProtocolDetected2("POP3", port, utils.BaseDir)

	// Namap with NSE
	nmapOutputFile := dir + "pop3_scan_" + port 
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, nmapOutputFile, "pop3-ntlm-info,pop3-capabilities,ssl-cert,ssl-date", checks.OptVVerbose)

	// NC banner grabbing
	ncArgs := []string{"nc", "-nv", utils.Target, port}
	ncPath := fmt.Sprintf("%spop3_banner_%s.out", dir, port)
	commands.CallRunTool(ncArgs, ncPath, checks.OptVVerbose)
}
