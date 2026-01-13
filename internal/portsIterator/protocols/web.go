package protocols

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// HTTP enumerates HyperText Transfer Protocol (80,443,8080/TCP)
func HTTP() {
	if utils.IsVisited("http") {
		return
	}

	dir := utils.ProtocolDetected("HTTP", utils.BaseDir)
	commands.CallIndividualPortScanner(utils.Target, "80,443,8080", dir+"http_scan", checks.OptVVerbose)

	// Port 80 enumeration
	enumerateHTTPPort80(dir)

	// Port 443 enumeration
	enumerateHTTPPort443(dir)

	// Port 8080 enumeration
	enumerateHTTPPort8080(dir)
}

func enumerateHTTPPort80(dir string) {
	// WordPress on port 80
	commands.CallWPEnumeration(fmt.Sprintf("http://%s:80", utils.Target), dir, "80", checks.OptVVerbose)

	// Nikto on port 80 (with configurable timeout)
	nikto80Args := []string{"nikto", "-host", fmt.Sprintf("http://%s:80", utils.Target), "-maxtime", common.GetTimeoutSeconds()}
	nikto80Path := fmt.Sprintf("%snikto_80.out", dir)
	commands.CallRunTool(nikto80Args, nikto80Path, checks.OptVVerbose)

	// Wafw00f on port 80
	wafw00f80Args := []string{"wafw00f", "-v", "--timeout", common.GetTimeoutSeconds(), fmt.Sprintf("http://%s:80", utils.Target)}
	wafw00f80Path := fmt.Sprintf("%swafw00f_80.out", dir)
	commands.CallRunTool(wafw00f80Args, wafw00f80Path, checks.OptVVerbose)

	// WhatWeb on port 80
	whatWeb80Args := []string{"whatweb", "-a", "3", "-v", fmt.Sprintf("http://%s:80", utils.Target)}
	whatWeb80Path := fmt.Sprintf("%swhatweb_80.out", dir)
	commands.CallRunTool(whatWeb80Args, whatWeb80Path, checks.OptVVerbose)

	// Dirsearch - Light dirbusting on port 80
	dirsearch80Path := fmt.Sprintf("%sdirsearch_80.out", dir)
	dirsearch80Args := []string{"dirsearch", "-t", "10", "-u", fmt.Sprintf("http://%s:80", utils.Target), "-o", dirsearch80Path, "--max-time", common.GetTimeoutSeconds(), "--quiet"}
	commands.CallRunTool(dirsearch80Args, dirsearch80Path, checks.OptVVerbose)

	if *checks.OptBrute {
		// CeWL + Ffuf Keywords Bruteforcing
		commands.CallRunCewlandFfufKeywords(utils.Target, dir, "80", checks.OptVVerbose)
		commands.CallRunCewlandFfufKeywords(utils.Target, dir, "443", checks.OptVVerbose)
	}
}

func enumerateHTTPPort443(dir string) {
	// WordPress on port 443
	commands.CallWPEnumeration(fmt.Sprintf("https://%s:443", utils.Target), dir, "443", checks.OptVVerbose)

	// Nikto on port 443 (with configurable timeout)
	nikto443Args := []string{"nikto", "-host", fmt.Sprintf("https://%s:443", utils.Target), "-maxtime", common.GetTimeoutSeconds()}
	nikto443Path := fmt.Sprintf("%snikto_443.out", dir)
	commands.CallRunTool(nikto443Args, nikto443Path, checks.OptVVerbose)

	// Wafw00f on port 443
	wafw00f443Args := []string{"wafw00f", "-v", "--timeout", common.GetTimeoutSeconds(), fmt.Sprintf("https://%s:443", utils.Target)}
	wafw00f443Path := fmt.Sprintf("%swafw00f_443.out", dir)
	commands.CallRunTool(wafw00f443Args, wafw00f443Path, checks.OptVVerbose)

	// WhatWeb on port 443
	whatWeb443Args := []string{"whatweb", "-a", "3", "-v", fmt.Sprintf("http://%s:443", utils.Target)}
	whatWeb443Path := fmt.Sprintf("%swhatweb_443.out", dir)
	commands.CallRunTool(whatWeb443Args, whatWeb443Path, checks.OptVVerbose)

	// Dirsearch - Light dirbusting on port 443
	dirsearch443Path := fmt.Sprintf("%sdirsearch_443.out", dir)
	dirsearch443Args := []string{"dirsearch", "-t", "10", "-u", fmt.Sprintf("https://%s:443", utils.Target), "-o", dirsearch443Path, "--max-time", common.GetTimeoutSeconds(), "--quiet"}
	commands.CallRunTool(dirsearch443Args, dirsearch443Path, checks.OptVVerbose)

	// TestSSL on port 443
	testssl := "testssl"
	if !utils.CheckToolExists("testssl") {
		if utils.CheckToolExists("testssl.sh") {
			testssl = "testssl.sh"
		}
	}

	// testssl with 10 minute timeout (--connect-timeout applies per connection)
	testsslArgs := []string{testssl, "--connect-timeout", "30", "--openssl-timeout", "30", fmt.Sprintf("https://%s:443", utils.Target)}
	testsslPath := fmt.Sprintf("%stestssl.out", dir)
	commands.CallRunTool(testsslArgs, testsslPath, checks.OptVVerbose)
}

func enumerateHTTPPort8080(dir string) {
	// WordPress on port 8080
	commands.CallWPEnumeration(fmt.Sprintf("http://%s:8080", utils.Target), dir, "8080", checks.OptVVerbose)

	// Tomcat
	commands.CallTomcatEnumeration(utils.Target, fmt.Sprintf("http://%s:8080/docs", utils.Target), dir, "8080", checks.OptBrute, checks.OptVVerbose)
}
