package protocols

import (
	"fmt"
	"net/http"
	"time"
	"crypto/tls"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)


func IsHTTPService(url string) bool {
        client := &http.Client{
                Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
        }

	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := client.Get(url)
		if err == nil && resp != nil {
			defer resp.Body.Close()

			// Check for any status code
			if resp.StatusCode > 0 {
				return true
			}
		}

	}
        return false
}

func IsHTTPSService(url string) bool {
	tlsConfig := &tls.Config{
		// A recon tool must probe endpoints presenting self-signed or otherwise
		// invalid certificates, so certificate verification is deliberately skipped.
		InsecureSkipVerify: true, //nolint:gosec // scanner must reach hosts with invalid TLS certs
		MinVersion:         tls.VersionTLS10, // allow TLS 1.0 and above
		MaxVersion:         tls.VersionTLS13,
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for attempt := 1; attempt <= 3; attempt++ {
		resp, err := client.Get(url)
		if err == nil && resp != nil {
			defer resp.Body.Close()

			// Check for any status code
			if resp.StatusCode > 0 {
				return true
			}
		}

	}
        return false
}


// HTTP(s) port
func HTTP(port string, scheme string) {

	if *checks.OptVVerbose {
		utils.PrintSafe("Testing port: %s -> scheme: %s\n",port,scheme)
	}

	dir := utils.ProtocolDetected2("HTTP", port, utils.BaseDir)

	// nmap + nse
	commands.CallIndividualPortScannerWithNSEScripts(utils.Target, port, dir+"http_scan_"+port, "http-* and not (brute or fuzzer or dos)", checks.OptVVerbose)

	// WhatWeb
	whatWebArgs := []string{"whatweb", "-a", "3", "-v", fmt.Sprintf("%s://%s:%s", scheme, utils.Target, port)}
	whatWebPath := fmt.Sprintf("%swhatweb_%s.out", dir,port)
	commands.CallRunTool(whatWebArgs, whatWebPath, checks.OptVVerbose)

	// Wafw00f
	wafw00fArgs := []string{"wafw00f", "-v", "--timeout", common.GetTimeoutSeconds(), fmt.Sprintf("%s://%s:%s",scheme, utils.Target, port)}
	wafw00fPath := fmt.Sprintf("%swafw00f_%s.out", dir,port)
	commands.CallRunTool(wafw00fArgs, wafw00fPath, checks.OptVVerbose)

	// Nikto
	niktoArgs := []string{"nikto", "-host", fmt.Sprintf("%s://%s:%s", scheme, utils.Target, port), "-maxtime", common.GetTimeoutSeconds()}
	niktoPath := fmt.Sprintf("%snikto_%s.out", dir,port)
	commands.CallRunTool(niktoArgs, niktoPath, checks.OptVVerbose)

	// Nuclei
	nucleiArgs := []string{
		"nuclei",
		"-target", fmt.Sprintf("%s://%s:%s", scheme, utils.Target, port),
		"-t", "http/",
		"-silent",
		"-no-color",
		"-timeout", common.GetTimeoutSeconds(),
	}
	nucleiPath := fmt.Sprintf("%snuclei_%s.out", dir,port)
	commands.CallRunTool(nucleiArgs, nucleiPath, checks.OptVVerbose)

	// testssl with 10 minute timeout
	if scheme == "https" {
		// The Kali package installs the binary as 'testssl.sh'; fall back to it if 'testssl' is absent.
		testssl := "testssl"
		if !utils.CheckToolExists("testssl") && utils.CheckToolExists("testssl.sh") {
			testssl = "testssl.sh"
		}
		testsslArgs := []string{testssl, "--connect-timeout", "30", "--openssl-timeout", "30", fmt.Sprintf("https://%s:%s", utils.Target, port)}
		testsslPath := fmt.Sprintf("%stestssl_%s.out", dir, port)
		commands.CallRunTool(testsslArgs, testsslPath, checks.OptVVerbose)
	}

	// Dirsearch
	dirsearchPath := fmt.Sprintf("%sdirsearch_%s.out", dir,port)
	dirsearchArgs := []string{"dirsearch", "-t", "10", "-u", fmt.Sprintf("%s://%s:%s", scheme,utils.Target,port), "-o", dirsearchPath, "--max-time", common.GetTimeoutSeconds(), "--quiet"}
	commands.CallRunTool(dirsearchArgs, dirsearchPath, checks.OptVVerbose)

	// gowitness
	gowitnessPath1 := fmt.Sprintf("%sgowitness_screenshots", dir)
	gowitnessPath2 := fmt.Sprintf("%sgowitness_%s.out", dir,port)
	gowitnessArgs := []string{"gowitness", "scan", "single", "-u", fmt.Sprintf("%s://%s:%s", scheme,utils.Target,port), "--delay", "30", "--debug-log", "--write-stdout", "--write-screenshots" , "--screenshot-path", gowitnessPath1}
	commands.CallRunTool(gowitnessArgs, gowitnessPath2, checks.OptVVerbose)

	// Check for WordPress and run wpscan
	commands.CallWPEnumeration(fmt.Sprintf("%s://%s:%s", scheme, utils.Target,port), dir, port, checks.OptVVerbose)

	// Check for Tomcat and run gobuster + hydra
	commands.CallTomcatEnumeration(utils.Target, fmt.Sprintf("%s://%s:%s/docs",scheme, utils.Target, port), dir, port, checks.OptBrute, checks.OptVVerbose)

	// CeWL + Ffuf Keywords Bruteforcing
	if *checks.OptBrute {
		commands.CallRunCewlandFfufKeywords(utils.Target, dir, port, checks.OptVVerbose)
	}
}



