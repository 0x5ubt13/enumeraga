package protocols

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator/common"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

const (
	webProbeTimeout     = 3 * time.Second
	webProbeConcurrency = 10
)

var (
	httpProbeClient = &http.Client{
		Timeout: webProbeTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpsProbeClient = &http.Client{
		Timeout: webProbeTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
)

// RunWhatWebForDetectedWebPorts probes open ports and launches whatweb when HTTP(S) is detected.
func RunWhatWebForDetectedWebPorts(openPortsSlice []string) {
	ports := uniqueSortedPorts(openPortsSlice)
	if len(ports) == 0 {
		return
	}

	sem := make(chan struct{}, webProbeConcurrency)
	var wg sync.WaitGroup

	var dir string
	var dirOnce sync.Once
	getDir := func() string {
		dirOnce.Do(func() {
			dir = utils.ProtocolDetected("HTTP", utils.BaseDir)
		})
		return dir
	}

	for _, port := range ports {
		// Port 80 and 443 already launch whatweb via the standard HTTP protocol flow.
		if port == "80" || port == "443" {
			continue
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(port string) {
			defer wg.Done()
			defer func() { <-sem }()

			scheme := detectWebScheme(port)
			if scheme == "" {
				return
			}

			whatWebArgs := []string{"whatweb", "-a", "3", "-v", fmt.Sprintf("%s://%s:%s", scheme, utils.Target, port)}
			whatWebPath := fmt.Sprintf("%swhatweb_%s.out", getDir(), port)
			commands.CallRunTool(whatWebArgs, whatWebPath, checks.OptVVerbose)
		}(port)
	}

	wg.Wait()
}

func detectWebScheme(port string) string {
	if probeWebScheme("https", port) {
		return "https"
	}
	if probeWebScheme("http", port) {
		return "http"
	}
	return ""
}

func probeWebScheme(scheme, port string) bool {
	targetURL := fmt.Sprintf("%s://%s:%s", scheme, utils.Target, port)
	req, err := http.NewRequest(http.MethodHead, targetURL, nil)
	if err != nil {
		return false
	}

	client := httpProbeClient
	if scheme == "https" {
		client = httpsProbeClient
	}

	resp, err := client.Do(req)
	if err != nil {
		if scheme == "https" && isTLSCertValidationError(err) {
			// HTTPS endpoint detected but certificate validation failed.
			return true
		}

		// Retry with GET for servers that reject HEAD.
		req, err = http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			return false
		}
		req.Header.Set("Range", "bytes=0-0")

		resp, err = client.Do(req)
		if err != nil {
			if scheme == "https" && isTLSCertValidationError(err) {
				// HTTPS endpoint detected but certificate validation failed.
				return true
			}
			return false
		}
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	return resp.StatusCode >= 100 && resp.StatusCode < 600
}

func isTLSCertValidationError(err error) bool {
	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return true
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}

	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return true
	}

	return false
}

func uniqueSortedPorts(openPortsSlice []string) []string {
	seen := make(map[string]struct{}, len(openPortsSlice))
	portNumbers := make([]int, 0, len(openPortsSlice))

	for _, port := range openPortsSlice {
		if _, ok := seen[port]; ok {
			continue
		}
		portNum, err := strconv.Atoi(port)
		if err != nil {
			continue
		}
		seen[port] = struct{}{}
		portNumbers = append(portNumbers, portNum)
	}

	sort.Ints(portNumbers)
	ports := make([]string, 0, len(portNumbers))
	for _, portNum := range portNumbers {
		ports = append(ports, strconv.Itoa(portNum))
	}
	return ports
}

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
	whatWeb443Args := []string{"whatweb", "-a", "3", "-v", fmt.Sprintf("https://%s:443", utils.Target)}
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
