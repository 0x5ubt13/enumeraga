package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/config"
	"github.com/0x5ubt13/enumeraga/internal/installer"
	"github.com/0x5ubt13/enumeraga/internal/scans"
	"github.com/0x5ubt13/enumeraga/internal/types"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/xuri/excelize/v2"
)

// getTimeoutSeconds returns the configured timeout in seconds as a string.
// Uses ToolTimeout (in minutes) from utils package.
func getTimeoutSeconds() string {
	return strconv.Itoa(utils.ToolTimeout * 60)
}

// WPEnumeration provides enumeration for WordPress
func WPEnumeration(targetUrl, caseDir, port string, OptVVerbose *bool) {
	// Identify WordPress: Run curl
	curl := exec.Command("curl", "-s", "-X", "GET", targetUrl)
	curlOutput, err := curl.Output()
	if err != nil {
		if *OptVVerbose {
			utils.ErrorMsg(fmt.Sprintf("Failed to curl target for WordPress detection: %v", err))
		}
		return
	}

	// grep 'wp-content'
	if !strings.Contains(string(curlOutput), "wp-content") {
		return
	}

	// Detected, prepare to run wpscan (with connection timeouts)
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!]", "WordPress detected. Running", "WPScan", "...")
	wpScanArgs := []string{"wpscan", "--url", targetUrl, "-e", "p,u", "--request-timeout", "30", "--connect-timeout", "30", "--max-threads", "5"}
	wpScanPath := fmt.Sprintf("%swpscan_%s.out", caseDir, port)
	CallRunTool(wpScanArgs, wpScanPath, OptVVerbose)
}

func tomcatEnumeration(target, targetUrl, caseDir, port string, OptBrute *bool, OptVVerbose *bool) {
	// Identify Tomcat: Run curl
	curl := exec.Command("curl", "-s", "-X", "GET", targetUrl)
	curlOutput, err := curl.Output()
	if err != nil {
		if *OptVVerbose {
			utils.ErrorMsg(fmt.Sprintf("Failed to curl target for Tomcat detection: %v", err))
		}
		return
	}

	// grep 'tomcat'
	if !strings.Contains(strings.ToLower(string(curlOutput)), "tomcat") {
		return
	}

	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!]", "Tomcat detected. Running", "Gobuster", "...")

	// Run Gobuster
	gobusterArgs := []string{"gobuster", "-z", "-q", "dir", "-e", "-u", fmt.Sprintf("%s:%s", target, port), "-w", utils.DirListMedium, "--timeout", getTimeoutSeconds() + "s"}
	gobusterPath := fmt.Sprintf("%stomcat_gobuster.out", caseDir)
	CallRunTool(gobusterArgs, gobusterPath, OptVVerbose)

	// Run hydra
	if !*OptBrute {
		return
	}

	hydraArgs := []string{
		"hydra",
		"-L", utils.UsersList,
		"-P", utils.DarkwebTop1000,
		"-f", target,
		"http-get", "/manager/html",
	}
	hydraPath := fmt.Sprintf("%stomcat_hydra.out", caseDir)
	CallRunTool(hydraArgs, hydraPath, OptVVerbose)
}

func runCewlAndFfuf(target, caseDir, port, scheme string, OptVVerbose *bool) {
	keywordsList := fmt.Sprintf("%scewl_keywordslist_%s.out", caseDir, port)
	targetURL := fmt.Sprintf("%s://%s:%s", scheme, target, port)
	cewlArgs := []string{"cewl", "-m7", "--lowercase", "-w", keywordsList, targetURL}
	cewlPath := fmt.Sprintf("%scewl_%s.out", caseDir, port)
	if err := runTool(cewlArgs, cewlPath, port, OptVVerbose); err == nil {
		printToolSuccess(port, "cewl", cewlPath, -1, -1)
	}

	ffufArgs := []string{
		"ffuf",
		"-w", fmt.Sprintf("%s:FOLDERS,%s:KEYWORDS,%s:EXTENSIONS", utils.DirListMedium, keywordsList, utils.ExtensionsList),
		"-u", fmt.Sprintf("%s://%s/FOLDERS/KEYWORDSEXTENSIONS", scheme, target),
		"-v",
		"-maxtime", getTimeoutSeconds(),
		"-maxtime-job", getTimeoutSeconds(),
	}
	utils.PrintSafe("%s\n", utils.Debug("[?] Debug: ffuf keywords command:", ffufArgs))
	ffufPath := fmt.Sprintf("%sffuf_keywords_%s.out", caseDir, port)
	if err := runTool(ffufArgs, ffufPath, port, OptVVerbose); err == nil {
		printToolSuccess(port, "ffuf", ffufPath, -1, -1)
	}
}

func runCewlandFfufKeywords(target, caseDir, port string, OptVVerbose *bool) {
	if port == "80" {
		runCewlAndFfuf(target, caseDir, port, "http", OptVVerbose)
		return
	}
	runCewlAndFfuf(target, caseDir, port, "https", OptVVerbose)
}

func printToolSuccess(command, tool, filePath string, completed, total int) {
	if completed == -1 {
		completed, total = utils.ToolRegistry.GetProgress()
	}
	runningTools := utils.ToolRegistry.GetRunningTools()

	progressStr := fmt.Sprintf("[%d/%d]", completed, total)

	// If command (port) is not empty, show it in the message
	var toolDesc string
	if command != "" {
		toolDesc = fmt.Sprintf("%s on port %s", tool, command)
	} else {
		toolDesc = tool
	}

	utils.PrintCustomBiColourMsg("green", "cyan",
		fmt.Sprintf("[+] Done! '%s' finished successfully %s",
			toolDesc, progressStr))

	utils.PrintCustomBiColourMsg("yellow", "cyan",
		fmt.Sprintf("    Shortcut: less -R '%s'", filePath))

	n := len(runningTools)
	if n > 0 && n <= 10 {
		utils.PrintCustomBiColourMsg("cyan", "white",
			fmt.Sprintf("    Still running: %s", strings.Join(runningTools, ", ")))
	} else if n > 10 {
		utils.PrintCustomBiColourMsg("cyan", "white",
			fmt.Sprintf("    Still running: %d tools", n))
	}
}

// Handle messages for HTTP tools to avoid confusion
func announceTool(tool, port string) {
	total := utils.ToolRegistry.GetTotal()
	running := len(utils.ToolRegistry.GetRunningTools())

	var label string
	if port != "" {
		label = fmt.Sprintf("%s on port %s", tool, port)
	} else {
		label = tool
	}
	utils.PrintCustomBiColourMsg("yellow", "cyan",
		fmt.Sprintf("[!] Running '%s' (%d tools total, %d running)", label, total, running))
}

// Handle messages for HTTP tools to avoid confusion
func announceCloudTool(tool string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Running '", tool, "'. Please wait...")
}

// Announce tool and run it
func runTool(args []string, filePath string, port string, OptVVerbose *bool) error {
	// Check if shutdown is in progress before starting
	if utils.IsShuttingDown() {
		return nil
	}

	args = applyGentleArgs(args)

	tool := args[0]
	cmdArgs := args[1:]
	announceTool(tool, port)

	if delay := utils.ToolStartDelay(); delay > 0 {
		time.Sleep(delay)
	}

	// Use CommandContext to allow cancellation via global context
	ctx := utils.GetGlobalContext()
	cmd := exec.CommandContext(ctx, tool, cmdArgs...)

	// Create pipes to capture the command's output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating stdout pipe: %s", err))
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating stderr pipe: %s", err))
		return err
	}

	// Create a file to write the output to
	file, err := os.Create(filePath)
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating output file: %s", err))
		return err
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			utils.ErrorMsg(fmt.Sprintf("Error closing file: %s", err))
		}
	}(file)

	// Start the command asynchronously in a goroutine
	if err := cmd.Start(); err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error starting command %s: %v", tool, err))
		return err
	}

	// Capture stdout and stderr concurrently to prevent blocking
	var wg sync.WaitGroup
	wg.Add(2)

	// Capture and write the command's stdout to a file
	go func() {
		defer wg.Done()
		_, err := io.Copy(file, stdout)
		if err != nil {
			if *OptVVerbose {
				utils.ErrorMsg(fmt.Sprintf("Error copying stdout for tool %s: %s", tool, err))
			}
		}
	}()

	// Discard stderr to prevent buffer blocking (tools often write progress to stderr)
	go func() {
		defer wg.Done()
		_, err := io.Copy(io.Discard, stderr)
		if err != nil {
			if *OptVVerbose {
				utils.ErrorMsg(fmt.Sprintf("Error discarding stderr for tool %s: %s", tool, err))
			}
		}
	}()

	// Wait for output capture to complete
	wg.Wait()

	// Wait for the command to complete
	if err := cmd.Wait(); err != nil {
		// Check if the error was due to context cancellation (shutdown)
		if ctx.Err() == context.Canceled {
			utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Tool '", tool, "' terminated due to shutdown")
			return err
		}
		if tool == "nikto" || tool == "fping" {
			// Nikto and fping don't have a clean exit
			// We return nil as success for these tools
			return nil
		} else {
			utils.PrintSafe("%s %s %s %s\n", utils.Red("Command"), tool, utils.Red("finished with error:"), utils.Red(err))
			return err
		}
	}

	return nil
}

// RunRangeTools enumerates a whole CIDR range using specific range tools
func RunRangeTools(targetRange string, OptVVerbose *bool, OptOutput *string) {
	// Validate CIDR range before proceeding
	if err := utils.ValidateCIDR(targetRange); err != nil {
		utils.ErrorMsg(fmt.Sprintf("Invalid CIDR range provided: %v", err))
		return
	}

	// Print Flag detected
	utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] ", "-r", " flag detected. Proceeding to scan CIDR range with dedicated range enumeration tools.")

	// Make CIDR dir
	cidrDir := fmt.Sprintf("%s/%s_range_enum/", *OptOutput, strings.Replace(targetRange, "/", "_", 1))
	_, err := utils.CustomMkdir(cidrDir)
	if err != nil {
		utils.ErrorMsg("error trying to make dir")
	}

	// Get wordlists for the range
	if err := utils.GetWordlists(OptVVerbose); err != nil {
		utils.ErrorMsg(fmt.Sprintf("wordlist warning: %v", err))
	}

	// run nbtscan-unixwiz
	nbtscanArgs := []string{"nbtscan-unixwiz", "-f", targetRange}
	nbtscanPath := fmt.Sprintf("%snbtscan-unixwiz.out", cidrDir)
	CallRunTool(nbtscanArgs, nbtscanPath, OptVVerbose)

	// run Responder-RunFinger
	responderArgs := []string{"responder-RunFinger", "-i", targetRange}
	responderPath := fmt.Sprintf("%srunfinger.out", cidrDir)
	CallRunTool(responderArgs, responderPath, OptVVerbose)

	// run OneSixtyOne
	oneSixtyOneArgs := []string{"onesixtyone", "-c", utils.UsersList, targetRange, "-w", "100"}
	oneSixtyOnePath := fmt.Sprintf("%sonesixtyone.out", cidrDir)
	CallRunTool(oneSixtyOneArgs, oneSixtyOnePath, OptVVerbose)

	// run fping
	fpingArgs := []string{"fping", "-asgq", targetRange}
	fpingPath := fmt.Sprintf("%sfping.out", cidrDir)
	CallRunTool(fpingArgs, fpingPath, OptVVerbose)

	// run Metasploit scan module for EternalBlue
	answer := utils.OSCPConsent("Metasploit")
	if answer == 'n' {
		return
	}
	msfEternalBlueArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use scanner/smb/smb_ms17_010;set rhosts %s;set threads 10;run;exit", targetRange)}
	msfEternalBluePath := fmt.Sprintf("%seternalblue_sweep.txt", cidrDir)
	callEternalBlueSweepCheck(msfEternalBlueArgs, msfEternalBluePath, cidrDir, OptVVerbose)
}

// eternalBlueSweepCheck is a wee fun module to detect quite low-hanging fruit
func eternalBlueSweepCheck(msfEternalBlueArgs []string, msfEternalBluePath, dir string, OptVVerbose *bool) {
	// Run msf recon first
	if err := runTool(msfEternalBlueArgs, msfEternalBluePath, "445", OptVVerbose); err == nil {
		printToolSuccess("445", "msfconsole (eternalblue)", msfEternalBluePath, -1, -1)
	}

	var confirmedVuln = false

	// Check how many of them are likely
	file, err := os.Open(msfEternalBluePath)
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error opening eternal blue results file: %v", err))
		return
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			utils.ErrorMsg(fmt.Sprintf("Error closing file: %s", err))
		}
	}(file)

	confirmedFile := fmt.Sprintf("%seternalblue_confirmed.txt", dir)
	confirmed, err := os.Create(confirmedFile)
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating confirmed file: %v", err))
		return
	}
	defer func(confirmed *os.File) {
		err := confirmed.Close()
		if err != nil {
			utils.ErrorMsg(fmt.Sprintf("Error closing file: %s", err))
		}
	}(confirmed)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Grep -i likely
		if strings.Contains(strings.ToLower(line), "likely") {
			confirmedVuln = true
			if _, err := confirmed.WriteString(line + "\n"); err != nil {
				utils.ErrorMsg(fmt.Sprintf("Error writing string: %s", err))
				return
			}
		}
	}
	if err := scanner.Err(); err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error scanning file %s: %s", msfEternalBluePath, err))
	}

	if !confirmedVuln {
		utils.PrintCustomBiColourMsg("red", "cyan", "[-] No matches", "<- Metasploit module for EternalBlue")
		return
	}

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Positive Match! IPs vulnerable to ", "EternalBlue", " !\n\tShortcut: '", fmt.Sprintf("less -R '%s'", confirmedFile), "'")
}

// Goroutine for eternalBlueSweepCheck()
func callEternalBlueSweepCheck(msfEternalBlueArgs []string, msfEternalBluePath, dir string, OptVVerbose *bool) {
	runAsync(func() {
		eternalBlueSweepCheck(msfEternalBlueArgs, msfEternalBluePath, dir, OptVVerbose)
	})
}

// CallWPEnumeration is an async wrapper for WordPress enumeration.
func CallWPEnumeration(targetUrl, caseDir, port string, OptVVerbose *bool) {
	runAsync(func() {
		WPEnumeration(targetUrl, caseDir, port, OptVVerbose)
	})
}

// CallTomcatEnumeration is an async wrapper for Tomcat enumeration.
func CallTomcatEnumeration(target, targetUrl, caseDir, port string, OptBrute, OptVVerbose *bool) {
	runAsync(func() {
		tomcatEnumeration(target, targetUrl, caseDir, port, OptBrute, OptVVerbose)
	})
}

// CallRunCewlandFfufKeywords is a Goroutine for runCewlandFfufKeywords()
func CallRunCewlandFfufKeywords(target, caseDir, port string, OptVVerbose *bool) {
	runAsync(func() {
		runCewlandFfufKeywords(target, caseDir, port, OptVVerbose)
	})
}

// AsyncFunc is the function signature for async functions
type AsyncFunc func()

// NmapScanFunc is the function signature for nmap scan functions that return error
type NmapScanFunc func() error

// runAsync is a simple helper to run a function asynchronously with WaitGroup tracking and worker pool throttling
func runAsync(fn AsyncFunc) {
	utils.Wg.Add(1)
	go func() {
		defer utils.Wg.Done()

		// Acquire a worker slot (blocks if pool is full)
		pool := utils.GetWorkerPool()
		if !pool.Acquire() {
			// Shutdown in progress, skip
			return
		}
		defer pool.Release()

		fn()
	}()
}

// runNmapScanAsync is a generic helper to run nmap scans asynchronously with tool registration and worker pool throttling
// It handles: WaitGroup, tool registration, goroutine spawning, error handling, success printing, and concurrency limiting
func runNmapScanAsync(toolName string, port string, outFile string, scanFunc NmapScanFunc) {
	utils.ToolRegistry.RegisterTool(toolName)
	utils.Wg.Add(1)

	go func(name, portNum, outputFile string) {
		defer utils.Wg.Done()

		// Acquire a worker slot (blocks if pool is full)
		pool := utils.GetWorkerPool()
		if !pool.Acquire() {
			// Shutdown in progress, skip this tool
			utils.ToolRegistry.CompleteTool(name, false)
			return
		}
		defer pool.Release()

		utils.ToolRegistry.StartTool(name)
		if delay := utils.ToolStartDelay(); delay > 0 {
			time.Sleep(delay)
		}
		if err := scanFunc(); err != nil {
			utils.ErrorMsg(fmt.Sprintf("%s failed: %v", name, err))
			utils.ToolRegistry.CompleteTool(name, false)
			return
		}
		completed, total := utils.ToolRegistry.CompleteTool(name, true)
		printToolSuccess(portNum, name, outputFile+".nmap", completed, total)
	}(toolName, port, outFile)
}

func applyGentleArgs(args []string) []string {
	if !utils.GentleMode || len(args) == 0 {
		return args
	}

	tool := args[0]
	out := make([]string, len(args))
	copy(out, args)

	switch tool {
	case "ffuf":
		out = setFlagValue(out, "-rate", "50")
		out = setFlagValue(out, "-t", "2")
	case "dirsearch":
		out = setFlagValue(out, "-t", "2")
	case "gobuster":
		out = setFlagValue(out, "-t", "5")
	case "hydra":
		out = setFlagValue(out, "-t", "2")
	case "wpscan":
		out = setFlagValue(out, "--max-threads", "1")
	case "whatweb":
		out = setFlagValue(out, "-a", "1")
	}

	return out
}

func setFlagValue(args []string, flag string, value string) []string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			args[i+1] = value
			return args
		}
	}
	return append(args, flag, value)
}

// portPatternTable maps ports to the path substrings that unambiguously identify them.
var portPatternTable = []struct {
	port     string
	patterns []string
}{
	{"80", []string{"_80.out", "/80/"}},
	{"443", []string{"_443.out", "/443/", "testssl.out"}},
	{"8080", []string{"_8080.out", "/8080/"}},
	{"8443", []string{"_8443.out", "/8443/"}},
}

// httpPortTools are tools whose output filenames embed the port number within /http/ paths.
var httpPortTools = []string{"wafw00f", "whatweb", "dirsearch", "nikto"}

// extractPortFromPath extracts the port number from an output file path.
func extractPortFromPath(filePath string) string {
	for _, entry := range portPatternTable {
		for _, pat := range entry.patterns {
			if strings.Contains(filePath, pat) {
				return entry.port
			}
		}
	}

	if strings.Contains(filePath, "/http/") {
		basename := filepath.Base(filePath)
		for _, tool := range httpPortTools {
			if strings.HasPrefix(basename, tool) {
				if strings.Contains(basename, "80") {
					return "80"
				}
				if strings.Contains(basename, "443") {
					return "443"
				}
				break
			}
		}
	}

	// Fall back to "tool_PORT.out" filename convention
	parts := strings.Split(filepath.Base(filePath), "_")
	if len(parts) >= 2 {
		portStr := strings.TrimSuffix(parts[len(parts)-1], ".out")
		if _, err := strconv.Atoi(portStr); err == nil {
			return portStr
		}
	}
	return ""
}

// CallRunTool is a Goroutine for runTool() with worker pool throttling
func CallRunTool(args []string, filePath string, OptVVerbose *bool) {
	toolName := args[0]
	port := extractPortFromPath(filePath)
	if port != "" {
		toolName = fmt.Sprintf("%s on port %s", args[0], port)
	}

	utils.ToolRegistry.RegisterTool(toolName)
	utils.Wg.Add(1)

	go func(args []string, filePath string, OptVVerbose *bool, name, portNum string) {
		defer utils.Wg.Done()

		// Acquire a worker slot (blocks if pool is full)
		pool := utils.GetWorkerPool()
		if !pool.Acquire() {
			// Shutdown in progress, skip this tool
			utils.ToolRegistry.CompleteTool(name, false)
			return
		}
		defer pool.Release()

		utils.ToolRegistry.StartTool(name)
		err := runTool(args, filePath, portNum, OptVVerbose)
		completed, total := utils.ToolRegistry.CompleteTool(name, err == nil)
		if err == nil {
			printToolSuccess(portNum, args[0], filePath, completed, total)
		}
	}(args, filePath, OptVVerbose, toolName, port)
}

// CallIndividualPortScannerWithNSEScripts is a Goroutine for individualPortScannerWithNSEScripts()
func CallIndividualPortScannerWithNSEScripts(target, port, outFile, scripts string, OptVVerbose *bool) {
	toolName := fmt.Sprintf("nmap NSE on port %s", port)
	runNmapScanAsync(toolName, port, outFile, func() error {
		return scans.IndividualPortScannerWithNSEScripts(target, port, outFile, scripts, OptVVerbose)
	})
}

// CallIndividualPortScannerWithNSEScriptsAndScriptArgs is a Goroutine for scans.IndividualPortScannerWithNSEScriptsAndScriptArgs()
func CallIndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string, OptVVerbose *bool) {
	toolName := fmt.Sprintf("nmap NSE with args on port %s", port)
	runNmapScanAsync(toolName, port, outFile, func() error {
		return scans.IndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts, scriptArgs, OptVVerbose)
	})
}

// CallIndividualUDPPortScannerWithNSEScripts is a Goroutine for scans.IndividualUDPPortScannerWithNSEScripts()
func CallIndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string, OptVVerbose *bool) {
	toolName := fmt.Sprintf("nmap UDP on port %s", port)
	runNmapScanAsync(toolName, port, outFile, func() error {
		return scans.IndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts, OptVVerbose)
	})
}

// CallIndividualPortScanner is a Goroutine for scans.IndividualPortScanner()
func CallIndividualPortScanner(target, port, outFile string, OptVVerbose *bool) {
	toolName := fmt.Sprintf("nmap on port %s", port)
	runNmapScanAsync(toolName, port, outFile, func() error {
		return scans.IndividualPortScanner(target, port, outFile, OptVVerbose)
	})
}

// CallFullAggressiveScan is a Goroutine for scans.FullAggressiveScan()
func CallFullAggressiveScan(target, ports, outFile string, OptVVerbose *bool) {
	toolName := "nmap full aggressive scan"
	// Adding one likely closed port for OS fingerprinting purposes
	portsWithClosed := ports + ",1337"
	runNmapScanAsync(toolName, "", outFile, func() error {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting ", "main aggressive nmap scan ", "against all open ports on '", target, "' and sending it to the background")
		return scans.FullAggressiveScan(target, portsWithClosed, outFile, OptVVerbose)
	})
}

/* --------------------------------
   |  Cloud enumeration commands  |
   -------------------------------- */

// InstallWithPipxOSAgnostic installs a pipx in any supported OS
func InstallWithPipxOSAgnostic(tool string) error {
	// Check pipx is not there in the first place just in case
	if !utils.CheckToolExists("pipx") {
		fmt.Println("Installing pipx")

		switch utils.HostOS.OS {
		case "windows":
			// Use PowerShell to install pipx on Windows
			cmd := exec.Command("powershell", "-Command", "iwr https://bootstrap.pypa.io/get-pip.py -OutFile get-pip.py; python get-pip.py; pip install pipx; pipx ensurepath")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("error installing pipx on Windows: %v", err)
			}
		case "darwin":
			// Use Homebrew to install pipx on macOS
			cmd := exec.Command("/bin/sh", "-c", "brew install pipx")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("error installing pipx on macOS: %v", err)
			}
		case "linux":
			// Use apt-get to install pipx on Linux
			utils.AptGetUpdateCmd()
			utils.AptGetInstallCmd("pipx")
		default:
			return fmt.Errorf("unsupported operating system")
		}
	}

	command := fmt.Sprintf("pipx install %s", tool)
	var cmd *exec.Cmd
	if utils.HostOS.OS == "windows" {
		cmd = exec.Command("powershell", "-Command", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// resolveGCPIAMBruteEmail determines the service account email to use with gcp-iam-brute.
// Priority: explicit config override → client_email from creds JSON → gcloud config get-value account.
func resolveGCPIAMBruteEmail(cfg *config.CloudConfig) (string, error) {
	if cfg.GCPIAMBruteEmail != "" {
		return cfg.GCPIAMBruteEmail, nil
	}
	if cfg.CredsFile != "" {
		data, err := os.ReadFile(cfg.CredsFile) //nolint:gosec // path already validated by validateCredsFile
		if err == nil {
			var creds struct {
				ClientEmail string `json:"client_email"`
			}
			if jsonErr := json.Unmarshal(data, &creds); jsonErr == nil && creds.ClientEmail != "" {
				return creds.ClientEmail, nil
			}
		}
	}
	// Try the Google tokeninfo endpoint using any raw access token from the environment.
	// This works for stolen ya29.xxx tokens that are not registered with gcloud.
	for _, envKey := range []string{"GOOGLE_OAUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN"} {
		token := strings.TrimSpace(os.Getenv(envKey))
		if token == "" {
			continue
		}
		resp, httpErr := http.Get("https://oauth2.googleapis.com/tokeninfo?access_token=" + token) //nolint:noctx,gosec // public endpoint, token is alphanumeric
		if httpErr != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		var info struct {
			Email string `json:"email"`
		}
		decErr := json.NewDecoder(resp.Body).Decode(&info)
		resp.Body.Close()
		if decErr == nil && info.Email != "" {
			return info.Email, nil
		}
	}
	out, err := exec.Command("gcloud", "config", "get-value", "account").Output()
	if err == nil {
		email := strings.TrimSpace(string(out))
		if email != "" && email != "(unset)" {
			return email, nil
		}
	}
	return "", fmt.Errorf("could not determine service account email; use --iam-brute-email to set it explicitly")
}

// shellQuote wraps s in single quotes, escaping any embedded single quotes.
// Use this when interpolating file paths into shell command strings.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// ResolveGCPProject returns the active GCP project ID.
// Priority: explicit cfg.GCPProject → well-known env vars → gcloud config get-value project.
// Returns ("", nil) when no project can be determined so callers can decide whether to skip.
func ResolveGCPProject(cfg *config.CloudConfig) (string, error) {
	if cfg.GCPProject != "" {
		return cfg.GCPProject, nil
	}
	for _, envKey := range []string{"GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "CLOUDSDK_CORE_PROJECT"} {
		if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
			return v, nil
		}
	}
	out, err := exec.Command("gcloud", "config", "get-value", "project").Output()
	if err != nil {
		return "", fmt.Errorf("gcloud config get-value project failed: %w", err)
	}
	project := strings.TrimSpace(string(out))
	if project == "" || project == "(unset)" {
		return "", nil
	}
	return project, nil
}

// resolveGCPIAMBruteToken obtains a GCP access token.
// Checks environment variables first (set by --gcp-token or the Docker wrapper) so that
// stolen ya29.xxx tokens work without being registered with gcloud.
func resolveGCPIAMBruteToken(_ *config.CloudConfig) (string, error) {
	for _, envKey := range []string{"GOOGLE_OAUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN"} {
		if token := strings.TrimSpace(os.Getenv(envKey)); token != "" {
			return token, nil
		}
	}
	out, err := exec.Command("gcloud", "auth", "print-access-token").Output()
	if err != nil {
		return "", fmt.Errorf("gcloud auth print-access-token failed: %w", err)
	}
	token := strings.TrimSpace(string(out))
	if token == "" {
		return "", fmt.Errorf("gcloud auth print-access-token returned an empty token")
	}
	return token, nil
}

// PrepCloudTool preps the program to run a cloud tool
// To add more cloud enumeration capabilities, add new switch cases here
// PrepCloudTool preps the program to run a cloud tool.
// To add more cloud enumeration capabilities, add a new case and a corresponding prep function.
func PrepCloudTool(tool, filePath string, cfg *config.CloudConfig, OptVVerbose *bool) error {
	var (
		commandToRun string
		err          error
	)

	switch tool {
	case "scoutsuite":
		commandToRun, err = prepScoutsuite(cfg, filePath)
	case "prowler":
		commandToRun, err = prepProwler(cfg, filePath)
	case "cloudfox":
		commandToRun, err = prepCloudfox(cfg, filePath)
	case "pmapper":
		commandToRun, err = prepPmapper(cfg, filePath)
	case "kubenumerate":
		commandToRun, err = prepKubenumerate(cfg, filePath)
	case "gcp_scanner":
		commandToRun, err = prepGcpScanner(cfg, filePath)
	case "monkey365":
		return runMonkey365(cfg, filePath)
	case "nuclei":
		commandToRun, err = prepNuclei(cfg)
	case "gcp_iam_brute":
		commandToRun, err = prepGcpIAMBrute(cfg)
	default:
		utils.ErrorMsg(fmt.Sprintf("Tool %s not supported", tool))
	}

	if err != nil {
		return err
	}
	if commandToRun == "" {
		return nil
	}

	toolOutput := fmt.Sprintf("%soutput.out", filePath)
	if _, mkErr := utils.CustomMkdir(filePath); mkErr != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating custom dir %s: %v", filePath, mkErr))
	}
	runCloudTool(strings.Split(commandToRun, " "), toolOutput, OptVVerbose)
	return nil
}

func prepScoutsuite(cfg *config.CloudConfig, filePath string) (string, error) {
	if !utils.CheckToolExists("scout") {
		if err := InstallWithPipxOSAgnostic("scoutsuite"); err != nil {
			utils.PrintCustomBiColourMsg("red", "cyan", "[-]", "Error installing scout via pipx")
			return "", err
		}
	}
	// ScoutSuite depends on pkg_resources (setuptools), which is absent in Python 3.12+
	// virtual environments. Inject it silently — pipx inject is idempotent.
	_ = exec.Command("pipx", "inject", "scoutsuite", "setuptools").Run()
	cmd := fmt.Sprintf("scout %s --no-browser --report-dir %s", cfg.Provider, filePath)
	if cfg.Provider == "gcp" {
		if cfg.CredsFile != "" {
			cmd += fmt.Sprintf(" --service-account %s", shellQuote(cfg.CredsFile))
		} else {
			// ScoutSuite requires exactly one of -u/--user-account or -s/--service-account.
			// Without a key file, use user-account mode which picks up ADC.
			cmd += " -u"
		}
	}
	return cmd, nil
}

func prepProwler(cfg *config.CloudConfig, filePath string) (string, error) {
	if !utils.CheckToolExists("prowler") {
		if err := InstallWithPipxOSAgnostic("prowler"); err != nil {
			utils.PrintCustomBiColourMsg("red", "cyan", "[-]", "Error installing prowler via pipx")
			return "", err
		}
	}
	cmd := fmt.Sprintf("prowler %s -o %s", cfg.Provider, filePath)
	if cfg.Provider == "gcp" && cfg.CredsFile != "" {
		cmd += fmt.Sprintf(" --credentials-file %s", shellQuote(cfg.CredsFile))
	}
	return cmd, nil
}

func prepCloudfox(cfg *config.CloudConfig, filePath string) (string, error) {
	binary := "cloudfox"
	if !utils.CheckToolExists("cloudfox") {
		utils.PrintCustomBiColourMsg("red", "yellow", "[-] CloudFox ", "not found. Attempting to download it now from GitHub...")
		binaryPath, err := utils.DownloadFromGithubAndInstall("cloudfox")
		if err != nil {
			return "", fmt.Errorf("error downloading cloudfox: %v", err)
		}
		binary = binaryPath
	}

	switch cfg.Provider {
	case "aws":
		cmd := fmt.Sprintf("%s aws all-checks --outdir %s", binary, filePath)
		if cfg.AWSProfile != "" {
			cmd += fmt.Sprintf(" --profile %s", cfg.AWSProfile)
		}
		return cmd, nil
	case "gcp":
		// GOOGLE_APPLICATION_CREDENTIALS env var is set by validateCredsFile upstream.
		cmd := fmt.Sprintf("%s gcp all-checks --outdir %s", binary, filePath)
		if cfg.GCPProject != "" {
			cmd += fmt.Sprintf(" --project %s", cfg.GCPProject)
		}
		return cmd, nil
	case "azure":
		return fmt.Sprintf("%s azure inventory --outdir %s", binary, filePath), nil
	default:
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] CloudFox ", "does not support provider '", cfg.Provider, "'. Skipping...")
		return "", nil
	}
}

func prepPmapper(cfg *config.CloudConfig, filePath string) (string, error) {
	if cfg.Provider != "aws" {
		utils.PrintCustomBiColourMsg("red", "yellow", "[-]", " PMapper ", "only supports", " AWS ", ". Skipping it...")
		return "", nil
	}
	return fmt.Sprintf("source /opt/conda/etc/profile.d/conda.sh && conda init bash && conda activate pmapper && export PRINCIPALMAPPER_DATA_DIR=%s && pmapper graph create", filePath), nil
}

func prepKubenumerate(cfg *config.CloudConfig, filePath string) (string, error) {
	if cfg.Provider != "k8s" {
		utils.PrintCustomBiColourMsg("red", "yellow", "[-]", " Kubenumerate ", "must be run with the", " k8s ", "flag. Skipping it...")
		return "", nil
	}
	return fmt.Sprintf("python3 kubenumerate.py -o %s", filePath), nil
}

func prepGcpScanner(cfg *config.CloudConfig, filePath string) (string, error) {
	if cfg.Provider != "gcp" {
		utils.PrintCustomBiColourMsg("red", "yellow", "[-]", " gcp_scanner ", "must be run with the", " gcp ", "flag. Skipping it...")
		return "", nil
	}

	// Newer PyPI releases install the entry-point as "gcp-scanner" (hyphen);
	// older ones used "gcp_scanner" (underscore). Accept either.
	binary := ""
	switch {
	case utils.CheckToolExists("gcp-scanner"):
		binary = "gcp-scanner"
	case utils.CheckToolExists("gcp_scanner"):
		binary = "gcp_scanner"
	default:
		if err := InstallWithPipxOSAgnostic("gcp-scanner"); err != nil {
			utils.PrintCustomBiColourMsg("red", "cyan", "[-]", "Error installing gcp-scanner via pipx")
			return "", err
		}
		if utils.CheckToolExists("gcp-scanner") {
			binary = "gcp-scanner"
		} else {
			binary = "gcp_scanner"
		}
	}

	// gcp-scanner requires exactly one auth flag: -k (SA key), -at (access token),
	// -g (gcloud profile path), -m (metadata server), or -rt (refresh token).
	cmd := fmt.Sprintf("%s -o %s", binary, filePath)
	if cfg.GCPProject != "" {
		cmd += fmt.Sprintf(" -p %s", cfg.GCPProject)
	}
	switch {
	case cfg.CredsFile != "":
		// SA JSON key file
		cmd += fmt.Sprintf(" -k %s", shellQuote(cfg.CredsFile))
	case os.Getenv("CLOUDSDK_AUTH_ACCESS_TOKEN") != "" || os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN") != "":
		// gcp-scanner -at expects a FILE PATH, not the raw token string.
		// Write the token to a temp file and pass that.
		token := os.Getenv("CLOUDSDK_AUTH_ACCESS_TOKEN")
		if token == "" {
			token = os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN")
		}
		// gcp-scanner expects {"access_token": "..."} JSON, not a plain token string.
		tokenFile := os.TempDir() + "/enumeraga-gcp-at.json"
		tokenJSON := fmt.Sprintf(`{"access_token":%q}`, strings.TrimSpace(token))
		if err := os.WriteFile(tokenFile, []byte(tokenJSON), 0600); err != nil {
			utils.ErrorMsg(fmt.Errorf("gcp-scanner: failed to write token file: %w", err))
		} else {
			cmd += fmt.Sprintf(" -at %s", tokenFile)
		}
	default:
		// Fall back to gcloud profile if available
		if home, err := os.UserHomeDir(); err == nil {
			gcloudDir := home + "/.config/gcloud"
			if _, err := os.Stat(gcloudDir); err == nil {
				cmd += fmt.Sprintf(" -g %s", gcloudDir)
			}
		}
	}
	return cmd, nil
}

func prepNuclei(cfg *config.CloudConfig) (string, error) {
	if !cfg.NucleiEnabled {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] ", "Nuclei", " disabled. Skipping cloud template scan...")
		return "", nil
	}
	if cfg.NucleiTargetURL == "" {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Nuclei", "skipped: no target URL provided (set NucleiTargetURL in config to enable cloud template scans)")
		return "", nil
	}
	if !utils.CheckToolExists("nuclei") {
		utils.PrintCustomBiColourMsg("red", "yellow", "[-] nuclei", "not found. Install it via: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
		return "", nil
	}
	return fmt.Sprintf("nuclei -u %s -t cloud/%s/ -silent -no-interactivity -no-color", cfg.NucleiTargetURL, cfg.Provider), nil
}

func prepGcpIAMBrute(cfg *config.CloudConfig) (string, error) {
	if cfg.Provider != "gcp" {
		utils.PrintCustomBiColourMsg("red", "yellow", "[-]", " gcp_iam_brute ", "must be run with the", " gcp ", "flag. Skipping it...")
		return "", nil
	}
	if !cfg.GCPIAMBruteEnabled {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] gcp_iam_brute", "disabled. Skipping...")
		return "", nil
	}
	if cfg.GCPProject == "" {
		project, err := ResolveGCPProject(cfg)
		if err != nil {
			utils.PrintCustomBiColourMsg("red", "yellow", "[-] gcp_iam_brute",
				fmt.Sprintf("could not auto-detect GCP project: %v. Skipping...", err))
			return "", nil
		}
		if project == "" {
			utils.PrintCustomBiColourMsg("red", "yellow", "[-] gcp_iam_brute",
				"requires --project to be set and none could be auto-detected. Skipping...")
			return "", nil
		}
		cfg.GCPProject = project
	}
	if !utils.CheckToolExists("gcp_iam_brute") {
		if err := installer.InstallGCPIAMBrute(); err != nil {
			return "", fmt.Errorf("gcp_iam_brute install failed: %w", err)
		}
	}
	email, err := resolveGCPIAMBruteEmail(cfg)
	if err != nil {
		utils.PrintCustomBiColourMsg("red", "yellow", "[-] gcp_iam_brute", fmt.Sprintf("could not determine service account email: %v. Skipping...", err))
		return "", nil
	}
	token, err := resolveGCPIAMBruteToken(cfg)
	if err != nil {
		utils.PrintCustomBiColourMsg("red", "yellow", "[-] gcp_iam_brute", fmt.Sprintf("could not obtain access token: %v. Skipping...", err))
		return "", nil
	}
	// Access tokens are alphanumeric (ya29.*) — no spaces, safe to interpolate into the command.
	return fmt.Sprintf("gcp-iam-brute --access-token %s --project-id %s --service-account-email %s", token, cfg.GCPProject, email), nil
}

// runMonkey365 generates a temporary PowerShell script and executes it with pwsh.
// monkey365 is a PowerShell module so it cannot be invoked as a plain CLI command;
// instead we write a .ps1 that imports the module and calls Invoke-Monkey365 with
// the appropriate parameters, then run it non-interactively via pwsh.
func runMonkey365(cfg *config.CloudConfig, filePath string) error {
	// Build the Invoke-Monkey365 parameter block dynamically.
	// ClientSecret must be converted to a SecureString inline.
	var psLines []string
	psLines = append(psLines, `Import-Module monkey365 -ErrorAction Stop`)
	psLines = append(psLines, `$param = @{`)
	psLines = append(psLines, `    Instance = 'Azure'`)
	psLines = append(psLines, `    Collect  = 'All'`)
	psLines = append(psLines, `    ExportTo = @("JSON","HTML")`)
	psLines = append(psLines, fmt.Sprintf(`    OutDir   = '%s'`, filePath))

	if cfg.AzureTenantID != "" {
		psLines = append(psLines, fmt.Sprintf(`    TenantID = '%s'`, cfg.AzureTenantID))
	}
	if cfg.AzureSubscription != "" {
		psLines = append(psLines, fmt.Sprintf(`    Subscriptions = '%s'`, cfg.AzureSubscription))
	}
	if cfg.AzureClientID != "" {
		psLines = append(psLines, fmt.Sprintf(`    ClientId = '%s'`, cfg.AzureClientID))
	}
	if cfg.AzureClientSecret != "" {
		// Avoid embedding the secret as a plain string in the script —
		// read it from an env var that we set in the child process environment instead.
		psLines = append(psLines, `    ClientSecret = ($env:MONKEY365_CLIENT_SECRET | ConvertTo-SecureString -AsPlainText -Force)`)
	}

	psLines = append(psLines, `}`)
	psLines = append(psLines, `Invoke-Monkey365 @param`)

	script := strings.Join(psLines, "\n")

	// Write to a temp file so we don't need to escape the whole block for -Command.
	tmpFile, err := os.CreateTemp("", "monkey365-*.ps1")
	if err != nil {
		return fmt.Errorf("monkey365: failed to create temp script: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(script); err != nil {
		tmpFile.Close()
		return fmt.Errorf("monkey365: failed to write temp script: %w", err)
	}
	tmpFile.Close()

	toolOutput := fmt.Sprintf("%soutput.out", filePath)
	args := []string{"-NonInteractive", "-File", tmpFile.Name()}

	// Pass the client secret via env var to avoid it appearing in the script file on disk.
	ctx := utils.GetGlobalContext()
	cmd := exec.CommandContext(ctx, "pwsh", args...) //nolint:gosec // args are constructed from validated config fields, not raw user input
	if cfg.AzureClientSecret != "" {
		cmd.Env = append(os.Environ(), fmt.Sprintf("MONKEY365_CLIENT_SECRET=%s", cfg.AzureClientSecret))
	} else {
		cmd.Env = os.Environ()
	}

	announceCloudTool("monkey365")

	file, err := os.Create(toolOutput)
	if err != nil {
		return fmt.Errorf("monkey365: failed to create output file: %w", err)
	}
	defer file.Close()

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("monkey365: stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("monkey365: stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("monkey365: failed to start pwsh: %w", err)
	}

	multiWriter := io.MultiWriter(os.Stdout, file)
	go func() { _, _ = io.Copy(multiWriter, stdout) }()
	go func() { _, _ = io.Copy(os.Stderr, stderr) }()

	if err := cmd.Wait(); err != nil {
		if ctx.Err() == context.Canceled {
			utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] monkey365 terminated due to shutdown")
			return nil
		}
		return fmt.Errorf("monkey365: pwsh exited with error: %w", err)
	}

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] monkey365 finished. Output: ", filePath)
	return nil
}

// runCloudTool is a new version of runTool for cloud - Announce cloud tool and run it
func runCloudTool(args []string, filePath string, OptVVerbose *bool) {
	// Check if shutdown is in progress before starting
	if utils.IsShuttingDown() {
		return
	}

	tool := args[0]
	cmdArgs := args[1:]
	command := strings.Join(cmdArgs, " ")

	utils.PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> About to run ", tool, " against ", cmdArgs[0], " using the following command: ", strings.Join(args, " "))
	announceCloudTool(tool)

	// Use CommandContext to allow cancellation via global context
	ctx := utils.GetGlobalContext()
	cmd := exec.CommandContext(ctx, tool, cmdArgs...)

	// Create a pipe to capture the command's output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating stdout pipe: %s", err))
		return
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("failed to get stderr pipe: %v", err))
		return
	}

	// Create a file to write the output to
	file, err := os.Create(filePath)
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating output file: %s", err))
		return
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			if *OptVVerbose {
				utils.ErrorMsg(fmt.Sprintf("Error closing file: %s", err))
			}
		}
	}(file)

	// Start the command asynchronously in a goroutine
	if err := cmd.Start(); err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error starting command %s: %v", tool, err))
		return
	}

	// gcp-iam-brute emits thousands of lines of verbose progress; send it to file only.
	var stdoutDst io.Writer
	var stderrDst io.Writer
	if tool == "gcp-iam-brute" {
		stdoutDst = file
		stderrDst = file
	} else {
		stdoutDst = io.MultiWriter(os.Stdout, file)
		stderrDst = os.Stderr
	}

	go func() {
		_, err := io.Copy(stdoutDst, stdout)
		if err != nil {
			if *OptVVerbose {
				utils.ErrorMsg(fmt.Sprintf("Error copying stdout for tool %s: %v", tool, err))
			}
		}
	}()

	go func() {
		_, err := io.Copy(stderrDst, stderr)
		if err != nil {
			if *OptVVerbose {
				utils.ErrorMsg(fmt.Sprintf("Error copying stderr: %v", err))
			}
		}
	}()

	// Wait for the command to complete
	if err := cmd.Wait(); err != nil {
		// Check if the error was due to context cancellation (shutdown)
		if ctx.Err() == context.Canceled {
			utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Cloud tool '", tool, "' terminated due to shutdown")
			return
		}
		if tool == "nikto" || tool == "fping" {
			// Nikto and fping don't have a clean exit
			utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! '", tool, "' finished successfully")
			if filePath != "/dev/null" {
				utils.PrintCustomBiColourMsg("yellow", "cyan", "\tShortcut: less -R '", filePath, "'")
			}
			return
		} else {
			utils.PrintSafe("%s %s %s %s\n", utils.Red("Command"), tool, utils.Red("finished with error:"), utils.Red(err))
			return
		}
	}

	printToolSuccess(command, tool, filePath, -1, -1)
}

// RunCloudScan orchestrates the cloud security scanning
func RunCloudScan(cfg *config.CloudConfig) error {
	findings := make([]types.Finding, 0)

	for _, provider := range cfg.Providers {
		// Run tools concurrently if enabled
		if cfg.Concurrent {
			results := make(chan types.ScanResult)
			toolsLaunched := 0

			if cfg.ScoutSuiteEnabled {
				toolsLaunched++
				go func() {
					result := runScoutSuite(provider, cfg)
					results <- result
				}()
			}

			if cfg.ProwlerEnabled {
				toolsLaunched++
				go func() {
					result := runProwler(provider, cfg)
					results <- result
				}()
			}

			// Collect results based on how many tools were actually launched
			for i := 0; i < toolsLaunched; i++ {
				result := <-results
				if result.Error != nil {
					utils.ErrorMsg(fmt.Sprintf("Error running %s for %s: %v",
						result.Tool, result.Provider, result.Error))
					continue
				}
				findings = append(findings, result.Findings...)
			}
		}
	}

	// Generate report
	return generateReport(findings, cfg)
}

func runScoutSuite(provider string, cfg *config.CloudConfig) types.ScanResult {
	announceCloudTool("ScoutSuite")

	// Prepare output directory
	outputDir := fmt.Sprintf("%s/scoutsuite_%s", cfg.OutputPath, provider)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return types.ScanResult{
			Provider: provider,
			Tool:     "ScoutSuite",
			Error:    fmt.Errorf("failed to create output directory: %v", err),
		}
	}

	// Prepare command arguments
	args := []string{
		"scout",
		provider,
		"--format", "json",
		"--report-dir", outputDir,
		"--no-browser",
	}

	// Add provider-specific arguments
	switch provider {
	case "aws":
		if cfg.AWSProfile != "" {
			args = append(args, "--profile", cfg.AWSProfile)
		}
	case "azure":
		if cfg.AzureSubscription != "" {
			args = append(args, "--subscription", cfg.AzureSubscription)
		}
	case "gcp":
		if cfg.GCPProject != "" {
			args = append(args, "--project", cfg.GCPProject)
		}
		if cfg.CredsFile != "" {
			args = append(args, "--service-account", cfg.CredsFile)
		} else {
			args = append(args, "-u")
		}
	}

	// Run ScoutSuite
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return types.ScanResult{
			Provider:  provider,
			Tool:      "ScoutSuite",
			RawOutput: string(output),
			Error:     fmt.Errorf("ScoutSuite failed: %v", err),
		}
	}

	// Parse results
	findings, err := parseScoutSuiteResults(outputDir)
	if err != nil {
		return types.ScanResult{
			Provider:  provider,
			Tool:      "ScoutSuite",
			RawOutput: string(output),
			Error:     fmt.Errorf("failed to parse ScoutSuite results: %v", err),
		}
	}

	return types.ScanResult{
		Provider:  provider,
		Tool:      "ScoutSuite",
		Findings:  findings,
		RawOutput: string(output),
	}
}

func runProwler(provider string, cfg *config.CloudConfig) types.ScanResult {
	announceCloudTool("Prowler")

	// Prepare output directory
	outputDir := fmt.Sprintf("%s/prowler_%s", cfg.OutputPath, provider)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return types.ScanResult{
			Provider: provider,
			Tool:     "Prowler",
			Error:    fmt.Errorf("failed to create output directory: %v", err),
		}
	}

	// Prepare command arguments
	outputFile := fmt.Sprintf("%s/prowler_report.json", outputDir)
	args := []string{
		"prowler",
		provider,
		"-M", "json",
		"-o", outputFile,
		"--no-banner",
	}

	// Add provider-specific arguments
	switch provider {
	case "aws":
		if cfg.AWSProfile != "" {
			args = append(args, "-p", cfg.AWSProfile)
		}
	case "azure":
		if cfg.AzureSubscription != "" {
			args = append(args, "-s", cfg.AzureSubscription)
		}
	case "gcp":
		if cfg.GCPProject != "" {
			args = append(args, "-P", cfg.GCPProject)
		}
	}

	// Run Prowler
	cmd := exec.Command(args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return types.ScanResult{
			Provider:  provider,
			Tool:      "Prowler",
			RawOutput: string(output),
			Error:     fmt.Errorf("prowler failed: %v", err),
		}
	}

	// Parse results
	findings, err := parseProwlerResults(outputFile)
	if err != nil {
		return types.ScanResult{
			Provider:  provider,
			Tool:      "Prowler",
			RawOutput: string(output),
			Error:     fmt.Errorf("failed to parse Prowler results: %v", err),
		}
	}

	return types.ScanResult{
		Provider:  provider,
		Tool:      "Prowler",
		Findings:  findings,
		RawOutput: string(output),
	}
}

func parseScoutSuiteResults(outputDir string) ([]types.Finding, error) {
	// Read ScoutSuite's JSON report
	reportFile := filepath.Join(outputDir, "scoutsuite-report", "report.json")
	data, err := os.ReadFile(reportFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read ScoutSuite report: %v", err)
	}

	// Parse JSON
	var report struct {
		Findings map[string]map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse ScoutSuite JSON: %v", err)
	}

	// Convert to our Finding type
	var findings []types.Finding
	for service, serviceFindings := range report.Findings {
		for id, data := range serviceFindings {
			finding := types.Finding{
				ID:          id,
				Service:     service,
				Tool:        "ScoutSuite",
				Severity:    mapScoutSuiteSeverity(data),
				Resource:    getStringValue(data, "resource"),
				Description: getStringValue(data, "description"),
				Remediation: getStringValue(data, "remediation"),
				RawData:     data,
			}
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func parseProwlerResults(filePath string) ([]types.Finding, error) {
	// Read Prowler's JSON report
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Prowler report: %v", err)
	}

	// Parse JSON
	var prowlerFindings []struct {
		Status      string `json:"Status"`
		ServiceName string `json:"ServiceName"`
		ResourceID  string `json:"ResourceId"`
		Message     string `json:"Message"`
		Severity    string `json:"Severity"`
		Risk        string `json:"Risk"`
		Remediation string `json:"Remediation"`
	}
	if err := json.Unmarshal(data, &prowlerFindings); err != nil {
		return nil, fmt.Errorf("failed to parse Prowler JSON: %v", err)
	}

	// Convert to our Finding type
	var findings []types.Finding
	for _, pf := range prowlerFindings {
		finding := types.Finding{
			Service:     pf.ServiceName,
			Tool:        "Prowler",
			Severity:    mapProwlerSeverity(pf.Severity),
			Resource:    pf.ResourceID,
			Description: pf.Message,
			Remediation: pf.Remediation,
			RawData:     pf,
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

func mapScoutSuiteSeverity(data interface{}) types.Severity {
	if m, ok := data.(map[string]interface{}); ok {
		if level, ok := m["level"].(string); ok {
			switch strings.ToLower(level) {
			case "critical":
				return types.Critical
			case "high":
				return types.High
			case "medium":
				return types.Medium
			case "low":
				return types.Low
			}
		}
	}
	return types.Info
}

func mapProwlerSeverity(severity string) types.Severity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return types.Critical
	case "HIGH":
		return types.High
	case "MEDIUM":
		return types.Medium
	case "LOW":
		return types.Low
	default:
		return types.Info
	}
}

func getStringValue(data interface{}, key string) string {
	if m, ok := data.(map[string]interface{}); ok {
		if val, ok := m[key].(string); ok {
			return val
		}
	}
	return ""
}

func generateReport(findings []types.Finding, cfg *config.CloudConfig) error {
	f := excelize.NewFile()
	defer func() {
		if err := f.Close(); err != nil {
			utils.ErrorMsg(fmt.Sprintf("Error closing Excel file: %v", err))
		}
	}()

	// Remove default Sheet1
	_ = f.DeleteSheet("Sheet1")

	// Sort findings by provider and severity
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Provider != findings[j].Provider {
			return findings[i].Provider < findings[j].Provider
		}
		return string(findings[i].Severity) < string(findings[j].Severity)
	})

	// Group findings by provider
	providerFindings := make(map[string][]types.Finding)
	for _, finding := range findings {
		providerFindings[finding.Provider] = append(providerFindings[finding.Provider], finding)
	}

	// Create summary sheet
	createSummarySheet(f, providerFindings)

	// Create provider-specific sheets
	for provider, findings := range providerFindings {
		createProviderSheet(f, provider, findings)
	}

	// Generate output filename with timestamp
	timestamp := time.Now().Format("20060102_150405")
	outputPath := fmt.Sprintf("%s/cloud_security_scan_%s.xlsx", cfg.OutputPath, timestamp)

	// Save the Excel file
	if err := f.SaveAs(outputPath); err != nil {
		return fmt.Errorf("error saving Excel file: %v", err)
	}

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Report generated successfully: ", outputPath)
	return nil
}

func createSummarySheet(f *excelize.File, providerFindings map[string][]types.Finding) {
	sheetName := "Summary"
	_, _ = f.NewSheet(sheetName)

	// Set headers
	headers := []string{"Provider", "Critical", "High", "Medium", "Low", "Info", "Total"}
	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		_ = f.SetCellValue(sheetName, cell, header)
	}

	// Add provider summaries
	row := 2
	for provider, findings := range providerFindings {
		severityCounts := countSeverities(findings)
		total := len(findings)

		_ = f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), provider)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), severityCounts[types.Critical])
		_ = f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), severityCounts[types.High])
		_ = f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), severityCounts[types.Medium])
		_ = f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), severityCounts[types.Low])
		_ = f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), severityCounts[types.Info])
		_ = f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), total)
		row++
	}
}

func createProviderSheet(f *excelize.File, provider string, findings []types.Finding) {
	_, _ = f.NewSheet(provider)

	// Set headers
	headers := []string{"Severity", "Service", "Resource", "Description", "Remediation"}
	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		_ = f.SetCellValue(provider, cell, header)
	}

	// Add findings
	for i, finding := range findings {
		row := i + 2
		_ = f.SetCellValue(provider, fmt.Sprintf("A%d", row), finding.Severity)
		_ = f.SetCellValue(provider, fmt.Sprintf("B%d", row), finding.Service)
		_ = f.SetCellValue(provider, fmt.Sprintf("C%d", row), finding.Resource)
		_ = f.SetCellValue(provider, fmt.Sprintf("D%d", row), finding.Description)
		_ = f.SetCellValue(provider, fmt.Sprintf("E%d", row), finding.Remediation)
	}
}

func countSeverities(findings []types.Finding) map[types.Severity]int {
	counts := make(map[types.Severity]int)
	for _, finding := range findings {
		counts[finding.Severity]++
	}
	return counts
}
