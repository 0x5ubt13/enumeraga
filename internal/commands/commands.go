package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/config"
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

func runCewlandFfufKeywords(target, caseDir, port string, OptVVerbose *bool) {
	if port == "80" {
		keywordsList := fmt.Sprintf("%scewl_keywordslist_80.out", caseDir)
		targetURL := fmt.Sprintf("http://%s:80", target)
		cewlArgs := []string{"cewl", "-m7", "--lowercase", "-w", keywordsList, targetURL}
		cewlPath := fmt.Sprintf("%scewl_80.out", caseDir)
		if err := runTool(cewlArgs, cewlPath, port, OptVVerbose); err == nil {
			printToolSuccess(port, "cewl", cewlPath, -1, -1)
		}

		ffufArgs := []string{
			"ffuf",
			"-w", fmt.Sprintf("%s:FOLDERS,%s:KEYWORDS,%s:EXTENSIONS", utils.DirListMedium, keywordsList, utils.ExtensionsList),
			"-u", fmt.Sprintf("http://%s/FOLDERS/KEYWORDSEXTENSIONS", target),
			"-v",
			"-maxtime", getTimeoutSeconds(),
			"-maxtime-job", getTimeoutSeconds(),
		}
		utils.PrintSafe("%s\n", utils.Debug("[?] Debug: ffuf keywords command:", ffufArgs))
		ffufPath := fmt.Sprintf("%sffuf_keywords_80.out", caseDir)
		if err := runTool(ffufArgs, ffufPath, port, OptVVerbose); err == nil {
			printToolSuccess(port, "ffuf", ffufPath, -1, -1)
		}
		return
	}

	keywordsList := fmt.Sprintf("%scewl_keywordslist_443.out", caseDir)
	targetURL := fmt.Sprintf("https://%s:443", target)
	cewlArgs := []string{"cewl", "-m7", "--lowercase", "-w", keywordsList, targetURL}
	cewlPath := fmt.Sprintf("%scewl_443.out", caseDir)
	if err := runTool(cewlArgs, cewlPath, port, OptVVerbose); err == nil {
		printToolSuccess(port, "cewl", cewlPath, -1, -1)
	}

	ffufArgs := []string{
		"ffuf",
		"-w", fmt.Sprintf("%s:FOLDERS,%s:KEYWORDS,%s:EXTENSIONS", utils.DirListMedium, keywordsList, utils.ExtensionsList),
		"-u", fmt.Sprintf("https://%s/FOLDERS/KEYWORDSEXTENSIONS", target),
		"-v",
		"-maxtime", getTimeoutSeconds(),
		"-maxtime-job", getTimeoutSeconds(),
	}
	ffufPath := fmt.Sprintf("%sffuf_keywords_443.out", caseDir)
	if err := runTool(ffufArgs, ffufPath, port, OptVVerbose); err == nil {
		printToolSuccess(port, "ffuf", ffufPath, -1, -1)
	}
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

	if len(runningTools) > 0 && len(runningTools) <= 10 {
		utils.PrintCustomBiColourMsg("cyan", "white",
			fmt.Sprintf("    Still running: %s", strings.Join(runningTools, ", ")))
	} else if len(runningTools) > 10 {
		utils.PrintCustomBiColourMsg("cyan", "white",
			fmt.Sprintf("    Still running: %d tools", len(runningTools)))
	}
}

// Handle messages for HTTP tools to avoid confusion
func announceTool(command, tool string) {
	total := utils.ToolRegistry.GetTotal()
	running := len(utils.ToolRegistry.GetRunningTools())

	if strings.Contains(command, "80") {
		utils.PrintCustomBiColourMsg("yellow", "cyan",
			fmt.Sprintf("[!] Running '%s on port 80' (%d tools total, %d running)",
				tool, total, running))
	} else if strings.Contains(command, "443") {
		utils.PrintCustomBiColourMsg("yellow", "cyan",
			fmt.Sprintf("[!] Running '%s on port 443' (%d tools total, %d running)",
				tool, total, running))
	} else {
		utils.PrintCustomBiColourMsg("yellow", "cyan",
			fmt.Sprintf("[!] Running '%s' (%d tools total, %d running)",
				tool, total, running))
	}
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

	tool := args[0]
	cmdArgs := args[1:]
	command := strings.Join(cmdArgs, " ")
	announceTool(command, tool)

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
	if err := scanner.Err(); err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error while creating new scanner on file %s: %s", msfEternalBluePath, err))
		return
	}

	for scanner.Scan() {
		line := scanner.Text()
		// Grep -i likely
		if strings.Contains(strings.ToLower(line), "likely") {
			confirmedVuln = true
			_, err := confirmed.WriteString(line + "\n")
			if err != nil {
				utils.ErrorMsg(fmt.Sprintf("Error writing string: %s", err))
				return
			}
		}
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
		if err := scanFunc(); err != nil {
			utils.ErrorMsg(fmt.Sprintf("%s failed: %v", name, err))
			utils.ToolRegistry.CompleteTool(name, false)
			return
		}
		completed, total := utils.ToolRegistry.CompleteTool(name, true)
		printToolSuccess(portNum, name, outputFile+".nmap", completed, total)
	}(toolName, port, outFile)
}

// extractPortFromPath extracts port number from file path for tool naming
func extractPortFromPath(filePath string) string {
	// Check for explicit port numbers in filename or path
	if strings.Contains(filePath, "_80.out") || strings.Contains(filePath, "/80/") {
		return "80"
	} else if strings.Contains(filePath, "_443.out") || strings.Contains(filePath, "/443/") || strings.Contains(filePath, "testssl.out") {
		return "443"
	} else if strings.Contains(filePath, "_8080.out") || strings.Contains(filePath, "/8080/") {
		return "8080"
	} else if strings.Contains(filePath, "_8443.out") || strings.Contains(filePath, "/8443/") {
		return "8443"
	}

	// Check for /http/ directory (ports 80, 443, 8080, 8443)
	if strings.Contains(filePath, "/http/") {
		basename := filepath.Base(filePath)
		// Tools that are specific to certain ports
		if strings.HasPrefix(basename, "wafw00f") || strings.HasPrefix(basename, "whatweb") ||
			strings.HasPrefix(basename, "dirsearch") || strings.HasPrefix(basename, "nikto") {
			// These could be 80 or 443 - check filename more carefully
			if strings.Contains(basename, "80") {
				return "80"
			} else if strings.Contains(basename, "443") {
				return "443"
			}
		}
	}

	// Try to extract port from path pattern like "tool_PORT.out"
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

// PrepCloudTool preps the program to run a cloud tool
// To add more cloud enumeration capabilities, add new switch cases here
func PrepCloudTool(tool, filePath, provider string, OptVVerbose *bool) error {
	var commandToRun string

	// Get name of the tool first
	switch tool {
	case "scoutsuite":
		if !utils.CheckToolExists("scout") {
			err := InstallWithPipxOSAgnostic("scoutsuite")
			if err != nil {
				utils.PrintCustomBiColourMsg("red", "cyan", "[-]", "Error installing scout via pipx")
				return err
			}
		}

		// Future: Add CLI flags to pass Azure credentials for non-interactive auth
		commandToRun = fmt.Sprintf("scout %s --no-browser --report-dir %s", provider, filePath)

	case "prowler":
		if !utils.CheckToolExists("prowler") {
			err := InstallWithPipxOSAgnostic("prowler")
			if err != nil {
				utils.PrintCustomBiColourMsg("red", "cyan", "[-]", "Error installing prowler via pipx")
				return err
			}
		}
		commandToRun = fmt.Sprintf("prowler %s -o %s", provider, filePath)

	case "cloudfox":
		if !utils.CheckToolExists("cloudfox") {
			utils.PrintCustomBiColourMsg("red", "yellow", "[-] CloudFox ", "not found. Attempting to download it now from GitHub...")
			binaryPath, err := utils.DownloadFromGithubAndInstall("cloudfox")
			if err != nil {
				return fmt.Errorf("error downloading cloudfox: %v", err)
			}

			commandToRun = fmt.Sprintf("%s %s all-checks --outdir %s", binaryPath, provider, filePath)
		} else {
			commandToRun = fmt.Sprintf("cloudfox %s all-checks --outdir %s", provider, filePath)
		}

	case "pmapper":
		if provider != "aws" {
			utils.PrintCustomBiColourMsg("red", "yellow", "[-]", " PMapper ", "only supports", " AWS ", ". Skipping it...")
			break
		}

		// // Run conda init
		// condaErr := exec.Command("conda", "init", "bash")
		// if condaErr != nil {
		// 	return fmt.Errorf("error running conda init: %v", condaErr)
		// }

		commandToRun = fmt.Sprintf("source /opt/conda/etc/profile.d/conda.sh && conda init bash && conda activate pmapper && export PRINCIPALMAPPER_DATA_DIR=%s && pmapper graph create", filePath)
	case "kubenumerate":
		if provider != "k8s" {
			utils.PrintCustomBiColourMsg("red", "yellow", "[-]", " Kubenumerate ", "must be run with the", " k8s ", "flag. Skipping it...")
			break
		}
		commandToRun = fmt.Sprintf("python3 kubenumerate.py -o %s", filePath)
	default:
		// Case not registered, try and run it anyway see what could go wrong
		utils.ErrorMsg(fmt.Sprintf("Tool %s not supported", tool))
	}

	// Run the tool
	toolOutput := fmt.Sprintf("%soutput.out", filePath)
	// Ensure path exists
	_, err := utils.CustomMkdir(filePath)
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating custom dir %s: %v", filePath, err))
	}

	cmd := strings.Split(commandToRun, " ")
	runCloudTool(cmd, toolOutput, OptVVerbose)

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

	// Use MultiWriter to copy stdout to both console and file simultaneously
	multiWriter := io.MultiWriter(os.Stdout, file)

	go func() {
		_, err := io.Copy(multiWriter, stdout)
		if err != nil {
			if *OptVVerbose {
				utils.ErrorMsg(fmt.Sprintf("Error copying stdout for tool %s: %v", tool, err))
			}
		}
	}()

	go func() {
		_, err := io.Copy(os.Stderr, stderr)
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
