package commands

import (
	"bufio"
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/infra"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/scans"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// WPEnumeration provides enumeration for WordPress
func WPEnumeration(targetUrl, caseDir, port string) {
	// Identify WordPress: Run curl
	curl := exec.Command("curl", "-s", "-X", "GET", targetUrl)
	curlOutput, _ := curl.Output()

	// grep 'wp-content'
	if !strings.Contains(string(curlOutput), "wp-content") {
		return
	}

	// Detected, prepare to run wpscan
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!]", "WordPress detected. Running", "WPScan", "...")
	wpScanArgs := []string{"wpscan", "--url", targetUrl, "-e", "p,u"}
	wpScanPath := fmt.Sprintf("%swpscan_%s.out", caseDir, port)
	runTool(wpScanArgs, wpScanPath)
}

func tomcatEnumeration(target, targetUrl, caseDir, port string) {
	// Identify Tomcat: Run curl
	curl := exec.Command("curl", "-s", "-X", "GET", targetUrl)
	curlOutput, _ := curl.Output()

	// grep 'wp-content'
	if !strings.Contains(strings.ToLower(string(curlOutput)), "tomcat") {
		return
	}

	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!]", "Tomcat detected. Running", "Gobuster", "...")

	// Run Gobuster
	gobusterArgs := []string{"gobuster", "-z", "-q", "dir", "-e", "u", fmt.Sprintf("%s:%s", target, port), "-w", utils.DirListMedium}
	gobusterPath := fmt.Sprintf("%stomcat_gobuster.out", caseDir)
	CallRunTool(gobusterArgs, gobusterPath)

	// Run hydra
	if !*infra.OptBrute {
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
	CallRunTool(hydraArgs, hydraPath)
}

func runCewlandFfufKeywords(target, caseDir, port string) {
	if port == "80" {
		keywordsList := fmt.Sprintf("%scewl_keywordslist_80.out", caseDir)
		targetURL := fmt.Sprintf("http://%s:80", target)
		cewlArgs := []string{"cewl", "-m7", "--lowercase", "-w", keywordsList, targetURL}
		cewlPath := fmt.Sprintf("%scewl_80.out", caseDir)
		runTool(cewlArgs, cewlPath)

		ffufArgs := []string{
			"ffuf",
			"-w", fmt.Sprintf("%s:FOLDERS,%s:KEYWORDS,%s:EXTENSIONS", utils.DirListMedium, keywordsList, utils.ExtensionsList),
			"-u", fmt.Sprintf("http://%s/FOLDERS/KEYWORDSEXTENSIONS", target),
			"-v",
			"-maxtime", "300",
			"-maxtime-job", "300",
		}
		fmt.Println(utils.Debug("Debug: ffuf keywords command:", ffufArgs))
		ffufPath := fmt.Sprintf("%sffuf_keywords_80.out", caseDir)
		runTool(ffufArgs, ffufPath)
		return
	}

	keywordsList := fmt.Sprintf("%scewl_keywordslist_433.out", caseDir)
	targetURL := fmt.Sprintf("http://%s:443", target)
	cewlArgs := []string{"cewl", "-m7", "--lowercase", "-w", keywordsList, targetURL}
	cewlPath := fmt.Sprintf("%scewl_443.out", caseDir)
	runTool(cewlArgs, cewlPath)

	ffufArgs := []string{
		"ffuf",
		"-w", fmt.Sprintf("%s:FOLDERS,%s:KEYWORDS,%s:EXTENSIONS", utils.DirListMedium, keywordsList, utils.ExtensionsList),
		"-u", fmt.Sprintf("http://%s/FOLDERS/KEYWORDSEXTENSIONS", target),
		"-v",
		"-maxtime", "300",
		"-maxtime-job", "300",
	}
	ffufPath := fmt.Sprintf("%sffuf_keywords_443.out", caseDir)
	runTool(ffufArgs, ffufPath)
}

func printToolSuccess(command, tool, filePath string) {
	if strings.Contains(command, "80") {
		utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! '", fmt.Sprintf("%s on port 80", tool), "' finished successfully")
		fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(filePath))
		return
	}

	if strings.Contains(command, "443") {
		utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! '", fmt.Sprintf("%s on port 443", tool), "' finished successfully")
		fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(filePath))
		return
	}

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! '", tool, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(filePath))
}

// Handle messages for HTTP tools to avoid confusion
func announceTool(command, tool string) {
	if strings.Contains(command, "80") {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Running '", fmt.Sprintf("%s on port 80", tool), "' and sending it to the background")
	}

	if strings.Contains(command, "443") {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Running '", fmt.Sprintf("%s on port 443", tool), "' and sending it to the background")
	}

	if !strings.Contains(command, "80") && !strings.Contains(command, "443") {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Running '", tool, "' and sending it to the background")
	}
}

// Announce tool and run it
func runTool(args []string, filePath string) {
	tool := args[0]
	cmdArgs := args[1:]
	command := strings.Join(cmdArgs, " ")
	announceTool(command, tool)

	cmd := exec.Command(tool, cmdArgs...)

	// Create a pipe to capture the command's output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating stdout pipe: %s", err))
		os.Exit(1)
	}

	//stderr, err := cmd.StderrPipe()
	//if err != nil {
	//	utils.ErrorMsg(fmt.Sprintf("failed to get stderr pipe: %v", err))
	//	return
	//}

	// Create a file to write the output to
	file, err := os.Create(filePath)
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating output file: %s", err))
		os.Exit(1)
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			utils.ErrorMsg(fmt.Sprintf("Error closing file: %s", err))
		}
	}(file)

	// Start the command asynchronously in a goroutine
	if err := cmd.Start(); err != nil {
		utils.ErrorMsg(fmt.Sprintf("%s%s", "Error starting command:", err))
	}

	//// Copy the output to stdout and stderr
	//go io.Copy(os.Stdout, stdout)
	//go io.Copy(os.Stderr, stderr)

	// This goroutine will capture and write the command's output to a file
	go func() {
		_, err := io.Copy(file, stdout)
		if err != nil {
			if *infra.OptVVerbose {
				utils.ErrorMsg(fmt.Sprintf("Error copying output for tool %s: %s", tool, err))
			}
		}
	}()

	// Wait for the command to complete
	if err := cmd.Wait(); err != nil {
		if tool == "nikto" || tool == "fping" {
			// Nikto and fping don't have a clean exit
			utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! '", tool, "' finished successfully")
			if filePath != "/dev/null" {
				fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(filePath))
			}
		} else {
			fmt.Println(utils.Red("Command"), tool, utils.Red("finished with error:"), utils.Red(err))
		}
	}

	printToolSuccess(command, tool, filePath)
}

// RunRangeTools enumerates a whole CIDR range using specific range tools
func RunRangeTools(targetRange string) {
	// Print Flag detected
	utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] ", "-r", " flag detected. Proceeding to scan CIDR range with dedicated range enumeration tools.")

	// Make CIDR dir
	cidrDir := fmt.Sprintf("%s/%s_range_enum/", *infra.OptOutput, strings.Replace(targetRange, "/", "_", 1))
	utils.CustomMkdir(cidrDir)

	// Get wordlists for the range
	utils.GetWordlists(infra.OptVVerbose)

	// run nbtscan-unixwiz
	nbtscanArgs := []string{"nbtscan-unixwiz", "-f", targetRange}
	nbtscanPath := fmt.Sprintf("%snbtscan-unixwiz.out", cidrDir)
	CallRunTool(nbtscanArgs, nbtscanPath)

	// run Responder-RunFinger
	responderArgs := []string{"responder-RunFinger", "-i", targetRange}
	responderPath := fmt.Sprintf("%srunfinger.out", cidrDir)
	CallRunTool(responderArgs, responderPath)

	// run OneSixtyOne
	oneSixtyOneArgs := []string{"onesixtyone", "-c", utils.UsersList, targetRange, "-w", "100"}
	oneSixtyOnePath := fmt.Sprintf("%sonesixtyone.out", cidrDir)
	CallRunTool(oneSixtyOneArgs, oneSixtyOnePath)

	// run fping
	fpingArgs := []string{"fping", "-asgq", targetRange}
	fpingPath := fmt.Sprintf("%sfping.out", cidrDir)
	CallRunTool(fpingArgs, fpingPath)

	// run Metasploit scan module for EternalBlue
	answer := utils.OSCPConsent("Metasploit")
	if answer == 'n' {
		return
	}
	msfEternalBlueArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use scanner/smb/smb_ms17_010;set rhosts %s;set threads 10;run;exit", targetRange)}
	msfEternalBluePath := fmt.Sprintf("%seternalblue_sweep.txt", cidrDir)
	callEternalBlueSweepCheck(msfEternalBlueArgs, msfEternalBluePath, cidrDir)
}

// eternalBlueSweepCheck is a wee fun module to detect quite low-hanging fruit
func eternalBlueSweepCheck(msfEternalBlueArgs []string, msfEternalBluePath, dir string) {
	// Run msf recon first
	runTool(msfEternalBlueArgs, msfEternalBluePath)

	var confirmedVuln = false

	// Check how many of them are likely
	file, err := os.Open(msfEternalBluePath)
	if err != nil {
		log.Fatal(err)
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
		fmt.Println(err)
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
		log.Fatal(err)
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

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Positive Match! IPs vulnerable to ", "EternalBlue", " !\n\tShortcut: '", fmt.Sprintf("less -R %s", confirmedFile), "'")
}

// Goroutine for eternalBlueSweepCheck()
func callEternalBlueSweepCheck(msfEternalBlueArgs []string, msfEternalBluePath, dir string) {
	utils.Wg.Add(1)

	go func(msfEternalBlueArgs []string, msfEternalBluePath, dir string) {
		defer utils.Wg.Done()

		eternalBlueSweepCheck(msfEternalBlueArgs, msfEternalBluePath, dir)
	}(msfEternalBlueArgs, msfEternalBluePath, dir)
}

func CallWPEnumeration(targetUrl, caseDir, port string) {
	utils.Wg.Add(1)

	go func(targetUrl, caseDir, port string) {
		defer utils.Wg.Done()

		WPEnumeration(targetUrl, caseDir, port)
	}(targetUrl, caseDir, port)
}

func CallTomcatEnumeration(target, targetUrl, caseDir, port string) {
	utils.Wg.Add(1)

	go func(target, targetUrl, caseDir, port string) {
		defer utils.Wg.Done()

		tomcatEnumeration(target, targetUrl, caseDir, port)
	}(target, targetUrl, caseDir, port)
}

// CallRunCewlandFfufKeywords is a Goroutine for runCewlandFfufKeywords()
func CallRunCewlandFfufKeywords(target, caseDir, port string) {
	utils.Wg.Add(1)

	go func(target, caseDir, port string) {
		defer utils.Wg.Done()

		runCewlandFfufKeywords(target, caseDir, port)
	}(target, caseDir, port)
}

// CallRunTool is a Goroutine for runTool()
func CallRunTool(args []string, filePath string) {
	utils.Wg.Add(1)

	go func(args []string, filePath string) {
		defer utils.Wg.Done()

		go runTool(args, filePath)
	}(args, filePath)
}

// CallIndividualPortScannerWithNSEScripts is a Goroutine for individualPortScannerWithNSEScripts()
func CallIndividualPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	utils.Wg.Add(1)

	go func(target, port, outFile, scripts string) {
		defer utils.Wg.Done()

		scans.IndividualPortScannerWithNSEScripts(target, port, outFile, scripts)
	}(target, port, outFile, scripts)
}

// CallIndividualPortScannerWithNSEScriptsAndScriptArgs is a Goroutine for scans.IndividualPortScannerWithNSEScriptsAndScriptArgs()
func CallIndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string) {
	utils.Wg.Add(1)

	go func(target, port, outFile, scripts string, scriptArgs map[string]string) {
		defer utils.Wg.Done()

		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")
		scans.IndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts, scriptArgs)
	}(target, port, outFile, scripts, scriptArgs)
}

// CallIndividualUDPPortScannerWithNSEScripts is a Goroutine for scans.IndividualUDPPortScannerWithNSEScripts()
func CallIndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	utils.Wg.Add(1)

	go func(target, port, outFile, scripts string) {
		defer utils.Wg.Done()

		scans.IndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts)
	}(target, port, outFile, scripts)
}

// CallIndividualPortScanner is a Goroutine for scans.IndividualPortScanner()
func CallIndividualPortScanner(target, port, outFile string) {
	utils.Wg.Add(1)

	go func(target, port, outFile string) {
		defer utils.Wg.Done()

		scans.IndividualPortScanner(target, port, outFile)
	}(target, port, outFile)
}

// CallFullAggressiveScan is a Goroutine for scans.FullAggressiveScan()
func CallFullAggressiveScan(target, ports, outFile string) {
	utils.Wg.Add(1)

	go func(target, ports, outFile string) {
		defer utils.Wg.Done()

		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting ", "main aggressive nmap scan ", "against all open ports on'", target, "' and sending it to the background")
		ports = ports + ",1337" // Adding one likely closed port for OS fingerprinting purposes
		scans.FullAggressiveScan(target, ports, outFile)
	}(target, ports, outFile)
}

/* --------------------------------
   |  Cloud enumeration commands  |
   -------------------------------- */

// runToolInVirtualEnv attempts to leverage shell scripting to download, install, and run a python tool, all contained
// within a virtual environment
func runToolInVirtualEnv(args []string, filePath string) error {
	// Create a temporary directory for the virtual environment
	fmt.Println(utils.Cyan("[*] Debug -> filePath ", filePath))
	tempDir := fmt.Sprintf("%svenv/", filePath)
	fmt.Println(utils.Cyan("[*] Debug -> creating tempDir ", tempDir))
	_, err := utils.CustomMkdir(tempDir)
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("failed to create temp dir: %v", err))
	}
	defer fmt.Println("temp dir ", tempDir, " deleted.")
	defer os.RemoveAll(tempDir) // Clean up the temp directory

	// Create the virtual environment
	//venvPath := filepath.Join(tempDir, "venv")
	cmd := exec.Command("python3", "-m", "venv", tempDir)

	if err := cmd.Run(); err != nil {
		fmt.Printf("failed to create virtualenv: %v\n", err)
	}

	// Activate the virtual environment and install tool
	activateScript := filepath.Join(tempDir, "bin", "activate")
	var installAndRunCmd string
	switch args[0] {
	case "scoutsuite":
		installAndRunCmd = fmt.Sprintf("source %s && pip install %s && scout %s", activateScript, args[0], strings.Join(args[1:], " "))
	default:
		installAndRunCmd = fmt.Sprintf("source %s && pip install %s && %s", activateScript, args[0], strings.Join(args, " "))
	}
	cmd = exec.Command("bash", "-c", installAndRunCmd)

	// Get the output pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("failed to get stdout pipe: %v", err))
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("failed to get stderr pipe: %v", err))
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		utils.ErrorMsg(fmt.Sprintf("failed to start command: %v", err))
	}

	// Copy the output to stdout and stderr
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Installing ", args[0], " via ", "pip", " in a ", "virtual environment. It might take a while...")

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		utils.ErrorMsg(fmt.Sprintf("failed to create virtualenv: %v", err))
	}

	//if err := cmd.Run(); err != nil {
	//	fmt.Errorf("failed to install tool %s: %v", args[0], err)
	//	os.Exit(22)
	//}

	//// Run the tool
	//toolOutput := fmt.Sprintf("%soutput.out", filePath)
	//command := []string{"bash", "-c", fmt.Sprintf("source %s && %s"), activateScript, Strings.args)}
	//
	//runCloudTool(command, toolOutput)
	//cmd = exec.Command("bash", "-c", runCmd)
	//if err := cmd.Run(); err != nil {
	//	return fmt.Errorf("failed to run tool: %v", err)
	//}

	return nil
}

// Scoutsuite launches scout.py
func Scoutsuite(provider, scoutDir string) {
	// run Scout
	// call venv
	// source into the venv
	// run the tool
	// := []string{"python3 -m venv . && \
	//				source ./bin/activate && \
	//				pip install -r 			}

	scoutArgs := []string{"scoutsuite", provider}
	err := runToolInVirtualEnv(scoutArgs, scoutDir)
	if err != nil {
		utils.ErrorMsg(err)
	}
}

// Prowler launches prowler
func Prowler(provider, prowlerDir string) {
	// run Prowler
	prowlerArgs := []string{"prowler", provider}
	prowlerPath := fmt.Sprintf("%sprowler_log.out", prowlerDir)
	CallRunTool(prowlerArgs, prowlerPath)
}

// runCloudTool is a new version of runTool for cloud - Announce cloud tool and run it
func runCloudTool(args []string, filePath string) {
	tool := args[0]
	cmdArgs := args[1:]
	command := strings.Join(cmdArgs, " ")
	announceTool(command, tool)

	cmd := exec.Command(tool, cmdArgs...)

	// Create a pipe to capture the command's output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("Error creating stdout pipe: %s", err))
		os.Exit(1)
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
		os.Exit(1)
	}

	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			utils.ErrorMsg(fmt.Sprintf("Error closing file: %s", err))
		}
	}(file)

	// Start the command asynchronously in a goroutine
	if err := cmd.Start(); err != nil {
		utils.ErrorMsg(fmt.Sprintf("%s%s", "Error starting command:", err))
	}

	// Copy the output to stdout and stderr
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	// This goroutine will capture and write the command's output to a file
	go func() {
		_, err := io.Copy(file, stdout)
		if err != nil {
			if *infra.OptVVerbose {
				utils.ErrorMsg(fmt.Sprintf("Error copying output for tool %s: %s", tool, err))
			}
		}
	}()

	// Wait for the command to complete
	if err := cmd.Wait(); err != nil {
		if tool == "nikto" || tool == "fping" {
			// Nikto and fping don't have a clean exit
			utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! '", tool, "' finished successfully")
			if filePath != "/dev/null" {
				fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(filePath))
			}
		} else {
			fmt.Println(utils.Red("Command"), tool, utils.Red("finished with error:"), utils.Red(err))
		}
	}

	printToolSuccess(command, tool, filePath)
}
