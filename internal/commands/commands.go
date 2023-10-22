package commands

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/scans"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// Enumeration for WordPress
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

func TomcatEnumeration(target, targetUrl, caseDir, port string) {
	// Identify Tomat: Run curl
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
	if !*utils.OptBrute {
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

// Announce tool and run it
func runTool(args []string, filePath string) {
	tool := args[0]
	cmdArgs := args[1:]

	// Handle messages for HTTP tools to avoid confusion
	command := strings.Join(cmdArgs, " ")
	if strings.Contains(command, "80") {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Running '", fmt.Sprintf("%s on port 80", tool), "' and sending it to the background")
	}

	if strings.Contains(command, "443") {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Running '", fmt.Sprintf("%s on port 443", tool), "' and sending it to the background")
	}

	if !strings.Contains(command, "80") && !strings.Contains(command, "443") {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Running '", tool, "' and sending it to the background")
	}

	cmd := exec.Command(tool, cmdArgs...)

	// Create a pipe to capture the command's output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("Error creating stdout pipe:", err)
		os.Exit(1)
	}

	// Create a file to write the output
	file, err := os.Create(filePath)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		os.Exit(1)
	}
	defer file.Close()

	// Start the command asynchronously in a goroutine
	if err := cmd.Start(); err != nil {
		fmt.Printf("%s%s\n", "Error starting command:", err)
	}

	// This goroutine will capture and write the command's output to a file
	go func() {
		_, err := io.Copy(file, stdout)
		if err != nil {
			if *utils.OptVVervose {
				fmt.Println("Error copying output for tool", tool, ":", err)
			}
		}
	}()

	// Wait for the command to complete
	if err := cmd.Wait(); err != nil {
		if tool == "nikto" || tool == "fping" {
			// Nikto and fping don't have a clean exit
			utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! '", fmt.Sprintf("%s on port 80", tool), "' finished successfully")
			fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(filePath))
		} else {
			fmt.Println(utils.Red("Command"), tool, utils.Red("finished with error:"), utils.Red(err))
		}
	}

	printToolSuccess(command, tool, filePath)
}

// Enumerate a whole CIDR range using specific range tools
func RunRangeTools(targetRange string) {
	// Print Flag detected
	utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] ", "-r", " flag detected. Proceeding to scan CIDR range with dedicated range enumeration tools.")

	// Make CIDR dir
	cidrDir := fmt.Sprintf("%s/%s_range_enum/", *utils.OptOutput, strings.Replace(targetRange, "/", "_", 1))
	utils.CustomMkdir(cidrDir)

	// Get wordlists for the range
	utils.GetWordlists()

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
	msfEternalBlueArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use scanner/smb/smb_ms17_010;set rhosts %s;set threads 10;run;exit", targetRange)}
	msfEternalBluePath := fmt.Sprintf("%seternalblue_sweep.txt", cidrDir)
	callEternalBlueSweepCheck(msfEternalBlueArgs, msfEternalBluePath, cidrDir)
}

// Wee fun module to detect quite low hanging fruit
func eternalBlueSweepCheck(msfEternalBlueArgs []string, msfEternalBluePath, dir string) {
	// Run msf recon first
	runTool(msfEternalBlueArgs, msfEternalBluePath)

	var confirmedVuln = false

	// Check how many of them are likely
	file, err := os.Open(msfEternalBluePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	confirmedFile := fmt.Sprintf("%seternalblue_confirmed.txt", dir)
	confirmed, err := os.Create(confirmedFile)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer confirmed.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// Grep -i likely
		if strings.Contains(strings.ToLower(line), "likely") {
			confirmedVuln = true
			confirmed.WriteString(line + "\n")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
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

// Goroutine for runCewlandFfufKeywords()
func CallRunCewlandFfufKeywords(target, caseDir, port string) {
	utils.Wg.Add(1)

	go func(target, caseDir, port string) {
		defer utils.Wg.Done()

		runCewlandFfufKeywords(target, caseDir, port)
	}(target, caseDir, port)
}

// Goroutine for runTool()
func CallRunTool(args []string, filePath string) {
	utils.Wg.Add(1)

	go func(args []string, filePath string) {
		defer utils.Wg.Done()

		go runTool(args, filePath)
	}(args, filePath)
}

// Goroutine for individualPortScannerWithNSEScripts()
func CallIndividualPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	utils.Wg.Add(1)

	go func(target, port, outFile, scripts string) {
		defer utils.Wg.Done()

		scans.IndividualPortScannerWithNSEScripts(target, port, outFile, scripts)
	}(target, port, outFile, scripts)
}

// Goroutine for scans.IndividualPortScannerWithNSEScriptsAndScriptArgs()
func CallIndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string) {
	utils.Wg.Add(1)

	go func(target, port, outFile, scripts string, scriptArgs map[string]string) {
		defer utils.Wg.Done()

		scans.IndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts, scriptArgs)
	}(target, port, outFile, scripts, scriptArgs)
}

// Goroutine for scans.IndividualUDPPortScannerWithNSEScripts()
func CallIndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	utils.Wg.Add(1)

	go func(target, port, outFile, scripts string) {
		defer utils.Wg.Done()

		scans.IndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts)
	}(target, port, outFile, scripts)
}

// Goroutine for scans.IndividualPortScanner()
func CallIndividualPortScanner(target, port, outFile string) {
	utils.Wg.Add(1)

	go func(target, port, outFile string) {
		defer utils.Wg.Done()

		scans.IndividualPortScanner(target, port, outFile)
	}(target, port, outFile)
}

// Goroutine for scans.FullAggressiveScan()
func CallFullAggressiveScan(target, ports, outFile string) {
	utils.Wg.Add(1)

	go func(target, ports, outFile string) {
		defer utils.Wg.Done()

		scans.FullAggressiveScan(target, ports, outFile)
	}(target, ports, outFile)
}
