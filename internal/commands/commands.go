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

// WPEnumeration provides enumeration for WordPress
func WPEnumeration(targetUrl, caseDir, port string, OptVVerbose *bool) {
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
	runTool(wpScanArgs, wpScanPath, OptVVerbose)
}

func tomcatEnumeration(target, targetUrl, caseDir, port string, OptBrute *bool, OptVVerbose *bool) {
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
		runTool(cewlArgs, cewlPath, OptVVerbose)

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
		runTool(ffufArgs, ffufPath, OptVVerbose)
		return
	}

	keywordsList := fmt.Sprintf("%scewl_keywordslist_433.out", caseDir)
	targetURL := fmt.Sprintf("http://%s:443", target)
	cewlArgs := []string{"cewl", "-m7", "--lowercase", "-w", keywordsList, targetURL}
	cewlPath := fmt.Sprintf("%scewl_443.out", caseDir)
	runTool(cewlArgs, cewlPath, OptVVerbose)

	ffufArgs := []string{
		"ffuf",
		"-w", fmt.Sprintf("%s:FOLDERS,%s:KEYWORDS,%s:EXTENSIONS", utils.DirListMedium, keywordsList, utils.ExtensionsList),
		"-u", fmt.Sprintf("http://%s/FOLDERS/KEYWORDSEXTENSIONS", target),
		"-v",
		"-maxtime", "300",
		"-maxtime-job", "300",
	}
	ffufPath := fmt.Sprintf("%sffuf_keywords_443.out", caseDir)
	runTool(ffufArgs, ffufPath, OptVVerbose)
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

// Handle messages for HTTP tools to avoid confusion
func announceCloudTool(tool string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Running '", tool, "'. Please wait...")
}

// Announce tool and run it
func runTool(args []string, filePath string, OptVVerbose *bool) {
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
	go func(OptVVerbose *bool) {
		_, err := io.Copy(file, stdout)
		if err != nil {
			if *OptVVerbose {
				utils.ErrorMsg(fmt.Sprintf("Error copying output for tool %s: %s", tool, err))
			}
		}
	}(OptVVerbose)

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
func RunRangeTools(targetRange string, OptVVerbose *bool, OptOutput *string) {
	// Print Flag detected
	utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] ", "-r", " flag detected. Proceeding to scan CIDR range with dedicated range enumeration tools.")

	// Make CIDR dir
	cidrDir := fmt.Sprintf("%s/%s_range_enum/", *OptOutput, strings.Replace(targetRange, "/", "_", 1))
	utils.CustomMkdir(cidrDir)

	// Get wordlists for the range
	utils.GetWordlists(OptVVerbose)

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
	runTool(msfEternalBlueArgs, msfEternalBluePath, OptVVerbose)

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
func callEternalBlueSweepCheck(msfEternalBlueArgs []string, msfEternalBluePath, dir string, OptVVerbose *bool) {
	utils.Wg.Add(1)

	go func(msfEternalBlueArgs []string, msfEternalBluePath, dir string) {
		defer utils.Wg.Done()

		eternalBlueSweepCheck(msfEternalBlueArgs, msfEternalBluePath, dir, OptVVerbose)
	}(msfEternalBlueArgs, msfEternalBluePath, dir)
}

func CallWPEnumeration(targetUrl, caseDir, port string, OptVVerbose *bool) {
	utils.Wg.Add(1)

	go func(targetUrl, caseDir, port string, OptVVerbose *bool) {
		defer utils.Wg.Done()

		WPEnumeration(targetUrl, caseDir, port, OptVVerbose)
	}(targetUrl, caseDir, port, OptVVerbose)
}

func CallTomcatEnumeration(target, targetUrl, caseDir, port string, OptBrute, OptVVerbose *bool) {
	utils.Wg.Add(1)

	go func(target, targetUrl, caseDir, port string, OptBrute, OptVVerbose *bool) {
		defer utils.Wg.Done()

		tomcatEnumeration(target, targetUrl, caseDir, port, OptBrute, OptVVerbose)
	}(target, targetUrl, caseDir, port, OptBrute, OptVVerbose)
}

// CallRunCewlandFfufKeywords is a Goroutine for runCewlandFfufKeywords()
func CallRunCewlandFfufKeywords(target, caseDir, port string, OptVVerbose *bool) {
	utils.Wg.Add(1)

	go func(target, caseDir, port string, OptVVerbose *bool) {
		defer utils.Wg.Done()

		runCewlandFfufKeywords(target, caseDir, port, OptVVerbose)
	}(target, caseDir, port, OptVVerbose)
}

// CallRunTool is a Goroutine for runTool()
func CallRunTool(args []string, filePath string, OptVVerbose *bool) {
	utils.Wg.Add(1)

	go func(args []string, filePath string, OptVVerbose *bool) {
		defer utils.Wg.Done()

		go runTool(args, filePath, OptVVerbose)
	}(args, filePath, OptVVerbose)
}

// CallIndividualPortScannerWithNSEScripts is a Goroutine for individualPortScannerWithNSEScripts()
func CallIndividualPortScannerWithNSEScripts(target, port, outFile, scripts string, OptVVerbose *bool) {
	utils.Wg.Add(1)

	go func(target, port, outFile, scripts string, OptVVerbose *bool) {
		defer utils.Wg.Done()

		scans.IndividualPortScannerWithNSEScripts(target, port, outFile, scripts, OptVVerbose)
	}(target, port, outFile, scripts, OptVVerbose)
}

// CallIndividualPortScannerWithNSEScriptsAndScriptArgs is a Goroutine for scans.IndividualPortScannerWithNSEScriptsAndScriptArgs()
func CallIndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string, OptVVerbose *bool) {
	utils.Wg.Add(1)

	go func(target, port, outFile, scripts string, scriptArgs map[string]string, OptVVerbose *bool) {
		defer utils.Wg.Done()

		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")
		scans.IndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts, scriptArgs, OptVVerbose)
	}(target, port, outFile, scripts, scriptArgs, OptVVerbose)
}

// CallIndividualUDPPortScannerWithNSEScripts is a Goroutine for scans.IndividualUDPPortScannerWithNSEScripts()
func CallIndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string, OptVVerbose *bool) {
	utils.Wg.Add(1)

	go func(target, port, outFile, scripts string, OptVVerbose *bool) {
		defer utils.Wg.Done()

		scans.IndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts, OptVVerbose)
	}(target, port, outFile, scripts, OptVVerbose)
}

// CallIndividualPortScanner is a Goroutine for scans.IndividualPortScanner()
func CallIndividualPortScanner(target, port, outFile string, OptVVerbose *bool) {
	utils.Wg.Add(1)

	go func(target, port, outFile string, OptVVerbose *bool) {
		defer utils.Wg.Done()

		scans.IndividualPortScanner(target, port, outFile, OptVVerbose)
	}(target, port, outFile, OptVVerbose)
}

// CallFullAggressiveScan is a Goroutine for scans.FullAggressiveScan()
func CallFullAggressiveScan(target, ports, outFile string, OptVVerbose *bool) {
	utils.Wg.Add(1)

	go func(target, ports, outFile string, OptVVerbose *bool) {
		defer utils.Wg.Done()

		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting ", "main aggressive nmap scan ", "against all open ports on'", target, "' and sending it to the background")
		ports = ports + ",1337" // Adding one likely closed port for OS fingerprinting purposes
		scans.FullAggressiveScan(target, ports, outFile, OptVVerbose)
	}(target, ports, outFile, OptVVerbose)
}

/* --------------------------------
   |  Cloud enumeration commands  |
   -------------------------------- */

// Use pipx for all python packages
// func installWithPipx(tool string) error {
// 	if !utils.CheckToolExists("pipx") {
// 		fmt.Println("Installing pipx")
// 		utils.AptGetUpdateCmd()
// 		utils.AptGetInstallCmd("pipx")
// 	}
// 	command := fmt.Sprintf("pipx install %s", tool)
// 	cmd := exec.Command("/bin/sh", "-c", command)
// 	cmd.Stdout = os.Stdout
// 	cmd.Stderr = os.Stderr
// 	return cmd.Run()
// }

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

		// TODO: add flags to pass azure creds?
		commandToRun = fmt.Sprintf("scout %s --no-browser", provider)

	case "prowler":
		if !utils.CheckToolExists("prowler") {
			err := InstallWithPipxOSAgnostic("prowler")
			if err != nil {
				utils.PrintCustomBiColourMsg("red", "cyan", "[-]", "Error installing prowler via pipx")
				return err
			}
		}
		commandToRun = fmt.Sprintf("prowler %s", provider)

	case "cloudfox":
		if !utils.CheckToolExists("cloudfox") {
			utils.PrintCustomBiColourMsg("red", "yellow", "[-] CloudFox ", "not found. Attempting to download it now from GitHub...")
			binaryPath, err := utils.DownloadFromGithubAndInstall("cloudfox")
			if err != nil {
				return fmt.Errorf("error downloading cloudfox: %v", err)
			}

			commandToRun = fmt.Sprintf("%s %s all-checks", binaryPath, provider)
		} else {
			commandToRun = fmt.Sprintf("cloudfox %s all-checks", provider)
		}
	default:
		// Case not registered, try and run it anyway see what could go wrong
		commandToRun = fmt.Sprintf("%s %s", tool, provider)
	}

	// Run the tool
	toolOutput := fmt.Sprintf("%soutput.out", filePath)
	// Ensure path exists
	utils.CustomMkdir(filePath)
	cmd := strings.Split(commandToRun, " ")
	runCloudTool(cmd, toolOutput, OptVVerbose)

	return nil
}

// runCloudTool is a new version of runTool for cloud - Announce cloud tool and run it
func runCloudTool(args []string, filePath string, OptVVerbose *bool) {
	tool := args[0]
	cmdArgs := args[1:]
	command := strings.Join(cmdArgs, " ")
	
	utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Debug -> About to run ", tool, " against ", cmdArgs[0], " using the following command: ", strings.Join(args, " "))
	announceCloudTool(tool)
	
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
			if *OptVVerbose {
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
