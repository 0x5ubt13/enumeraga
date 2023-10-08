package commands

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/flags"
	"github.com/0x5ubt13/enumeraga/internal/scans"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

func aptGetUpdateCmd() {
	// Run the apt-get update command
	fmt.Printf("%s %s%s ", utils.Yellow("[!] Running"), utils.Cyan("apt-get update"), utils.Yellow("..."))
	update := exec.Command("apt-get", "update")

	// Redirect the command's error output to the standard output in terminal
	update.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *flags.OptDbg {
		fmt.Println(utils.Cyan("[*] Debug -> printing apt-get update's output ------"))
		update.Stdout = os.Stdout
	}

	// Run the command
	updateErr := update.Run()
	if updateErr != nil {
		if *flags.OptDbg {
			fmt.Printf("Debug - Error running apt-get update: %v\n", updateErr)
		}
		return
	}

	fmt.Println(utils.Green("Done!"))
}

func installEnum4linuxNg() error {
	// Ask for consent first of all
	utils.PrintCustomBiColourMsg("yellow", "cyan", "Do you want for ", "Enumeraga ", "to try and handle the installation of '", "enum4linux-ng", "'? \nIt might be the case you have it in your machine but not in your $PATH.\nBear in mind that this will call '", "pip", "' as root (", "[Y] ", "'yes, install it for me' / ", "[N] ", "'no, I want to install it myself': ")
	consentv2 := bufio.NewScanner(os.Stdin)
	consentv2.Scan()
	userInputv2 := strings.ToLower(consentv2.Text())

	if userInputv2 != "yes" && userInputv2 != "y" {
		consentv2Err := fmt.Errorf("%s", "Error. Consent not given")
		return consentv2Err
	}

	fmt.Printf("%s %s%s\n", utils.Yellow("[!] Checking pre-requisites to install '"), utils.Cyan("enum4linux-ng"), utils.Yellow("'..."))

	reqs := []string{"python3-ldap3", "python3-yaml", "python3-impacket", "pip"}
	for _, tool := range reqs {
		if !updated {
			aptGetUpdateCmd()
			updated = true
		}
		aptGetInstallCmd(tool)
	}

	// Run git clone "https://github.com/cddmp/enum4linux-ng"
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Installing '", "enum4linux-ng", "' ...")

	// Git clone
	gitClone := exec.Command("git", "clone", "https://github.com/cddmp/enum4linux-ng", "/usr/share/enum4linux-ng")

	// Redirect the command's error output to the standard output in terminal
	gitClone.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *flags.OptDbg {
		fmt.Println(utils.Cyan("[*] Debug -> printing git clone's output ------"))
		gitClone.Stdout = os.Stdout
	}

	// Run the command
	gitCloneErr := gitClone.Run()
	if gitCloneErr != nil {
		if *flags.OptDbg {
			fmt.Printf("Debug - Error running git clone: %v\n", gitCloneErr)
		}
		return gitCloneErr
	}

	// Run Pip install wheel
	pipInstallWheel := exec.Command("pip", "install", "wheel", "clone")

	// Redirect the command's error output to the standard output in terminal
	pipInstallWheel.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *flags.OptDbg {
		fmt.Println(utils.Cyan("[*] Debug -> printing pip install wheel's output ------"))
		pipInstallWheel.Stdout = os.Stdout
	}

	// Run the command
	pipInstallWheelErr := pipInstallWheel.Run()
	if gitCloneErr != nil {
		if *flags.OptDbg {
			fmt.Printf("Debug - Error running pip install wheel: %v\n", pipInstallWheelErr)
		}
		return pipInstallWheelErr
	}

	// Run Pip install -r requirements.txt
	pipInstallRequirements := exec.Command("pip", "install", "-r", "/usr/share/enum4linux-ng/requirements.txt")

	// Redirect the command's error output to the standard output in terminal
	pipInstallRequirements.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *flags.OptDbg {
		fmt.Println(utils.Cyan("[*] Debug -> printing pip install wheel's output ------"))
		pipInstallRequirements.Stdout = os.Stdout
	}

	// Run the command
	pipInstallRequirementsErr := pipInstallRequirements.Run()
	if pipInstallRequirementsErr != nil {
		if *flags.OptDbg {
			fmt.Printf("Debug - Error running pip install -r requirements.txt: %v\n", pipInstallRequirementsErr)
		}
		return pipInstallRequirementsErr
	}

	// Make executable
	chmod := exec.Command("chmod", "+x", "/usr/share/enum4linux-ng/enum4linux-ng.py")

	// Redirect the command's error output to the standard output in terminal
	chmod.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *flags.OptDbg {
		fmt.Println(utils.Cyan("[*] Debug -> printing chmod's output ------"))
		chmod.Stdout = os.Stdout
	}

	// Run chmod
	chmodErr := chmod.Run()
	if chmodErr != nil {
		if *flags.OptDbg {
			fmt.Printf("Debug - Error running chmod: %v\n", chmodErr)
		}
		return chmodErr
	}

	// Create symbolic link
	ln := exec.Command("ln", "-s", "/usr/share/enum4linux-ng/enum4linux-ng.py", "/usr/bin/enum4linux-ng")

	// Redirect the command's error output to the standard output in terminal
	ln.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *flags.OptDbg {
		fmt.Println(utils.Cyan("[*] Debug -> printing git clone's output ------"))
		ln.Stdout = os.Stdout
	}

	// Run the command
	lnErr := ln.Run()
	if lnErr != nil {
		if *flags.OptDbg {
			fmt.Printf("Debug - Error running git clone: %v\n", lnErr)
		}
		return lnErr
	}

	fmt.Println(utils.Green("Done!"))
	return nil
}

func aptGetInstallCmd(tool string) {
	printInstallingTool(tool)

	if tool == "finger" {
		tool = "nfs-common"
	}

	if tool == "seclists" {
		tool = "nfs-common"
	}

	if tool == "msfconsole" {
		tool = "metasploit-framework"
	}

	if tool == "responder-RunFinger" {
		tool = "responder"
	}

	if tool == "impacket-rpcdump" {
		tool = "python3-impacket"
	}

	aptGetInstall := exec.Command("apt", "install", "-y", tool)

	aptGetInstallErr := aptGetInstall.Run()
	if aptGetInstallErr != nil {
		// if !strings.Contains(string(aptGetInstall.Stdout), "Unable to locate package") {
		if *flags.OptDbg {
			fmt.Printf("Debug - Error executing apt-get: %v\n", aptGetInstallErr)
		}

		// Notify of enum4linux-ng as it's not currently in the official kali repo
		if tool == "enum4linux-ng" {
			installErr := installEnum4linuxNg()
			if installErr != nil {
				utils.ErrorMsg(installErr.Error())
				utils.PrintCustomBiColourMsg("red", "cyan", "[-] Error. ", "enum4linux-ng", " needs to be manually installed.\nPlease see: ", "https://github.com/cddmp/enum4linux-ng/blob/master/README.md#kali-linuxdebianubuntulinux-mint")
				os.Exit(2)
			}
			return
		}

		utils.PrintCustomBiColourMsg("red", "cyan", "[-] Error. Please install the following package manually: '", tool, "'\n[-] Aborting...")
		os.Exit(2)
	}

	fmt.Printf("%s\n", utils.Green("Done!"))
}

// Enumeration for WordPress
func WPEnumeration(targetUrl, caseDir, port string) {
	// Identify WordPress: Run curl
	curl := exec.Command("curl", "-s", "-X", "GET", targetUrl)
	curlOutput, _ := curl.Output()

	// grep 'wp-content'
	if !strings.Contains(string(curlOutput), "wp-content") {
		if *flags.OptDbg { fmt.Println(utils.Debug("Debug Error: wordpress not detected")) }
		return
	}

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
		if *flags.OptDbg { fmt.Println(utils.Debug("Debug Error: tomcat not detected")) }
		return
	}

	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!]", "Tomcat detected. Running", "WPScan", "...")

	// Run Gobuster
	gobusterArgs := []string{"gobuster", "-z", "-q", "dir", "-e", "u", fmt.Sprintf("%s:8080", target), "-w", dirListMedium}
	gobusterPath := fmt.Sprintf("%stomcat_gobuster.out", caseDir)
	callRunTool(gobusterArgs, gobusterPath)

	// Run hydra
	if !*flags.OptBrute { return }

	hydraArgs := []string{
		"hydra",
		"-L", usersList,
		"-P", darkwebTop1000,
		"-f", target,
		"http-get", "/manager/html",
	}
	hydraPath := fmt.Sprintf("%stomcat_hydra.out", caseDir)
	callRunTool(hydraArgs, hydraPath)
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
			"-w", fmt.Sprintf("%s:FOLDERS,%s:KEYWORDS,%s:EXTENSIONS", dirListMedium, keywordsList, extensionsList),
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
		"-w", fmt.Sprintf("%s:FOLDERS,%s:KEYWORDS,%s:EXTENSIONS", dirListMedium, keywordsList, extensionsList),
		"-u", fmt.Sprintf("http://%s/FOLDERS/KEYWORDSEXTENSIONS", target),
		"-v",
		"-maxtime", "300",
		"-maxtime-job", "300",
	}
	ffufPath := fmt.Sprintf("%sffuf_keywords_443.out", caseDir)
	runTool(ffufArgs, ffufPath)
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

	if *flags.OptDbg {
		fmt.Printf("%s%s %s\n", utils.Debug("Debug - command to exec: "), tool, command)
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
			if *flags.OptDbg {
				fmt.Println("Error copying output for tool", tool, ":", err)
			}
		}
	}()

	// Wait for the command to complete (optional)
	if err := cmd.Wait(); err != nil {
		if tool == "nikto" || tool == "fping" {
			// Nikto and fping don't have a clean exit
			utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! '", fmt.Sprintf("%s on port 80", tool), "' finished successfully")
			fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(filePath))
		} else {
			fmt.Println(utils.Red("Command"), tool, utils.Red("finished with error:"), utils.Red(err))
		}
	}

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

// Enumerate a whole CIDR range using specific range tools
func RunRangeTools(targetRange string) {
	// Print Flag detected
	utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] ", "-r", " flag detected. Proceeding to scan CIDR range with dedicated range enumeration tools.")
	if *flags.OptDbg {
		fmt.Println("[*] Debug: target CIDR range string -> ", targetRange)
	}

	// Make CIDR dir
	cidrDir := fmt.Sprintf("%s/%s_range_enum/", *flags.OptOutput, strings.Replace(targetRange, "/", "_", 1))
	if *flags.OptDbg {
		fmt.Println("[*] Debug: cidrDir -> ", cidrDir)
	}
	utils.CustomMkdir(cidrDir)

	// Get wordlists for the range
	utils.GetWordlists()

	// run nbtscan-unixwiz
	nbtscanArgs := []string{"nbtscan-unixwiz", "-f", targetRange}
	nbtscanPath := fmt.Sprintf("%snbtscan-unixwiz.out", cidrDir)
	callRunTool(nbtscanArgs, nbtscanPath)

	// run Responder-RunFinger
	responderArgs := []string{"responder-RunFinger", "-i", targetRange}
	responderPath := fmt.Sprintf("%srunfinger.out", cidrDir)
	callRunTool(responderArgs, responderPath)

	// run OneSixtyOne
	oneSixtyOneArgs := []string{"onesixtyone", "-c", usersList, targetRange, "-w", "100"}
	oneSixtyOnePath := fmt.Sprintf("%sonesixtyone.out", cidrDir)
	callRunTool(oneSixtyOneArgs, oneSixtyOnePath)

	// run fping
	fpingArgs := []string{"fping", "-asgq", targetRange}
	fpingPath := fmt.Sprintf("%sfping.out", cidrDir)
	callRunTool(fpingArgs, fpingPath)

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
func callRunCewlandFfufKeywords(target, caseDir, port string) {
	utils.Wg.Add(1)

	go func(target, caseDir, port string) {
		defer utils.Wg.Done()

		runCewlandFfufKeywords(target, caseDir, port)
	}(target, caseDir, port)
}

// Goroutine for runTool()
func callRunTool(args []string, filePath string) {
	utils.Wg.Add(1)

	go func(args []string, filePath string) {
		defer utils.Wg.Done()

		go runTool(args, filePath)
	}(args, filePath)
}

// Goroutine for individualPortScannerWithNSEScripts()
func callIndividualPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	utils.Wg.Add(1)

	go func(target, port, outFile, scripts string) {
		defer utils.Wg.Done()

		individualPortScannerWithNSEScripts(target, port, outFile, scripts)
	}(target, port, outFile, scripts)
}

// Goroutine for scans.IndividualPortScannerWithNSEScriptsAndScriptArgs()
func callIndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string) {
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
func callscans.IndividualPortScanner(target, port, outFile string) {
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
