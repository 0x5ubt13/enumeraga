package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	// "strings"
	"log"

	zglob "github.com/mattn/go-zglob"
)

func wgetCmd(outputFile string, url string) {
	wget := exec.Command("wget", "--no-check-certificate", "-O", outputFile, url)
	
	if *optDbg {
		// Redirect the command's output to the standard output in terminal
		wget.Stdout = os.Stdout
		wget.Stderr = os.Stderr
	}

	// Run the command
	wgetErr := wget.Run()
	if wgetErr != nil {
		if *optDbg {
			fmt.Printf("Debug - Error running wget: %v\n", wgetErr)
			fmt.Printf("Debug - Trying curl")
		}
		curlCmd(outputFile, url)
		return
	}
}


func curlCmd(outputFile string, url string) {
	curl := exec.Command("curl", "-o", outputFile, url, "-L")
	
	if *optDbg {
		// Redirect the command's output to the standard output in terminal
		curl.Stdout = os.Stdout
		curl.Stderr = os.Stderr
	}

	// Run the command
	curlErr := curl.Run()
	if curlErr != nil {
		if *optDbg {fmt.Printf("Debug - Error running curl: %v\n", curlErr)}

		return
	}
}

func dpkgCmd(debPkgPath string) {
	dpkg := exec.Command("sudo", "dpkg", "-i", debPkgPath)

	if *optDbg {
		// Redirect the command's output to the standard output in terminal
		dpkg.Stdout = os.Stdout
		dpkg.Stderr = os.Stderr
	}

	// Run the command
	dpkgErr := dpkg.Run()
	if dpkgErr != nil {
		if *optDbg {fmt.Printf("Debug - Error running wget: %v\n", dpkgErr)}
		return
	}
}

func aptGetUpdateCmd() {
	// Run the apt-get update command
	fmt.Printf("%s %s%s ", yellow("[!] Running"), cyan("apt-get update"), yellow("..."))
	update := exec.Command("apt-get", "update")

	// Redirect the command's error output to the standard output in terminal
	update.Stderr = os.Stderr
	
	// Only print to stdout if debugging 
	if *optDbg {
		fmt.Println(cyan("[*] Debug -> printing apt-get update's output ------"))
		update.Stdout = os.Stdout
	}

	// Run the command
	updateErr := update.Run()
	if updateErr != nil {
		if *optDbg {fmt.Printf("Debug - Error running apt-get update: %v\n", updateErr)}
		return
	}

	fmt.Println(green("Done!"))

}

func aptGetInstallCmd(tool string) {
	printInstallingTool(tool)

	if tool == "finger" {
		tool = "nfs-common"
	}

	aptGetInstall := exec.Command("apt", "install", "-y", tool)

	aptGetInstallErr := aptGetInstall.Run()
	if aptGetInstallErr != nil {
		// if !strings.Contains(string(aptGetInstall.Stdout), "Unable to locate package") {
		if *optDbg {fmt.Printf("Debug - Error executing apt-get: %v\n", aptGetInstallErr)}
		fmt.Printf(
			"%s\n%s\n%s\n",
			red("[-] Error. Please install the following package manually: "),
			cyan(tool),
			red("[-] Aborting..."),
		)
		os.Exit(2)

		// Commenting this all out as it's not working in my WSL-based debian. Leaving it here for the future perhaps?
		// deleteLineFromFile("/etc/apt/sources.list", "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware")
		// fmt.Printf(
		// 	"%s\n%s %s %s %s", 
		// 	red("[-] It looks like apt-get is unable to locate some of the tools with your current sources."),
		// 	yellow("[!] Do you want to try"),
		// 	cyan("Kali's packaging repository source"),
		// 	yellow("(cleanup will be performed afterwards)?"),
		// 	yellow("[Y] yes / [N] no): "),
		// )
		// consent := bufio.NewScanner(os.Stdin)
		// consent.Scan()
		// userInput := strings.ToLower(consent.Text())
		// if userInput != "y" && userInput != "yes" {
		// 	printConsentNotGiven("Kali's packaging repository source")
		// 	// Making sure we clean up if we are recursing this function
		// 	deleteLineFromFile("/etc/apt/sources.list", "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware")
		// 	os.Exit(2)
		// }		
		// installWithKaliSourceRepo(tools)
	}

	fmt.Printf("%s\n", green("Done!"))
}

func hydraBruteforcing(target, dir, protocol string) {
	if *optBrute {
		fmt.Printf("Running Hydra for %s\n", protocol)
		hydra := exec.Command(
			"hydra",
			"-L", usersList,
			"-P", darkwebTop1000,
			fmt.Sprintf("%s://%s", protocol, target),
			"-f",
		)
		// hydra.Stdout = os.Stdout
		// hydra.Stderr = os.Stderr

		if err := hydra.Run(); err != nil {
			log.Fatalf("Error running Hydra for %s: %v\n", protocol, err)
		}

		fmt.Printf("Finished Hydra for %s\n", protocol)
	}
}

func rmCmd(filePath string) {
	rm := exec.Command("rm", "-f", filePath)

	if *optDbg {
		// Redirect the command's output to the standard output in terminal
		rm.Stdout = os.Stdout
		rm.Stderr = os.Stderr
	}

	// Run the command
	rmErr := rm.Run()
	if rmErr != nil {
		if *optDbg {fmt.Printf("Debug - Error running apt-get update: %v\n", rmErr)}
		return
	}
}

// Announce tool and run it
func runTool(args []string, filePath string) {
	// TODO: pass output filename as arg
	tool := args[0]
	command := strings.Join(args, ",")
	printCustomTripleMsg("yellow", "cyan", "[!] Running", tool, "and sending it to the background")

	if *optDbg {fmt.Printf("Debug - command to exec: %s", command)}

	cmd := exec.Command(command)

    // Create a pipe to capture the command's output
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        fmt.Println("Error creating stdout pipe:", err)
        os.Exit(1)
    }

    // Start the command asynchronously in a goroutine
    if err := cmd.Start(); err != nil {
        fmt.Println("Error starting command:", err)
        os.Exit(1)
    }

    // This goroutine will capture and print the command's output
    go func() {
        _, err := io.Copy(os.Stdout, stdout)
        if err != nil {
            fmt.Println("Error copying output:", err)
        }
    }()

    // Wait for the command to complete (optional)
    if err := cmd.Wait(); err != nil {
        fmt.Println("Command finished with error:", err)
        os.Exit(1)
    } else {
		printCustomTripleMsg("green", "cyan", "[+]", tool, "finished successfully")
	}
}	

// Enumerate a whole CIDR range using specific range tools
func runRangeTools(targetRange string) {
	// Prep

	// Print Flag detected
	printCustomTripleMsg("yellow", "cyan", "[*]", "CIDR Range", "flag detected. Proceeding to scan CIDR range with dedicated range enumeration tools.")
	if *optDbg { fmt.Println("[*] Debug: target CIDR range string -> ", targetRange) }

	// Make CIDR dir
	cidrDir := fmt.Sprintf("%s/%s_range_enum/", *optOutput, strings.Replace(targetRange, "/", "_", 1))
	if *optDbg { fmt.Println("[*] Debug: cidrDir -> ", cidrDir) }
	customMkdir(cidrDir)

	// Locate the "SNMP/snmp.txt" file
	snmpListSlice, err := zglob.Glob("SNMP/snmp.txt")
	if err != nil {
		log.Fatalf("Error locating 'SNMP/snmp.txt': %v\n", err)
	}
	snmpList := snmpListSlice[0]
	if *optDbg { fmt.Printf("snmp_list: %v\n", snmpList) }

 	// Run range tools

    // nbtscan-unixwiz
	nbtscanArgs := []string{"nbtscan-unixwiz", "-f", targetRange}
	nbtscanPath	:= fmt.Sprintf("%snbtscan-unixwiz.out", cidrDir)
	callRunTool(nbtscanArgs, nbtscanPath)
    
	// Responder-RunFinger
	responderArgs := []string{"responder-RunFinger", "-i", targetRange}
	responderPath := fmt.Sprintf("%srunfinger.out", cidrDir)
	callRunTool(responderArgs, responderPath)

	// OneSixtyOne
    oneSixtyOneArgs := []string{"onesixtyone", "-c", usersList, targetRange, "-w", "100"}
    oneSixtyOnePath := fmt.Sprintf("%sonesixtyone.out", cidrDir)
	callRunTool(oneSixtyOneArgs, oneSixtyOnePath)

    // fping
	fpingArgs := []string{"fping", "-asgq", targetRange}
    fpingPath := fmt.Sprintf("%sfping.out", cidrDir)
	callRunTool(fpingArgs, fpingPath)

	// Metasploit scan module for EternalBlue
    msfEternalBlueArgs := []string{"msfconsole", "-q", "-x", fmt.Sprintf("use use scanner/smb/smb_ms17_010;set rhosts %s;set threads 10;run;exit", targetRange)}
    msfEternalBluePath := fmt.Sprintf("%seternalblue_sweep", cidrDir)
	callRunTool(msfEternalBlueArgs, msfEternalBluePath)

    // TODO: implement function post_eternalblue_sweep_check()
}

// Goroutine for runTool()
func callRunTool(args []string, filePath string) {
	wg.Add(1)

	go func(args []string, filePath string) {
		defer wg.Done()

		runTool(args, filePath)
	}(args, filePath)
}

// Goroutine for individualPortScannerWithNSEScripts()
func callIndividualPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	wg.Add(1)

	go func(target, port, outFile, scripts string) {
		defer wg.Done()

		individualPortScannerWithNSEScripts(target, port, outFile, scripts)
	}(target, port, outFile, scripts)
}

// Goroutine for individualPortScannerWithNSEScriptsAndScriptArgs()
func callIndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string) {
	wg.Add(1)

	go func(target, port, outFile, scripts string, scriptArgs map[string]string) {
		defer wg.Done()

		individualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts, scriptArgs)
	}(target, port, outFile, scripts, scriptArgs)
}

// Goroutine for individualPortScannerWithNSEScriptsAndScriptArgs()
func callIndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	wg.Add(1)

	go func(target, port, outFile, scripts string) {
		defer wg.Done()

		individualUDPPortScannerWithNSEScripts(target, port, outFile, scripts)
	}(target, port, outFile, scripts)
}

// Goroutine for individualPortScanner()
func callIndividualPortScanner(target, port, outFile string) {
	wg.Add(1)

	go func(target, port, outFile string) {
		defer wg.Done()

		individualPortScanner(target, port, outFile)
	}(target, port, outFile)
}

// Goroutine for individualPortScanner()
func callFullAggressiveScan(target, ports, outFile string) {
	wg.Add(1)

	go func(target, ports, outFile string) {
		defer wg.Done()

		fullAggressiveScan(target, ports, outFile)
	}(target, ports, outFile)
}

