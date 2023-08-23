package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	// "bufio"
	// "sync"

	getopt "github.com/pborman/getopt/v2"
)

// Perform pre-flight checks and return total lines if multi-target
func checks() int {
	var totalLines int

	// Check 0: banner!
	if !*optQuiet {printBanner()}
	printPhase(0)

	// Check 1: optional arguments passed fine?
	getopt.Parse()
	// Get the remaining positional parameters
	// args := getopt.Args()
	if *optDbg {
		fmt.Println("--- Debug ---")
		// fmt.Printf("Again: %t\n", *optAgain)
		fmt.Printf("Brute: %t\n", *optBrute)
		// fmt.Printf("DNS: %s\n", *optDNS)
		fmt.Printf("Help: %t\n", *optHelp) 	
		// fmt.Printf("Output: %s\n", *optOutput)
		// fmt.Printf("Top ports: %s\n", *optTopPorts) 
		fmt.Printf("Quiet: %t\n", *optQuiet)	
		// fmt.Printf("Range: %s\n", *optRange)	
		fmt.Printf("Target: %s\n", *optTarget)
		fmt.Println("--- Debug ---\n\n")
	}
	
	// Check 2: Help flag passed?
	if *optHelp {
		if !*optQuiet {(cyan("[*] Help flag detected. Aborting other checks and printing usage.\n\n"))}
        getopt.Usage()
        os.Exit(0)
    }

	// Check 3: am I groot?!
	if os.Geteuid() != 0 {errorMsg("Please run me as root!")}

	// Check 4: Ensure there is a target
	if *optTarget == "" {
		errorMsg("You must provide an IP address or targets file with the flag -t to start the attack.")
		os.Exit(1)
	}
	
	// Check 5: Ensure base output directory is correctly set and exists
	customMkdir(*optOutput)
	if !*optQuiet {fmt.Printf("%s %s %s\n", green("[+] Using"), yellow(*optOutput), green("as base directory to save the output files"))}

	// Check 6: Determine whether it is a single target or multi-target   
	targetInput := net.ParseIP(*optTarget)
	if *optDbg {fmt.Printf("Debug: targetInput := %s\n", targetInput.To4())}
	if targetInput.To4() == nil {
		// Multi-target
		// Check file exists and get lines
		_, totalLines = readTargetsFile(*optTarget)
	} else {
		totalLines = 0
	}

	// Check 7: key tools exist in the system
	keyTools := []string{
		"locate",
		"nmap",
		"hydra",
		"nfs-common",
		"updatedb",
		"locate",
		"odat",
		"ssh-audit",
		"seclists",
		"cewl",
		"wafW00f",
		"fping",
		"ident-user-enum",
	}

	// Loop through listed tool see which ones are missing
	missingTools := []string{}
	fullConsent := false
	for _, tool := range keyTools {
		if checkToolExists(tool) {
			continue
		}
		
		// If full consent was given, stop prompting the user
		if fullConsent == true {
			missingTools = append(missingTools, tool)
			continue
		}

		// Ask user
		userConsent := consent(tool)
		
		if userConsent == 'a' {
			fullConsent = true
			missingTools = append(missingTools, tool)
		}
		
		if userConsent == 'y' {
			missingTools = append(missingTools, tool)
			continue
		}
	}	

	// Install all those who are missing
	installMissingTools(missingTools)

	// End of checks
	return totalLines
}

func checkToolExists(tool string) bool {
	// Add more tool checks as required
	_, err := exec.LookPath(tool)
	if err == nil {
		if *optDbg {fmt.Printf("'%s' is installed.\n", tool)}
		return true
	}

	return false
}

func isCompatibleDistro() bool {
	// Check if OS is debian-like
	cat := exec.Command("cat", "/etc/os-release")
	output, err := cat.CombinedOutput()
	if err != nil {
		fmt.Printf("Error reading /etc/os-release: %v\n", err)
		os.Exit(1)
	}

	compatibleDistro := strings.Contains(strings.ToLower(string(output)), "debian")
	if !compatibleDistro {
		fmt.Printf(
			"%s\n%s",
			red("[-] This system is not running a Debian-like distribution."),
			red("Please install the tools manually"),  
		)
		return false
	}

	return true
}