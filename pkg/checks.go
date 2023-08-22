package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"bufio"

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

	for _, tool := range keyTools {
		checkToolExists(tool)
	}

	return totalLines
}

func checkToolExists(tool string) {
	// TODO: add more tool checks as required
	_, err := exec.LookPath(tool)
	if err == nil {
		if *optDbg {fmt.Printf("'%s' is installed.\n", tool)}
		return
	}

	// Err not nil - Tool not found
	fmt.Printf(
		"%s '%s' %s\n",
		red("[-] Enumeraga needs"),
		cyan(tool), 
		red("to be installed"),
	)
	
	// Check if OS is debian-like
	cat := exec.Command("cat", "/etc/*-release")
	output, err := cat.CombinedOutput()
	if err != nil {
		fmt.Printf("Error reading /etc/*-release: %v\n", err)
		os.Exit(1)
	}

	compatibleDistro := strings.Contains(strings.ToLower(strings.Split(string(output), "=")[1], "debian"))
	if !compatibleDistro {
		fmt.Printf(
			"%s\n%s %s %s",
			red("[-] This system is not running a Debian-like distribution."),
			red("Please install"), 
			cyan(tool), 
			red("manually."),
		)
		os.Exit(1)
	}

	// Ask for user consent
	fmt.Printf("%s %s %s", yellow("Do you want to install"), cyan(tool), yellow("(yes/no): )"))
	consent := bufio.NewScanner(os.Stdin)
	consent.Scan()
	userInput := strings.ToLower(consent.Text())

	if userInput != "yes" || userInput != "y" {
		fmt.Printf("%s\n", red("[-] Please install it manually. Aborting..."))
		os.Exit(1)
	}

	// User consented to install
	installTool(tool)
}

func installTool(tool string) {
	// Run the apt-get command to install the package
	cmd := exec.Command("apt-get", "install", tool)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Execute the command
	err := cmd.Run()
	if err != nil {
		fmt.Printf("Error executing apt-get: %v\n", err)
		return
	}

	fmt.Printf("%s %s %s", green("[+]"), cyan(tool), green("has been installed."))
}