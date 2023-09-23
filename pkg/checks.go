package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"

	// zglob "github.com/mattn/go-zglob"
	getopt "github.com/pborman/getopt/v2"
)

// Perform pre-flight checks and return total lines if multi-target
func checks() int {
	// Parse optional arguments
	getopt.Parse()

	// Check 0: banner!
	if !*optQuiet {
		printBanner()
	}

	if !*optQuiet { fmt.Printf("\n%s%s%s\n", cyan("[*] ---------- "), green("Starting checks phase"), cyan(" ----------")) }

	if len(os.Args) == 1 {
		errorMsg("No arguments were provided.")
		getopt.Usage()
		printUsageExamples()
		os.Exit(1)
	}

	// Check 1: optional arguments passed fine?
	// Get the remaining positional parameters
	// args := getopt.Args()
	if *optDbg {
		fmt.Println(debug("--- Debug ---"))
		// fmt.Printf("Again: %t\n", *optAgain)
		fmt.Printf("%s%t\n", debug("Brute: "), *optBrute)
		// fmt.Printf("DNS: %s\n", *optDNS)
		fmt.Printf("%s%t\n", debug("Help: "), *optHelp)
		fmt.Printf("%s%t\n", debug("Install: "), *optInstall)
		fmt.Printf("%s%s\n", debug("Output: "), *optOutput)
		// fmt.Printf("Top ports: %s\n", *optTopPorts)
		fmt.Printf("%s%t\n", debug("Quiet: "), *optQuiet)
		fmt.Printf("%s%s\n", debug("Range:"), *optRange)
		fmt.Printf("%s%s\n", debug("Target: "), *optTarget)
	}

	// Check 2: Help flag passed?
	if *optHelp {
		if !*optQuiet { fmt.Println(cyan("[*] Help flag detected. Aborting other checks and printing usage.\n")) }
		getopt.Usage() 
		printUsageExamples()
		os.Exit(0)
	}

	// Check 3: am I groot?!
	if os.Geteuid() != 0 {
		errorMsg("Please run me as root!")
		os.Exit(99)
	}

	// Check 4: : key tools exist in the system
	if *optInstall { fmt.Println(cyan("[*] Install flag detected. Aborting other checks and running pre-requisites check.\n")) }
	if !*optQuiet { fmt.Println(cyan("[*] Checking all tools are installed... ")) }
	installMissingTools()

	if *optDbg { fmt.Printf("%s\n", green("[*] Debug - All tools have been installed.")) }
	if *optInstall { 
		fmt.Println(green("[+] All pre-required tools have been installed! You're good to go! Run your first scan with enumeraga -t!"))
		os.Exit(0) 
	}

	// Check 5: Ensure there is a target
	if *optTarget == "" {
		errorMsg("You must provide an IP address or targets file with the flag -t to start the attack.")
		os.Exit(1)
	}

	// Check 6: Ensure base output directory is correctly set and exists
	customMkdir(*optOutput)
	if !*optQuiet {
		printCustomBiColourMsg("green", "yellow", "[+] Using '", *optOutput, "' as base directory to save the ", "output ", "files")
	}

	// Check 7: Determine whether it is a single target or multi-target
	var totalLines int
	targetInput := net.ParseIP(*optTarget)
	if *optDbg {
		fmt.Printf("%s%s\n", debug("Debug: targetInput = "), targetInput.To4())
	}
	if targetInput.To4() == nil {
		// Multi-target
		// Check file exists and get lines
		_, totalLines = readTargetsFile(*optTarget)
	} else {
		totalLines = 0
	}

	// End of checks
	return totalLines
}

func checkToolExists(tool string) bool {
	// Add more tool checks as required

	// Check with exec.LookPath
	_, lookPatherr := exec.LookPath(tool)
	if lookPatherr == nil {
		if *optDbg {
			fmt.Printf("%s%s%s\n", green("Debug - '"), green(tool), green("' is installed"))
		}
		return true
	} else {
		if *optDbg {
			fmt.Println(debug("Debug - Error: ", lookPatherr.Error()))
		}
	}

	return false
}


