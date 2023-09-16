package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	zglob "github.com/mattn/go-zglob"
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
	printPhase(0)

	if len(os.Args) == 1 {
		errorMsg("No arguments were provided.")
		getopt.Usage()
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
		fmt.Printf("%s%s\n", debug("Output: "), *optOutput)
		// fmt.Printf("Top ports: %s\n", *optTopPorts)
		fmt.Printf("%s%t\n", debug("Quiet: "), *optQuiet)
		fmt.Printf("%s%s\n", debug("Range:"), *optRange)
		fmt.Printf("%s%s\n", debug("Target: "), *optTarget)
	}

	// Check 2: Help flag passed?
	if *optHelp {
		if !*optQuiet {
			fmt.Println(cyan("[*] Help flag detected. Aborting other checks and printing usage.\n"))
		}
		getopt.Usage()
		os.Exit(0)
	}

	// Check 3: am I groot?!
	if os.Geteuid() != 0 {
		errorMsg("Please run me as root!")
		os.Exit(99)
	}

	// Check 4: Ensure there is a target
	if *optTarget == "" {
		errorMsg("You must provide an IP address or targets file with the flag -t to start the attack.")
		os.Exit(1)
	}

	// Check 5: Ensure base output directory is correctly set and exists
	customMkdir(*optOutput)
	if !*optQuiet {
		printCustomBiColourMsg("green", "yellow", "[+] Using '", *optOutput, "' as base directory to save the ", "output ", "files")
	}

	// Check 6: Determine whether it is a single target or multi-target
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

	// Check 7: key tools exist in the system
	if !*optQuiet {
		fmt.Println(cyan("[*] Checking all tools are installed... "))
	}
	installMissingTools()

	if *optDbg {
		fmt.Printf("%s\n", green("[*] Debug - All tools have been installed."))
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

	// Check with zglob
	_, zglobErr := zglob.Glob(tool)
	if zglobErr == nil {
		if *optDbg {
			fmt.Printf("%s%s%s\n", green("Debug - '"), green(tool), green("' is installed"))
		}
		return true
	} else {
		if *optDbg {
			fmt.Println("Error: ", zglobErr.Error())
		}
	}

	// Last resource, check with locate
	if !updatedbRan {
		updatedb()
	}

	// Run locate
	locate := exec.Command("locate", tool)
	locateOutput, _ := locate.Output()

	if string(locateOutput) == "" {
		if *optDbg {
			fmt.Println(debug("Debug - Error: locate could not find tool on the system"))
		}
		return false
	}

	if *optDbg {
		fmt.Printf("%s%s%s\n", green("Debug - '"), green(tool), green("' is installed"))
	}

	fmt.Println(green("Done!"))
	return true
}

// Function to handle calling updatedb
func updatedb() {
	// Ask whether user wants updatedb ran
	printCustomBiColourMsg(
		"yellow", "cyan", "[!] It has been noticed that running", "updatedb", "in", "WSL systems", 
		"may take forever.\nDo you want to try locate packages without running", "updatedb", 
		"?\n[Y] yes, don't run updatedb, I don't want to wait that much! | [any other key] no, please, run updatedb, I'm good with waiting:",
	)
	updatedbQuestion := bufio.NewScanner(os.Stdin)
	updatedbQuestion.Scan()
	userInput := strings.ToLower(updatedbQuestion.Text())

	if userInput == "yes" || userInput == "y" {
		return
	}
	
	updatedbRan = true
	fmt.Printf("%s %s%s ", yellow("[!] Running"), cyan("updatedb"), yellow("..."))
	updatedb := exec.Command("updatedb")
	updatedbErr := updatedb.Start()
	if updatedbErr != nil {
		if *optDbg {
			fmt.Println(debug("Debug - Updatedb error: ", updatedbErr))
		}
		os.Exit(42)
	}

	err := updatedb.Wait()
	if err != nil {
		if *optDbg {
			fmt.Printf("%s%v\n", debug("Debug - Command finished with error: "), err)
		}
		os.Exit(44)
	}

	fmt.Println(green("Done!"))
}

func isCompatibleDistro() error {
	// Check if OS is debian-like
	cat := exec.Command("cat", "/etc/os-release")
	output, err := cat.CombinedOutput()
	if err != nil {
		fmt.Printf("Error reading /etc/os-release: %v\n", err)
		os.Exit(5)
	}

	compatibleDistro := strings.Contains(strings.ToLower(string(output)), "debian")
	if !compatibleDistro {
		errorMsg("This system is not running a Debian-like distribution. Please install the tools manually.")
		return fmt.Errorf("not compatible distro")
	}

	return nil
}
