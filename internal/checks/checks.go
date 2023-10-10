package checks

import (
	"fmt"
	"net"
	"os"

	"github.com/0x5ubt13/enumeraga/internal/utils"
	getopt "github.com/pborman/getopt/v2"
)

// Perform pre-flight checks and return total lines if multi-target
func Run() int {
	// Parse optional arguments
	getopt.Parse()

	// Check 0: banner!
	if !*utils.OptQuiet {
		utils.PrintBanner()
	}

	if !*utils.OptQuiet {
		fmt.Printf("\n%s%s%s\n", utils.Cyan("[*] ---------- "), utils.Green("Starting checks phase"), utils.Cyan(" ----------"))
	}

	if len(os.Args) == 1 {
		utils.ErrorMsg("No arguments were provided.")
		getopt.Usage()
		utils.PrintUsageExamples()
		os.Exit(1)
	}

	// Check 1: optional arguments passed fine?
	if *utils.OptDbg {
		fmt.Println(utils.Debug("--- Debug ---"))
		fmt.Printf("%s%t\n", utils.Debug("Brute: "), *utils.OptBrute)
		fmt.Printf("%s%t\n", utils.Debug("Help: "), *utils.OptHelp)
		fmt.Printf("%s%t\n", utils.Debug("Install: "), *utils.OptInstall)
		fmt.Printf("%s%s\n", utils.Debug("Output: "), *utils.OptOutput)
		// fmt.Printf("Top ports: %s\n", *utils.OptTopPorts) // TODO
		fmt.Printf("%s%t\n", utils.Debug("Quiet: "), *utils.OptQuiet)
		fmt.Printf("%s%s\n", utils.Debug("Range:"), *utils.OptRange)
		fmt.Printf("%s%s\n", utils.Debug("Target: "), *utils.OptTarget)
	}

	// Check 2: Help flag passed?
	if *utils.OptHelp {
		if !*utils.OptQuiet {
			fmt.Println(utils.Cyan("[*] Help flag detected. Aborting other checks and printing usage.\n"))
		}
		getopt.Usage()
		utils.PrintUsageExamples()
		os.Exit(0)
	}

	// Check 3: am I groot?!
	if os.Geteuid() != 0 {
		utils.ErrorMsg("Please run me as root!")
		os.Exit(99)
	}

	// Check 4: : key tools exist in the system
	if *utils.OptInstall {
		fmt.Println(utils.Cyan("[*] Install flag detected. Aborting other checks and running pre-requisites check.\n"))
	}
	if !*utils.OptQuiet {
		fmt.Println(utils.Cyan("[*] Checking all tools are installed... "))
	}
	utils.InstallMissingTools()

	if *utils.OptDbg {
		fmt.Printf("%s\n", utils.Green("[*] Debug - All tools have been installed."))
	}
	if *utils.OptInstall {
		fmt.Println(utils.Green("[+] All pre-required tools have been installed! You're good to go! Run your first scan with enumeraga -t!"))
		os.Exit(0)
	}

	// Check 5: Ensure there is a target
	if *utils.OptTarget == "" {
		utils.ErrorMsg("You must provide an IP address or targets file with the flag -t to start the attack.")
		os.Exit(1)
	}

	// Check 6: Ensure base output directory is correctly set and exists
	utils.CustomMkdir(*utils.OptOutput)
	if !*utils.OptQuiet {
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Using '", *utils.OptOutput, "' as base directory to save the ", "output ", "files")
	}

	// Check 7: Determine whether it is a single target or multi-target
	targetInput := net.ParseIP(*utils.OptTarget)
	if *utils.OptDbg {
		fmt.Printf("%s%s\n", utils.Debug("Debug: targetInput = "), targetInput.To4())
	}

	if targetInput.To4() == nil {
		// Multi-target
		// Check file exists and get lines
		_, totalLines := utils.ReadTargetsFile(*utils.OptTarget)
		return totalLines
	}

	// End of checks
	return 0
}
