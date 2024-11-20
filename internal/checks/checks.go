package checks

import (
	"fmt"
	"net"
	"os"

	// "github.com/0x5ubt13/enumeraga/cloud/cloudScanner"
	"github.com/0x5ubt13/enumeraga/internal/utils"

	getopt "github.com/pborman/getopt/v2"
)

// Run pre-flight checks and return total lines if multi-target
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

	// Check 1: Args passed fine?
	if len(os.Args) == 1 {
		utils.ErrorMsg("No arguments were provided.")
		getopt.Usage()
		utils.PrintUsageExamples()
		os.Exit(1)
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

	// Check 3.5: if this is for cloud, get into cloud flow instead
	cloudArg := os.Args[1]

    switch cloudArg {
    case "c", "cl", "clo", "clou", "cloud":
        fmt.Println(utils.Cyan("[*] Cloud argument detected. Starting Cloud enumeration.\n"))
        cloudScanner.Run()
		/* placeholder for when 'enumeraga infra' and enumeraga 'cloud' are both implemented
		case "i", "in", "inf", "infr", "infra":
		*/
	}

	// Check 4: key tools exist in the system
	if !*utils.OptQuiet {
		fmt.Println(utils.Cyan("[*] Checking all tools are installed... "))
	}

	utils.InstallMissingTools('i')

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
	if targetInput.To4() == nil {
		// Multi-target
		// Check file exists and get lines
		_, totalLines := utils.ReadTargetsFile(*utils.OptTarget)
		return totalLines
	}

	// End of checks
	return 0
}
