package infra

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/pborman/getopt/v2"
	"net"
	"os"
)

func Run(OptHelp, OptInstall, OptNmapOnly, OptQuiet, OptVVerbose *bool, OptOutput, OptTarget *string) int {
	// Parse optional infra arguments, getting rid of the 'infra' arg
	os.Args = os.Args[1:]
	getopt.Parse()

	// Check 0: banner!
	if !*OptQuiet {
		utils.PrintBanner()
	}

	if !*OptQuiet {
		fmt.Printf("\n%s%s%s\n", utils.Cyan("[*] ---------- "), utils.Green("Starting infra checks phase"), utils.Cyan(" ----------"))
	}

	// Check 1: Args passed fine?
	if len(os.Args) == 1 {
		utils.ErrorMsg("No arguments were provided.")
		getopt.Usage()
		utils.PrintInfraUsageExamples()
		os.Exit(1)
	}

	// Check 2: Help flag or nmap flag passed?
	if *OptHelp {
		if !*OptQuiet {
			fmt.Println(utils.Cyan("[*] Help flag detected. Aborting other checks and printing usage.\n"))
		}
		getopt.Usage()
		utils.PrintInfraUsageExamples()
		os.Exit(0)
	}

	if *OptNmapOnly {
		if !*OptQuiet {
			fmt.Println(utils.Cyan("[*] Nmap only flag detected. Aborting other functionality of Enumeraga and only launching nmap scans.\n"))
		}
	}

	// Check 3: I AM GROOT!!!!
	utils.CheckAdminPrivileges("infra")

	// Check 4: key tools exist in the system
	if !*OptQuiet && !*OptNmapOnly {
		fmt.Println(utils.Cyan("[*] Checking all tools are installed... "))
	}

	if !*OptNmapOnly {
		utils.InstallMissingTools('i', OptInstall)
	}

	if *OptInstall && !*OptNmapOnly {
		fmt.Println(utils.Green("[+] All pre-required tools have been installed! You're good to go! Run your first scan with enumeraga infra -t!"))
		os.Exit(0)
	}

	// Call check 5
	checkFive(OptTarget)

	// Call check 6
	checkSix(OptOutput, OptQuiet, OptVVerbose)

	// Check 8: Determine whether it is a single target or multi-target and return number of lines
	return checkSeven(OptTarget)

	// End of checks
}

// checkFive ensures there's a valid target
func checkFive(OptTarget *string) {
	if *OptTarget == "" {
		utils.ErrorMsg("You must provide an IP address or targets file with the flag -t to start the attack.")
		os.Exit(1)
	}
}

// checkSix ensures base output directory is correctly set and exists
func checkSix(OptOutput *string, OptQuiet, OptVVerbose *bool) {
	_, err := utils.CustomMkdir(*OptOutput)
	if err != nil {
		if *OptVVerbose {
			utils.ErrorMsg(err)
		}
	} else {
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Directory ", *OptOutput, " created successfully")
	}
	if !*OptQuiet {
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Using '", *OptOutput, "' as base directory to save the ", "output ", "files")
	}
}

// checkSeven finishes this section by returning number of lines if multi-target or 0 if single-target
func checkSeven(OptTarget *string) int {
	targetInput := net.ParseIP(*OptTarget)

	// Check if it's a valid IP address (IPv4 or IPv6)
	if targetInput != nil {
		// Valid IP - single target mode
		return 0
	}

	// Not a valid IP - assume it's a targets file
	// Validate file exists before attempting to read
	if err := utils.ValidateFilePath(*OptTarget); err != nil {
		utils.ErrorMsg(fmt.Sprintf("Target validation failed: %v", err))
		os.Exit(1)
	}

	// Multi-target. Check file exists and get lines
	_, totalLines := utils.ReadTargetsFile(OptTarget)
	return totalLines
}
