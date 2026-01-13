package infra

import (
	"fmt"
	"net"
	"os"

	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/pborman/getopt/v2"
)

func Run(OptHelp, OptInstall, OptNmapOnly, OptQuiet, OptVVerbose *bool, OptOutput, OptTarget *string) (int, error) {
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
		printInfraUsage()
		utils.PrintInfraUsageExamples()
		return 0, fmt.Errorf("no arguments provided")
	}

	// Check 2: Help flag or nmap flag passed?
	if *OptHelp {
		if !*OptQuiet {
			fmt.Println(utils.Cyan("[*] Help flag detected. Aborting other checks and printing usage.\n"))
		}
		printInfraUsage()
		utils.PrintInfraUsageExamples()
		return 0, utils.ErrHelpRequested
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
		return 0, utils.ErrInstallComplete
	}

	// Call check 5
	if err := checkFive(OptTarget); err != nil {
		return 0, err
	}

	// Call check 6
	checkSix(OptOutput, OptQuiet, OptVVerbose)

	// Check 8: Determine whether it is a single target or multi-target and return number of lines
	lines, err := checkSeven(OptTarget)
	return lines, err

	// End of checks
}

// printInfraUsage prints only the infra-relevant flags, not cloud flags
func printInfraUsage() {
	fmt.Println("Usage: enumeraga infra [OPTIONS]")
	fmt.Println("\nOptions:")
	fmt.Println("  -b, --brute          Activate all fuzzing and bruteforce in the tool")
	fmt.Println("  -h, --help           Display this help and exit")
	fmt.Println("  -i, --install        Only try to install pre-requisite tools and exit")
	fmt.Println("  -n, --nmap-only      Activate nmap scans only and ignore all other tools")
	fmt.Println("  -o, --output DIR     Select a different base folder for output (default: /tmp/enumeraga_output)")
	fmt.Println("  -p, --top-ports N    Run port sweep with nmap --top-ports=N")
	fmt.Println("  -q, --quiet          Don't print the banner and decrease overall verbosity")
	fmt.Println("  -r, --range CIDR     Specify a CIDR range to use tools for whole subnets")
	fmt.Println("  -t, --target TARGET  Specify target single IP / List of IPs file (required)")
	fmt.Println("  -T, --timeout MINS   Maximum time in minutes for long-running tools (default: 10)")
	fmt.Println("  -V, --vv             Flood your terminal with plenty of verbosity!")
	fmt.Println()
}

// checkFive ensures there's a valid target
func checkFive(OptTarget *string) error {
	if *OptTarget == "" {
		utils.ErrorMsg("You must provide an IP address or targets file with the flag -t to start the attack.")
		return fmt.Errorf("no target provided")
	}
	return nil
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
func checkSeven(OptTarget *string) (int, error) {
	targetInput := net.ParseIP(*OptTarget)

	// Check if it's a valid IP address (IPv4 or IPv6)
	if targetInput != nil {
		// Valid IP - single target mode
		return 0, nil
	}

	// Not a valid IP - try to resolve as hostname/URL
	resolvedIP, err := utils.ResolveHostToIP(*OptTarget)
	if err == nil {
		// Successfully resolved hostname to IP
		utils.PrintCustomBiColourMsg("green", "cyan", "[+] Resolved hostname '", *OptTarget, "' to IP: ", resolvedIP)
		// Update OptTarget to use the resolved IP for scanning
		*OptTarget = resolvedIP
		return 0, nil
	}

	// Not a valid IP or hostname - assume it's a targets file
	// Validate file exists before attempting to read
	if err := utils.ValidateFilePath(*OptTarget); err != nil {
		utils.ErrorMsg(fmt.Sprintf("Target validation failed: %v", err))
		return 0, fmt.Errorf("target validation failed: %w", err)
	}

	// Multi-target. Check file exists and get lines
	_, totalLines := utils.ReadTargetsFile(OptTarget)
	return totalLines, nil
}
