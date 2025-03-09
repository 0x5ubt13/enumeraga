package infra

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/pborman/getopt/v2"
	"net"
	"os"
)

//var (
//	// DEV: initialising vars only once they have been implemented/ported in the code
//	// optAgain 	= getopt.BoolLong("again", 'a', "Repeat the scan and compare with initial ports discovered.")
//
//	// OptBrute Activates all fuzzing and bruteforce in the script
//	OptBrute = getopt.BoolLong("brute", 'b', "Activate all fuzzing and bruteforce in the tool.")
//
//	// Specify custom DNS servers.
//	// Default option: -n
//	// OptDNS 		= getopt.StringLong("DNS", 'd', "", "Specify custom DNS servers. Default option: -n")
//
//	// OptHelp displays help dialogue and exit
//	OptHelp = getopt.BoolLong("help", 'h', "Display this help and exit.")
//
//	// OptInstall Only try to install pre-requisite tools and exit
//	OptInstall = getopt.BoolLong("install", 'i', "Only try to install pre-requisite tools and exit.")
//
//	// OptNmapOnly only runs nmap, ignoring all tools prerequisites
//	OptNmapOnly = getopt.BoolLong("nmap-only", 'n', "Activate nmap scans only in Enumeraga and ignore all other tools, including their installation.")
//
//	// OptOutput selects a different base folder for the output
//	// Default option: "/tmp/enumeraga_output"
//	OptOutput = getopt.StringLong("output", 'o', "/tmp/enumeraga_output", "Select a different base folder for the output.")
//
//	// OptTopPorts runs port sweep with nmap and the flag --top-ports=<your input>
//	OptTopPorts = getopt.StringLong("top-ports", 'p', "", "Run port sweep with nmap and the flag --top-ports=<your input>")
//
//	// OptQuiet makes the tool not print the banner and decreases the overall verbosity
//	OptQuiet = getopt.BoolLong("quiet", 'q', "Don't print the banner and decrease overall verbosity.")
//
//	// OptRange specifies a CIDR range to use tools for whole subnets
//	OptRange = getopt.StringLong("range", 'r', "", "Specify a CIDR range to use tools for whole subnets.")
//
//	// OptTarget specifies a single IP target or a file with a list of IPs.
//	OptTarget = getopt.StringLong("target", 't', "", "Specify target single IP / List of IPs file.")
//
//	// OptVVerbose floods your terminal with plenty of verbosity!
//	OptVVerbose = getopt.BoolLong("vv", 'V', "Flood your terminal with plenty of verbosity!")
//
//	// Adding placeholder for OptVhost
//	// OptVhost = getopt.StringLong("", '', "", "")
//
//	// Arm64 determines if software like odat, not currently available for aarch64
//	//Arm64 bool
//)

func Run(OptBrute, OptHelp, OptInstall, OptNmapOnly, OptQuiet, OptVVerbose *bool, OptOutput, OptTopPorts, OptRange, OptTarget *string) int {
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

	// Check 3: am I groot?!
	if os.Geteuid() != 0 {
		utils.ErrorMsg("Please run the infra part as root so nmap doesn't fail!")
		os.Exit(99)
	}

	// Check 4: key tools exist in the system
	if !*OptQuiet && !*OptNmapOnly {
		fmt.Println(utils.Cyan("[*] Checking all tools are installed... "))
	}

	if !*OptNmapOnly {
		utils.InstallMissingTools('i', OptInstall, OptVVerbose)
	}

	if *OptInstall && !*OptNmapOnly {
		fmt.Println(utils.Green("[+] All pre-required tools have been installed! You're good to go! Run your first scan with enumeraga infra -t!"))
		os.Exit(0)
	}

	// Call check 5
	checkFive(OptTarget)

	// Call check 6
	checkSix(OptOutput, OptQuiet, OptVVerbose)

	// Call check 7
	//checkSeven()

	// Check 8: Determine whether it is a single target or multi-target and return number of lines
	return checkEight(OptTarget)

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

// checkSeven checks processor's architecture to weed out tools that aren't currently supported on Aarch64
//func checkSeven() {
//	if runtime.GOARCH == "arm64" {
//		Arm64 = true
//	}
//}

// checkEight finishes this section by returning number of lines if multi-target or 0 if single-target
func checkEight(OptTarget *string) int {
	targetInput := net.ParseIP(*OptTarget)
	if targetInput.To4() == nil {
		// Multi-target
		// Check file exists and get lines
		_, totalLines := utils.ReadTargetsFile(OptTarget)
		return totalLines
	}

	// Return 0 if not multi-target
	return 0
}
