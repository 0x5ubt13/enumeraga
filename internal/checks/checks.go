package checks

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/cloud"
	"github.com/0x5ubt13/enumeraga/internal/infra"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/pborman/getopt/v2"
	"os"
)

var (
	// DEV: initialising vars only once they have been implemented/ported in the code
	// optAgain 	= getopt.BoolLong("again", 'a', "Repeat the scan and compare with initial ports discovered.")

	// OptBrute Activates all fuzzing and bruteforce in the script
	OptBrute = getopt.BoolLong("brute", 'b', "Activate all fuzzing and bruteforce in the tool.")

	// OptGentle throttles scans and tools for a gentler profile
	OptGentle = getopt.BoolLong("gentle", 'g', "Throttle scans and tools for a gentler scan profile.")

	// Specify custom DNS servers.
	// Default option: -n
	// OptDNS 		= getopt.StringLong("DNS", 'd', "", "Specify custom DNS servers. Default option: -n")

	// OptHelp displays help dialogue and exit
	OptHelp = getopt.BoolLong("help", 'h', "Display this help and exit.")

	// OptInstall Only try to install pre-requisite tools and exit
	OptInstall = getopt.BoolLong("install", 'i', "Only try to install pre-requisite tools and exit.")

	// OptNmapOnly only runs nmap, ignoring all tools prerequisites
	OptNmapOnly = getopt.BoolLong("nmap-only", 'n', "Activate nmap scans only in Enumeraga and ignore all other tools, including their installation.")

	// OptOutput selects a different base folder for the output
	// Default option: "/tmp/enumeraga_output"
	OptOutput = getopt.StringLong("output", 'o', "/tmp/enumeraga_output", "Select a different base folder for the output.")

	// OptTopPorts runs port sweep with nmap and the flag --top-ports=<your input>
	OptTopPorts = getopt.StringLong("top-ports", 'p', "", "Run port sweep with nmap and the flag --top-ports=<your input>")

	// OptQuiet makes the tool not print the banner and decreases the overall verbosity
	OptQuiet = getopt.BoolLong("quiet", 'q', "Don't print the banner and decrease overall verbosity.")

	// OptRange specifies a CIDR range to use tools for whole subnets
	OptRange = getopt.StringLong("range", 'r', "", "Specify a CIDR range to use tools for whole subnets.")

	// OptTarget specifies a single IP target or a file with a list of IPs.
	OptTarget = getopt.StringLong("target", 't', "", "Specify target single IP / List of IPs file.")

	// OptVVerbose floods your terminal with plenty of verbosity!
	OptVVerbose = getopt.BoolLong("vv", 'V', "Flood your terminal with plenty of verbosity!")

	// OptVersion displays version information and exits
	OptVersion = getopt.BoolLong("version", 'v', "Display version information and exit.")

	// OptTimeout sets the maximum time (in minutes) for long-running tools like nikto, dirsearch, hydra
	// Default: 10 minutes
	OptTimeout = getopt.IntLong("timeout", 'T', 10, "Maximum time in minutes for long-running tools (nikto, dirsearch, etc). Default: 10")

	// Adding placeholder for OptVhost
	// OptVhost = getopt.StringLong("", '', "", "")
)

// Run pre-flight checks and return total lines if multi-target
func Run() (int, error) {
	// Parse flags early to check for --version
	getopt.Parse()

	// Set global timeout from CLI flag
	utils.ToolTimeout = *OptTimeout

	// Check for version flag
	if *OptVersion {
		fmt.Println(utils.GetVersion())
		os.Exit(0)
	}

	// Check if infra flow or cloud flow apply
	if len(os.Args) < 2 {
		utils.ErrorMsg("You need to choose between `enumeraga infra` or `enumeraga cloud`")
		return 0, fmt.Errorf("no subcommand provided: use 'infra' or 'cloud'")
	}

	switch os.Args[1] {
	case "c", "cl", "clo", "clou", "cloud":
		utils.SetGentleMode(false)
		fmt.Printf("\n%s%s%s\n", utils.Cyan("[*] ---------- "), utils.Green("Starting Cloud checks phase"), utils.Cyan(" ----------"))

		if err := cloud.Run(OptOutput, OptHelp, OptQuiet, OptVVerbose); err != nil {
			return 0, err
		}
		return 0, nil
	case "i", "in", "inf", "infr", "infra":
		utils.SetGentleMode(*OptGentle)
		// Infra checks now moved to internal/infra/infra.go
		return infra.Run(OptHelp, OptInstall, OptNmapOnly, OptQuiet, OptVVerbose, OptOutput, OptTarget)

	default:
		utils.ErrorMsg("You need to choose between `enumeraga infra` or `enumeraga cloud`")
		return 0, fmt.Errorf("invalid subcommand '%s': use 'infra' or 'cloud'", os.Args[1])
	}
}
