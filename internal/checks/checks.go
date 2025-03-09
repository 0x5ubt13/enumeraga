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

	// Adding placeholder for OptVhost
	// OptVhost = getopt.StringLong("", '', "", "")

	// Arm64 determines if software like odat, not currently available for aarch64
	//Arm64 bool
)

// Run pre-flight checks and return total lines if multi-target
func Run() int {
	// Set current version
	utils.Version = "v0.2.0-beta"

	// Check if infra flow or cloud flow apply
	if len(os.Args) < 2 {
		utils.ErrorMsg("You need to choose between `enumeraga infra` or `enumeraga cloud`")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "c", "cl", "clo", "clou", "cloud":
		fmt.Printf("\n%s%s%s\n", utils.Cyan("[*] ---------- "), utils.Green("Starting Cloud checks phase"), utils.Cyan(" ----------"))

		cloud.Run(OptOutput, OptHelp, OptQuiet, OptVVerbose)
	case "i", "in", "inf", "infr", "infra":
		// Infra checks now moved to internal/infra/infra.go
		return infra.Run(OptBrute, OptHelp, OptInstall, OptNmapOnly, OptQuiet, OptVVerbose, OptOutput, OptTopPorts, OptRange, OptTarget)

	default:
		utils.ErrorMsg("You need to choose between `enumeraga infra` or `enumeraga cloud`")
		os.Exit(1)
	}

	return 0
}
