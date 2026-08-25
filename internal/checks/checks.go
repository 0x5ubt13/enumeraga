package checks

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/bounds"
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

	// OptBounded enforces the strict bounded contract: single target, no port
	// widening, no re-sweeps. Implied by any of the bound flags below.
	OptBounded = getopt.BoolLong("bounded", 0, "Enforce a strict scan contract: single target, no port widening, no re-sweeps.")

	// OptPorts specifies an exact port list. Mutually exclusive with --top-ports.
	OptPorts = getopt.StringLong("ports", 0, "", "Scan exactly these ports and no others, e.g. '80,443' or '80,U:53'. Implies --bounded.")

	// OptRate caps requests per second (packets per second for nmap).
	OptRate = getopt.IntLong("rate", 0, 0, "Cap requests/packets per second. Implies --bounded.")

	// OptConcurrency caps how many tool processes run simultaneously.
	OptConcurrency = getopt.IntLong("concurrency", 0, 0, "Maximum simultaneous tool processes. Implies --bounded.")

	// OptMaxRuntime caps the wall-clock duration of the whole run, in seconds.
	OptMaxRuntime = getopt.IntLong("max-runtime", 0, 0, "Wall-clock limit in seconds for the whole run. Implies --bounded.")

	// OptAllowMultiTarget permits a targets file or CIDR range under --bounded.
	OptAllowMultiTarget = getopt.BoolLong("allow-multi-target", 0, "Permit a targets file or CIDR range under --bounded.")

	// OptAllowUnthrottledTools runs tools that cannot honour --rate rather than skipping them.
	OptAllowUnthrottledTools = getopt.BoolLong("allow-unthrottled-tools", 0, "Run tools that have no rate control instead of skipping them.")

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
		// The grammar and mutual-exclusion checks run inside infra.Run, immediately
		// after the parse that populates these flags: validating from here beforehand
		// would read every flag as its zero value, because the parse in this function
		// stops at the 'infra' subcommand argument.
		lines, err := infra.Run(OptHelp, OptInstall, OptNmapOnly, OptQuiet, OptVVerbose, OptOutput, OptTarget, validateBounds)
		if err != nil {
			return lines, err
		}
		// The multi-target refusal is settled here because it needs checkSeven's
		// count of the lines in a targets file.
		if err := applyBounds(lines); err != nil {
			utils.ErrorMsg(err.Error())
			return 0, err
		}
		return lines, nil

	default:
		utils.ErrorMsg("You need to choose between `enumeraga infra` or `enumeraga cloud`")
		return 0, fmt.Errorf("invalid subcommand '%s': use 'infra' or 'cloud'", os.Args[1])
	}
}

// validatedBounds holds the result of validateBounds, so the grammar checks can
// run at the earliest possible moment while the multi-target refusal — which
// needs a target count that is only known later — is settled afterwards, without
// parsing the flags twice.
var validatedBounds *bounds.Bounds

// validateBounds checks the bound flags for grammar and mutual-exclusion
// violations. It is handed to infra.Run so it runs immediately after the flags
// are parsed, before tool installation or output directories: a caller passing a
// malformed --ports should be told so at once, not several minutes into a run.
func validateBounds() error {
	b, err := bounds.Validate(bounds.Config{
		Bounded:               *OptBounded,
		Ports:                 *OptPorts,
		TopPorts:              *OptTopPorts,
		Rate:                  *OptRate,
		Concurrency:           *OptConcurrency,
		MaxRuntimeSeconds:     *OptMaxRuntime,
		AllowMultiTarget:      *OptAllowMultiTarget,
		AllowUnthrottledTools: *OptAllowUnthrottledTools,
		Range:                 *OptRange,
		Gentle:                *OptGentle,
		Target:                *OptTarget,
	})
	if err != nil {
		return err
	}
	validatedBounds = b
	return nil
}

// applyBounds completes bound handling and installs the result for the run.
// totalLines is non-zero when the target is a file of targets, which a bounded
// run refuses: scope must not widen beyond the single host the caller named.
// This check waits for checkSeven's line count, so it cannot run as early as the
// grammar checks in validateBounds.
func applyBounds(totalLines int) error {
	b := validatedBounds
	if b == nil {
		// validateBounds was not reached, so validate now rather than proceeding
		// with an unbounded run the caller did not ask for.
		if err := validateBounds(); err != nil {
			return err
		}
		b = validatedBounds
	}

	if b.Enabled && !b.AllowMultiTarget && totalLines > 0 {
		return fmt.Errorf("a bounded run takes a single target, but '%s' contains %d targets; pass --allow-multi-target to permit it", *OptTarget, totalLines)
	}

	bounds.Active = b

	if b.Enabled && !*OptQuiet {
		utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Bounded run: ", b.SummaryLine())
	}
	return nil
}
