package flags

import getopt "github.com/pborman/getopt/v2"


// Declare global flags and have getopt return pointers to the values.
var (
	// DEV: initialising vars only once they have been implemented/ported in the code
	// optAgain 	= getopt.BoolLong("again", 'a', "Repeat the scan and compare with initial ports discovered.")

	// Activate all fuzzing and bruteforcing in the script
	OptBrute = getopt.BoolLong("brute", 'b', "Activate all fuzzing and bruteforcing in the script.")

	// Specify custom DNS servers. 
	// Default option: -n
	// OptDNS 		= getopt.StringLong("DNS", 'd', "", "Specify custom DNS servers. Default option: -n")

	// Activate debug text
	OptDbg	= getopt.BoolLong("Debug", 'D', "Activate debug text")

	// Display help dialogue and exit
	OptHelp	= getopt.BoolLong("help", 'h', "Display this help and exit.")

	// Only try to install pre-requisite tools and exit
	OptInstall = getopt.BoolLong("install", 'i', "Only try to install pre-requisite tools and exit.")

	// Select a different base folder for the output
	// Default option: "/tmp/enumeraga_output"
	OptOutput	= getopt.StringLong("output", 'o', "/tmp/enumeraga_output", "Select a different base folder for the output.")

	// Run port sweep with nmap and the flag --top-ports=<your input>
	// optTopPorts = getopt.StringLong("top", 'p', "", "Run port sweep with nmap and the flag --top-ports=<your input>")
	// DEV/TODO: For ^^^, use nmap.WithMostCommonPorts()

	// Don't print the banner and decrease overall verbosity
	OptQuiet = getopt.BoolLong("quiet", 'q', "Don't print the banner and decrease overall verbosity.")

	// Specify a CIDR range to use tools for whole subnets
	OptRange = getopt.StringLong("range", 'r', "", "Specify a CIDR range to use tools for whole subnets.")

	// Specify target single IP / List of IPs file.
	OptTarget = getopt.StringLong("target", 't', "", "Specify target single IP / List of IPs file.")

	// Flood your terminal with plenty of verbosity!
	OptVVervose	= getopt.BoolLong("vv", 'V', "Flood your terminal with plenty of verbosity!")
)