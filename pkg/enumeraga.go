package main

import (
	// "context"
	"fmt"
	// "log"
	// "os"
	// "time"

	// "github.com/fatih/color"
	
	getopt "github.com/pborman/getopt/v2"
	
)

// Declare flags and have getopt return pointers to the values.
var optAgain 	= getopt.BoolLong("again", 'a', "Repeat the scan and compare with initial ports discovered.")
var optBrute	= getopt.BoolLong("brute", 'b', "Activate all fuzzing and bruteforcing in the script.")
var optDNS 		= getopt.StringLong("DNS", 'd', "", "Specify custom DNS servers. Default option: -n")
var optHelp 	= getopt.BoolLong("help", 'h', "Display this help and exit.")
var optOutput	= getopt.StringLong("output", 'o', "/tmp/autoEnum_output", "Select a different base folder for the output." )
var optTopPorts = getopt.StringLong("top", 'p', "", "Run port sweep with nmap and the flag --top-ports=<your input>")
var optQuiet 	= getopt.BoolLong("quiet", 'q', "Don't print the banner and decrease overall verbosity.")
var optRange 	= getopt.StringLong("range", 'r', "", "Specify a CIDR range to use tools for whole subnets")
var optTarget 	= getopt.StringLong("target", 't', "", "Specify target single IP / List of IPs file.")

func main() {
	// Parse the program arguments
	// getopt.Parse()
	// Get the remaining positional parameters
	// args := getopt.Args()
	
	// Perform pre-flight checks and get number of lines.
	totalLines := checks()

	// Get CIDR
	// printPhase(1)

	// Main flow:
	if totalLines == 0 {
		printPhase(3)
		singleTarget(*optTarget, *optOutput)
	} else {
		printPhase(33)
		multiTarget(optTarget)
	}

	// fmt.Printf("Debug: data: %s\n", targets)
	fmt.Printf("Debug: lines: %v\n", totalLines)

	// scan
	//scan()

	fmt.Println("End of main function")
}