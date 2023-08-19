package main

import (
	// "context"
	"fmt"
	// "log"
	// "os"
	// "time"

	// "github.com/fatih/color"	
)

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