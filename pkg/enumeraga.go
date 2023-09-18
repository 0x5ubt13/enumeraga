package main

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var wg sync.WaitGroup

// Main logic of enumeraga
func main() {
	// Timing the execution
	start := time.Now()

	// DEV: Helpful strings for debugging purposes to check how goroutines work
	if *optDbg {
		fmt.Println(debug("Debug Start of main function"))
		defer fmt.Println(debug("Debug End of main function"))
	}

	// Perform pre-flight checks and get number of lines.
	totalLines := checks()
	if *optDbg {
		fmt.Printf("%s%v\n", debug("Debug - lines: "), totalLines)
	}

	// Cidr handling
	cidrErr := cidrInit()
	if cidrErr != nil {
		printCustomBiColourMsg("yellow", "red", "[!] CIDR range ", "NOT ", "detected. Aborting CIDR enumeration for this run")
		printCustomBiColourMsg("cyan", "yellow", "[*] Remember you can also pass a range in ", "CIDR notation ", "to use ", "enum tools ", "that scan a wide range with '", "-r", "'")
	}

	// Main flow:
	flowErr := targetInit(totalLines)
	if flowErr != nil {
		errorMsg(fmt.Sprintf("%s", flowErr))
	}

	// Finish and show elapsed time
	finishLine(start)

	// Wait for goroutines to finish to terminate the program
	wg.Wait()
}

// Check whether a target CIDR range has been passed to Enumeraga
func cidrInit() error {
	printPhase(1)
	if *optRange != "" {
		// Run CIDR range tools
		runRangeTools(*optRange)
		return nil
	}

	return fmt.Errorf("CIDR range target not passed to Enumeraga")
}

// Start of main flow:
// Check total number of lines to select targets accordingly
func targetInit(totalLines int) error {
	// If bruteforce flag was passed, initialise the wordlists
	if *optBrute { getWordlists() }

	if totalLines != 0 { multiTarget(optTarget) }

	err := singleTarget(*optTarget, *optOutput, false)
	if err != nil {
		return err
	}

	return nil
}

// Run all phases of scanning using a single target
func singleTarget(target string, baseFilePath string, multiTarget bool) error {
	if *optDbg {
		fmt.Println(debug("Debug Start of singleTarget function"))
		defer fmt.Println(debug("Debug End of singleTarget function"))
		fmt.Printf("%s%s\n", debug("Debug - Single target: "), target)
		fmt.Printf("%s%s\n", debug("Debug - Base file path: "), baseFilePath)
	}

	// Make base dir for the target
	targetPath := fmt.Sprintf("%s/%s/", baseFilePath, target)
	customMkdir(targetPath)

	// Perform ports sweep
	if !multiTarget && !*optQuiet { printPhase(2) }
	printCustomBiColourMsg("cyan", "yellow", "[*] Sweeping TCP and UDP ports on target '", target, "'...")
	if *optDbg { fmt.Println(debug("Debug - Starting TCP ports sweep")) }
	sweptHostTcp := tcpPortSweep(target)

	if *optDbg { fmt.Println(debug("Debug - Starting UDP ports sweep")) }
	sweptHostUdp := udpPortSweep(target)


	// Save open ports in dedicated slice
	// Convert slice to nmap-friendly formatted numbers
	openPortsSlice := []string{}

	// Create a string slice using strconv.FormatUint
	// ... Append strings to it.
	for _, host := range sweptHostTcp {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			// Error below: string(port.State) not working for some reason, therefore using Sprintf
			if fmt.Sprintf("%s", port.State) == "open" {
				if *optDbg && *optVVervose {
					fmt.Println(debug("Debug Open port:", port.ID))
				}
				text := strconv.FormatUint(uint64(port.ID), 10)
				openPortsSlice = append(openPortsSlice, text)
			}
		}
	}

	// Same than above but for the swept ports running on UDP
	for _, host := range sweptHostUdp {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			// Error below: string(port.State) not working for some reason, therefore using Sprintf
			if fmt.Sprintf("%s", port.State) == "open" {
				if *optDbg && *optVVervose {
					fmt.Println(debug("Debug Open port:", port.ID))
				}
				text := strconv.FormatUint(uint64(port.ID), 10)
				openPortsSlice = append(openPortsSlice, text)
			}
		}
	}

	// Join our string slice.
	openPorts := removeDuplicates(strings.Join(openPortsSlice, ","))


	if len(openPorts) > 0 {
		printCustomBiColourMsg("green", "cyan", "[+] Open ports for target '", target, "' : ", openPorts)
		writePortsToFile(targetPath, openPorts, target)

		// Launch main aggressive nmap scan in parallel that covers all open ports found
		outFile := targetPath + "aggressive_scan"
		callFullAggressiveScan(target, openPorts, outFile)
	} else {
		return fmt.Errorf("no ports were found open")
	}

	// Run ports iterator with the open ports found
	if !multiTarget && !*optQuiet { printPhase(3) }
	portsIterator(target, targetPath, openPortsSlice)

	return nil
}

// Wrapper of single target for multi-target
func multiTarget(targetsFile *string) {
	if *optDbg {
		fmt.Println(debug("Debug Start of multiTarget function"))
		defer fmt.Println(debug("Debug End of multiTarget function"))
	}

	if !*optQuiet { printCustomBiColourMsg("green", "yellow", "[+] Using multi-targets file: '", *targetsFile, "'") }
	fileNameWithExtension := strings.Split(*targetsFile, "/")
	fileName := strings.Split(fileNameWithExtension[len(fileNameWithExtension)-1], ".")

	// Make base folder for the output
	targetsBaseFilePath := fmt.Sprintf("%s/%s", *optOutput, fileName[0])
	customMkdir(targetsBaseFilePath)

	// Loop through the targets in the file
	targets, lines := readTargetsFile(*targetsFile)
	if !*optQuiet {
		printCustomBiColourMsg("green", "yellow", "[+] Found", fmt.Sprintf("%d", lines), "targets")
	}
	for i := 0; i < lines; i++ {
		target := targets[i]
		printCustomBiColourMsg("green", "yellow", "[+] Attacking target", fmt.Sprint(i+1), "of", fmt.Sprint(lines), ":", target)
		err := singleTarget(target, targetsBaseFilePath, true)
		if err != nil {
			printCustomBiColourMsg("red", "yellow", "[-] No open ports were found in host '", target, "'. Aborting the rest of scans for this host")
		}
	}
}
