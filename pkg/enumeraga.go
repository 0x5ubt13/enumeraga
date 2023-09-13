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
	// Timing the execution time
	defer timeTracker(time.Now(), "main")

	if *optDbg { 
		fmt.Println("Debug - Start of main function") 
		defer fmt.Println("Debug - End of main function") 
	}

	// Perform pre-flight checks and get number of lines.
	totalLines := checks()
	if *optDbg { fmt.Printf("Debug - lines: %v\n", totalLines) }

	// Cidr handling
	cidrErr := cidrInit()
	if cidrErr != nil {
		printCustomTripleMsg("yellow", "red", "[!] CIDR range", "NOT", "detected. Remember you can also pass a range in CIDR notation to use enum tools that scan a wide range with '-r'")
	}

	// Main flow:
	flowErr := targetInit(totalLines)
	if flowErr != nil {
		errorMsg(fmt.Sprintf("%s", flowErr))
	} 

	// Wait for goroutines to finish
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

// Main flow
// Check total number of lines. 
// If it's 0, init singleTarget
// If it's not 0, init multiTarget
func targetInit(totalLines int) error {
	// If bruteforce flag was passed, initialise the wordlists
	if *optBrute { getWordlists() }

	if totalLines != 0 {
		multiTarget(optTarget)
		// if err != nil {
		// 	return err
		// }
		// return nil
	}

	err := singleTarget(*optTarget, *optOutput, false)
	if err != nil {
		return err
	}

	return nil
}

// Run all phases of scanning using a single target
func singleTarget(target string, baseFilePath string, multiTarget bool) error {
	if *optDbg {
		fmt.Println("Debug - Start of singleTarget function") 
		defer fmt.Println("Debug - End of singleTarget function") 
		fmt.Printf("Debug - Single target: %s\n", target)
		fmt.Printf("Debug - Base file path: %s\n", baseFilePath)
	}
	
	targetPath := fmt.Sprintf("%s/%s/", baseFilePath, target)
	// Make base dir for the target
	customMkdir(targetPath)

	// Perform ports sweep
	if !multiTarget && !*optQuiet {printPhase(2)}
	sweptHost := portSweep(target)

	// Save open ports in dedicated slice
	// Convert slice to nmap-friendly formatted numbers
    openPortsSlice := []string{}
    
    // Create a string slice using strconv.FormatUint
    // ... Append strings to it.
    for _, host := range sweptHost {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			// Error below: string(port.State) not working for some reason, therefore using Sprintf
			if fmt.Sprintf("%s", port.State) == "open" {
				if *optDbg && *optVVervose {fmt.Println("Debug - Open port:", port.ID)}
				text := strconv.FormatUint(uint64(port.ID), 10)
				openPortsSlice = append(openPortsSlice, text)
			}
		}
    }
    
    // Join our string slice.
    openPorts := strings.Join(openPortsSlice, ",")

	if len(openPorts) > 0 {
		fmt.Printf("%s %s: %v\n", green("[+] Open ports for target"), yellow(target), openPorts)
		writePortsToFile(targetPath, openPorts, target)

		// Launch main aggressive nmap scan in parallel that covers all open ports found
		outFile := targetPath + "aggressive_scan"
		callFullAggressiveScan(target, openPorts, outFile)
	} else {
		return fmt.Errorf("no ports were found open") 
	}

	if !multiTarget && !*optQuiet {printPhase(3)}

	// Run ports iterator with the open ports found
	portsIterator(target, targetPath, openPortsSlice)

	return nil
}

// Wrapper of single target for multi-target
func multiTarget(targetsFile *string) {
	if *optDbg { 
		fmt.Println("Debug - Start of multiTarget function") 
		defer fmt.Println("Debug - End of multiTarget function") 
	}

	if !*optQuiet { fmt.Printf("%s%s\n", green("[+] Using multi-targets file: "), yellow(*targetsFile)) }
	fileNameWithExtension := strings.Split(*targetsFile, "/")
	fileName := strings.Split(fileNameWithExtension[len(fileNameWithExtension)-1], ".")

	// Make base folder for the output
	targetsBaseFilePath := fmt.Sprintf("%s/%s", *optOutput, fileName[0])
	customMkdir(targetsBaseFilePath)

	// Loop through the targets in the file
	targets, lines := readTargetsFile(*targetsFile)
	if !*optQuiet { printCustomTripleMsg("green", "yellow", "[+] Found", fmt.Sprintf("%d", lines), "targets")}
	for i := 0; i < lines; i++ {
		target := targets[i]
		fmt.Printf("%s %v %s %v: %s\n", green("[+] Attacking target"), yellow(i+1), green("of"), yellow(lines), yellow(target))
		err := singleTarget(target, targetsBaseFilePath, true)
		if err != nil {
			printCustomTripleMsg("red", "yellow", "[-] No open ports were found in host", target, ". Aborting the rest of scans for this host")
		}
	}
}