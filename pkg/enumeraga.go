package main

import (
	"fmt"
	"strconv"
	"strings"
)

// Main logic of enumeraga
func main() {
	// Perform pre-flight checks and get number of lines.
	totalLines := checks()

	// Get CIDR
	// printPhase(1)

	// Main flow:
	if totalLines == 0 {
		singleTarget(*optTarget, *optOutput, false)
	} else {
		multiTarget(optTarget)
	}

	if *optDbg {
		fmt.Printf("Debug - lines: %v\n", totalLines)
		fmt.Println("Debug - End of main function")
	}
}

// Run all phases of scanning using a single target
func singleTarget(target string, baseFilePath string, multiTarget bool) {
	if *optDbg {
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
			// string(port.State) not working for some reason, therefore using Sprintf
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
	} else {
		fmt.Printf("%s %s%s\n", red("[-] No open ports were found in host"), yellow(target), red(". Aborting the rest of scans for this host"))
		return 
	}

	if !multiTarget && !*optQuiet {printPhase(3)}

	// Launch main aggressive nmap scan that covers all open ports found
	
	
	// Run ports iterator with the open ports found
	portsIterator(target, targetPath, openPortsSlice)


}

// Wrapper of single target for multi-target
func multiTarget(targetsFile *string) {
	if !*optQuiet { fmt.Printf("%s%s\n", green("[+] Using multi-targets file: "), yellow(*targetsFile)) }
	fileNameWithExtension := strings.Split(*targetsFile, "/")
	fileName := strings.Split(fileNameWithExtension[len(fileNameWithExtension)-1], ".")

	// Make base folder for the output
	targetsBaseFilePath := fmt.Sprintf("%s/%s", *optOutput, fileName[0])
	customMkdir(targetsBaseFilePath)

	// Loop through the targets in the file
	targets, lines := readTargetsFile(*targetsFile)
	if !*optQuiet { fmt.Printf("%s %s %s\n", green("[+] Found"), yellow(lines), green("targets")) }
	for i := 0; i < lines; i++ {
		target := targets[i]
		fmt.Printf("%s %v %s %v: %s\n", green("[+] Attacking target"), yellow(i+1), green("of"), yellow(lines), yellow(target))
		singleTarget(target, targetsBaseFilePath, true)
	}
}