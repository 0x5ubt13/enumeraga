package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator"
	"github.com/0x5ubt13/enumeraga/internal/scans"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// Main logic of enumeraga
func main() {
	// Timing the execution
	start := time.Now()

	// Perform pre-flight checks and get number of lines.
	totalLines := checks.Run()
	if *utils.OptDbg {
		fmt.Printf("%s%v\n", utils.Debug("Debug - lines: "), totalLines)
	}

	// Cidr handling
	cidrErr := cidrInit()
	if cidrErr != nil {
		utils.PrintCustomBiColourMsg("yellow", "red", "[!] CIDR range ", "NOT ", "detected. Aborting CIDR enumeration for this run")
		utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Remember you can also pass a range in ", "CIDR notation ", "to use ", "enum tools ", "that scan a wide range with '", "-r", "'")
	}

	if !*utils.OptQuiet {
		fmt.Printf("%s%s%s\n\n", utils.Cyan("[*] ---------- "), utils.Green("Checks phase complete"), utils.Cyan(" ----------"))
		fmt.Printf("%s%s%s\n", utils.Cyan("[*] ---------- "), utils.Green("Starting enumeration phase"), utils.Cyan(" ----------"))
	}

	// Main flow
	flowErr := targetInit(totalLines)
	if flowErr != nil {
		utils.ErrorMsg(fmt.Sprintf("%s", flowErr))
	}

	// Finish and show elapsed time
	utils.FinishLine(start, utils.Interrupted)

	// Wait for goroutines to finish to terminate the program
	utils.Wg.Wait()
}

// Check whether a target CIDR range has been passed to Enumeraga
func cidrInit() error {
	if *utils.OptRange != "" {
		commands.RunRangeTools(*utils.OptRange)
		return nil
	}

	return fmt.Errorf("CIDR range target not passed to Enumeraga")
}

// Start of main flow:
// Check total number of lines to select targets accordingly
func targetInit(totalLines int) error {
	// If bruteforce flag was passed, initialise the wordlists
	if *utils.OptBrute {
		utils.GetWordlists()
	}

	// If not single target, initialise multi target flow
	if totalLines != 0 {
		multiTarget(utils.OptTarget)
		return nil
	}

	// If made it this far, run single target scan
	err := singleTarget(*utils.OptTarget, *utils.OptOutput, false)
	if err != nil {
		utils.Interrupted = true
		return err
	}

	return nil
}

// Run all phases of scanning using a single target
func singleTarget(target string, baseFilePath string, multiTarget bool) error {
	if *utils.OptDbg {
		fmt.Println(utils.Debug("Debug Start of singleTarget function"))
		defer fmt.Println(utils.Debug("Debug End of singleTarget function"))
		fmt.Printf("%s%s\n", utils.Debug("Debug - Single target: "), target)
		fmt.Printf("%s%s\n", utils.Debug("Debug - Base file path: "), baseFilePath)
	}

	// Make base dir for the target
	targetPath := fmt.Sprintf("%s/%s/", baseFilePath, target)
	utils.CustomMkdir(targetPath)

	// Perform ports sweep
	utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Sweeping TCP and UDP ports on target '", target, "'...")
	if *utils.OptDbg {
		fmt.Println(utils.Debug("Debug - Starting TCP ports sweep"))
	}
	sweptHostTcp := scans.TcpPortSweep(target)

	if *utils.OptDbg {
		fmt.Println(utils.Debug("Debug - Starting UDP ports sweep"))
	}
	sweptHostUdp := scans.UdpPortSweep(target)

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
				if *utils.OptDbg && *utils.OptVVervose {
					fmt.Println(utils.Debug("Debug Open port:", port.ID))
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
				if *utils.OptDbg && *utils.OptVVervose {
					fmt.Println(utils.Debug("Debug Open port:", port.ID))
				}
				text := strconv.FormatUint(uint64(port.ID), 10)
				openPortsSlice = append(openPortsSlice, text)
			}
		}
	}

	// Join our string slice.
	openPorts := utils.RemoveDuplicates(strings.Join(openPortsSlice, ","))

	if len(openPorts) > 0 {
		utils.PrintCustomBiColourMsg("green", "cyan", "[+] Open ports for target '", target, "' : ", openPorts)
		utils.WritePortsToFile(targetPath, openPorts, target)

		// Launch main aggressive nmap scan in parallel that covers all open ports found
		outFile := targetPath + "aggressive_scan"
		commands.CallFullAggressiveScan(target, openPorts, outFile)
	} else {
		return fmt.Errorf("no ports were found open")
	}

	// Run ports iterator with the open ports found
	portsIterator.Run(target, targetPath, openPortsSlice)

	return nil
}

// Wrapper of single target for multi-target
func multiTarget(targetsFile *string) {
	if *utils.OptDbg {
		fmt.Println(utils.Debug("Debug Start of multiTarget function"))
		defer fmt.Println(utils.Debug("Debug End of multiTarget function"))
	}

	if !*utils.OptQuiet {
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Using multi-targets file: '", *targetsFile, "'")
	}

	fileNameWithExtension := strings.Split(*targetsFile, "/")
	fileName := strings.Split(fileNameWithExtension[len(fileNameWithExtension)-1], ".")

	// Make base folder for the output
	targetsBaseFilePath := fmt.Sprintf("%s/%s", *utils.OptOutput, fileName[0])
	utils.CustomMkdir(targetsBaseFilePath)

	// Loop through the targets in the file
	targets, lines := utils.ReadTargetsFile(*targetsFile)
	if !*utils.OptQuiet {
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Found", fmt.Sprintf("%d", lines), "targets")
	}

	for i := 0; i < lines; i++ {
		target := targets[i]
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Attacking target", fmt.Sprint(i+1), "of", fmt.Sprint(lines), ":", target)
		err := singleTarget(target, targetsBaseFilePath, true)
		if err != nil {
			utils.PrintCustomBiColourMsg("red", "yellow", "[-] No open ports were found in host '", target, "'. Aborting the rest of scans for this host")
		}
	}
}
