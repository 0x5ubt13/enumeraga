package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/portsIterator"
	"github.com/0x5ubt13/enumeraga/internal/scans"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/Ullaakut/nmap/v3"
)

// Main logic of Enumeraga infra
func main() {
	// Initialize global context with signal handling for graceful shutdown
	utils.InitGlobalContext()

	// Show version info
	if utils.Version != "dev" {
		fmt.Printf("%s\n", utils.GetVersion())
	} else {
		fmt.Println("----------\n[!] WARNING: \nYou're running a version currently under beta development. \nPlease use the latest pre-compiled version of Enumeraga in the official repo instead (unless you're helping me debug).\nThanks!\n----------")
	}

	// Perform pre-flight checks and get number of lines if cloud logic hasn't kicked off.
	totalLines, err := checks.Run()
	if err != nil {
		os.Exit(1)
	}

	// Initialize worker pool for concurrent tool execution (limits goroutines)
	utils.InitWorkerPool(utils.MaxWorkersForMode())

	// Timing the execution
	start := time.Now()

	// Cidr handling
	cidrErr := cidrInit()
	if cidrErr != nil {
		utils.PrintCustomBiColourMsg("yellow", "red", "[!] CIDR range ", "NOT ", "detected. Aborting CIDR enumeration for this run")
		utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Remember you can also pass a range in ", "CIDR notation ", "to use ", "enum tools ", "that scan a wide range with '", "-r", "'")
	}

	if !*checks.OptQuiet {
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

	// Print final tool execution summary
	utils.ToolRegistry.PrintFinalSummary()
}

// Check whether a target CIDR range has been passed to Enumeraga
func cidrInit() error {
	if *checks.OptRange != "" {
		commands.RunRangeTools(*checks.OptRange, checks.OptVVerbose, checks.OptOutput)
		return nil
	}

	return fmt.Errorf("CIDR range target not passed to Enumeraga")
}

// Start of main flow:
// Check total number of lines to select targets accordingly
func targetInit(totalLines int) error {
	// If bruteforce flag was passed, initialise the wordlists
	if *checks.OptBrute && !*checks.OptNmapOnly {
		if !*checks.OptQuiet {
			fmt.Printf("%s\n", utils.Cyan("[*] Bruteforce flag detected. Activating fuzzing and bruteforce tools where applicable."))
		}
		if err := utils.GetWordlists(checks.OptVVerbose); err != nil {
			utils.ErrorMsg(fmt.Sprintf("Failed to locate wordlists: %v", err))
		}
	}

	// If not single target, initialise multi target flow
	if totalLines != 0 {
		multiTarget(checks.OptTarget)
		return nil
	}

	// If made it this far, run single target scan
	err := singleTarget(*checks.OptTarget, *checks.OptOutput)
	if err != nil {
		utils.Interrupted = true
		return err
	}

	utils.PrintCustomBiColourMsg("green", "yellow", "[+] Done! All well-known ports included in Enumeraga for '", utils.Target, "' were successfully parsed.")

	return nil
}

func sweepPorts() ([]nmap.Host, []nmap.Host, error) {
	var tcpHosts, udpHosts []nmap.Host
	var tcpErr, udpErr error

	// If top ports flag passed, branch to use a common ports scan instead
	if *checks.OptTopPorts != "" {
		tcpHosts, tcpErr = scans.TcpPortSweepWithTopPorts(utils.Target, checks.OptTopPorts, checks.OptVVerbose)
		udpHosts, udpErr = scans.UdpPortSweep(utils.Target, checks.OptVVerbose)
	} else if utils.TimesSwept == 0 {
		tcpHosts, tcpErr = scans.TcpPortSweep(utils.Target, checks.OptVVerbose)
		udpHosts, udpErr = scans.UdpPortSweep(utils.Target, checks.OptVVerbose)
	} else {
		tcpHosts, tcpErr = scans.SlowerTcpPortSweep(utils.Target, checks.OptVVerbose)
		udpHosts, udpErr = scans.SlowerUdpPortSweep(utils.Target, checks.OptVVerbose)
	}

	// Combine errors if both failed
	if tcpErr != nil && udpErr != nil {
		return nil, nil, fmt.Errorf("TCP scan error: %v; UDP scan error: %v", tcpErr, udpErr)
	}
	if tcpErr != nil {
		utils.ErrorMsg(fmt.Sprintf("TCP scan failed: %v", tcpErr))
	}
	if udpErr != nil {
		utils.ErrorMsg(fmt.Sprintf("UDP scan failed: %v", udpErr))
	}

	return tcpHosts, udpHosts, nil
}

// Run all phases of scanning using a single target
func singleTarget(target string, baseFilePath string) error {
	// Clean up trailing not alphanumeric characters in target
	target = strings.TrimFunc(target, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '.' && r != '-'
	})

	// Validate target is not empty after trimming
	if target == "" {
		return fmt.Errorf("target is empty after sanitization")
	}

	utils.Target = target

	// Make base dir for the target
	targetPath := fmt.Sprintf("%s/%s/", baseFilePath, target)
	_, err := utils.CustomMkdir(targetPath)
	if err != nil {
		if *checks.OptVVerbose {
			utils.ErrorMsg(err)
		}
	}

	// Perform ports sweep
	utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Sweeping TCP and UDP ports on target '", target, "', please wait...")
	sweptHostTcp, sweptHostUdp, sweepErr := sweepPorts()
	if sweepErr != nil {
		return fmt.Errorf("port sweep failed: %w", sweepErr)
	}

	// Save open ports in dedicated slice
	// Convert slice to nmap-friendly formatted numbers
	openPortsSlice := utils.GetOpenPortsSlice(sweptHostTcp, sweptHostUdp)

	// Join our string slice for printing purposes
	openPorts := utils.RemoveDuplicates(strings.Join(openPortsSlice, ","))

	// Introducing a control to repeat the scan in case there are no ports or there is only one port open
	// Do it only once
	if len(openPorts) <= 1 && utils.TimesSwept == 1 {
		sweptHostTcpSecond, sweptHostUdpSecond, secondSweepErr := sweepPorts()
		if secondSweepErr != nil {
			utils.ErrorMsg(fmt.Sprintf("Second port sweep failed: %v", secondSweepErr))
		} else {
			openPortsSliceSecondTry := utils.GetOpenPortsSlice(sweptHostTcpSecond, sweptHostUdpSecond)

			if len(openPortsSliceSecondTry) > len(openPortsSlice) {
				openPorts = utils.RemoveDuplicates(strings.Join(openPortsSliceSecondTry, ","))
				utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] More ports found in the second slow run for target '", target, "'.")
			} else {
				utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] No further ports were found in the second slow run for target '", target, "'.")
			}
		}
	}

	if len(openPorts) > 0 {
		utils.PrintCustomBiColourMsg("green", "cyan", "[+] Open ports for target '", target, "' : ", openPorts)
		if _, err := utils.WritePortsToFile(targetPath, openPorts, target); err != nil {
			utils.ErrorMsg(fmt.Sprintf("Failed to write ports to file: %v", err))
		}

		// Launch main aggressive nmap scan in parallel that covers all open ports found
		outFile := targetPath + "aggressive_scan"
		commands.CallFullAggressiveScan(target, openPorts, outFile, checks.OptVVerbose)
	} else {
		return fmt.Errorf("no ports were found open")
	}

	// Run ports iterator with the open ports found if nmap only flag not passed
	if *checks.OptNmapOnly {
		return nil
	}
	utils.BaseDir = targetPath
	portsIterator.Run(openPortsSlice)

	return nil
}

// Wrapper of single target for multi-target
func multiTarget(targetsFile *string) {
	if !*checks.OptQuiet {
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Using multi-targets file: '", *targetsFile, "'")
	}

	fileNameWithExtension := strings.Split(*targetsFile, "/")
	fileName := strings.Split(fileNameWithExtension[len(fileNameWithExtension)-1], ".")

	// Make base folder for the output
	targetsBaseFilePath := fmt.Sprintf("%s/%s", *checks.OptOutput, fileName[0])
	_, err := utils.CustomMkdir(targetsBaseFilePath)
	if err != nil {
		if *checks.OptVVerbose {
			utils.ErrorMsg(err)
		}
	}

	// Loop through the targets in the file
	targets, lines := utils.ReadTargetsFile(checks.OptTarget)
	if !*checks.OptQuiet {
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Found ", fmt.Sprintf("%d", lines), " targets")
	}

	for i := 0; i < lines; i++ {
		// Reset visited flags for each new target to allow fresh enumeration
		utils.ResetVisitedFlags()

		target := targets[i]

		// Clean up trailing not alphanumeric characters in target
		target = strings.TrimFunc(target, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '.' && r != '-' && r != ':'
		})

		// Skip empty targets after sanitization
		if target == "" {
			utils.PrintCustomBiColourMsg("yellow", "red", "[!] Skipping empty target at line ", fmt.Sprint(i+1))
			continue
		}

		// Try to resolve hostname/URL to IP if it's not already an IP
		resolvedTarget := target
		if ip := strings.TrimSpace(target); ip != "" {
			// Check if it's not already an IP address
			if net.ParseIP(ip) == nil {
				// Try to resolve as hostname/URL
				if resolvedIP, err := utils.ResolveHostToIP(ip); err == nil {
					utils.PrintCustomBiColourMsg("green", "cyan", "[+] Resolved hostname '", target, "' to IP: ", resolvedIP)
					resolvedTarget = resolvedIP
				} else {
					utils.PrintCustomBiColourMsg("red", "yellow", "[-] Failed to resolve hostname '", target, "': ", err.Error())
					continue
				}
			}
		}

		// Launch enumeration for the target
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Attacking target ", fmt.Sprint(i+1), " of ", fmt.Sprint(lines), ": ", resolvedTarget)
		err := singleTarget(resolvedTarget, targetsBaseFilePath)
		if err != nil {
			utils.PrintCustomBiColourMsg("red", "yellow", "[-] No open ports were found in host '", resolvedTarget, "'. Aborting the rest of scans for this host")
			continue
		}

		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Done! All well-known ports included in Enumeraga for '", resolvedTarget, "' were successfully parsed.")
	}
}
