package scans

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/utils"
	nmap "github.com/Ullaakut/nmap/v3"
)

// TcpPortSweep runs a quick port sweep on TCP.
func TcpPortSweep(target string) []nmap.Host {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p1-65535 --min-rate=2000 --privileged <target>`,
	// with a 15-minute timeout.
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts("1-65535"),
		nmap.WithMinRate(2000),
		nmap.WithPrivileged(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVerbose {
			fmt.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	utils.TimesSwept += 1

	return result.Hosts
}

func SlowerTcpPortSweep(target string) []nmap.Host {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p1-65535 --min-rate=2000 --privileged <target>`,
	// with a 15-minute timeout.
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts("1-65535"),
		nmap.WithMinRate(500),
		nmap.WithPrivileged(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVerbose {
			fmt.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	utils.TimesSwept = 0

	return result.Hosts
}

// TcpPortSweepWithTopPorts runs the quickest port sweep on TCP
func TcpPortSweepWithTopPorts(target string) []nmap.Host {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	topPorts, err := strconv.Atoi(*utils.OptTopPorts)
	if err != nil {
		log.Fatalf("unable to convert top ports var: %v", err)
	}

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithMostCommonPorts(topPorts),
		nmap.WithTargets(target),
		nmap.WithMinRate(2000),
		nmap.WithPrivileged(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVerbose {
			fmt.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	return result.Hosts
}

// UdpPortSweep runs a quick port sweep on UDP
func UdpPortSweep(target string) []nmap.Host {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -sU -p111,161,162,10161,10162,623 --min-rate=2000 --privileged <target>`,
	// with a 15-minute timeout.
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithUDPScan(),
		nmap.WithPorts("111,161,162,10161,10162,623"),
		nmap.WithMinRate(2000),
		nmap.WithPrivileged(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner udpPortSweep: %s %v", target, err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVerbose {
			log.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan udpPortSweep: %v", err)
	}

	return result.Hosts
}

// SlowerUdpPortSweep runs a slower port sweep on UDP
func SlowerUdpPortSweep(target string) []nmap.Host {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -sU -p111,161,162,10161,10162,623 --min-rate=2000 --privileged <target>`,
	// with a 15-minute timeout.
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithUDPScan(),
		nmap.WithPorts("111,161,162,10161,10162,623"),
		nmap.WithMinRate(500),
		nmap.WithPrivileged(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner udpPortSweep: %s %v", target, err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVerbose {
			log.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan udpPortSweep: %v", err)
	}

	return result.Hosts
}

// Run an Nmap scan with NSE scripts
func IndividualPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts(port),
		nmap.WithPrivileged(),
		nmap.WithMinRate(500),
		nmap.WithDisabledDNSResolution(),
		nmap.WithDefaultScript(),
		nmap.WithServiceInfo(),
		nmap.WithNmapOutput(outFile+".nmap"),
		nmap.WithGrepOutput(outFile+".grep"),
		nmap.WithScripts(scripts),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner individualPortScannerWithNSEScripts: %s %s %s %v", target, port, outFile, err)
	}

	ticker := time.NewTicker(2 * time.Minute)
	done := make(chan bool)

	go func() {
		for {
			select {
			case t := <-ticker.C:
				utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan with NSE Scripts still running against port(s) '", port, "' on target '", target, "'. Please wait...")
				if *utils.OptVVerbose {
					fmt.Println(utils.Debug(t))
				}
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVerbose {
			log.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualPortScannerWithNSEScripts: %s %s %s %v", target, port, outFile, err)
	}

	ticker.Stop()
	done <- true

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(outFile+".nmap"))
}

// Run an Nmap scan with NSE scripts and NSE script arguments
func IndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts(port),
		nmap.WithPrivileged(),
		nmap.WithMinRate(500),
		nmap.WithDisabledDNSResolution(),
		nmap.WithDefaultScript(),
		nmap.WithServiceInfo(),
		nmap.WithNmapOutput(outFile+".nmap"),
		nmap.WithGrepOutput(outFile+".grep"),
		nmap.WithScripts(scripts),
		nmap.WithScriptArguments(scriptArgs),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner individualPortScannerWithNSEScriptsAndScriptArgs: %s %s %s %v", target, port, outFile, err)
	}

	ticker := time.NewTicker(2 * time.Minute)
	done := make(chan bool)

	go func() {
		for {
			select {
			case t := <-ticker.C:
				utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan with NSE scripts and args still running against port(s) '", port, "' on target '", target, "'. Please wait...")
				if *utils.OptVVerbose {
					fmt.Println(utils.Debug(t))
				}
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVerbose {
			log.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualPortScannerWithNSEScriptsAndScriptArgs: %s %s %s %v", target, port, outFile, err)
	}

	ticker.Stop()
	done <- true

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(outFile+".nmap"))
}

// Run an UDP Nmap scan with NSE scripts
func IndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting UDP scan against port(s) '", port, "' on target '", target, "' and sending it to the background")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithUDPScan(),
		nmap.WithPorts(port),
		nmap.WithPrivileged(),
		nmap.WithMinRate(500),
		nmap.WithDisabledDNSResolution(),
		nmap.WithDefaultScript(),
		nmap.WithServiceInfo(),
		nmap.WithNmapOutput(outFile+".nmap"),
		nmap.WithGrepOutput(outFile+".grep"),
		nmap.WithScripts(scripts),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner individualUDPPortScannerWithNSEScripts: %s %s %s %v", target, port, outFile, err)
	}

	ticker := time.NewTicker(2 * time.Minute)
	done := make(chan bool)

	go func() {
		for {
			select {
			case t := <-ticker.C:
				utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan on UDP with NSE scripts still running against port(s) '", port, "' on target '", target, "'. Please wait...")
				if *utils.OptVVerbose {
					fmt.Println(utils.Debug(t))
				}
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVerbose {
			log.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualUDPPortScannerWithNSEScripts: %s %s %s %v", target, port, outFile, err)
	}

	ticker.Stop()
	done <- true

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! UDP scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less"), utils.Cyan(outFile+".nmap"))
}

// Run a simple Nmap scan
func IndividualPortScanner(target, port, outFile string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts(port),
		nmap.WithPrivileged(),
		nmap.WithMinRate(500),
		nmap.WithDisabledDNSResolution(),
		nmap.WithDefaultScript(),
		nmap.WithServiceInfo(),
		nmap.WithNmapOutput(outFile+".nmap"),
		nmap.WithGrepOutput(outFile+".grep"),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner individualPortScanner: %s %s %s %v", target, port, outFile, err)
	}

	lapsed := 0
	ticker := time.NewTicker(1 * time.Minute)
	done := make(chan bool)

	go func() {
		for {
			select {
			case t := <-ticker.C:
				if *utils.OptVVerbose {
					fmt.Println(utils.Debug("Very verbose - ticker.C contents:", t))
				}

				lapsed++
				if lapsed == 1 {
					utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan still running against port(s) '", port, "' on target '", target, "'. Time lapsed: '", "1", "' minute. Please wait...")
				} else {
					utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan still running against port(s) '", port, "' on target '", target, "'. Time lapsed: '", strconv.Itoa(lapsed), "' minutes. Please wait...")
				}
			case <-done:
				return
			}
		}
	}()

	_, _, err = scanner.Run()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("unable to run nmap scan individualPortScanner: %s %s %s %v", target, port, outFile, err))
	}

	ticker.Stop()
	done <- true

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! Nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less"), utils.Cyan(outFile+".nmap"))
}

// Run main aggressive scan for all open ports on the target
func FullAggressiveScan(target, ports, outFile string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts(ports),
		nmap.WithPrivileged(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithNmapOutput(outFile+".nmap"),
		nmap.WithOSDetection(),
		nmap.WithServiceInfo(),
		nmap.WithDefaultScript(),
		nmap.WithGrepOutput(outFile+".grep"),
		nmap.WithSkipHostDiscovery(),
		nmap.WithVerbosity(2),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner fullAggressiveScan: %v", err)
	}

	lapsed := 0
	ticker := time.NewTicker(1 * time.Minute)
	done := make(chan bool)

	go func() {
		for {
			select {
			case t := <-ticker.C:
				if *utils.OptVVerbose {
					fmt.Println(utils.Debug("Very verbose - ticker.C contents:", t))
				}

				lapsed++
				if lapsed == 1 {
					utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Main nmap scan still running against all open ports on target '", target, "'. Time lapsed: '", "1", "' minute. Please wait...")
				} else {
					utils.PrintCustomBiColourMsg("cyan", "yellow", "[*] Main nmap scan still running against all open ports on target '", target, "'. Time lapsed: '", strconv.Itoa(lapsed), "' minutes. Please wait...")
				}
			case <-done:
				return
			}
		}
	}()

	_, _, err = scanner.Run()
	if err != nil {
		utils.ErrorMsg(fmt.Sprintf("unable to run nmap scan fullAggressiveScan: %s %s %s %v", target, ports, outFile, err))
	}

	ticker.Stop()
	done <- true

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! ", "Main aggressive nmap", " against all open ports on target '", target, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less"), utils.Cyan(outFile+".nmap"))
}
