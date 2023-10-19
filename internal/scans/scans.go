package scans

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/utils"
	nmap "github.com/Ullaakut/nmap/v3"
)

// Run a quick port sweep on TCP
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
		if *utils.OptVVervose {
			fmt.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	return result.Hosts
}

// Run a quick port sweep on UDP
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
		if *utils.OptVVervose {
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

	oN := outFile + ".nmap"
	oG := outFile + ".grep"

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
		nmap.WithNmapOutput(oN),
		nmap.WithGrepOutput(oG),
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
				if *utils.OptVVervose {
					fmt.Println(utils.Debug(t))
				}
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVervose {
			log.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualPortScannerWithNSEScripts: %s %s %s %v", target, port, outFile, err)
	}

	ticker.Stop()
	done <- true

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(oN))
}

// Run an Nmap scan with NSE scripts and NSE script arguments
func IndividualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")

	oN := outFile + ".nmap"
	oG := outFile + ".grep"

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
		nmap.WithNmapOutput(oN),
		nmap.WithGrepOutput(oG),
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
				if *utils.OptVVervose {
					fmt.Println(utils.Debug(t))
				}
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVervose {
			log.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualPortScannerWithNSEScriptsAndScriptArgs: %s %s %s %v", target, port, outFile, err)
	}

	ticker.Stop()
	done <- true

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less -R"), utils.Cyan(oN))
}

// Run an UDP Nmap scan with NSE scripts
func IndividualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting UDP scan against port(s) '", port, "' on target '", target, "' and sending it to the background")
	oN := outFile + ".nmap"
	oG := outFile + ".grep"

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
		nmap.WithNmapOutput(oN),
		nmap.WithGrepOutput(oG),
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
				if *utils.OptVVervose {
					fmt.Println(utils.Debug(t))
				}
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVervose {
			log.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualUDPPortScannerWithNSEScripts: %s %s %s %v", target, port, outFile, err)
	}

	ticker.Stop()
	done <- true

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! UDP scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less"), utils.Cyan(oN))
}

// Run a simple Nmap scan
func IndividualPortScanner(target, port, outFile string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")

	oN := outFile + ".nmap"
	oG := outFile + ".grep"

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
		nmap.WithNmapOutput(oN),
		nmap.WithGrepOutput(oG),
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
				lapsed++
				utils.PrintCustomBiColourMsg(
					"cyan", "yellow",
					"[*] Individual protocol nmap scan still running against port(s) '", port,
					"' on target '", target,
					"'. Time lapsed: '", string(rune(lapsed)), "' minutes. Please wait...")

				if *utils.OptVVervose {
					fmt.Println(utils.Debug(t))
				}
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVervose {
			log.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualPortScanner: %s %s %s %v", target, port, outFile, err)
	}

	ticker.Stop()
	done <- true

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! Nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less"), utils.Cyan(oN))
}

// Run main aggressive scan for all open ports on the target
func FullAggressiveScan(target, ports, outFile string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Starting ", "main aggressive nmap scan ", "against '", target, "' and sending it to the background")

	oN := outFile + ".nmap"
	oG := outFile + ".grep"
	ports = ports + ",1337" // Adding 1 likely closed port for OS fingerprinting purposes

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithPorts(ports),
		nmap.WithPrivileged(),
		nmap.WithDisabledDNSResolution(),
		nmap.WithNmapOutput(oN),
		nmap.WithOSDetection(),
		nmap.WithServiceInfo(),
		nmap.WithDefaultScript(),
		nmap.WithGrepOutput(oG),
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
				lapsed++
				utils.PrintCustomBiColourMsg(
					"cyan", "yellow",
					"[*] Main nmap scan still running against all open ports on target '", target,
					"'. Time lapsed: '", string(rune(lapsed)), "' minutes. Please wait...")

				if *utils.OptVVervose {
					fmt.Println(utils.Debug(t))
				}
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *utils.OptVVervose {
			log.Printf("run finished with warnings: %s\n", *warnings)
		} // Warnings are non-critical errors from nmap.
	}

	if err != nil {
		log.Printf("unable to run nmap scan fullAggressiveScan: %s %s %s %v", target, ports, outFile, err)
	}

	ticker.Stop()
	done <- true

	utils.PrintCustomBiColourMsg("green", "cyan", "[+] Done! ", "Main aggressive nmap", " against target '", target, "' finished successfully")
	fmt.Println(utils.Yellow("\tShortcut: less"), utils.Cyan(oN))
}
