package main

import (
	"context"
	"fmt"
	"log"
	// "os"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"
)

// Run a quick port sweep on TCP
func tcpPortSweep(target string) []nmap.Host {
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
		if *optDbg { fmt.Printf("run finished with warnings: %s\n", *warnings) } // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	return result.Hosts
}

// Run a quick port sweep on UDP
func udpPortSweep(target string) []nmap.Host {
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
		if *optDbg { log.Printf("run finished with warnings: %s\n", *warnings) } // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan udpPortSweep: %v", err)
	}

	return result.Hosts
}

// Scan used in portsIterator.go for each open port identified
func individualPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	printCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")

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
				printCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan with NSE Scripts still running against port(s) '", port, "' on target '", target, "'. Please wait...")
				if *optDbg { fmt.Println(debug(t)) }
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *optDbg { log.Printf("run finished with warnings: %s\n", *warnings) } // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualPortScannerWithNSEScripts: %s %s %s %v", target, port, outFile, err)
	}

	ticker.Stop()
	done <- true

	printCustomBiColourMsg("green", "cyan", "[+] Done! nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(yellow("\tShortcut: less -R"), cyan(oN))
}

func individualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string) {
	printCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")
	
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
				printCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan with NSE scripts and args still running against port(s) '", port, "' on target '", target, "'. Please wait...")
				if *optDbg { fmt.Println(debug(t)) }
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *optDbg { log.Printf("run finished with warnings: %s\n", *warnings) } // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualPortScannerWithNSEScriptsAndScriptArgs: %s %s %s %v", target, port, outFile, err)
	}

	ticker.Stop()
	done <- true

	printCustomBiColourMsg("green", "cyan", "[+] Done! nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(yellow("\tShortcut: less -R"), cyan(oN))
}

func individualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	printCustomBiColourMsg("yellow", "cyan", "[!] Starting UDP scan against port(s) '", port, "' on target '", target, "' and sending it to the background")
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
				printCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan on UDP with NSE scripts still running against port(s) '", port, "' on target '", target, "'. Please wait...")
				if *optDbg { fmt.Println(debug(t)) }
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *optDbg { log.Printf("run finished with warnings: %s\n", *warnings) } // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualUDPPortScannerWithNSEScripts: %s %s %s %v", target, port, outFile, err)
	}

	ticker.Stop()
	done <- true

	printCustomBiColourMsg("green", "cyan", "[+] Done! UDP scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(yellow("\tShortcut: less"), cyan(oN))
}

func individualPortScanner(target, port, outFile string) {
	printCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' on target '", target, "' and sending it to the background")

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
	
	ticker := time.NewTicker(2 * time.Minute)
	done := make(chan bool)

	go func() {
		for {
			select {
			case t := <-ticker.C:
				printCustomBiColourMsg("cyan", "yellow", "[*] Individual protocol nmap scan still running against port(s) '", port, "' on target '", target, "'. Please wait...")
				if *optDbg { fmt.Println(debug(t)) }
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *optDbg { log.Printf("run finished with warnings: %s\n", *warnings) } // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Printf("unable to run nmap scan individualPortScanner: %s %s %s %v", target, port, outFile, err)
	}
	
	ticker.Stop()
	done <- true

	printCustomBiColourMsg("green", "cyan", "[+] Done! Nmap scan against port(s) '", port, "' on target '", target, "' finished successfully")
	fmt.Println(yellow("\tShortcut: less"), cyan(oN))

}

// Run main aggressive scan for the target
// Since this scan might be massive, 
func fullAggressiveScan(target, ports, outFile string) {
	printCustomBiColourMsg("yellow", "cyan", "[!] Starting ", "main aggressive nmap scan ", "against '", target, "' and sending it to the background")

	oN := outFile + ".nmap"
	oG := outFile + ".grep"

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

	ticker := time.NewTicker(1 * time.Minute)
	done := make(chan bool)

	go func() {
		for {
			select {
			case t := <-ticker.C:
				printCustomBiColourMsg("cyan", "yellow", "[*] Main nmap scan still running against all open ports on target '", target, "'")
				if *optDbg { fmt.Println(debug(t)) }
			case <-done:
				return
			}
		}
	}()

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		if *optDbg { log.Printf("run finished with warnings: %s\n", *warnings) } // Warnings are non-critical errors from nmap.
	}

	if err != nil {
		log.Printf("unable to run nmap scan fullAggressiveScan: %s %s %s %v", target, ports, outFile, err)
	}

	ticker.Stop()
	done <- true

	printCustomBiColourMsg("green", "cyan", "[+] Done! ", "Main aggresive nmap", " against target '", target, "' finished successfully")
	fmt.Println(yellow("\tShortcut: less"), cyan(oN))
}
