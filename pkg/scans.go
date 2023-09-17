package main

import (
	"context"
	"fmt"
	"log"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"
)

// Run a quick port sweep on TCP
func tcpPortSweep(target string) []nmap.Host {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p1-65535 --min-rate=2000 --privileged <target>`,
	// with a 5-minute timeout.
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
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	return result.Hosts
}

// Run a quick port sweep on UDP
func udpPortSweep(target string) []nmap.Host {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -sU -p111,161,162,10161,10162,623 --min-rate=2000 --privileged <target>`,
	// with a 5-minute timeout.
	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(target),
		nmap.WithUDPScan(),
		nmap.WithPorts("111,161,162,10161,10162,623"),
		nmap.WithMinRate(2000),
		nmap.WithPrivileged(),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	return result.Hosts
}

// Scan used in portsIterator.go for each open port identified
func individualPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	printCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' for '", target, "' and sending it to the background")

	oN := outFile + ".nmap"
	oG := outFile + ".grep"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	fmt.Printf("%s%s%s%s%s\n", green("[+] Done! Nmap scan against port '"), cyan(port), yellow("' for target '"), cyan(target), yellow("' completed successfully."))
}

func individualPortScannerWithNSEScriptsAndScriptArgs(target, port, outFile, scripts string, scriptArgs map[string]string) {
	printCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan against port(s) '", port, "' for target '", target, "' and sending it to the background")
	
	oN := outFile + ".nmap"
	oG := outFile + ".grep"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	printCustomBiColourMsg("green", "cyan", "[+] Done! nmap scan against port(s) '", port, "' for target '", target, "' finished successfully")
	fmt.Println(yellow("\tShortcut: less -R "), cyan(oN))}
	

func individualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	printCustomBiColourMsg("yellow", "cyan", "[!] Starting UDP scan against port(s) '", port, "' for target '", target, "' and sending it to the background")
	oN := outFile + ".nmap"
	oG := outFile + ".grep"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	printCustomBiColourMsg("green", "cyan", "[+] Done! UDP scan for port(s) '", port, "' against target '", target, "' finished successfully")
	fmt.Println(yellow("\tShortcut: less -R "), cyan(oN))
}

func individualPortScanner(target, port, outFile string) {
	printCustomBiColourMsg("yellow", "cyan", "[!] Starting nmap scan for port(s) '", port, "' against '", target, "' and sending it to the background")

	oN := outFile + ".nmap"
	oG := outFile + ".grep"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	printCustomBiColourMsg("green", "cyan", "[+] Done! Nmap scan against port(s) '", port, "' for target '", target, "' finished successfully")
	fmt.Println(yellow("\tShortcut: less -R "), cyan(oN))

}

// Run main aggressive scan for the target
func fullAggressiveScan(target, ports, outFile string) {
	printCustomBiColourMsg("yellow", "cyan", "[!] Starting ", "main aggressive vuln nmap scan ", "against '", target, "' and sending it to the background")

	oN := outFile + ".nmap"
	oG := outFile + ".grep"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
		nmap.WithScripts("vuln"),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	_, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	printCustomBiColourMsg("green", "cyan", "[+] Done! ", "Main aggresive vuln nmap", " against target '", target, "' finished successfully")
	fmt.Println(yellow("\tShortcut: less -R "), cyan(oN))
}
