package main

import (
	"context"
	"fmt"
	"log"
	"time"

	nmap "github.com/Ullaakut/nmap/v3"
)

func portSweep(target string) []nmap.Host {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
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

	// Use the results to print an example output
	// for _, host := range result.Hosts {
	// 	if len(host.Ports) == 0 || len(host.Addresses) == 0 {
	// 		continue
	// 	}

	// 	// fmt.Printf("Host %q:\n", host.Addresses[0])

	// 	for _, port := range host.Ports {
	// 		fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
	// 	}
	// }

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)

	return result.Hosts
}

// Scan used in portsIterator.go for each open port identified
func individualPortScannerWithNSEScripts(target, port, outFile, scripts string) {
	fmt.Printf("%s%s%s%s%s\n", yellow("[!] Starting scan against port '"), cyan(port), yellow("' for target '"), cyan(target), yellow("' and sending it to the background"))

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

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}

func individualUDPPortScannerWithNSEScripts(target, port, outFile, scripts string) {
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

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}

func individualPortScanner(target, port, outFile string) {
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

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
	}
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %.2f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}

// Run main aggressive scan for the target
func fullAggressiveScan(target, ports, outFile string) {
    fmt.Printf("%s %s %s%s%s\n", yellow("[!] Starting"), cyan("main aggressive vuln nmap scan"), yellow("against '"), cyan(target), yellow("' and sending it to the background"))

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

	printCustomTripleMsg("green", "cyan", "[+] Done! Main aggresive vuln nmap against target", target, "finished successfully")

}