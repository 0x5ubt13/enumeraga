package main

import (
	"fmt"
	"log"
	// "net"
	"os"
	// "os/exec"
	"regexp"
	"strings"

	"github.com/fatih/color"
	getopt "github.com/pborman/getopt/v2"
)

var (
	// Declare colour vars
    yellow 	= color.New(color.FgYellow).SprintFunc()
	red 	= color.New(color.FgRed).SprintFunc()
	green 	= color.New(color.FgGreen).SprintFunc()
	cyan 	= color.New(color.FgCyan).SprintFunc()

	// Declare flags and have getopt return pointers to the values.
	// DEV: initialising vars only once they have been implemented/ported in the code
	// optAgain 	= getopt.BoolLong("again", 'a', "Repeat the scan and compare with initial ports discovered.")
	optBrute	= getopt.BoolLong("brute", 'b', "Activate all fuzzing and bruteforcing in the script.")
	// var optDNS 		= getopt.StringLong("DNS", 'd', "", "Specify custom DNS servers. Default option: -n")
	optDbg 		= getopt.BoolLong("Debug", 'D', "Activate debug text")
	optHelp 	= getopt.BoolLong("help", 'h', "Display this help and exit.")
	optOutput	= getopt.StringLong("output", 'o', "/tmp/enumeraga_output", "Select a different base folder for the output." )
	// optTopPorts = getopt.StringLong("top", 'p', "", "Run port sweep with nmap and the flag --top-ports=<your input>")
	// DEV: For ^^, use nmap.WithMostCommonPorts()
	optQuiet 	= getopt.BoolLong("quiet", 'q', "Don't print the banner and decrease overall verbosity.")
	// optRange = getopt.StringLong("range", 'r', "", "Specify a CIDR range to use tools for whole subnets")
	optTarget 	= getopt.StringLong("target", 't', "", "Specify target single IP / List of IPs file.")
	optVVervose	= getopt.BoolLong("vv", 'V', "Flood your terminal with plenty of verbosity!")
	
	// Define a global regular expression pattern
	alphanumericRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)
)

func printBanner() {
	fmt.Printf("\n%s%s%s\n", yellow(" __________                                    ________"),cyan("________"), yellow("______ "))
	fmt.Printf("%s%s%s\n", yellow(" ___  ____/__________  ________ __________________    |"),cyan("_  ____/"), yellow("__    |"))
	fmt.Printf("%s%s%s\n", yellow(" __  __/  __  __ \\  / / /_  __ `__ \\  _ \\_  ___/_  /| |"),cyan("  / __ "), yellow("__  /| |"))
	fmt.Printf("%s%s%s\n", yellow(" _  /___  _  / / / /_/ /_  / / / / /  __/  /   _  ___ "),cyan("/ /_/ / "), yellow("_  ___ |"))
	fmt.Printf("%s%s%s\n", yellow(" /_____/  /_/ /_/\\__,_/ /_/ /_/ /_/\\___//_/    /_/  |_"),cyan("\\____/  "), yellow("/_/  |_|"))
	fmt.Printf("%s\n\n", green("                            by 0x5ubt13"))   
}

// Use isAlphanumeric for regexp
func isAlphanumeric(s string) bool {
  return alphanumericRegex.MatchString(s)
}

// Custom error message printed out to terminal
func errorMsg(errMsg string) {
	red("[-] Error detected: %s\n", errMsg)
}
                  
func readTargetsFile(filename string) ([]string, int) {
	// fetching the file
	data, err := os.ReadFile(*optTarget)
	if err != nil {panic(err)}

	// Get lines
	lines := strings.Split(string(data), "\n")
	return lines, len(lines)-1
}

func printPhase(phase int) {
	if !*optQuiet {
		fmt.Printf("\n%s%s ", cyan("[*] ---------- "), "Starting Phase")
		switch phase {
		case 0:
			fmt.Printf("%s%s", yellow("0"), ": running initial checks ")
		case 1:
			fmt.Printf("%s%s", yellow("1"), ": parsing the CIDR range ")
		case 2:
			fmt.Printf("%s%s", yellow("2"), ": sweeping target's ports ")
		case 22:
			fmt.Printf("%s%s", yellow("3"), ": running multi-target mode. Looping through the list, one target at a time ")
		case 3:
			fmt.Printf("%s%s", yellow("3"), ": parsing found ports ")
		case 4:
			fmt.Printf("%s%s", yellow("4"), ": background tools working ")
		default:
			errorMsg("Development error. There are currently 5 phases in the script ")
		}
		fmt.Printf("%s\n\n", cyan("----------"))
	}
}

func customMkdir(name string) {
	err := os.Mkdir(name, os.ModePerm)
	if err != nil {
		if *optVVervose {fmt.Println(red("[-] Error:"), red(err))}
	} else {
		if *optVVervose {fmt.Printf("%s %s %s\n", green("[+] Directory"), yellow(name), green("created successfully"))}
	}
}

func runningTool(tool string) {
	if !*optQuiet {
		fmt.Printf("%s %s %s\n", yellow("[!] Starting"), cyan(tool), yellow("and sending it to the background."))
	}
}

func announceProtocolDetected (string) {
	fmt.Printf("%s %s %s\n", green("[+]"), cyan("FTP"), green("service detected."))
}

func writeTextToFile(filePath string, message string) {
	// Open file
	f, err := os.Create(filePath)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

	_, err2 := fmt.Fprintln(f, message)
    if err2 != nil {
        log.Fatal(err2)
    }
}

// Write bytes output to file
func writePortsToFile(filePath string, ports string, host string) string {
	// Open file
	fileName := fmt.Sprintf("%sopen_ports.txt", filePath)
	f, err := os.Create(fileName)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

	_, err2 := fmt.Fprintln(f, ports)
    if err2 != nil {
        log.Fatal(err2)
    }
    fmt.Printf("%s %s %s %s\n", green("[+] Successfully written open ports for host"), yellow(host), green("to file"), yellow(fileName))

	return ports
}
