package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	zglob "github.com/mattn/go-zglob"
	getopt "github.com/pborman/getopt/v2"
)

var (
	// Declare colour vars
	yellow = color.New(color.FgYellow).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
	green  = color.New(color.FgHiGreen).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	debug  = color.New(color.FgMagenta).SprintFunc()

	// Declare flags and have getopt return pointers to the values.
	// DEV: initialising vars only once they have been implemented/ported in the code
	// optAgain 	= getopt.BoolLong("again", 'a', "Repeat the scan and compare with initial ports discovered.")
	optBrute	= getopt.BoolLong("brute", 'b', "Activate all fuzzing and bruteforcing in the script.")
	// var optDNS 		= getopt.StringLong("DNS", 'd', "", "Specify custom DNS servers. Default option: -n")
	optDbg		= getopt.BoolLong("Debug", 'D', "Activate debug text")
	optHelp		= getopt.BoolLong("help", 'h', "Display this help and exit.")
	optInstall	= getopt.BoolLong("install", 'i', "Only try to install requisites and exit.")
	optOutput	= getopt.StringLong("output", 'o', "/tmp/enumeraga_output", "Select a different base folder for the output.")
	// optTopPorts = getopt.StringLong("top", 'p', "", "Run port sweep with nmap and the flag --top-ports=<your input>")
	// DEV: For ^^^, use nmap.WithMostCommonPorts()
	optQuiet	= getopt.BoolLong("quiet", 'q', "Don't print the banner and decrease overall verbosity.")
	optRange	= getopt.StringLong("range", 'r', "", "Specify a CIDR range to use tools for whole subnets")
	optTarget	= getopt.StringLong("target", 't', "", "Specify target single IP / List of IPs file.")
	optVVervose	= getopt.BoolLong("vv", 'V', "Flood your terminal with plenty of verbosity!")

	// Declare wordlists global vars
	dirListMedium, darkwebTop1000, extensionsList, usersList, snmpList string

	// Declare globals updated and updatedb, as these may consume a lot of time and aren't needed more than once
	updated, wordlistsLocated bool
	
	// Sync: Define a mutex to synchronize access to standard output and a waitgroup to generate goroutines
	outputMutex sync.Mutex
	wg sync.WaitGroup
)

func printBanner() {
	fmt.Printf("\n%s%s%s\n", yellow(" __________                                    ________"), cyan("________"), yellow("______ "))
	fmt.Printf("%s%s%s\n", yellow(" ___  ____/__________  ________ __________________    |"), cyan("_  ____/"), yellow("__    |"))
	fmt.Printf("%s%s%s\n", yellow(" __  __/  __  __ \\  / / /_  __ `__ \\  _ \\_  ___/_  /| |"), cyan("  / __ "), yellow("__  /| |"))
	fmt.Printf("%s%s%s\n", yellow(" _  /___  _  / / / /_/ /_  / / / / /  __/  /   _  ___ "), cyan("/ /_/ / "), yellow("_  ___ |"))
	fmt.Printf("%s%s%s\n", yellow(" /_____/  /_/ /_/\\__,_/ /_/ /_/ /_/\\___//_/    /_/  |_"), cyan("\\____/  "), yellow("/_/  |_|"))
	fmt.Printf("%s\n\n", green("                            by 0x5ubt13"))
}

func printUsageExamples() {
	e := color.WhiteString("enumeraga")

	// Print "examples" in white
	fmt.Printf("\nExamples:\n ")
	printCustomBiColourMsg(
		"cyan", "yellow",
		e, " -i\n ", 
		e, " -bq -t ", "10.10.11.230", "\n ",
		e, " -V -r ", "10.129.121.0/24", " -t ", "10.129.121.60", "\n ",
		e, " -t ", "targets_file.txt", " -r ", "10.10.8.0/24",
	)
	}

// Check if OS is debian-like
func isCompatibleDistro() error {
	cat := exec.Command("cat", "/etc/os-release")
	output, err := cat.CombinedOutput()
	if err != nil {
		fmt.Printf("Error reading /etc/os-release: %v\n", err)
		os.Exit(5)
	}

	compatibleDistro := strings.Contains(strings.ToLower(string(output)), "debian")
	if !compatibleDistro {
		errorMsg("This system is not running a Debian-like distribution. Please install the tools manually.")
		return fmt.Errorf("not compatible distro")
	}

	return nil
}

// Custom error message printed out to terminal
func errorMsg(errMsg string) {
	fmt.Printf("%s %s\n", red("[-] Error detected:"), errMsg)
}

func readTargetsFile(filename string) ([]string, int) {
	// fetching the file
	data, err := os.ReadFile(*optTarget)
	if err != nil {
		panic(err)
	}

	// Get lines
	lines := strings.Split(string(data), "\n")
	return lines, len(lines) - 1
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
		if *optVVervose {
			fmt.Println(red("[-] Error:"), red(err))
		}
	} else {
		if *optVVervose {
			printCustomBiColourMsg("green", "yellow", "[+] Directory ", name, " created successfully")
		}
	}
}

// Announce protocol, create base dir and return its name
func protocolDetected(protocol, baseDir string) string {
	if !*optQuiet {
		printCustomBiColourMsg("green", "cyan", "[+] '", protocol, "' service detected")
	}
	protocolDir := fmt.Sprintf("%s%s/", baseDir, strings.ToLower(protocol))
	if *optDbg {
		fmt.Printf("%s\n", cyan("[*] Debug: protocolDir ->", protocolDir))
	}
	customMkdir(protocolDir)
	return protocolDir
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
	printCustomBiColourMsg("green", "yellow", "[+] Successfully written open ports for host '", host, "' to file '", fileName, "'")

	return ports
}

// Finish the main flow with time tracker and a couple nice messages to the terminal
func finishLine(start time.Time) {
	printPhase(4)
	elapsed := time.Since(start)

	if elapsed.Seconds() < 1 {
		// Convert duration to float of Milliseconds
		ms := float64(elapsed.Nanoseconds()) / 1e6
		output := fmt.Sprintf("%.2fms", ms)
		printCustomBiColourMsg("cyan", "green", "[*] Done! It only took '", output, "' to run ", "Enumeraga ", "based on your settings!! Please allow your tools some time to finish.\n")
		return
	}

	// Convert duration to float of Seconds
	s := elapsed.Seconds()
	output := fmt.Sprintf("%.2fs", s)
	printCustomBiColourMsg("cyan", "green", "[*] Done! It only took '", output, "' to run ", "Enumeraga ", "based on your settings!! Please allow your tools some time to finish.\n")
}

// Remove duplicate ports from the comma-separated ports string
func removeDuplicates(s string) string {
	parts := strings.Split(s, ",")
	seen := make(map[string]bool)
	result := []string{}

	for _, part := range parts {
		if !seen[part] {
			seen[part] = true
			result = append(result, part)
		}
	}

	return strings.Join(result, ",")
}

func consent(tool string) rune {
	// Ask for user consent
	printCustomBiColourMsg("red", "cyan", "[-] ", "Enumeraga ", "needs ", tool, " to be installed")

	printCustomBiColourMsg("yellow", "cyan", "Do you want to install '", tool, "' (", "[Y]", " 'yes' / ", "[N]", " 'no' / ", "[A]", " 'yes to all'): ")

	consent := bufio.NewScanner(os.Stdin)
	consent.Scan()
	userInput := strings.ToLower(consent.Text())

	if userInput == "yes" || userInput == "y" {
		return 'y'
	}

	if userInput == "all" || userInput == "a" {
		return 'a'
	}

	// If flow made it to down here, consent wasn't given
	printConsentNotGiven(tool)
	os.Exit(1)
	return 'n'
}

func installMissingTools() {
	keyTools := []string{
		"cewl",
		"enum4linux-ng",
		"dirsearch",
		"finger",
		"ffuf",
		"fping",
		"hydra",
		"ident-user-enum",
		"nikto",
		"nmap",
		"odat",
		"rusers",
		"seclists",
		"smbclient",
		"ssh-audit",
		"wafw00f",
		"whatweb",
	}

	// Loop through listed tool see which ones are missing
	missingTools := []string{}
	fullConsent := false
	for _, tool := range keyTools {
		if checkToolExists(tool) {
			continue
		}

		// If full consent was given, stop prompting the user
		if fullConsent {
			missingTools = append(missingTools, tool)
			continue
		}

		// Ask user
		userConsent := consent(tool)

		if userConsent == 'a' {
			fullConsent = true
			missingTools = append(missingTools, tool)
		}

		if userConsent == 'y' {
			missingTools = append(missingTools, tool)
			continue
		}
	}

	// Install all those that are missing
	compatibilityErr := isCompatibleDistro()
	if compatibilityErr != nil {
		os.Exit(3)
	}

	for _, tool := range missingTools {
		if !updated {
			aptGetUpdateCmd()
			updated = true
		}
		aptGetInstallCmd(tool)
	}
}

func printInstallingTool(tool string) {
	fmt.Printf("%s %s%s ", yellow("[!] Installing"), cyan(tool), yellow("..."))
}

func printConsentNotGiven(tool string) {
	fmt.Printf(
		"%s\n%s %s %s\n",
		red("[-] Consent not given."),
		red("[-] Please install"),
		cyan(tool),
		red("manually. Aborting..."),
	)
}

func getWordlists() {
	if wordlistsLocated { return } 
	wordlistsLocated = true

	// Locate the "raft-medium-directories-lowercase" file
	dirListMediumSlice, err := zglob.Glob("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt")
	if err != nil {
		log.Fatalf("Error locating 'raft-medium-directories-lowercase' with zglob: %v\n", err)
	}
	dirListMedium = dirListMediumSlice[0]

	// Locate the "darkweb2017-top1000.txt" file
	darkwebTop1000Slice, err := zglob.Glob("/usr/share/seclists/Passwords/darkweb2017-top100.txt")
	if err != nil {
		log.Fatalf("Error locating 'darkweb2017-top1000.txt': %v\n", err)
	}
	darkwebTop1000 = darkwebTop1000Slice[0]

	// Locate the "web-extensions.txt" file
	extensionsListSlice, err := zglob.Glob("/usr/share/seclists/Discovery/Web-Content/web-extensions.txt")
	if err != nil {
		log.Fatalf("Error locating 'web-extensions.txt': %v\n", err)
	}
	extensionsList = extensionsListSlice[0]

	// Locate the "top-usernames-shortlist" file
	usersListSlice, err := zglob.Glob("/usr/share/seclists/Usernames/top-usernames-shortlist.txt")
	if err != nil {
		log.Fatalf("Error locating 'top-usernames-shortlist': %v\n", err)
	}
	usersList = usersListSlice[0]

	// Locate the "snmp-onesixtyone" file
	snmpListSlice, err := zglob.Glob("/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt")
	if err != nil {
		log.Fatalf("Error locating 'SNMP/snmp.txt': %v\n", err)
	}
	snmpList := snmpListSlice[0]

	if *optDbg {
		fmt.Println("Located Files:")
		fmt.Printf("dir_list_medium: %v\n", dirListMedium)
		fmt.Printf("darkweb_top1000: %v\n", darkwebTop1000)
		fmt.Printf("extensions_list: %v\n", extensionsList)
		fmt.Printf("users_list: %v\n", usersList)
		fmt.Printf("snmp_list: %v\n", snmpList)
	}
}

// Loop over the necessary colours, printing one at a time
func printCustomBiColourMsg(dominantColour, secondaryColour string, text ...string) {
	// Lock the mutex to ensure exclusive access to standard output, 
	// avoiding printing different lines of output to console
	outputMutex.Lock()
	defer outputMutex.Unlock()

	for i, str := range text {
		if i%2 == 0 || i == 0 {
			switch dominantColour {
			case "green":
				fmt.Printf("%s", green(str))
			case "yellow":
				fmt.Printf("%s", yellow(str))
			case "red":
				fmt.Printf("%s", red(str))
			case "cyan":
				fmt.Printf("%s", cyan(str))
			}
			continue
		}

		switch secondaryColour {
		case "green":
			fmt.Printf("%s", green(str))
		case "yellow":
			fmt.Printf("%s", yellow(str))
		case "red":
			fmt.Printf("%s", red(str))
		case "cyan":
			fmt.Printf("%s", cyan(str))
		}
	}

	fmt.Printf("\n")
}