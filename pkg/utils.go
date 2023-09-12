package main

import (
	"bufio"
	"fmt"
	"log"
	// "net"
	"os"
	// "os/exec"
	"regexp"
	"strings"

	"github.com/fatih/color"
	getopt "github.com/pborman/getopt/v2"
	zglob "github.com/mattn/go-zglob"
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
	// DEV: For ^^^, use nmap.WithMostCommonPorts()
	optQuiet 	= getopt.BoolLong("quiet", 'q', "Don't print the banner and decrease overall verbosity.")
	optRange 	= getopt.StringLong("range", 'r', "", "Specify a CIDR range to use tools for whole subnets")
	optTarget 	= getopt.StringLong("target", 't', "", "Specify target single IP / List of IPs file.")
	optVVervose	= getopt.BoolLong("vv", 'V', "Flood your terminal with plenty of verbosity!")
	
	// Define a global regular expression pattern
	alphanumericRegex = regexp.MustCompile(`^[a-zA-Z0-9]+$`)

	// Declare wordlists global vars
    dirListMedium string
    darkwebTop1000 string
    extensionsList string
    usersList string
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
	fmt.Printf("%s %s\n", red("[-] Error detected:"), errMsg)
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
		if *optVVervose {printCustomTripleMsg("green", "yellow", "[+] Directory", name, "created successfully")}
	}
}

// Announce protocol, create base dir and return its name
func protocolDetected (protocol string) string {
	if !*optQuiet {printCustomTripleMsg("green", "cyan", "[+]", protocol, "service detected")}
	protocolDir := fmt.Sprintf("%s/%s/", *optOutput, strings.ToLower(protocol))
	if *optDbg {fmt.Printf("%s %s\n", "[*] Debug: protocolDir ->", protocolDir)}
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
    fmt.Printf("%s %s %s %s\n", green("[+] Successfully written open ports for host"), yellow(host), green("to file"), yellow(fileName))

	return ports
}

func consent(tool string) rune {
	// Ask for user consent
	fmt.Printf(
		"%s '%s' %s\n",
		red("[-] Enumeraga needs"),
		cyan(tool), 
		red("to be installed"),
	)

	fmt.Printf(
		"%s %s %s", 
		yellow("Do you want to install"), 
		cyan(tool), 
		yellow("([Y] yes / [N] no / [A] yes to all): "),
	)
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
	var updated bool

	keyTools := []string{
		"locate",
		"nmap",
		"hydra",
		"finger",
		"updatedb",
		"locate",
		"odat",
		"ssh-audit",
		"seclists",
		"cewl",
		"fping",
		"ident-user-enum",
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
	for _, tool := range missingTools {
		if !updated { aptGetUpdateCmd(); updated = true }
		aptGetInstallCmd(tool)
	}
}

// Commenting this all out as it's not working in my WSL-based debian. Leaving it here for the future perhaps?
// func installWithKaliSourceRepo(tools []string) {
// 	// Path to the sources.list file (typically located at /etc/apt/sources.list)
// 	sourcesListPath := "/etc/apt/sources.list"
// 	lineToAdd := "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware"
// 	debPkgName := "/tmp/kali-archive-keyring_2022.1_all.deb"
// 	keyRingUrl := "https://http.kali.org/kali/pool/main/k/kali-archive-keyring/kali-archive-keyring_2022.1_all.deb"

// 	// Open the sources.list file for appending (to add the line)
// 	file, err := os.OpenFile(sourcesListPath, os.O_APPEND|os.O_WRONLY, os.ModeAppend)
// 	if err != nil {
// 		fmt.Printf("Error opening sources.list file for appending: %v\n", err)
// 		os.Exit(1)
// 		return
// 	}
// 	defer file.Close()

// 	// Write the line to add
// 	_, err = file.WriteString(lineToAdd + "\n")
// 	if err != nil {
// 		fmt.Printf("Error adding line to sources.list: %v\n", err)
// 		return
// 	}

// 	// Download Debian package for Kali archive keys
// 	wgetCmd(debPkgName, keyRingUrl)

// 	// Install Debian package for Kali archive keys
// 	dpkgCmd(debPkgName)

// 	// Perform apt-get update
// 	aptGetUpdateCmd()

// 	// Now re-try the install function
// 	installMissingTools(tools)

// 	// Clean everything up
// 	rmCmd("/tmp/kali-archive-keyring_2022.1_all.deb")
// 	deleteLineFromFile(sourcesListPath, lineToAdd)

// 	if *optDbg {fmt.Println("Debug - source line added successfully.")}
// }

func printInstallingTool(tool string) {
	fmt.Printf("%s %s%s ", yellow("[!] Installing"), cyan(tool), yellow("..."))
}

func deleteLineFromFile(filePath, lineToDelete string) {
	// Open the file for reading
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file for reading: %v\n", err)
		return
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)

	// Create a slice to store the lines
	var lines []string

	// Iterate through the lines
	for scanner.Scan() {
		line := scanner.Text()

		// Check if the line matches the line to delete
		if line != lineToDelete {
			lines = append(lines, line)
		}
	}

	// Check for any scanner errors
	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return
	}

	// Open the file for writing (truncate mode)
	file, err = os.OpenFile(filePath, os.O_WRONLY|os.O_TRUNC, os.ModeAppend)
	if err != nil {
		fmt.Printf("Error opening file for writing: %v\n", err)
		return
	}
	defer file.Close()

	// Write the updated lines back to the file
	_, err = file.WriteString(strings.Join(lines, "\n") + "\n")
	if err != nil {
		fmt.Printf("Error writing updated content to file: %v\n", err)
		return
	}

	if *optDbg {fmt.Println("Debug - Line deleted successfully.")}
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
	// Locate the "raft-medium-directories-lowercase" file
	dirListMedium, err := zglob.Glob("raft-medium-directories-lowercase")
	if err != nil {
		log.Fatalf("Error locating 'raft-medium-directories-lowercase': %v\n", err)
	}
	
	// Locate the "darkweb2017-top1000.txt" file
	darkwebTop1000, err := zglob.Glob("darkweb2017-top1000.txt")
	if err != nil {
		log.Fatalf("Error locating 'darkweb2017-top1000.txt': %v\n", err)
	}
	
	// Locate the "web-extensions.txt" file
	extensionsList, err := zglob.Glob("web-extensions.txt")
	if err != nil {
		log.Fatalf("Error locating 'web-extensions.txt': %v\n", err)
	}
	
	// Locate the "top-usernames-shortlist" file
	usersList, err := zglob.Glob("top-usernames-shortlist")
	if err != nil {
		log.Fatalf("Error locating 'top-usernames-shortlist': %v\n", err)
	}

	if *optDbg {
		fmt.Println("Located Files:")
		fmt.Printf("dir_list_medium: %v\n", dirListMedium)
		fmt.Printf("darkweb_top1000: %v\n", darkwebTop1000)
		fmt.Printf("extensions_list: %v\n", extensionsList)
		fmt.Printf("users_list: %v\n", usersList)
	}
}

func printCustomTripleMsg(dominantColour, secondaryColour, start, middle, end string) {
	switch dominantColour {
	case "green":
		if secondaryColour == "cyan" {
			fmt.Printf("%s %s %s.\n", green(start), cyan(middle), green(end))
		}

		if secondaryColour == "yellow" {
			fmt.Printf("%s %s %s.\n", green(start), yellow(middle), green(end))
		}

	case "yellow":
		if secondaryColour == "cyan" {
			fmt.Printf("%s %s %s.\n", yellow(start), cyan(middle), yellow(end))
		}
		
	case "red":
		if secondaryColour == "cyan" {
			fmt.Printf("%s %s %s.\n", red(start), cyan(middle), red(end))
		}

		if secondaryColour == "yellow" {
			fmt.Printf("%s %s %s.\n", red(start), cyan(yellow), red(end))
		}

	case "cyan":
		if secondaryColour == "yellow" {
			fmt.Printf("%s %s %s.\n", cyan(start), yellow(middle), cyan(end))
		}
	}


}