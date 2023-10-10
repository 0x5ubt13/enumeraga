package utils

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

// Declare global variables available throughout Enumeraga
var (
	// Print a message in yellow colour
	Yellow = color.New(color.FgYellow).SprintFunc()

	// Print a message in red colour
	Red = color.New(color.FgRed).SprintFunc()

	// Print a message in green colour
	Green = color.New(color.FgHiGreen).SprintFunc()

	// Print a message in cyan colour
	Cyan = color.New(color.FgCyan).SprintFunc()

	// Print a message in magenta colour
	Debug = color.New(color.FgMagenta).SprintFunc()

	// Declare wordlists global vars
	DirListMedium, DarkwebTop1000, ExtensionsList, UsersList, SnmpList string

	// Declare globals updated and wordlistsLocated, as these may consume a lot of time and aren't needed more than once
	Updated, wordlistsLocated bool

	// Interrupted global, to show user different info if single IP target was unsuccessful
	Interrupted bool

	// Sync: Define a mutex to synchronize access to standard output
	outputMutex sync.Mutex

	// Sync: Define a waitgroup to generate goroutines
	Wg sync.WaitGroup

	// Declare global flags and have getopt return pointers to the values.
	// DEV: initialising vars only once they have been implemented/ported in the code
	// optAgain 	= getopt.BoolLong("again", 'a', "Repeat the scan and compare with initial ports discovered.")

	// Activate all fuzzing and bruteforcing in the script
	OptBrute = getopt.BoolLong("brute", 'b', "Activate all fuzzing and bruteforcing in the script.")

	// Specify custom DNS servers.
	// Default option: -n
	// OptDNS 		= getopt.StringLong("DNS", 'd', "", "Specify custom DNS servers. Default option: -n")

	// Activate debug text
	OptDbg = getopt.BoolLong("Debug", 'D', "Activate debug text")

	// Display help dialogue and exit
	OptHelp = getopt.BoolLong("help", 'h', "Display this help and exit.")

	// Only try to install pre-requisite tools and exit
	OptInstall = getopt.BoolLong("install", 'i', "Only try to install pre-requisite tools and exit.")

	// Select a different base folder for the output
	// Default option: "/tmp/enumeraga_output"
	OptOutput = getopt.StringLong("output", 'o', "/tmp/enumeraga_output", "Select a different base folder for the output.")

	// Run port sweep with nmap and the flag --top-ports=<your input>
	// optTopPorts = getopt.StringLong("top", 'p', "", "Run port sweep with nmap and the flag --top-ports=<your input>")
	// DEV/TODO: For ^^^, use nmap.WithMostCommonPorts()

	// Don't print the banner and decrease overall verbosity
	OptQuiet = getopt.BoolLong("quiet", 'q', "Don't print the banner and decrease overall verbosity.")

	// Specify a CIDR range to use tools for whole subnets
	OptRange = getopt.StringLong("range", 'r', "", "Specify a CIDR range to use tools for whole subnets.")

	// Specify target single IP / List of IPs file.
	OptTarget = getopt.StringLong("target", 't', "", "Specify target single IP / List of IPs file.")

	// Flood your terminal with plenty of verbosity!
	OptVVervose = getopt.BoolLong("vv", 'V', "Flood your terminal with plenty of verbosity!")
)

func PrintBanner() {
	fmt.Printf("\n%s%s%s\n", Yellow(" __________                                    ________"), Cyan("________"), Yellow("______ "))
	fmt.Printf("%s%s%s\n", Yellow(" ___  ____/__________  ________ __________________    |"), Cyan("_  ____/"), Yellow("__    |"))
	fmt.Printf("%s%s%s\n", Yellow(" __  __/  __  __ \\  / / /_  __ `__ \\  _ \\_  ___/_  /| |"), Cyan("  / __ "), Yellow("__  /| |"))
	fmt.Printf("%s%s%s\n", Yellow(" _  /___  _  / / / /_/ /_  / / / / /  __/  /   _  ___ "), Cyan("/ /_/ / "), Yellow("_  ___ |"))
	fmt.Printf("%s%s%s\n", Yellow(" /_____/  /_/ /_/\\__,_/ /_/ /_/ /_/\\___//_/    /_/  |_"), Cyan("\\____/  "), Yellow("/_/  |_|"))
	fmt.Printf("%s\n\n", Green("                            by 0x5ubt13"))
}

func PrintUsageExamples() {
	e := color.WhiteString("enumeraga")

	// Print "examples" in white
	fmt.Printf("\nExamples:\n ")
	PrintCustomBiColourMsg(
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
		ErrorMsg("This system is not running a Debian-like distribution. Please install the tools manually.")
		return fmt.Errorf("not compatible distro")
	}

	return nil
}

// Custom error message printed out to terminal
func ErrorMsg(errMsg string) {
	fmt.Printf("%s %s\n", Red("[-] Error detected:"), errMsg)
}

// Read a targets file from the argument path passed to -t
// Return number of targets, one per line
func ReadTargetsFile(filename string) ([]string, int) {
	// Fetch the file
	data, err := os.ReadFile(*OptTarget)
	if err != nil {
		panic(err)
	}

	// Get lines
	lines := strings.Split(string(data), "\n")
	return lines, len(lines) - 1
}

// Check first if it is possible to create new dir, and send custom msg if not.
func CustomMkdir(name string) {
	err := os.Mkdir(name, os.ModePerm)
	if err != nil {
		if *OptVVervose {
			fmt.Println(Red("[-] Error creating new dir:", err))
		}
	} else {
		if *OptVVervose {
			PrintCustomBiColourMsg("green", "yellow", "[+] Directory ", name, " created successfully")
		}
	}
}

// Announce protocol, create base dir and return its name
func ProtocolDetected(protocol, baseDir string) string {
	if !*OptQuiet {
		PrintCustomBiColourMsg("green", "cyan", "[+] '", protocol, "' service detected")
	}

	protocolDir := fmt.Sprintf("%s%s/", baseDir, strings.ToLower(protocol))
	if *OptDbg {
		fmt.Printf("%s\n", Cyan("[*] Debug: protocolDir ->", protocolDir))
	}

	CustomMkdir(protocolDir)

	return protocolDir
}

// Write text to a file
func WriteTextToFile(filePath string, message string) {
	// Open file
	f, err := os.Create(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// Write to it
	_, err2 := fmt.Fprintln(f, message)
	if err2 != nil {
		log.Fatal(err2)
	}
}

// Write bytes output to file
func WritePortsToFile(filePath string, ports string, host string) string {
	// Open file
	fileName := fmt.Sprintf("%sopen_ports.txt", filePath)
	f, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// Write to it
	_, err2 := fmt.Fprintln(f, ports)
	if err2 != nil {
		log.Fatal(err2)
	}
	PrintCustomBiColourMsg("green", "yellow", "[+] Successfully written open ports for host '", host, "' to file '", fileName, "'")

	return ports
}

// Finish the main flow with time tracker and a couple nice messages to the terminal
func FinishLine(start time.Time, interrupted bool) {
	elapsed := time.Since(start)
	var output string

	if elapsed.Seconds() < 1 {
		// Convert duration to float of Milliseconds
		ms := float64(elapsed.Nanoseconds()) / 1e6
		output = fmt.Sprintf("%.2fms", ms)
	} else {
		// Convert duration to float of Seconds
		s := elapsed.Seconds()
		output = fmt.Sprintf("%.2fs", s)
	}

	if interrupted {
		PrintCustomBiColourMsg("cyan", "green", "\n[*] Done! It only took '", output, "' to run ", "Enumeraga", "'s core functionality, although an error was detected.\n\tPlease check your arguments, program's output or connectivity and try again.\n")
		return
	}

	PrintCustomBiColourMsg("cyan", "green", "\n[*] Done! It only took '", output, "' to run ", "Enumeraga ", "based on your settings!! Please allow your tools some time to finish.")
	if !*OptQuiet {
		fmt.Printf("%s%s%s\n\n", Cyan("[*] ---------- "), Green("Enumeration phase complete"), Cyan(" ----------"))
		fmt.Printf("%s%s%s\n", Cyan("[*] ---------- "), Green("Program complete. Awaiting tools to finish"), Cyan(" ----------"))
	}
}

// Remove duplicate ports from the comma-separated ports string
func RemoveDuplicates(s string) string {
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

// Ask for user consent
func Consent(tool string) rune {
	PrintCustomBiColourMsg("red", "cyan", "[-] ", "Enumeraga ", "needs ", tool, " to be installed")
	PrintCustomBiColourMsg("yellow", "cyan", "Do you want to install '", tool, "' (", "[Y]", " 'yes' / ", "[N]", " 'no' / ", "[A]", " 'yes to all'): ")

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
	return 'n'
}

// Check tool exists with exec.LookPath (equivalent to `which <tool>`)
func checkToolExists(tool string) bool {
	_, lookPatherr := exec.LookPath(tool)
	if lookPatherr != nil {
		if *OptDbg {
			fmt.Println(Debug("Debug - Error: ", lookPatherr.Error()))
		}
		return false
	}

	if *OptDbg {
		fmt.Printf("%s%s%s\n", Green("Debug - '"), Green(tool), Green("' is installed"))
	}

	return true
}

// Instruct the program to try and install tools that are absent from the pentesting distro
func InstallMissingTools() {
	keyTools := []string{
		"cewl",
		"enum4linux-ng",
		"dirsearch",
		"finger",
		"ffuf",
		"fping",
		"hydra",
		"ident-user-enum",
		"impacket-rpcdump",
		"msfconsole",
		"nbtscan-unixwiz",
		"nikto",
		"nmap",
		"odat",
		"responder-RunFinger",
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
		userConsent := Consent(tool)

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
		if !Updated {
			AptGetUpdateCmd()
			Updated = true
		}
		AptGetInstallCmd(tool)
	}
}

func PrintInstallingTool(tool string) {
	fmt.Printf("%s %s%s ", Yellow("[!] Installing"), Cyan(tool), Yellow("..."))
}

func printConsentNotGiven(tool string) {
	fmt.Printf(
		"%s\n%s %s %s\n",
		Red("[-] Consent not given."),
		Red("[-] Please install"),
		Cyan(tool),
		Red("manually. Aborting..."),
	)
}

// Run the apt-get update command
func AptGetUpdateCmd() {
	fmt.Printf("%s %s%s ", Yellow("[!] Running"), Cyan("apt-get update"), Yellow("..."))
	update := exec.Command("apt-get", "update")

	// Redirect the command's error output to the standard output in terminal
	update.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *OptDbg {
		fmt.Println(Cyan("[*] Debug -> printing apt-get update's output ------"))
		update.Stdout = os.Stdout
	}

	// Run the command
	updateErr := update.Run()
	if updateErr != nil {
		if *OptDbg {
			fmt.Printf("Debug - Error running apt-get update: %v\n", updateErr)
		}
		return
	}

	fmt.Println(Green("Done!"))
}

// Run the apt-get install <tool> command
func AptGetInstallCmd(tool string) {
	// Moving to go due to import cycle
	PrintInstallingTool(tool)

	if tool == "finger" {
		tool = "nfs-common"
	}

	if tool == "seclists" {
		tool = "nfs-common"
	}

	if tool == "msfconsole" {
		tool = "metasploit-framework"
	}

	if tool == "responder-RunFinger" {
		tool = "responder"
	}

	if tool == "impacket-rpcdump" {
		tool = "python3-impacket"
	}

	aptGetInstall := exec.Command("apt", "install", "-y", tool)

	aptGetInstallErr := aptGetInstall.Run()
	if aptGetInstallErr != nil {
		// if !strings.Contains(string(aptGetInstall.Stdout), "Unable to locate package") {
		if *OptDbg {
			fmt.Printf("Debug - Error executing apt-get: %v\n", aptGetInstallErr)
		}

		// Notify of enum4linux-ng as it's not currently in the official kali repo
		if tool == "enum4linux-ng" {
			installErr := installEnum4linuxNg()
			if installErr != nil {
				ErrorMsg(installErr.Error())
				PrintCustomBiColourMsg("red", "cyan", "[-] Error. ", "enum4linux-ng", " needs to be manually installed.\nPlease see: ", "https://github.com/cddmp/enum4linux-ng/blob/master/README.md#kali-linuxdebianubuntulinux-mint")
				os.Exit(2)
			}
			return
		}

		PrintCustomBiColourMsg("red", "cyan", "[-] Error. Please install the following package manually: '", tool, "'\n[-] Aborting...")
		os.Exit(2)
	}

	fmt.Printf("%s\n", Green("Done!"))
}

// Try and install Enum4linux-ng on behalf of the user
func installEnum4linuxNg() error {
	// Ask for consent first of all
	PrintCustomBiColourMsg(
		"yellow", "cyan",
		"Do you want for ", "Enumeraga ",
		"to try and handle the installation of '", "enum4linux-ng",
		"'?\nIt might be the case you have it in your machine but not in your $PATH.\nBear in mind that this will call '", "pip", "' as root",
	)

	userInput := Consent("enum4linux-ng using pip as root")
	if userInput == 'n' {
		consentErr := fmt.Errorf("%s", "Error. Consent not given")
		return consentErr
	}

	fmt.Printf("%s %s%s\n", Yellow("[!] Checking pre-requisites to install '"), Cyan("enum4linux-ng"), Yellow("'..."))

	reqs := []string{"python3-ldap3", "python3-yaml", "python3-impacket", "pip"}
	for _, tool := range reqs {
		if !Updated {
			AptGetUpdateCmd()
			Updated = true
		}
		AptGetInstallCmd(tool)
	}

	// Run git clone "https://github.com/cddmp/enum4linux-ng"
	PrintCustomBiColourMsg("yellow", "cyan", "[!] Installing '", "enum4linux-ng", "' ...")

	// Git clone
	gitClone := exec.Command("git", "clone", "https://github.com/cddmp/enum4linux-ng", "/usr/share/enum4linux-ng")

	// Redirect the command's error output to the standard output in terminal
	gitClone.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *OptDbg {
		fmt.Println(Cyan("[*] Debug -> printing git clone's output ------"))
		gitClone.Stdout = os.Stdout
	}

	// Run the command
	gitCloneErr := gitClone.Run()
	if gitCloneErr != nil {
		if *OptDbg {
			fmt.Printf("Debug - Error running git clone: %v\n", gitCloneErr)
		}
		return gitCloneErr
	}

	// Run Pip install wheel
	pipInstallWheel := exec.Command("pip", "install", "wheel", "clone")

	// Redirect the command's error output to the standard output in terminal
	pipInstallWheel.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *OptDbg {
		fmt.Println(Cyan("[*] Debug -> printing pip install wheel's output ------"))
		pipInstallWheel.Stdout = os.Stdout
	}

	// Run the command
	pipInstallWheelErr := pipInstallWheel.Run()
	if gitCloneErr != nil {
		if *OptDbg {
			fmt.Printf("Debug - Error running pip install wheel: %v\n", pipInstallWheelErr)
		}
		return pipInstallWheelErr
	}

	// Run Pip install -r requirements.txt
	pipInstallRequirements := exec.Command("pip", "install", "-r", "/usr/share/enum4linux-ng/requirements.txt")

	// Redirect the command's error output to the standard output in terminal
	pipInstallRequirements.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *OptDbg {
		fmt.Println(Cyan("[*] Debug -> printing pip install wheel's output ------"))
		pipInstallRequirements.Stdout = os.Stdout
	}

	// Run the command
	pipInstallRequirementsErr := pipInstallRequirements.Run()
	if pipInstallRequirementsErr != nil {
		if *OptDbg {
			fmt.Printf("Debug - Error running pip install -r requirements.txt: %v\n", pipInstallRequirementsErr)
		}
		return pipInstallRequirementsErr
	}

	// Make executable
	chmod := exec.Command("chmod", "+x", "/usr/share/enum4linux-ng/enum4linux-ng.py")

	// Redirect the command's error output to the standard output in terminal
	chmod.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *OptDbg {
		fmt.Println(Cyan("[*] Debug -> printing chmod's output ------"))
		chmod.Stdout = os.Stdout
	}

	// Run chmod
	chmodErr := chmod.Run()
	if chmodErr != nil {
		if *OptDbg {
			fmt.Printf("Debug - Error running chmod: %v\n", chmodErr)
		}
		return chmodErr
	}

	// Create symbolic link
	ln := exec.Command("ln", "-s", "/usr/share/enum4linux-ng/enum4linux-ng.py", "/usr/bin/enum4linux-ng")

	// Redirect the command's error output to the standard output in terminal
	ln.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *OptDbg {
		fmt.Println(Cyan("[*] Debug -> printing git clone's output ------"))
		ln.Stdout = os.Stdout
	}

	// Run the command
	lnErr := ln.Run()
	if lnErr != nil {
		if *OptDbg {
			fmt.Printf("Debug - Error running git clone: %v\n", lnErr)
		}
		return lnErr
	}

	fmt.Println(Green("Done!"))
	return nil
}

func GetWordlists() {
	if wordlistsLocated {
		return
	}
	wordlistsLocated = true

	// Locate the "raft-medium-directories-lowercase" file
	dirListMediumSlice, err := zglob.Glob("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt")
	if err != nil {
		log.Fatalf("Error locating 'raft-medium-directories-lowercase' with zglob: %v\n", err)
	}
	DirListMedium = dirListMediumSlice[0]

	// Locate the "darkweb2017-top1000.txt" file
	DarkwebTop1000Slice, err := zglob.Glob("/usr/share/seclists/Passwords/darkweb2017-top100.txt")
	if err != nil {
		log.Fatalf("Error locating 'darkweb2017-top1000.txt': %v\n", err)
	}
	DarkwebTop1000 = DarkwebTop1000Slice[0]

	// Locate the "web-extensions.txt" file
	ExtensionsListSlice, err := zglob.Glob("/usr/share/seclists/Discovery/Web-Content/web-extensions.txt")
	if err != nil {
		log.Fatalf("Error locating 'web-extensions.txt': %v\n", err)
	}
	ExtensionsList = ExtensionsListSlice[0]

	// Locate the "top-usernames-shortlist" file
	UsersListSlice, err := zglob.Glob("/usr/share/seclists/Usernames/top-usernames-shortlist.txt")
	if err != nil {
		log.Fatalf("Error locating 'top-usernames-shortlist': %v\n", err)
	}
	UsersList = UsersListSlice[0]

	// Locate the "snmp-onesixtyone" file
	snmpListSlice, err := zglob.Glob("/usr/share/seclists/Discovery/SNMP/snmp-onesixtyone.txt")
	if err != nil {
		log.Fatalf("Error locating 'SNMP/snmp.txt': %v\n", err)
	}
	SnmpList := snmpListSlice[0]

	if *OptDbg {
		fmt.Println("Located Files:")
		fmt.Printf("dir_list_medium: %v\n", DirListMedium)
		fmt.Printf("darkweb_top1000: %v\n", DarkwebTop1000)
		fmt.Printf("extensions_list: %v\n", ExtensionsList)
		fmt.Printf("users_list: %v\n", UsersList)
		fmt.Printf("snmp_list: %v\n", SnmpList)
	}
}

// Loop over the necessary colours, printing one at a time
func PrintCustomBiColourMsg(dominantColour, secondaryColour string, text ...string) {
	// Lock the mutex to ensure exclusive access to standard output,
	// avoiding printing different lines of output to console
	outputMutex.Lock()
	defer outputMutex.Unlock()

	for i, str := range text {
		if i%2 == 0 || i == 0 {
			switch dominantColour {
			case "green":
				fmt.Printf("%s", Green(str))
			case "yellow":
				fmt.Printf("%s", Yellow(str))
			case "red":
				fmt.Printf("%s", Red(str))
			case "cyan":
				fmt.Printf("%s", Cyan(str))
			}
			continue
		}

		switch secondaryColour {
		case "green":
			fmt.Printf("%s", Green(str))
		case "yellow":
			fmt.Printf("%s", Yellow(str))
		case "red":
			fmt.Printf("%s", Red(str))
		case "cyan":
			fmt.Printf("%s", Cyan(str))
		}
	}

	fmt.Printf("\n")
}
