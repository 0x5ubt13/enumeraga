package utils

import (
	"bufio"
	"fmt"
	"github.com/Ullaakut/nmap/v3"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	zglob "github.com/mattn/go-zglob"
	getopt "github.com/pborman/getopt/v2"
)

// Declare global variables available throughout Enumeraga
var (
	// Yellow prints a message in yellow colour
	Yellow = color.New(color.FgYellow).SprintFunc()

	// Red prints a message in red colour
	Red = color.New(color.FgRed).SprintFunc()

	// Green prints a message in green colour
	Green = color.New(color.FgHiGreen).SprintFunc()

	// Cyan prints a message in cyan colour
	Cyan = color.New(color.FgCyan).SprintFunc()

	// Debug prints a message in magenta colour
	Debug = color.New(color.FgMagenta).SprintFunc()

	// DarkwebTop1000 and others below are globally available wordlists
	DarkwebTop1000 string
	ExtensionsList string
	UsersList      string
	SnmpList       string
	DirListMedium  string

	// TimesSwept keeps track of how many ports have been tried to be swept for a host
	TimesSwept int

	// Declare globals updated and wordlistsLocated, as these may consume a lot of time and aren't needed more than once
	Updated, wordlistsLocated bool

	// Interrupted global, to show user different info if single IP target was unsuccessful
	Interrupted bool

	// Sync: Define a mutex to synchronize access to standard output
	outputMutex sync.Mutex

	// Wg sync: Define a WaitGroup to generate goroutines
	Wg sync.WaitGroup

	// Declare global flags and have getopt return pointers to the values.
	// DEV: initialising vars only once they have been implemented/ported in the code
	// optAgain 	= getopt.BoolLong("again", 'a', "Repeat the scan and compare with initial ports discovered.")

	// OptBrute Activates all fuzzing and bruteforce in the script
	OptBrute = getopt.BoolLong("brute", 'b', "Activate all fuzzing and bruteforce in the tool.")

	// Specify custom DNS servers.
	// Default option: -n
	// OptDNS 		= getopt.StringLong("DNS", 'd', "", "Specify custom DNS servers. Default option: -n")

	// OptHelp displays help dialogue and exit
	OptHelp = getopt.BoolLong("help", 'h', "Display this help and exit.")

	// OptInstall Only try to install pre-requisite tools and exit
	OptInstall = getopt.BoolLong("install", 'i', "Only try to install pre-requisite tools and exit.")

	// OptOutput selects a different base folder for the output
	// Default option: "/tmp/enumeraga_output"
	OptOutput = getopt.StringLong("output", 'o', "/tmp/enumeraga_output", "Select a different base folder for the output.")

	// OptTopPorts runs port sweep with nmap and the flag --top-ports=<your input>
	OptTopPorts = getopt.StringLong("top-ports", 'p', "", "Run port sweep with nmap and the flag --top-ports=<your input>")

	// OptQuiet makes the tool not print the banner and decreases the overall verbosity
	OptQuiet = getopt.BoolLong("quiet", 'q', "Don't print the banner and decrease overall verbosity.")

	// OptRange specifies a CIDR range to use tools for whole subnets
	OptRange = getopt.StringLong("range", 'r', "", "Specify a CIDR range to use tools for whole subnets.")

	// OptTarget specifies a single IP target or a file with a list of IPs.
	OptTarget = getopt.StringLong("target", 't', "", "Specify target single IP / List of IPs file.")

	// OptVVerbose floods your terminal with plenty of verbosity!
	OptVVerbose = getopt.BoolLong("vv", 'V', "Flood your terminal with plenty of verbosity!")

	// Adding placeholder for OptVhost
	// OptVhost = getopt.StringLong("", '', "", "")

	BaseDir      string
	Target       string
	VisitedSMTP  bool
	VisitedHTTP  bool
	VisitedIMAP  bool
	VisitedSMB   bool
	VisitedSNMP  bool
	VisitedLDAP  bool
	VisitedRsvc  bool
	VisitedWinRM bool
	VisitedFTP   bool
)

func PrintBanner() {
	fmt.Printf("\n%s\n", Cyan("                                                     v0.2.0-beta"))
	fmt.Printf("%s%s%s\n", Yellow(" __________                                    ________"), Cyan("________"), Yellow("______ "))
	fmt.Printf("%s%s%s\n", Yellow(" ___  ____/__________  ________ __________________    |"), Cyan("_  ____/"), Yellow("__    |"))
	fmt.Printf("%s%s%s\n", Yellow(" __  __/  __  __ \\  / / /_  __ `__ \\  _ \\_  ___/_  /| |"), Cyan("  / __ "), Yellow("__  /| |"))
	fmt.Printf("%s%s%s\n", Yellow(" _  /___  _  / / / /_/ /_  / / / / /  __/  /   _  ___ "), Cyan("/ /_/ / "), Yellow("_  ___ |"))
	fmt.Printf("%s%s%s\n", Yellow(" /_____/  /_/ /_/\\__,_/ /_/ /_/ /_/\\___//_/    /_/  |_"), Cyan("\\____/  "), Yellow("/_/  |_|"))
	fmt.Printf("%s\n\n", Green("                            by 0x5ubt13"))
}

func PrintUsageExamples() {
	e := color.WhiteString("enumeraga ")

	// Print "examples" in white
	fmt.Printf("\nExamples:\n ")
	PrintCustomBiColourMsg(
		"cyan", "yellow",
		e, "-i\n ",
		e, "-bq -t ", "10.10.11.230", "\n ",
		e, "-V -r ", "10.129.121.0/24", " -t ", "10.129.121.60", "\n ",
		e, "-t ", "targets_file.txt", " -r ", "10.10.8.0/24",
	)
}

func PrintCloudUsageExamples() {
	e := color.WhiteString("enumeraga cloud ")

	// Print "examples" in white
	fmt.Printf("\nExamples:\n ")
	PrintCustomBiColourMsg(
		"cyan", "yellow",
		e, "aws\n ",
		e, "gcp\n ",
		e, "azure\n ",
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

// ErrorMsg gets a custom error message printed out to terminal
func ErrorMsg(errMsg string) {
	fmt.Printf("%s %s\n", Red("[-] Error detected:"), errMsg)
}

// ReadTargetsFile from the argument path passed to -t; returns number of targets, one per line
func ReadTargetsFile(filename string) ([]string, int) {
	data, err := os.ReadFile(*OptTarget)
	if err != nil {
		panic(err)
	}

	// Get lines
	lines := strings.Split(string(data), "\n")
	return lines, len(lines) - 1
}

// CustomMkdir checks first if it is possible to create new dir, and send custom msg if not.
func CustomMkdir(name string) {
	err := os.Mkdir(name, os.ModePerm)
	if err != nil {
		if *OptVVerbose {
			fmt.Println(Red("[-] Error creating new dir:", err))
		}
		return
	}
	if *OptVVerbose {
		PrintCustomBiColourMsg("green", "yellow", "[+] Directory ", name, " created successfully")
	}
}

// ProtocolDetected announces protocol, creates base dir and returns its name
func ProtocolDetected(protocol, baseDir string) string {
	if !*OptQuiet {
		PrintCustomBiColourMsg("green", "cyan", "[+] '", protocol, "' service detected")
	}
	protocolDir := fmt.Sprintf("%s%s/", baseDir, strings.ToLower(protocol))
	CustomMkdir(protocolDir)

	return protocolDir
}

func WriteTextToFile(filePath string, message string) {
	// Open file
	f, err := os.Create(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			fmt.Println(Red("[-] Error closing file:", err))
		}
	}(f)

	// Write to it
	_, err2 := fmt.Fprintln(f, message)
	if err2 != nil {
		log.Fatal(err2)
	}
}

func WritePortsToFile(filePath string, ports string, host string) string {
	// Open file
	fileName := fmt.Sprintf("%sopen_ports.txt", filePath)
	f, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			fmt.Println(Red("[-] Error closing file:", err))
		}
	}(f)

	// Write to it
	_, err2 := fmt.Fprintln(f, ports)
	if err2 != nil {
		log.Fatal(err2)
	}
	PrintCustomBiColourMsg("green", "yellow", "[+] Successfully written open ports for host '", host, "' to file '", fileName, "'")

	return ports
}

// FinishLine finishes the main flow with time tracker and prints a couple nice messages to the terminal
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

// RemoveDuplicates removes duplicate ports from the comma-separated ports string
func RemoveDuplicates(s string) string {
	parts := strings.Split(s, ",")
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, part := range parts {
		if !seen[part] {
			seen[part] = true
			result = append(result, part)
		}
	}
	return strings.Join(result, ",")
}

// GetOpenPortsSlice creates a string slice using strconv.FormatUint and append strings to it.
func GetOpenPortsSlice(sweptHostTcp, sweptHostUdp []nmap.Host) []string {
	openPortsSlice := make([]string, 0)

	for _, host := range sweptHostTcp {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			// Error below: String(port.State) not working for some reason, therefore using Sprintf
			if fmt.Sprintf("%s", port.State) == "open" {
				text := strconv.FormatUint(uint64(port.ID), 10)
				openPortsSlice = append(openPortsSlice, text)
			}
		}
	}

	// Same than above but for the swept ports running on UDP
	for _, host := range sweptHostUdp {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			// Error below: String(port.State) not working for some reason, therefore using Sprintf
			if fmt.Sprintf("%s", port.State) == "open" {
				text := strconv.FormatUint(uint64(port.ID), 10)
				openPortsSlice = append(openPortsSlice, text)
			}
		}
	}
	return openPortsSlice
}

// Consent asks for user consent
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

// OSCPConsent asks for user consent to run any forbidden tool for OSCP
func OSCPConsent(tool string) rune {
	PrintCustomBiColourMsg("red", "cyan", "[-] ", "Enumeraga ", "needs ", tool, " to be run, which won't be very good if you're trying OSCP 😬")
	PrintCustomBiColourMsg("yellow", "cyan", "Do you want to run '", tool, "' (", "[Y]", " 'yes' / ", "[N]", " 'no' / ", "[A]", " 'yes to all'): ")

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
	printOSCPConsentNotGiven(tool)
	return 'n'
}

// CheckToolExists checks that the tool exists with exec.LookPath (equivalent to `which <tool>`)
func CheckToolExists(tool string) bool {
	_, lookPatherr := exec.LookPath(tool)
	return lookPatherr == nil
}

// Separate function to add key tools
func getKeyTools() []string {
	return []string{
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
		// TODO: add nuclei!!!
		"odat",
		"responder-RunFinger",
		"rusers",
		"seclists",
		"smbclient",
		"ssh-audit",
		"testssl.sh",
		"wafw00f",
		"whatweb",
	}
}

func getKeyCloudTools() []string {
	return []string{
		"prowler",
		"scout",
		"cloudfox",
		/*
		- Prowler (https://github.com/prowler-cloud/prowler)
		- Scoutsuite (https://github.com/nccgroup/scoutsuite)
		- CloudFox (https://github.com/BishopFox/cloudfox)
			Note: it'd be good if pmapper was installed alongside cloudfox, with their integration it could also have it generate the default privesc query and images as output
		- Pmapper (https://github.com/nccgroup/PMapper)
		- Steampipe (https://github.com/turbot/steampipe)
		- Powerpipe (https://github.com/turbot/powerpipe)
		*/
	}
}

// InstallMissingTools instructs the program to try and install tools that are absent from the pentesting distro
func InstallMissingTools(kind rune) {
	if *OptInstall {
		fmt.Println(Cyan("[*] Install flag detected. Aborting other checks and running pre-requisites check.\n"))
	}

	var keyTools []string
	switch kind {
	case 'c':
		keyTools = getKeyCloudTools()
	case 'i':
		keyTools = getKeyTools()
	}

	// Loop through listed tool see which ones are missing
	var missingTools []string
	fullConsent := false
	for _, tool := range keyTools {
		if CheckToolExists(tool) {
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

func printOSCPConsentNotGiven(tool string) {
	fmt.Printf(
		"%s\n%s %s\n",
		Red("[-] Consent not given to run '"),
		Cyan(tool),
		Red(". Aborting..."),
	)
}

// AptGetUpdateCmd runs the apt-get update command
func AptGetUpdateCmd() {
	fmt.Printf("%s %s%s ", Yellow("[!] Running"), Cyan("apt-get update"), Yellow("..."))
	update := exec.Command("apt-get", "update")

	// Redirect the command's error output to the standard output in terminal
	update.Stderr = os.Stderr

	// Only print to stdout if very verbose flag
	if *OptVVerbose {
		fmt.Println(Cyan("[*] Debug -> printing apt-get update's output ------"))
		update.Stdout = os.Stdout
	}

	// Run the command
	updateErr := update.Run()
	if updateErr != nil {
		if *OptVVerbose {
			fmt.Printf("Debug - Error running apt-get update: %v\n", updateErr)
		}
		return
	}

	fmt.Println(Green("Done!"))
}

// AptGetInstallCmd runs the apt-get install <tool> command
func AptGetInstallCmd(tool string) {
	// Moving to go due to import cycle
	PrintInstallingTool(tool)

	if tool == "finger" {
		tool = "nfs-common"
	}

	// if tool == "seclists" {
	// 	tool = "nfs-common"
	// }

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
		if *OptVVerbose {
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

func enum4linuxNgPreReqs() {
	reqs := []string{"python3-ldap3", "python3-yaml", "python3-impacket", "pip"}
	for _, tool := range reqs {
		if !Updated {
			AptGetUpdateCmd()
			Updated = true
		}
		AptGetInstallCmd(tool)
	}
}

// gitCloneCmd clones the git repo in the system
func gitCloneCmd(repoName, repoUrl string) error {
	localDir := "/usr/share/" + repoName
	gitClone := exec.Command("git", "clone", repoUrl, localDir)

	// Redirect the command's error output to the standard output in terminal
	gitClone.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *OptVVerbose {
		fmt.Println(Cyan("[*] Very verbose -> printing git clone's output ------"))
		gitClone.Stdout = os.Stdout
	}

	// Run the command
	gitCloneErr := gitClone.Run()
	if gitCloneErr != nil {
		if *OptVVerbose {
			fmt.Printf("Very verbose -> Error running git clone: %v\n", gitCloneErr)
		}
		return gitCloneErr
	}

	return nil
}

// pipInstallCmd runs pip install <package>
func pipInstallCmd(pipPackage ...string) error {
	pipInstall := exec.Command("pip", "install", pipPackage[0], pipPackage[1])

	// Redirect the command's error output to the standard output in terminal
	pipInstall.Stderr = os.Stderr

	// Only print to stdout if very verbose
	if *OptVVerbose {
		fmt.Println(Cyan("[*] Very verbose -> printing pip install output ------"))
		pipInstall.Stdout = os.Stdout
	}

	// Run the command
	pipInstallErr := pipInstall.Run()
	if pipInstallErr != nil {
		if *OptVVerbose {
			fmt.Printf("Very verbose - Error running pip install wheel: %v\n", pipInstallErr)
		}
		return pipInstallErr
	}

	return nil
}

// runChmod runs chmod in the system
func runChmod(command ...string) error {
	cmd := exec.Command("chmod", command[0], command[1])

	// Redirect the command's error output to the standard output in terminal
	cmd.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *OptVVerbose {
		fmt.Println(Cyan("[*] Very verbose -> printing cmd's output ------"))
		cmd.Stdout = os.Stdout
	}

	// Run cmd
	cmdErr := cmd.Run()
	if cmdErr != nil {
		if *OptVVerbose {
			fmt.Printf("Very verbose -> Error running cmd: %v\n", cmdErr)
		}
		return cmdErr
	}

	return nil
}

// runLn links files for execution within the $PATH
func runLn(command ...string) error {
	cmd := exec.Command("ln", command[0], command[1], command[2])

	// Redirect the command's error output to the standard output in terminal
	cmd.Stderr = os.Stderr

	// Only print to stdout if debugging
	if *OptVVerbose {
		fmt.Println(Cyan("[*] Very verbose -> printing ln's output ------"))
		cmd.Stdout = os.Stdout
	}

	// Run cmd
	cmdErr := cmd.Run()
	if cmdErr != nil {
		if *OptVVerbose {
			fmt.Printf("Very verbose -> Error running ln: %v\n", cmdErr)
		}
		return cmdErr
	}

	return nil
}

// installEnum4linuxNg tries to install Enum4linux-ng on behalf of the user
func installEnum4linuxNg() error {
	// Print ask for consent
	PrintCustomBiColourMsg(
		"yellow", "cyan",
		"Do you want for ", "Enumeraga ", "to try and handle the installation of '", "enum4linux-ng",
		"'?\nIt might be the case you have it in your machine but not in your $PATH.\nBear in mind that this will call '", "pip", "' as root",
	)

	// Get consent
	userInput := Consent("enum4linux-ng using pip as root")
	if userInput == 'n' {
		consentErr := fmt.Errorf("%s", "Error. Consent not given")
		return consentErr
	}

	fmt.Printf("%s %s%s\n", Yellow("[!] Checking pre-requisites to install '"), Cyan("enum4linux-ng"), Yellow("'..."))

	// Check and installed pre-requisites
	enum4linuxNgPreReqs()

	// Run git clone "https://github.com/cddmp/enum4linux-ng"
	PrintCustomBiColourMsg("yellow", "cyan", "[!] Installing '", "enum4linux-ng", "' ...")
	gitCloneErr := gitCloneCmd("enum4linux-ng", "https://github.com/cddmp/enum4linux-ng")
	if gitCloneErr != nil {
		return gitCloneErr
	}

	// Run pip to install wheel and clone
	pipInstallWheelAndCloneErr := pipInstallCmd("wheel", "clone")
	if pipInstallWheelAndCloneErr != nil {
		return pipInstallWheelAndCloneErr
	}

	// Run Pip install -r requirements.txt
	pipInstallRequisitesCmd := pipInstallCmd("-r", "/usr/share/enum4linux-ng/requirements.txt")
	if pipInstallRequisitesCmd != nil {
		return pipInstallRequisitesCmd
	}

	// Make executable
	runChmodErr := runChmod("+x", "/usr/share/enum4linux-ng/enum4linux-ng.py")
	if runChmodErr != nil {
		return runChmodErr
	}

	// Create symbolic link
	lnErr := runLn("-s", "/usr/share/enum4linux-ng/enum4linux-ng.py", "/usr/bin/enum4linux-ng")
	if lnErr != nil {
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

	if *OptVVerbose {
		fmt.Println("Located Files:")
		fmt.Printf("dir_list_medium: %v\n", DirListMedium)
		fmt.Printf("darkweb_top1000: %v\n", DarkwebTop1000)
		fmt.Printf("extensions_list: %v\n", ExtensionsList)
		fmt.Printf("users_list: %v\n", UsersList)
		fmt.Printf("snmp_list: %v\n", SnmpList)
	}
}

// PrintCustomBiColourMsg loops over the necessary colours, printing one at a time
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
