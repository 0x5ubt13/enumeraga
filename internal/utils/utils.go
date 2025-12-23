package utils

import (
	"archive/zip"
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
	"github.com/Ullaakut/nmap/v3"
	"github.com/fatih/color"
	"github.com/mattn/go-zglob"
)

// Host is a struct that holds the OS and architecture of the host to identify the correct tools to install
type Host struct {
	OS   string
	Arch string
}

// Declare global variables available throughout Enumeraga
var (
	HostOS = Host{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

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

	// ToolRegistry tracks all enumeration tools and their progress
	ToolRegistry *ToolTracker

	BaseDir      string
	Target       string
	Version      string
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

func init() {
	ToolRegistry = NewToolTracker()
}

func PrintBanner() {
	fmt.Printf("\n%s\n", Cyan("                                                     ", Version))
	fmt.Printf("%s%s%s\n", Yellow(" __________                                    ________"), Cyan("________"), Yellow("______ "))
	fmt.Printf("%s%s%s\n", Yellow(" ___  ____/__________  ________ __________________    |"), Cyan("_  ____/"), Yellow("__    |"))
	fmt.Printf("%s%s%s\n", Yellow(" __  __/  __  __ \\  / / /_  __ `__ \\  _ \\_  ___/_  /| |"), Cyan("  / __ "), Yellow("__  /| |"))
	fmt.Printf("%s%s%s\n", Yellow(" _  /___  _  / / / /_/ /_  / / / / /  __/  /   _  ___ "), Cyan("/ /_/ / "), Yellow("_  ___ |"))
	fmt.Printf("%s%s%s\n", Yellow(" /_____/  /_/ /_/\\__,_/ /_/ /_/ /_/\\___//_/    /_/  |_"), Cyan("\\____/  "), Yellow("/_/  |_|"))
	fmt.Printf("%s\n\n", Green("                            by 0x5ubt13"))
}

// ValidateIP checks if the provided string is a valid IPv4 or IPv6 address
func ValidateIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// ResolveHostToIP resolves a hostname or URL to an IP address
// It accepts domain names (example.com), URLs (http://example.com), and already-valid IPs
// Returns the resolved IP address or error if resolution fails
func ResolveHostToIP(host string) (string, error) {
	// First, try to parse as IP address - if it's already an IP, return it
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// Remove common URL schemes if present (http://, https://, etc.)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "ftp://")

	// Remove path components if URL contains them
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Try to parse again after cleanup - maybe it was a URL with an IP
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// Perform DNS lookup
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname %s: %v", host, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for hostname: %s", host)
	}

	// Return the first IPv4 address found, or first IPv6 if no IPv4 exists
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	// If no IPv4 found, return first IPv6
	return ips[0].String(), nil
}

// ValidateCIDR checks if the provided string is a valid CIDR notation
func ValidateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR range: %s - %v", cidr, err)
	}
	return nil
}

// ValidatePort checks if the provided port number is valid (1-65535)
func ValidatePort(port string) error {
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port number: %s - not a number", port)
	}
	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port number: %d - must be between 1 and 65535", portNum)
	}
	return nil
}

// ValidatePorts checks if the provided comma-separated port list is valid
func ValidatePorts(ports string) error {
	portList := strings.Split(ports, ",")
	for _, port := range portList {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		// Handle port ranges like "1-100"
		if strings.Contains(port, "-") {
			rangeParts := strings.Split(port, "-")
			if len(rangeParts) != 2 {
				return fmt.Errorf("invalid port range format: %s", port)
			}
			if err := ValidatePort(rangeParts[0]); err != nil {
				return err
			}
			if err := ValidatePort(rangeParts[1]); err != nil {
				return err
			}
			start, _ := strconv.Atoi(rangeParts[0])
			end, _ := strconv.Atoi(rangeParts[1])
			if start > end {
				return fmt.Errorf("invalid port range: %s - start port greater than end port", port)
			}
		} else {
			if err := ValidatePort(port); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateFilePath checks if the provided file path exists and is readable
func ValidateFilePath(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", path)
	}
	if err != nil {
		return fmt.Errorf("error accessing file: %s - %v", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", path)
	}
	return nil
}

func PrintInfraUsageExamples() {
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
		e, "azure",
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
func ErrorMsg(errMsg any) {
	fmt.Printf("%s %s\n", Red("[-] Error detected:"), errMsg)
}

// ReadTargetsFile from the argument path passed to -t; returns number of targets, one per line
func ReadTargetsFile(optTarget *string) ([]string, int) {
	data, err := os.ReadFile(*optTarget)
	if err != nil {
		ErrorMsg(fmt.Sprintf("Failed to read targets file: %v", err))
		return nil, 0
	}

	// Get lines
	lines := strings.Split(string(data), "\n")
	// Filter out empty lines
	nonEmptyLines := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			nonEmptyLines = append(nonEmptyLines, trimmedLine)
		}
	}
	return nonEmptyLines, len(nonEmptyLines)
}

// CustomMkdir checks first if it is possible to create new dir, and send custom msg if not.
func CustomMkdir(name string) (string, error) {
	err := os.MkdirAll(name, os.ModePerm)
	if err != nil {
		return "", err
	}
	return name, nil
}

// ProtocolDetected announces protocol, creates base dir and returns its name
func ProtocolDetected(protocol, baseDir string) string {
	PrintCustomBiColourMsg("green", "cyan", "[+] '", protocol, "' service detected")

	protocolDir := fmt.Sprintf("%s%s/", baseDir, strings.ToLower(protocol))
	_, err := CustomMkdir(protocolDir)
	if err != nil {
		ErrorMsg(fmt.Sprintf("Error creating protocol directory: %v", err))
	}

	return protocolDir
}

func WriteTextToFile(filePath string, message string) error {
	// Open file
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer func(f *os.File) {
		if closeErr := f.Close(); closeErr != nil {
			ErrorMsg(fmt.Sprintf("Error closing file %s: %v", filePath, closeErr))
		}
	}(f)

	// Write to it
	if _, err := fmt.Fprintln(f, message); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", filePath, err)
	}
	return nil
}

func WritePortsToFile(filePath string, ports string, host string) (string, error) {
	// Open file
	fileName := fmt.Sprintf("%sopen_ports.txt", filePath)
	f, err := os.Create(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to create ports file %s: %w", fileName, err)
	}
	defer func(f *os.File) {
		if closeErr := f.Close(); closeErr != nil {
			ErrorMsg(fmt.Sprintf("Error closing file %s: %v", fileName, closeErr))
		}
	}(f)

	// Write to it
	if _, err := fmt.Fprintln(f, ports); err != nil {
		return "", fmt.Errorf("failed to write ports to file %s: %w", fileName, err)
	}
	PrintCustomBiColourMsg("green", "yellow", "[+] Successfully written open ports for host '", host, "' to file '", fileName, "'")

	return ports, nil
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
	fmt.Printf("%s%s%s\n\n", Cyan("[*] ---------- "), Green("Enumeration phase complete"), Cyan(" ----------"))
	fmt.Printf("%s%s%s\n", Cyan("[*] ---------- "), Green("Program complete. Awaiting tools to finish"), Cyan(" ----------"))
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
			if port.State.String() == "open" {
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
			if port.State.String() == "open" {
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
		"testssl",
		"wafw00f",
		"whatweb",
	}
}

func getKeyCloudTools() []string {
	return []string{
		"prowler",    // (https://github.com/prowler-cloud/prowler)
		"scoutsuite", // (https://github.com/nccgroup/scoutsuite)
		"cloudfox",   // (https://github.com/BishopFox/cloudfox)
		/*
			Note: it'd be good if pmapper was installed alongside cloudfox, with their integration it could also have it generate the default privesc query and images as output
				- Pmapper (https://github.com/nccgroup/PMapper)
				- Steampipe (https://github.com/turbot/steampipe)
				- Powerpipe (https://github.com/turbot/powerpipe)
		*/
	}
}

// InstallMissingTools instructs the program to try and install tools that are absent from the pentesting distro.
// Case 'c' installs key cloud tools
// Case 'i' installs key infra tools
func InstallMissingTools(kind rune, optInstall *bool) {
	if *optInstall {
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
		// Check for tools conflicting with arm64
		if runtime.GOARCH == "arm64" {
			if tool == "odat" {
				continue
			}
		}

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

	// Run the command
	updateErr := update.Run()
	if updateErr != nil {
		ErrorMsg(fmt.Sprintf("[?] Debug -> Error running apt-get update: %v\n", updateErr))
		return
	}

	fmt.Printf("%s\n", Green("Done!"))
}

// AptGetInstallCmd runs the apt-get install <tool> command
func AptGetInstallCmd(tool string) {
	// Moving to go due to import cycle
	PrintInstallingTool(tool)

	if tool == "finger" {
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

	// Run the command
	gitCloneErr := gitClone.Run()
	if gitCloneErr != nil {
		ErrorMsg(fmt.Sprintf("Error running git clone: %v\n", gitCloneErr))
		return gitCloneErr
	}

	return nil
}

// pipInstallCmd runs pip install <packages>
func pipInstallCmd(pipPackage ...string) error {
	if len(pipPackage) == 0 {
		return fmt.Errorf("at least one package must be passed to the function")
	}

	args := append([]string{"install", "--break-system-packages"}, pipPackage...)
	pipInstall := exec.Command("pip", args...)

	// Redirect the command's error output to the standard output in terminal
	pipInstall.Stderr = os.Stderr

	// Run the command
	pipInstallErr := pipInstall.Run()
	if pipInstallErr != nil {
		ErrorMsg(fmt.Sprintf("Very verbose - Error running pip install wheel: %v\n", pipInstallErr))
		return pipInstallErr
	}
	return nil
}

// runChmod runs chmod in the system
func runChmod(command ...string) error {
	cmd := exec.Command("chmod", command[0], command[1])

	// Redirect the command's error output to the standard output in terminal
	cmd.Stderr = os.Stderr

	// Run cmd
	cmdErr := cmd.Run()
	if cmdErr != nil {
		ErrorMsg(fmt.Sprintf("Very verbose -> Error running cmd: %v\n", cmdErr))
		return cmdErr
	}
	return nil
}

// runLn links files for execution within the $PATH
func runLn(command ...string) error {
	cmd := exec.Command("ln", command[0], command[1], command[2])

	// Redirect the command's error output to the standard output in terminal
	cmd.Stderr = os.Stderr

	// Run cmd
	cmdErr := cmd.Run()
	if cmdErr != nil {
		ErrorMsg(fmt.Sprintf("Very verbose -> Error running ln: %v\n", cmdErr))
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

func GetWordlists(optVVerbose *bool) {
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
	DarkwebTop1000Slice, err := zglob.Glob("/usr/share/seclists/Passwords/darkweb2017-top1000.txt")
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
	SnmpList = snmpListSlice[0]

	if *optVVerbose {
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
			case "magenta":
				fmt.Printf("%s", Debug(str))
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

type Asset struct {
	BrowserDownloadURL string `json:"browser_download_url"`
	Name               string `json:"name"`
}

type Release struct {
	Assets     []Asset `json:"assets"`
	ZipballURL string  `json:"zipball_url"`
}

// GetDownloadURL returns the download URL for the tool according to the user's host OS and architecture
func GetDownloadURL(tool string, latest Release) (string, error) {
	switch tool {
	case "cloudfox":
		for _, asset := range latest.Assets {
			if HostOS.OS == "linux" && HostOS.Arch == "amd64" && filepath.Ext(asset.Name) == ".zip" && asset.Name == "cloudfox-linux-amd64.zip" {
				return asset.BrowserDownloadURL, nil
			}
			if HostOS.OS == "linux" && HostOS.Arch == "386" && filepath.Ext(asset.Name) == ".zip" && asset.Name == "cloudfox-linux-386.zip" {
				return asset.BrowserDownloadURL, nil
			}
			if HostOS.OS == "darwin" && HostOS.Arch == "amd64" && filepath.Ext(asset.Name) == ".zip" && asset.Name == "cloudfox-macos-amd64.zip" {
				return asset.BrowserDownloadURL, nil
			}
			if HostOS.OS == "darwin" && HostOS.Arch == "arm64" && filepath.Ext(asset.Name) == ".zip" && asset.Name == "cloudfox-macos-arm64.zip" {
				return asset.BrowserDownloadURL, nil
			}
			if HostOS.OS == "windows" && HostOS.Arch == "amd64" && filepath.Ext(asset.Name) == ".zip" && asset.Name == "cloudfox-windows-amd64.zip" {
				return asset.BrowserDownloadURL, nil
			}
		}
		// Any other tool that needs downloading from GitHub can be added below:
		// case "":
		//     return return asset.BrowserDownloadURL, nil
	}

	PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> No suitable asset found. Host OS: ", HostOS.OS, " | Host Arch: ", HostOS.Arch, " | Assets: ", fmt.Sprintf("%v", latest.Assets))
	return "", fmt.Errorf("no suitable asset found")
}

func DownloadFileFromURL(url string, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func DownloadFromGithub(toolFullPath, downloadURL string) error {
	// Making the tool download OS-agnostic, instead of using wget
	out, err := os.Create(toolFullPath)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer func(out *os.File) {
		err := out.Close()
		if err != nil {
			ErrorMsg("error closing file")
		}
	}(out)

	// Get the data
	downloadResp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("error downloading file: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ErrorMsg(fmt.Sprintf("Error closing the request body: %v", err))
		}
	}(downloadResp.Body)

	// Write the data to the file
	_, err = io.Copy(out, downloadResp.Body)
	if err != nil {
		return fmt.Errorf("error writing to file: %v", err)
	}

	return nil
}

// FetchAndDownloadLatestVersionFromGitHub fetches the latest release from GitHub and downloads the tool
func FetchAndDownloadLatestVersionFromGitHub(tool string) (string, string, error) {
	// Create an OS-agnostic temp directory for the tool
	toolTmpDir := filepath.Join(os.TempDir(), tool)
	if err := os.MkdirAll(toolTmpDir, os.ModePerm); err != nil {
		return "", "", fmt.Errorf("error while creating tmp dir: %v", err)
	}

	var repo, toolFullPath string
	switch tool {
	case "cloudfox":
		repo = "BishopFox/cloudfox"
		toolFullPath = filepath.Join(toolTmpDir, tool+".zip")
	}

	assetResp, err := http.Get(fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo))
	if err != nil {
		return "", "", fmt.Errorf("error while fetching latest release: %v", err)
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ErrorMsg(fmt.Sprintf("Error closing the request body: %v", err))
		}
	}(assetResp.Body)

	var latestReleaseData Release
	if err := json.NewDecoder(assetResp.Body).Decode(&latestReleaseData); err != nil {
		return "", "", fmt.Errorf("error decoding latest release data: %v", err)
	}

	downloadURL, err := GetDownloadURL(tool, latestReleaseData)
	if err != nil {
		return "", "", fmt.Errorf("error getting download URL: %v", err)
	}

	PrintCustomBiColourMsg("yellow", "cyan", "[!] Suitable URL found for '", tool, "' for OS ", HostOS.OS, " and arch ", HostOS.Arch, ": ", downloadURL)

	err = DownloadFromGithub(toolFullPath, downloadURL)
	if err != nil {
		return "", "", err
	}

	return toolTmpDir, toolFullPath, nil
}

// Unzip extracts files from zip archives
func Unzip(src, dest string) (string, error) {
	r, err := zip.OpenReader(src)
	if err != nil {
		return "", err
	}
	defer func(r *zip.ReadCloser) {
		err := r.Close()
		if err != nil {
			ErrorMsg(fmt.Sprintf("Error closing the zip reader: %v", err))
		}
	}(r)

	var fpath string
	for _, f := range r.File {
		fpath = filepath.Join(dest, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return "", fmt.Errorf("illegal file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			_, err = CustomMkdir(fpath)
			if err != nil {
				return "", err
			}
			continue
		}

		if _, err = CustomMkdir(filepath.Dir(fpath)); err != nil {
			return "", err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return "", err
		}

		rc, err := f.Open()
		if err != nil {
			return "", err
		}

		_, err = io.Copy(outFile, rc)
		if err != nil {
			return "", err
		}

		err = outFile.Close()
		if err != nil {
			return "", err
		}

		err = rc.Close()
		if err != nil {
			return "", err
		}
	}
	return fpath, nil
}

func InstallBinary(tmpDirToolPath string) (string, error) {
	// Determine the destination path based on the operating system
	binaryName := filepath.Base(tmpDirToolPath)

	var destPath string
	switch HostOS.OS {
	case "windows":
		destPath = filepath.Join(os.Getenv("ProgramFiles"), binaryName)
	case "darwin", "linux":
		destPath = fmt.Sprintf("%s/%s", filepath.Join("/usr/local/bin"), binaryName)
	default:
		return "", fmt.Errorf("unsupported operating system to install binary: %s/%s. Please open PR or let me know to fix it", HostOS.OS, HostOS.Arch)
	}

	// Move the binary to the destination path
	if err := os.Rename(tmpDirToolPath, destPath); err != nil {
		fmt.Println("Error moving binary to PATH. Maybe you need sudo?:", err)
		return "", fmt.Errorf("error moving binary to PATH: %v", err)
	}

	// Make the binary executable (only needed for Unix-like systems)
	if HostOS.OS == "darwin" || HostOS.OS == "linux" {
		if err := os.Chmod(destPath, 0755); err != nil {
			fmt.Println("Error setting executable permissions:", err)
			return "", fmt.Errorf("error setting executable permissions: %v", err)
		}
	}

	return destPath, nil
}

func DownloadFromGithubAndInstall(tool string) (string, error) {
	tempDirPath, toolFullPath, err := FetchAndDownloadLatestVersionFromGitHub(tool)
	if err != nil {
		PrintCustomBiColourMsg("red", "cyan", "[-]", fmt.Sprintf("%s not found. Please install %s manually: %v", tool, tool, err))
		return "", fmt.Errorf("error downloading tool from github")
	}

	PrintCustomBiColourMsg("green", "cyan", "[+] Successfully downloaded ", tool, " to ", toolFullPath)

	// Unzip the file
	extractedFilePath, err := Unzip(toolFullPath, tempDirPath)
	if err != nil {
		fmt.Println("Error unzipping file:", err)
		return "", fmt.Errorf("error unzipping tool: %v", err)
	}

	PrintCustomBiColourMsg("green", "cyan", "[+] Successfully unzipped ", tool, " to ", extractedFilePath)

	// Install it
	binaryPath, err := InstallBinary(extractedFilePath)
	if err != nil {
		return "", fmt.Errorf("error installing %s: %v", tool, err)
	}

	PrintCustomBiColourMsg("green", "cyan", "[+] Successfully installed ", tool, " in path directory: ", binaryPath)

	return binaryPath, nil
}

// getLatestCondaVersion fetches the latest Conda version from the official Miniconda repository
func getLatestCondaVersion() (string, error) {
    url := "https://repo.anaconda.com/miniconda/"
    resp, err := http.Get(url)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()

    tokenizer := html.NewTokenizer(resp.Body)
    for {
        tokenType := tokenizer.Next()
        if tokenType == html.ErrorToken {
            return "", fmt.Errorf("latest Conda version for %s %s not found. Please install conda manually: %s", HostOS.OS, HostOS.Arch, tokenizer.Err())
        }
        token := tokenizer.Token()
        if tokenType == html.StartTagToken && token.Data == "a" {
			PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> ", fmt.Sprintf("%v\n", token))
            for _, attr := range token.Attr {
				PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> ", attr.Key, " -> ", attr.Val)
				// Linux x86_64
                if HostOS.OS == "linux" && HostOS.Arch == "amd64" && attr.Key == "href" && attr.Val == "Miniconda3-latest-Linux-x86_64.sh" {
                    return url + attr.Val, nil
                }

				// MacOSX arm64
				if HostOS.OS == "darwin" && HostOS.Arch == "arm64" && attr.Key == "href" && attr.Val == "Miniconda3-latest-MacOSX-arm64.sh" {
					return url + attr.Val, nil
				}

				// MacOSX amd64
				if HostOS.OS == "darwin" && HostOS.Arch == "amd64" && attr.Key == "href" && attr.Val == "Miniconda3-latest-MacOSX-x86_64.sh" {
					return url + attr.Val, nil
				}

				// Windows x86_64
				if HostOS.OS == "windows" && HostOS.Arch == "amd64" && attr.Key == "href" && attr.Val == "Miniconda3-latest-Windows-x86_64.exe" {
					return url + attr.Val, nil
				}
			}
		}
	}
}

func InstallConda() error {
    latestVersionURL, err := getLatestCondaVersion()
    if err != nil {
        ErrorMsg(fmt.Sprintf("Error fetching latest Conda version: %v", err))
        return err
    }
    fmt.Println("Found latest Conda installer version for host OS:", latestVersionURL)

	// Create an OS-agnostic temp directory for the tool
	toolTmpDir := filepath.Join(os.TempDir(), "conda")
	if err := os.MkdirAll(toolTmpDir, os.ModePerm); err != nil {
		return fmt.Errorf("error while creating tmp dir: %v", err)
	}

	fileName := strings.Split(latestVersionURL, "/")[len(strings.Split(latestVersionURL, "/"))-1]
	tmpFilePath := toolTmpDir + "/" + fileName
    err = DownloadFileFromURL(latestVersionURL, tmpFilePath)
    if err != nil {
        ErrorMsg(fmt.Sprintf("Error downloading file: %v", err))
        return fmt.Errorf("error downloading Conda installer: %v", err)
    }
    fmt.Println("Downloaded file to:", toolTmpDir)
	PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> Downloaded file to: ", tmpFilePath)

	if HostOS.OS == "windows" {
		fmt.Println("Please run the installer manually. It can be found at:", tmpFilePath)
		return nil
	}

	// Set executable permission
    err = os.Chmod(tmpFilePath, 0755)
    if err != nil {
        fmt.Println("Error setting executable permission:", err)
        return err
    }
    fmt.Println("Executable permission set for:", tmpFilePath)

    // Run the binary
    cmd := exec.Command(tmpFilePath)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
    err = cmd.Run()
    if err != nil {
        fmt.Println("Error running binary:", err)
        return err
    }
    fmt.Println("Binary executed successfully")

	PrintCustomBiColourMsg("green", "cyan", "[+] Successfully installed ", "Conda", ".")
	return nil
}

func CheckAdminPrivileges(cloudOrInfra string) {
	switch cloudOrInfra {
	case "cloud":
		switch HostOS.OS {
		case "windows":
			// Check for administrative privileges on Windows
			cmd := exec.Command("powershell", "-Command", "[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
			output, err := cmd.Output()
			if err != nil || string(output) != "True\n" {
				ErrorMsg("Windows detected. If the program fails, please, run it as administrator so logic like tools installation doesn't fail!")
			}
		case "linux", "darwin":
			// Check for root privileges on Unix-like systems
			if os.Geteuid() != 0 {
				ErrorMsg("Please run me as root so the tools don't fail!")
				// os.Exit(99)
			}
		default:
			ErrorMsg("Unsupported operating system")
			os.Exit(99)
		}
	case "infra":
		switch HostOS.OS {
		case "windows":
			// Windows not supported for infra scanning
			ErrorMsg("Windows detected. For now running the infra section of Enumeraga in Windows isn't supported. Should you wish to contribute or formally request it, please get in touch or open a PR.")
			os.Exit(99)
		case "linux", "darwin":
			// Check for root privileges on Unix-like systems
			if os.Geteuid() != 0 {
				ErrorMsg("Please run me as root so the tools don't fail!")
				// os.Exit(99)
			}
		default:
			ErrorMsg("Unsupported operating system")
			os.Exit(99)
		}
	default:
		ErrorMsg(fmt.Sprintf("Unknown mode: %s. Expected 'cloud' or 'infra'", cloudOrInfra))
		os.Exit(99)
	}
}
