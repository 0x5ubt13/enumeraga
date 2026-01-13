package installer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/utils/output"
)

// Consent asks for user consent to install a tool
func Consent(tool string) rune {
	output.PrintCustomBiColourMsg("red", "cyan", "[-] ", "Enumeraga ", "needs ", tool, " to be installed")
	output.PrintCustomBiColourMsg("yellow", "cyan", "Do you want to install '", tool, "' (", "[Y]", " 'yes' / ", "[N]", " 'no' / ", "[A]", " 'yes to all'): ")

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
	output.PrintCustomBiColourMsg("red", "cyan", "[-] ", "Enumeraga ", "needs ", tool, " to be run, which won't be very good if you're trying OSCP 😬")
	output.PrintCustomBiColourMsg("yellow", "cyan", "Do you want to run '", tool, "' (", "[Y]", " 'yes' / ", "[N]", " 'no' / ", "[A]", " 'yes to all'): ")

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
	if tool == "seclists" {
		_, err := os.Stat("/usr/share/seclists")
		return err == nil
	}
	_, lookPatherr := exec.LookPath(tool)
	return lookPatherr == nil
}

// getKeyTools returns the list of key infrastructure scanning tools
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
		"nuclei",
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

// getKeyCloudTools returns the list of key cloud scanning tools
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

// Global flag to track if apt-get update has been run
var Updated bool

// InstallMissingTools instructs the program to try and install tools that are absent from the pentesting distro.
// Case 'c' installs key cloud tools
// Case 'i' installs key infra tools
func InstallMissingTools(kind rune, optInstall *bool) {
	if *optInstall {
		fmt.Println(output.Cyan("[*] Install flag detected. Aborting other checks and running pre-requisites check.\n"))
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

// Check if OS is debian-like
func isCompatibleDistro() error {
	cat := exec.Command("cat", "/etc/os-release")
	outputBytes, err := cat.CombinedOutput()
	if err != nil {
		fmt.Printf("Error reading /etc/os-release: %v\n", err)
		os.Exit(5)
	}

	compatibleDistro := strings.Contains(strings.ToLower(string(outputBytes)), "debian")
	if !compatibleDistro {
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", "This system is not running a Debian-like distribution. Please install the tools manually.")
		return fmt.Errorf("not compatible distro")
	}

	return nil
}

func PrintInstallingTool(tool string) {
	fmt.Printf("%s %s%s ", output.Yellow("[!] Installing"), output.Cyan(tool), output.Yellow("..."))
}

func printConsentNotGiven(tool string) {
	fmt.Printf(
		"%s\n%s %s %s\n",
		output.Red("[-] Consent not given."),
		output.Red("[-] Please install"),
		output.Cyan(tool),
		output.Red("manually. Aborting..."),
	)
}

func printOSCPConsentNotGiven(tool string) {
	fmt.Printf(
		"%s\n%s %s\n",
		output.Red("[-] Consent not given to run '"),
		output.Cyan(tool),
		output.Red(". Aborting..."),
	)
}
