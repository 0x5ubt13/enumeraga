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

// stdinIsInteractive reports whether stdin is a terminal a user can answer from.
// Under `docker run` without -it, stdin is not a TTY: a prompt would be printed
// to nobody and Scan() returns immediately, reading as a declined install.
func stdinIsInteractive() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// Consent asks for user consent to install a tool
func Consent(tool string) rune {
	output.PrintCustomBiColourMsg("red", "cyan", "[-] ", "Enumeraga ", "needs the following package ", tool, " to be installed")

	// Without a terminal there is no one to answer; say so rather than appearing
	// to ask and then reporting that consent was withheld.
	if !stdinIsInteractive() {
		output.PrintCustomBiColourMsg("red", "cyan", "[-] ", "Non-interactive session", ": cannot prompt to install ", tool, ". Re-run with a TTY (docker run -it) or install it in the image.")
		return 'n'
	}

	output.PrintCustomBiColourMsgNoNL("yellow", "cyan", "Do you want to install '", tool , "' (", "[Y]", " 'yes' / ", "[N]", " 'no' / ", "[A]", " 'yes to all'): ")

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
	if tool == "gcp_iam_brute" {
		if _, err := os.Stat("/usr/local/bin/gcp-iam-brute"); err == nil {
			return true
		}
		if home, err := os.UserHomeDir(); err == nil {
			_, err := os.Stat(home + "/.local/bin/gcp-iam-brute")
			return err == nil
		}
		return false
	}
	_, lookPatherr := exec.LookPath(tool)
	return lookPatherr == nil
}

// isToolPresent reports whether a tool is already available, by either route it
// can arrive: registered as an apt package, or present as a binary on PATH.
// getKeyTools lists apt package names (ldap-utils, snmp, python3-impacket),
// which only dpkg can resolve. But tools installed out-of-band bypass dpkg
// entirely — the Docker image fetches nuclei as a pre-built binary into
// /usr/local/bin and creates /usr/share/seclists directly — so a dpkg-only
// check prompts to install tools that are in fact already there.
func isToolPresent(tool string) bool {
	return isToolPresentWith(tool, DpkgIsPackageInstalled, CheckToolExists)
}

// isToolPresentWith is isToolPresent with its lookups injected, so the either-source
// logic can be tested without depending on what happens to be installed.
func isToolPresentWith(tool string, dpkgLookup, binaryLookup func(string) bool) bool {
	return dpkgLookup(tool) || binaryLookup(tool)
}

// getKeyTools returns the list of key infrastructure scanning tools
func getKeyTools() []string {
	return []string{
		"braa",
		"cewl",
		"enum4linux-ng",
		"dirsearch",
		"finger",
		"ffuf",
		"fping",
		"hydra",
		"ident-user-enum",
		"nbtscan-unixwiz",
		"nikto",
		"nmap",
		"nuclei",
		"odat",
		"responder", //responder-RunFinger
		"rusers",
		"rwho",
		"seclists",
		"smbclient",
		"ssh-audit",
		"testssl.sh",
		"wafw00f",
		"whatweb",
		"gowitness",
		"netexec",
		"ldap-utils", // ldapsearch
		"nfs-client", // showmount
		"rsync",
		"openssl",
		"python3-impacket", // impacket-rpcdump
		"onesixtyone",
		"snmp", // snmpwalk
		"smbmap",
		"metasploit-framework", // msfconsole
		"cmseek",
		"sippts",
	}
}

// getKeyCloudTools returns the list of key cloud scanning tools
func getKeyCloudTools() []string {
	return []string{
		"nuclei",          // (https://github.com/projectdiscovery/nuclei)
		"gcp_iam_brute",   // (https://github.com/hac01/gcp-iam-brute)
		"prowler",         // (https://github.com/prowler-cloud/prowler)
		"scoutsuite",      // (https://github.com/nccgroup/scoutsuite)
		"cloudfox",        // (https://github.com/BishopFox/cloudfox)
		"aws-enumerator",  // (https://github.com/confused-binary/aws-enumerator)
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

		// check if tool is installed, as an apt package or a binary on PATH
		if isToolPresent(tool) {
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

// printConsentNotGiven reports a declined install. Declining skips this one tool
// and the scan carries on without it, so this must not claim to be aborting.
func printConsentNotGiven(tool string) {
	fmt.Printf(
		"%s\n%s %s %s\n",
		output.Red("[-] Consent not given."),
		output.Red("[-] Skipping checks that need"),
		output.Cyan(tool),
		output.Red("- install it manually to enable them."),
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

