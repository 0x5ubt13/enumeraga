package installer

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/0x5ubt13/enumeraga/internal/utils/output"
)

// AptGetUpdateCmd runs the apt-get update command
func AptGetUpdateCmd() {
	fmt.Printf("%s %s%s ", output.Yellow("[!] Running"), output.Cyan("apt-get update"), output.Yellow("..."))
	update := exec.Command("apt-get", "update")

	// Redirect the command's error output to the standard output in terminal
	update.Stderr = os.Stderr

	// Run the command
	updateErr := update.Run()
	if updateErr != nil {
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("[?] Debug -> Error running apt-get update: %v\n", updateErr))
		return
	}

	fmt.Printf("%s\n", output.Green("Done!"))
}

// AptGetInstallCmd runs the apt-get install <tool> command
func AptGetInstallCmd(tool string) {
	// Moving to go due to import cycle
	PrintInstallingTool(tool)

	// Map tool names to their package names
	packageMap := map[string]string{
		"finger":              "nfs-common",
		"msfconsole":          "metasploit-framework",
		"responder-RunFinger": "responder",
		"impacket-rpcdump":    "python3-impacket",
	}

	if pkg, exists := packageMap[tool]; exists {
		tool = pkg
	}

	aptGetInstall := exec.Command("apt", "install", "-y", tool)

	aptGetInstallErr := aptGetInstall.Run()
	if aptGetInstallErr != nil {
		// Notify of enum4linux-ng as it's not currently in the official kali repo
		if tool == "enum4linux-ng" {
			installErr := installEnum4linuxNg()
			if installErr != nil {
				output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", installErr.Error())
				output.PrintCustomBiColourMsg("red", "cyan", "[-] Error. ", "enum4linux-ng", " needs to be manually installed.\nPlease see: ", "https://github.com/cddmp/enum4linux-ng/blob/master/README.md#kali-linuxdebianubuntulinux-mint")
				os.Exit(2)
			}
			return
		}

		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error. Please install the following package manually: '", tool, "'\n[-] Aborting...")
		os.Exit(2)
	}

	fmt.Printf("%s\n", output.Green("Done!"))
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
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error running git clone: %v\n", gitCloneErr))
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
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Very verbose - Error running pip install wheel: %v\n", pipInstallErr))
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
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error", fmt.Sprintf("Very verbose -> Error running cmd: %v\n", cmdErr))
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
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Very verbose -> Error running ln: %v\n", cmdErr))
		return cmdErr
	}
	return nil
}

// installEnum4linuxNg tries to install Enum4linux-ng on behalf of the user
func installEnum4linuxNg() error {
	// Print ask for consent
	output.PrintCustomBiColourMsg(
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

	fmt.Printf("%s %s%s\n", output.Yellow("[!] Checking pre-requisites to install '"), output.Cyan("enum4linux-ng"), output.Yellow("'..."))

	// Check and installed pre-requisites
	enum4linuxNgPreReqs()

	// Run git clone "https://github.com/cddmp/enum4linux-ng"
	output.PrintCustomBiColourMsg("yellow", "cyan", "[!] Installing '", "enum4linux-ng", "' ...")
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

	fmt.Println(output.Green("Done!"))
	return nil
}
