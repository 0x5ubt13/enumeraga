package main

import (
	"fmt"
	"os"
	"os/exec"
	// "strings"
)

func wgetCmd(outputFile string, url string) {
	wget := exec.Command("wget", "--no-check-certificate", "-O", outputFile, url)
	
	if *optDbg {
		// Redirect the command's output to the standard output in terminal
		wget.Stdout = os.Stdout
		wget.Stderr = os.Stderr
	}

	// Run the command
	wgetErr := wget.Run()
	if wgetErr != nil {
		if *optDbg {
			fmt.Printf("Debug - Error running wget: %v\n", wgetErr)
			fmt.Printf("Debug - Trying curl")
		}
		curlCmd(outputFile, url)
		return
	}
}


func curlCmd(outputFile string, url string) {
	curl := exec.Command("curl", "-o", outputFile, url, "-L")
	
	if *optDbg {
		// Redirect the command's output to the standard output in terminal
		curl.Stdout = os.Stdout
		curl.Stderr = os.Stderr
	}

	// Run the command
	curlErr := curl.Run()
	if curlErr != nil {
		if *optDbg {fmt.Printf("Debug - Error running curl: %v\n", curlErr)}

		return
	}
}

func dpkgCmd(debPkgPath string) {
	dpkg := exec.Command("sudo", "dpkg", "-i", debPkgPath)

	if *optDbg {
		// Redirect the command's output to the standard output in terminal
		dpkg.Stdout = os.Stdout
		dpkg.Stderr = os.Stderr
	}

	// Run the command
	dpkgErr := dpkg.Run()
	if dpkgErr != nil {
		if *optDbg {fmt.Printf("Debug - Error running wget: %v\n", dpkgErr)}
		return
	}
}

func aptGetUpdateCmd() {
	// Run the apt-get update command
	update := exec.Command("apt-get", "update")

	// Redirect the command's output to the standard output in terminal
	update.Stdout = os.Stdout
	update.Stderr = os.Stderr

	// Run the command
	updateErr := update.Run()
	if updateErr != nil {
		if *optDbg {fmt.Printf("Debug - Error running apt-get update: %v\n", updateErr)}
		return
	}

	if *optDbg {green("[*] Debug - apt-get update completed successfully.")}
}

func aptGetInstallCmd(tool string) {
	printInstallingTool(tool)

	if tool == "finger" {
		tool = "nfs-common"
	}

	aptGetInstall := exec.Command("apt", "install", "-y", tool)

	aptGetInstallErr := aptGetInstall.Run()
	if aptGetInstallErr != nil {
		// if !strings.Contains(string(aptGetInstall.Stdout), "Unable to locate package") {
		if *optDbg {fmt.Printf("Debug - Error executing apt-get: %v\n", aptGetInstallErr)}
		fmt.Printf(
			"%s\n%s\n%s\n",
			red("[-] Please install the following tools manually: "),
			cyan(tool),
			red("[-] Aborting..."),
		)

		
		// Commenting this all out as it's not working in my WSL-based debian. Leaving it here for the future perhaps?
		// deleteLineFromFile("/etc/apt/sources.list", "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware")
		// fmt.Printf(
		// 	"%s\n%s %s %s %s", 
		// 	red("[-] It looks like apt-get is unable to locate some of the tools with your current sources."),
		// 	yellow("[!] Do you want to try"),
		// 	cyan("Kali's packaging repository source"),
		// 	yellow("(cleanup will be performed afterwards)?"),
		// 	yellow("[Y] yes / [N] no): "),
		// )
		// consent := bufio.NewScanner(os.Stdin)
		// consent.Scan()
		// userInput := strings.ToLower(consent.Text())
		// if userInput != "y" && userInput != "yes" {
		// 	printConsentNotGiven("Kali's packaging repository source")
		// 	// Making sure we clean up if we are recursing this function
		// 	deleteLineFromFile("/etc/apt/sources.list", "deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware")
		// 	os.Exit(1)
		// }		
		// installWithKaliSourceRepo(tools)
	}

	fmt.Printf("%s\n", green("Done!"))

}

func rmCmd(filePath string) {
	rm := exec.Command("rm", "-f", filePath)

	if *optDbg {
		// Redirect the command's output to the standard output in terminal
		rm.Stdout = os.Stdout
		rm.Stderr = os.Stderr
	}

	// Run the command
	rmErr := rm.Run()
	if rmErr != nil {
		if *optDbg {fmt.Printf("Debug - Error running apt-get update: %v\n", rmErr)}
		return
	}
}





