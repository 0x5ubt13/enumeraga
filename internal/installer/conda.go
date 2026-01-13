package installer

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/utils/output"
	"golang.org/x/net/html"
)

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
			output.PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> ", fmt.Sprintf("%v\n", token))
			for _, attr := range token.Attr {
				output.PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> ", attr.Key, " -> ", attr.Val)

				// Platform-specific installers map
				installers := map[string]string{
					"linux-amd64":   "Miniconda3-latest-Linux-x86_64.sh",
					"darwin-arm64":  "Miniconda3-latest-MacOSX-arm64.sh",
					"darwin-amd64":  "Miniconda3-latest-MacOSX-x86_64.sh",
					"windows-amd64": "Miniconda3-latest-Windows-x86_64.exe",
				}

				platformKey := fmt.Sprintf("%s-%s", HostOS.OS, HostOS.Arch)
				if expectedInstaller, exists := installers[platformKey]; exists {
					if attr.Key == "href" && attr.Val == expectedInstaller {
						return url + attr.Val, nil
					}
				}
			}
		}
	}
}

// InstallConda downloads and installs Conda/Miniconda
func InstallConda() error {
	latestVersionURL, err := getLatestCondaVersion()
	if err != nil {
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error fetching latest Conda version: %v", err))
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
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error downloading file: %v", err))
		return fmt.Errorf("error downloading Conda installer: %v", err)
	}
	fmt.Println("Downloaded file to:", toolTmpDir)
	output.PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> Downloaded file to: ", tmpFilePath)

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

	output.PrintCustomBiColourMsg("green", "cyan", "[+] Successfully installed ", "Conda", ".")
	return nil
}
