package installer

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/0x5ubt13/enumeraga/internal/utils/output"
	"golang.org/x/net/html"
)

// minicondaInstallers maps a "os-arch" key to the expected Miniconda installer filename.
var minicondaInstallers = map[string]string{
	"linux-amd64":   "Miniconda3-latest-Linux-x86_64.sh",
	"darwin-arm64":  "Miniconda3-latest-MacOSX-arm64.sh",
	"darwin-amd64":  "Miniconda3-latest-MacOSX-x86_64.sh",
	"windows-amd64": "Miniconda3-latest-Windows-x86_64.exe",
}

// getLatestCondaVersion fetches the latest Conda installer URL from the official Miniconda repository.
func getLatestCondaVersion() (string, error) {
	const repoURL = "https://repo.anaconda.com/miniconda/"

	resp, err := http.Get(repoURL) //nolint:gosec // URL is a hardcoded trusted constant
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	platformKey := fmt.Sprintf("%s-%s", HostOS.OS, HostOS.Arch)
	expectedInstaller, ok := minicondaInstallers[platformKey]
	if !ok {
		return "", fmt.Errorf("no Miniconda installer defined for platform %s", platformKey)
	}

	tokenizer := html.NewTokenizer(resp.Body)
	for {
		tokenType := tokenizer.Next()
		if tokenType == html.ErrorToken {
			return "", fmt.Errorf("installer %q not found in Miniconda repo: %v", expectedInstaller, tokenizer.Err())
		}
		if tokenType != html.StartTagToken {
			continue
		}
		token := tokenizer.Token()
		if token.Data != "a" {
			continue
		}
		output.PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> ", fmt.Sprintf("%v\n", token))
		for _, attr := range token.Attr {
			output.PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> ", attr.Key, " -> ", attr.Val)
			if attr.Key == "href" && attr.Val == expectedInstaller {
				return repoURL + attr.Val, nil
			}
		}
	}
}

// InstallConda downloads and installs Conda/Miniconda.
func InstallConda() error {
	latestVersionURL, err := getLatestCondaVersion()
	if err != nil {
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error fetching latest Conda version: %v", err))
		return err
	}
	fmt.Println("Found latest Conda installer version for host OS:", latestVersionURL)

	toolTmpDir := filepath.Join(os.TempDir(), "conda")
	if err := os.MkdirAll(toolTmpDir, os.ModePerm); err != nil {
		return fmt.Errorf("error while creating tmp dir: %v", err)
	}

	fileName := filepath.Base(latestVersionURL)
	tmpFilePath := filepath.Join(toolTmpDir, fileName)

	if err = DownloadFileFromURL(latestVersionURL, tmpFilePath); err != nil {
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error downloading file: %v", err))
		return fmt.Errorf("error downloading Conda installer: %v", err)
	}
	output.PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> Downloaded file to: ", tmpFilePath)

	if HostOS.OS == "windows" {
		fmt.Println("Please run the installer manually. It can be found at:", tmpFilePath)
		return nil
	}

	if err = os.Chmod(tmpFilePath, 0755); err != nil {
		return fmt.Errorf("error setting executable permission: %v", err)
	}

	cmd := exec.Command(tmpFilePath) //nolint:gosec // path is constructed from our own download
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("error running Conda installer: %v", err)
	}

	output.PrintCustomBiColourMsg("green", "cyan", "[+] Successfully installed ", "Conda", ".")
	return nil
}
