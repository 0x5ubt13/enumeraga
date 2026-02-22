package installer

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/utils/files"
	"github.com/0x5ubt13/enumeraga/internal/utils/output"
)

// Asset represents a GitHub release asset
type Asset struct {
	BrowserDownloadURL string `json:"browser_download_url"`
	Name               string `json:"name"`
}

// Release represents a GitHub release
type Release struct {
	Assets     []Asset `json:"assets"`
	ZipballURL string  `json:"zipball_url"`
}

// Host is a struct that holds the OS and architecture of the host
type Host struct {
	OS   string
	Arch string
}

// HostOS identifies the current host platform
var HostOS = Host{
	OS:   runtime.GOOS,
	Arch: runtime.GOARCH,
}

// GetDownloadURL returns the download URL for the tool according to the user's host OS and architecture
func GetDownloadURL(tool string, latest Release) (string, error) {
	switch tool {
	case "cloudfox":
		// Map of platform-specific filenames
		platformAssets := map[string]string{
			"linux-amd64":   "cloudfox-linux-amd64.zip",
			"linux-386":     "cloudfox-linux-386.zip",
			"darwin-amd64":  "cloudfox-macos-amd64.zip",
			"darwin-arm64":  "cloudfox-macos-arm64.zip",
			"windows-amd64": "cloudfox-windows-amd64.zip",
		}

		platformKey := fmt.Sprintf("%s-%s", HostOS.OS, HostOS.Arch)
		expectedAsset, exists := platformAssets[platformKey]
		if !exists {
			return "", fmt.Errorf("unsupported platform: %s", platformKey)
		}

		for _, asset := range latest.Assets {
			if asset.Name == expectedAsset && filepath.Ext(asset.Name) == ".zip" {
				return asset.BrowserDownloadURL, nil
			}
		}
		// Any other tool that needs downloading from GitHub can be added below:
		// case "":
		//     return asset.BrowserDownloadURL, nil
	}

	output.PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> No suitable asset found. Host OS: ", HostOS.OS, " | Host Arch: ", HostOS.Arch, " | Assets: ", fmt.Sprintf("%v", latest.Assets))
	return "", fmt.Errorf("no suitable asset found")
}

// DownloadFileFromURL downloads a file from a URL to the specified filepath
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

// DownloadFromGithub downloads a file from GitHub to the specified path
func DownloadFromGithub(toolFullPath, downloadURL string) error {
	// Making the tool download OS-agnostic, instead of using wget
	out, err := os.Create(toolFullPath)
	if err != nil {
		return fmt.Errorf("error creating file: %v", err)
	}
	defer func(out *os.File) {
		err := out.Close()
		if err != nil {
			output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", "error closing file")
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
			output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error closing the request body: %v", err))
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
			output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error closing the request body: %v", err))
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

	output.PrintCustomBiColourMsg("yellow", "cyan", "[!] Suitable URL found for '", tool, "' for OS ", HostOS.OS, " and arch ", HostOS.Arch, ": ", downloadURL)

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
			output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error closing the zip reader: %v", err))
		}
	}(r)

	var fpath string
	for _, f := range r.File {
		fpath = filepath.Join(dest, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return "", fmt.Errorf("illegal file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			_, err = files.CustomMkdir(fpath)
			if err != nil {
				return "", err
			}
			continue
		}

		if _, err = files.CustomMkdir(filepath.Dir(fpath)); err != nil {
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

// InstallBinary installs a binary to the system PATH
func InstallBinary(tool, extractedBinaryPath string) (string, error) {
	// Determine the destination path based on the operating system.
	binaryName, err := expectedBinaryName(tool)
	if err != nil {
		return "", err
	}

	var destPath string
	switch HostOS.OS {
	case "windows":
		destPath = filepath.Join(os.Getenv("ProgramFiles"), binaryName)
	case "darwin", "linux":
		destPath = fmt.Sprintf("%s/%s", filepath.Join("/usr/local/bin"), binaryName)
	default:
		return "", fmt.Errorf("unsupported operating system to install binary: %s/%s. Please open PR or let me know to fix it", HostOS.OS, HostOS.Arch)
	}

	info, err := os.Stat(extractedBinaryPath)
	if err != nil {
		return "", fmt.Errorf("error stating extracted binary path %s: %v", extractedBinaryPath, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("extracted binary path %s is a directory", extractedBinaryPath)
	}

	// Copy to destination path.
	if err := copyBinary(extractedBinaryPath, destPath, info.Mode()); err != nil {
		fmt.Println("Error copying binary to PATH. Maybe you need sudo?:", err)
		return "", fmt.Errorf("error copying binary to PATH: %v", err)
	}

	// Make the binary executable (only needed for Unix-like systems)
	if HostOS.OS == "darwin" || HostOS.OS == "linux" {
		// #nosec G703 -- destPath is constrained to a trusted install directory and expected binary name.
		if err := os.Chmod(destPath, 0755); err != nil {
			fmt.Println("Error setting executable permissions:", err)
			return "", fmt.Errorf("error setting executable permissions: %v", err)
		}
	}

	return destPath, nil
}

// DownloadFromGithubAndInstall downloads and installs a tool from GitHub
func DownloadFromGithubAndInstall(tool string) (string, error) {
	tempDirPath, toolFullPath, err := FetchAndDownloadLatestVersionFromGitHub(tool)
	if err != nil {
		output.PrintCustomBiColourMsg("red", "cyan", "[-]", fmt.Sprintf("%s not found. Please install %s manually: %v", tool, tool, err))
		return "", fmt.Errorf("error downloading tool from github")
	}

	output.PrintCustomBiColourMsg("green", "cyan", "[+] Successfully downloaded ", tool, " to ", toolFullPath)

	// Unzip the file
	_, err = Unzip(toolFullPath, tempDirPath)
	if err != nil {
		fmt.Println("Error unzipping file:", err)
		return "", fmt.Errorf("error unzipping tool: %v", err)
	}

	extractedBinaryPath, err := findExtractedBinary(tool, tempDirPath)
	if err != nil {
		return "", fmt.Errorf("error locating extracted binary for %s: %v", tool, err)
	}

	output.PrintCustomBiColourMsg("green", "cyan", "[+] Successfully unzipped ", tool, " to ", extractedBinaryPath)

	// Install it
	binaryPath, err := InstallBinary(tool, extractedBinaryPath)
	if err != nil {
		return "", fmt.Errorf("error installing %s: %v", tool, err)
	}

	output.PrintCustomBiColourMsg("green", "cyan", "[+] Successfully installed ", tool, " in path directory: ", binaryPath)

	return binaryPath, nil
}

func expectedBinaryName(tool string) (string, error) {
	switch tool {
	case "cloudfox":
		if HostOS.OS == "windows" {
			return "cloudfox.exe", nil
		}
		return "cloudfox", nil
	default:
		return "", fmt.Errorf("unsupported tool to install binary for: %s", tool)
	}
}

func findExtractedBinary(tool, extractedRoot string) (string, error) {
	binaryName, err := expectedBinaryName(tool)
	if err != nil {
		return "", err
	}

	root := filepath.Clean(extractedRoot)
	var binaryPath string

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(path) == binaryName && binaryPath == "" {
			binaryPath = path
		}
		return nil
	})
	if walkErr != nil {
		return "", fmt.Errorf("error walking extracted directory: %v", walkErr)
	}
	if binaryPath == "" {
		return "", fmt.Errorf("binary %s not found under %s", binaryName, extractedRoot)
	}

	return binaryPath, nil
}

func copyBinary(sourcePath, destPath string, mode os.FileMode) error {
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("error opening source binary %s: %v", sourcePath, err)
	}
	defer func(sourceFile *os.File) {
		_ = sourceFile.Close()
	}(sourceFile)

	// #nosec G703 -- destPath is constrained to a trusted install directory and expected binary name.
	destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
	if err != nil {
		return fmt.Errorf("error opening destination binary %s: %v", destPath, err)
	}
	defer func(destFile *os.File) {
		_ = destFile.Close()
	}(destFile)

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("error copying binary data: %v", err)
	}

	if err := destFile.Sync(); err != nil {
		return fmt.Errorf("error syncing destination binary: %v", err)
	}

	return nil
}
