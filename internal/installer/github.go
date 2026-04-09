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

// Host holds the OS and architecture of the host
type Host struct {
	OS   string
	Arch string
}

// HostOS identifies the current host platform
var HostOS = Host{
	OS:   runtime.GOOS,
	Arch: runtime.GOARCH,
}

// cloudfoxAssets maps a "os-arch" key to the expected cloudfox release asset filename.
var cloudfoxAssets = map[string]string{
	"linux-amd64":   "cloudfox-linux-amd64.zip",
	"linux-386":     "cloudfox-linux-386.zip",
	"darwin-amd64":  "cloudfox-macos-amd64.zip",
	"darwin-arm64":  "cloudfox-macos-arm64.zip",
	"windows-amd64": "cloudfox-windows-amd64.zip",
}


// GetDownloadURL returns the download URL for the tool matching the host platform.
func GetDownloadURL(tool string, latest Release) (string, error) {
	platformKey := fmt.Sprintf("%s-%s", HostOS.OS, HostOS.Arch)
	switch tool {
	case "cloudfox":
		expectedAsset, exists := cloudfoxAssets[platformKey]
		if !exists {
			return "", fmt.Errorf("unsupported platform: %s", platformKey)
		}
		for _, asset := range latest.Assets {
			if asset.Name == expectedAsset {
				return asset.BrowserDownloadURL, nil
			}
		}
	}

	output.PrintCustomBiColourMsg("magenta", "yellow", "[?] Debug -> No suitable asset found. Host OS: ", HostOS.OS, " | Host Arch: ", HostOS.Arch, " | Assets: ", fmt.Sprintf("%v", latest.Assets))
	return "", fmt.Errorf("no suitable asset found")
}

// downloadToFile is the shared implementation for downloading a URL to a local file.
func downloadToFile(url, path string) error {
	resp, err := http.Get(url) //nolint:gosec // callers are responsible for trusted URLs
	if err != nil {
		return fmt.Errorf("error downloading %s: %w", url, err)
	}
	defer resp.Body.Close()

	out, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating file %s: %w", path, err)
	}
	defer func() {
		if closeErr := out.Close(); closeErr != nil {
			output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("error closing file %s: %v", path, closeErr))
		}
	}()

	if _, err = io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("error writing to file %s: %w", path, err)
	}
	return nil
}

// DownloadFileFromURL downloads a file from url to the specified filepath.
func DownloadFileFromURL(url string, filepath string) error {
	return downloadToFile(url, filepath)
}

// DownloadFromGithub downloads a file from GitHub to toolFullPath.
func DownloadFromGithub(toolFullPath, downloadURL string) error {
	return downloadToFile(downloadURL, toolFullPath)
}

// FetchAndDownloadLatestVersionFromGitHub fetches the latest release from GitHub and downloads the tool.
func FetchAndDownloadLatestVersionFromGitHub(tool string) (string, string, error) {
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

	assetResp, err := http.Get(fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)) //nolint:gosec // URL is constructed from a hardcoded trusted constant
	if err != nil {
		return "", "", fmt.Errorf("error while fetching latest release: %v", err)
	}
	defer assetResp.Body.Close()

	var latestReleaseData Release
	if err := json.NewDecoder(assetResp.Body).Decode(&latestReleaseData); err != nil {
		return "", "", fmt.Errorf("error decoding latest release data: %v", err)
	}

	downloadURL, err := GetDownloadURL(tool, latestReleaseData)
	if err != nil {
		return "", "", fmt.Errorf("error getting download URL: %v", err)
	}

	output.PrintCustomBiColourMsg("yellow", "cyan", "[!] Suitable URL found for '", tool, "' for OS ", HostOS.OS, " and arch ", HostOS.Arch, ": ", downloadURL)

	if err = DownloadFromGithub(toolFullPath, downloadURL); err != nil {
		return "", "", err
	}

	return toolTmpDir, toolFullPath, nil
}

// extractZipEntry extracts a single zip entry into dest, handling both directories and files.
func extractZipEntry(f *zip.File, dest string) error {
	fpath := filepath.Join(dest, f.Name)
	if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
		return fmt.Errorf("illegal file path: %s", fpath)
	}

	if f.FileInfo().IsDir() {
		_, err := files.CustomMkdir(fpath)
		return err
	}

	if _, err := files.CustomMkdir(filepath.Dir(fpath)); err != nil {
		return err
	}

	outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
	if err != nil {
		return err
	}
	defer outFile.Close()

	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	_, err = io.Copy(outFile, rc)
	return err
}

// Unzip extracts all files from src into dest and returns the path of the last extracted entry.
func Unzip(src, dest string) (string, error) {
	r, err := zip.OpenReader(src)
	if err != nil {
		return "", err
	}
	defer r.Close()

	var fpath string
	for _, f := range r.File {
		fpath = filepath.Join(dest, f.Name)
		if err := extractZipEntry(f, dest); err != nil {
			return "", err
		}
	}
	return fpath, nil
}

// InstallBinary installs a binary to the system PATH.
func InstallBinary(tool, extractedBinaryPath string) (string, error) {
	binaryName, err := expectedBinaryName(tool)
	if err != nil {
		return "", err
	}

	var destPath string
	var needsChmod bool
	switch HostOS.OS {
	case "windows":
		destPath = filepath.Join(os.Getenv("ProgramFiles"), binaryName)
	case "darwin", "linux":
		destPath = filepath.Join("/usr/local/bin", binaryName)
		needsChmod = true
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

	if err := copyBinary(extractedBinaryPath, destPath, info.Mode()); err != nil {
		return "", fmt.Errorf("error copying binary to PATH (maybe you need sudo?): %v", err)
	}

	if needsChmod {
		// #nosec G703 -- destPath is constrained to a trusted install directory and expected binary name.
		if err := os.Chmod(destPath, 0755); err != nil {
			return "", fmt.Errorf("error setting executable permissions: %v", err)
		}
	}

	return destPath, nil
}

// DownloadFromGithubAndInstall downloads and installs a tool from GitHub.
func DownloadFromGithubAndInstall(tool string) (string, error) {
	tempDirPath, toolFullPath, err := FetchAndDownloadLatestVersionFromGitHub(tool)
	if err != nil {
		output.PrintCustomBiColourMsg("red", "cyan", "[-]", fmt.Sprintf("%s not found. Please install %s manually: %v", tool, tool, err))
		return "", fmt.Errorf("error downloading tool from github")
	}

	output.PrintCustomBiColourMsg("green", "cyan", "[+] Successfully downloaded ", tool, " to ", toolFullPath)

	if _, err = Unzip(toolFullPath, tempDirPath); err != nil {
		return "", fmt.Errorf("error unzipping tool: %v", err)
	}

	extractedBinaryPath, err := findExtractedBinary(tool, tempDirPath)
	if err != nil {
		return "", fmt.Errorf("error locating extracted binary for %s: %v", tool, err)
	}

	output.PrintCustomBiColourMsg("green", "cyan", "[+] Successfully unzipped ", tool, " to ", extractedBinaryPath)

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
		if filepath.Base(path) == binaryName {
			binaryPath = path
			return fs.SkipAll
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
	defer sourceFile.Close()

	// #nosec G703 -- destPath is constrained to a trusted install directory and expected binary name.
	destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode.Perm())
	if err != nil {
		return fmt.Errorf("error opening destination binary %s: %v", destPath, err)
	}
	defer destFile.Close()

	if _, err := io.Copy(destFile, sourceFile); err != nil {
		return fmt.Errorf("error copying binary data: %v", err)
	}

	if err := destFile.Sync(); err != nil {
		return fmt.Errorf("error syncing destination binary: %v", err)
	}

	return nil
}

// downloadIAMDatasetRoles fetches GCP IAM role definitions from the iam-dataset
// GitHub repository and writes each JSON file into destDir.
func downloadIAMDatasetRoles(destDir string) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("create roles dir: %w", err)
	}

	const apiURL = "https://api.github.com/repos/iann0036/iam-dataset/contents/gcp/roles/"
	resp, err := http.Get(apiURL) //nolint:gosec // URL is a hardcoded trusted constant
	if err != nil {
		return fmt.Errorf("fetch iam-dataset listing: %w", err)
	}
	defer resp.Body.Close()

	var entries []struct {
		Name        string `json:"name"`
		DownloadURL string `json:"download_url"`
		Type        string `json:"type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return fmt.Errorf("decode iam-dataset listing: %w", err)
	}

	for _, entry := range entries {
		if entry.Type != "file" || !strings.HasSuffix(entry.Name, ".json") {
			continue
		}
		fileResp, err := http.Get(entry.DownloadURL) //nolint:gosec // URL comes from GitHub API response for a trusted repo
		if err != nil {
			return fmt.Errorf("download %s: %w", entry.Name, err)
		}
		data, readErr := io.ReadAll(fileResp.Body)
		fileResp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("read %s: %w", entry.Name, readErr)
		}
		if err := os.WriteFile(filepath.Join(destDir, entry.Name), data, 0644); err != nil { //nolint:gosec // destDir is a trusted constant path
			return fmt.Errorf("write %s: %w", entry.Name, err)
		}
	}
	return nil
}
