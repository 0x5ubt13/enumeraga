package utils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	// Import the new packages for backward compatibility
	"github.com/0x5ubt13/enumeraga/internal/installer"
	utilscontext "github.com/0x5ubt13/enumeraga/internal/utils/context"
	"github.com/0x5ubt13/enumeraga/internal/utils/files"
	"github.com/0x5ubt13/enumeraga/internal/utils/network"
	"github.com/0x5ubt13/enumeraga/internal/utils/output"
	"github.com/0x5ubt13/enumeraga/internal/utils/state"
	"github.com/0x5ubt13/enumeraga/internal/utils/wordlists"
	"github.com/Ullaakut/nmap/v3"
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

	// Re-export color functions for backward compatibility
	Yellow = output.Yellow
	Red    = output.Red
	Green  = output.Green
	Cyan   = output.Cyan
	Debug  = output.Debug

	// Re-export wordlist paths for backward compatibility
	DarkwebTop1000 string
	ExtensionsList string
	UsersList      string
	SnmpList       string
	DirListMedium  string

	// TimesSwept keeps track of how many ports have been tried to be swept for a host
	TimesSwept int

	// ToolTimeout is the maximum time in minutes for long-running tools (nikto, dirsearch, etc).
	// Default: 10 minutes. Can be set via CLI flag -T/--timeout
	ToolTimeout = 10

	// GentleMode enables a throttled scan profile for infra scanning.
	GentleMode bool

	// Interrupted global, to show user different info if single IP target was unsuccessful
	Interrupted bool

	// Wg sync: Define a WaitGroup to generate goroutines
	Wg sync.WaitGroup

	// ToolRegistry tracks all enumeration tools and their progress
	ToolRegistry *ToolTracker

	BaseDir   string
	Target    string
	Version   string // Semantic version (e.g., "v0.2.1-beta")
	GitCommit string // Git commit hash
	BuildDate string // Build timestamp
)

const (
	// GentleMaxWorkers limits concurrent tools when gentle mode is enabled.
	GentleMaxWorkers = 2
	// GentleToolStartDelay adds spacing between tool starts in gentle mode.
	GentleToolStartDelay = 750 * time.Millisecond
)

func init() {
	ToolRegistry = NewToolTracker()
	// Set default version if not set by build flags
	if Version == "" {
		Version = "dev"
	}
	if GitCommit == "" {
		GitCommit = "unknown"
	}
	if BuildDate == "" {
		BuildDate = "unknown"
	}
}

// SetGentleMode enables or disables gentle scan behaviour.
func SetGentleMode(enabled bool) {
	GentleMode = enabled
}

// MaxWorkersForMode returns a max worker count honoring gentle mode.
// Returning 0 keeps the default worker pool size.
func MaxWorkersForMode() int {
	if GentleMode {
		return GentleMaxWorkers
	}
	return 0
}

// ToolStartDelay returns the configured delay between tool starts.
func ToolStartDelay() time.Duration {
	if GentleMode {
		return GentleToolStartDelay
	}
	return 0
}

// GetVersion returns the full version string
func GetVersion() string {
	if Version == "dev" {
		return "enumeraga development build"
	}
	commitShort := GitCommit
	if len(commitShort) > 7 {
		commitShort = commitShort[:7]
	}
	return fmt.Sprintf("enumeraga %s (commit: %s, built: %s)", Version, commitShort, BuildDate)
}

// ===============================================
// BACKWARD COMPATIBILITY ALIASES
// These functions delegate to the new packages
// ===============================================

// PrintBanner displays the enumeraga ASCII art banner with version information.
func PrintBanner() {
	output.PrintBanner(Version)
}

// PrintCustomBiColourMsg is a backward compatibility alias
func PrintCustomBiColourMsg(dominantColour, secondaryColour string, text ...string) {
	output.PrintCustomBiColourMsg(dominantColour, secondaryColour, text...)
}

// PrintInfraUsageExamples is a backward compatibility alias
func PrintInfraUsageExamples() {
	output.PrintInfraUsageExamples()
}

// PrintCloudUsageExamples is a backward compatibility alias
func PrintCloudUsageExamples() {
	output.PrintCloudUsageExamples()
}

// Network validation aliases
func ValidateIP(ip string) error {
	return network.ValidateIP(ip)
}

func ResolveHostToIP(host string) (string, error) {
	return network.ResolveHostToIP(host)
}

func ValidateCIDR(cidr string) error {
	return network.ValidateCIDR(cidr)
}

func ValidatePort(port string) error {
	return network.ValidatePort(port)
}

func ValidatePorts(ports string) error {
	return network.ValidatePorts(ports)
}

func ValidateFilePath(path string) error {
	return network.ValidateFilePath(path)
}

// State management aliases
func IsVisited(protocol string) bool {
	return state.IsVisited(protocol)
}

func ResetVisitedFlags() {
	state.ResetVisitedFlags()
}

// File operations aliases
func ReadTargetsFile(optTarget *string) ([]string, int) {
	return files.ReadTargetsFile(optTarget)
}

func CustomMkdir(name string) (string, error) {
	return files.CustomMkdir(name)
}

func ProtocolDetected(protocol, baseDir string) string {
	return files.ProtocolDetected(protocol, baseDir)
}

func WriteTextToFile(filePath string, message string) error {
	return files.WriteTextToFile(filePath, message)
}

func WritePortsToFile(filePath string, ports string, host string) (string, error) {
	return files.WritePortsToFile(filePath, ports, host)
}

func RemoveDuplicates(s string) string {
	return files.RemoveDuplicates(s)
}

func GetOpenPortsSlice(sweptHostTcp, sweptHostUdp []nmap.Host) []string {
	return files.GetOpenPortsSlice(sweptHostTcp, sweptHostUdp)
}

// Wordlist management aliases
func GetWordlists(optVVerbose *bool) error {
	err := wordlists.GetWordlists(optVVerbose)
	// Update global variables for backward compatibility
	DarkwebTop1000 = wordlists.DarkwebTop1000
	ExtensionsList = wordlists.ExtensionsList
	UsersList = wordlists.UsersList
	SnmpList = wordlists.SnmpList
	DirListMedium = wordlists.DirListMedium
	return err
}

// Context management aliases
func InitGlobalContext() context.Context {
	return utilscontext.InitGlobalContext()
}

func GetGlobalContext() context.Context {
	return utilscontext.GetGlobalContext()
}

func IsShuttingDown() bool {
	return utilscontext.IsShuttingDown()
}

func CancelGlobalContext() {
	utilscontext.CancelGlobalContext()
}

// Worker pool aliases
func InitWorkerPool(maxWorkers int) {
	utilscontext.InitWorkerPool(maxWorkers)
}

func GetWorkerPool() *utilscontext.WorkerPool {
	return utilscontext.GetWorkerPool()
}

// Installer aliases
func Consent(tool string) rune {
	return installer.Consent(tool)
}

func OSCPConsent(tool string) rune {
	return installer.OSCPConsent(tool)
}

func CheckToolExists(tool string) bool {
	return installer.CheckToolExists(tool)
}

func InstallMissingTools(kind rune, optInstall *bool) {
	installer.InstallMissingTools(kind, optInstall)
}

func AptGetUpdateCmd() {
	installer.AptGetUpdateCmd()
}

func AptGetInstallCmd(tool string) {
	installer.AptGetInstallCmd(tool)
}

func DownloadFromGithubAndInstall(tool string) (string, error) {
	return installer.DownloadFromGithubAndInstall(tool)
}

func InstallConda() error {
	return installer.InstallConda()
}

// Re-export Updated flag for backward compatibility
var Updated bool

func SetUpdated(value bool) {
	Updated = value
	installer.Updated = value
}

// ===============================================
// CORE FUNCTIONALITY (Kept in utils.go)
// ===============================================

// FinishLine finishes the main flow with time tracker and prints nice messages to the terminal
func FinishLine(start time.Time, interrupted bool) {
	elapsed := time.Since(start)
	var outputStr string

	if elapsed.Seconds() < 1 {
		// Convert duration to float of Milliseconds
		ms := float64(elapsed.Nanoseconds()) / 1e6
		outputStr = fmt.Sprintf("%.2fms", ms)
	} else {
		// Convert duration to float of Seconds
		s := elapsed.Seconds()
		outputStr = fmt.Sprintf("%.2fs", s)
	}

	if interrupted {
		PrintCustomBiColourMsg("cyan", "green", "\n[*] Done! It only took '", outputStr, "' to run ", "Enumeraga", "'s core functionality, although an error was detected.\n\tPlease check your arguments, program's output or connectivity and try again.\n")
		return
	}

	PrintCustomBiColourMsg("cyan", "green", "\n[*] Done! It only took '", outputStr, "' to run ", "Enumeraga ", "based on your settings!! Please allow your tools some time to finish.")
	fmt.Printf("%s%s%s\n\n", Cyan("[*] ---------- "), Green("Enumeration phase complete"), Cyan(" ----------"))
	fmt.Printf("%s%s%s\n", Cyan("[*] ---------- "), Green("Program complete. Awaiting tools to finish"), Cyan(" ----------"))
}

// CheckAdminPrivileges checks for appropriate permissions based on scanning mode
func CheckAdminPrivileges(cloudOrInfra string) {
	switch cloudOrInfra {
	case "cloud":
		switch HostOS.OS {
		case "windows":
			// Check for administrative privileges on Windows
			cmd := exec.Command("powershell", "-Command", "[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)")
			outputBytes, err := cmd.Output()
			if err != nil || string(outputBytes) != "True\n" {
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

// ErrorMsg is maintained for backward compatibility - delegates to logger
func ErrorMsg(errMsg any) {
	GetLogger().Error("%v", errMsg)
}

// PrintSafe is maintained for backward compatibility - delegates to logger
func PrintSafe(format string, args ...any) {
	GetLogger().Printf(format, args...)
}

// ===============================================
//  Deprecated global variables for compatibility
// ===============================================

// Deprecated: Use state.IsVisited() instead
var (
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
