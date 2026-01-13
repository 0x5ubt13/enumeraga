package common

import (
	"fmt"
	"strconv"

	"github.com/0x5ubt13/enumeraga/internal/checks"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// GetTimeoutSeconds returns the configured timeout in seconds as a string.
// Uses ToolTimeout (in minutes) from utils package.
func GetTimeoutSeconds() string {
	return strconv.Itoa(utils.ToolTimeout * 60)
}

// BuildOutputPath constructs a standardized output file path for a tool.
func BuildOutputPath(dir, toolName string) string {
	return fmt.Sprintf("%s%s.out", dir, toolName)
}

// RunHydraBrute runs hydra brute force attack for a given service if brute mode is enabled.
func RunHydraBrute(service, dir string) {
	if !*checks.OptBrute {
		return
	}
	hydraArgs := []string{
		"hydra",
		"-L", utils.UsersList,
		"-P", utils.DarkwebTop1000,
		"-f",
		"-t", "4",
		"-W", "30",
		fmt.Sprintf("%s://%s", service, utils.Target),
	}
	hydraPath := BuildOutputPath(dir, "hydra_"+service)
	commands.CallRunTool(hydraArgs, hydraPath, checks.OptVVerbose)
}
