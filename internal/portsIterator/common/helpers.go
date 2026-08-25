package common

import (
	"fmt"
	"strconv"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
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

// RunHydraBrute runs a hydra brute force attack against a service if brute mode
// is enabled.
//
// Every service enumeraga hands to hydra is brute-forced over TCP, so port is
// checked against the TCP side of the caller's --ports list rather than the UDP
// side. Without that check a handler reached from a UDP-only discovery — rdp and
// mysql both have UDP transports — would brute-force a TCP port nobody authorised.
//
// The port is also passed to hydra explicitly instead of letting it fall back to
// the service's default. That keeps the attempt on the port that was actually
// authorised: the FTP handler, for instance, is dispatched for both 20 and 21, and
// hydra's own default of 21 would be out of scope for a caller who named only 20.
func RunHydraBrute(service, port, dir string) {
	if !*checks.OptBrute {
		return
	}
	if !bounds.Active.PortInScope(port, false) {
		return
	}
	hydraArgs := []string{
		"hydra",
		"-L", utils.UsersList,
		"-P", utils.DarkwebTop1000,
		"-f",
		"-t", "4",
		"-W", "30",
		fmt.Sprintf("%s://%s:%s", service, utils.Target, port),
	}
	hydraPath := BuildOutputPath(dir, "hydra_"+service)
	commands.CallRunTool(hydraArgs, hydraPath, checks.OptVVerbose)
}
