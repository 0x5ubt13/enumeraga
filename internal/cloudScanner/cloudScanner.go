package cloudScanner

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"os"
)

func Run(provider string) {
	providerDir := fmt.Sprintf("%s_%s/", utils.BaseDir, provider)

	commands.Scoutsuite(provider, fmt.Sprintf("%s_scout/", providerDir))
	commands.Prowler(provider, fmt.Sprintf("%s_prowler/", providerDir))
	//commands.CloudFox()
	// commands.Pmapper()
	// commands.Steampipe()
	// commands.Powerpipe()
	// if GCP:
	// commands.GCPwn()
	// if AWS:
	// commands.Pacu()???

	os.Exit(0)
}
