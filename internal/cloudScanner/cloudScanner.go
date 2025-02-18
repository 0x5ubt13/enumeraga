package cloudScanner

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"os"
)

func Run(provider string) {
	providerDir := fmt.Sprintf("%s/%s/", utils.BaseDir, provider)
	_, err := utils.CustomMkdir(providerDir)
	if err != nil {
		utils.ErrorMsg(err)
	}
	fmt.Println(utils.Cyan("[*] Debug -> providerDir = ", providerDir))

	// Launch scoutsuite's function inside commands.
	//TODO: change to goroutine
	commands.Scoutsuite(provider, fmt.Sprintf("%sscoutsuite/", providerDir))
	//commands.Prowler(provider, fmt.Sprintf("%sprowler/", providerDir))
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

// Create new parser?
