package cloudScanner

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"os"
)

func Run(provider string, OptVVerbose *bool) {
	providerDir := fmt.Sprintf("%s/%s/", utils.BaseDir, provider)
	_, err := utils.CustomMkdir(providerDir)
	if err != nil {
		utils.ErrorMsg(err)
	}
	fmt.Println(utils.Cyan("[*] Debug -> providerDir = ", providerDir))

	// Launch scoutsuite's function inside commands.
	//TODO: think: change to goroutine??? Probs too much smashing the cloud provider??
	runTool("scoutsuite", provider, fmt.Sprintf("%sscoutsuite/", providerDir), OptVVerbose)
	runTool("prowler", provider, fmt.Sprintf("%sprowler/", providerDir), OptVVerbose)
	runTool("cloudfox", provider, fmt.Sprintf("%scloud_fox/", providerDir), OptVVerbose)
	// commands.Pmapper()
	// commands.Steampipe()
	// commands.Powerpipe()
	// if GCP:
	// commands.GCPwn()
	// if AWS:
	// commands.Pacu()???

	os.Exit(0)
}

// runTool runs the specified tool
func runTool(tool, provider, path string, OptVVerbose *bool) {
	// Ensure path exists before continuing
	_, err := utils.CustomMkdir(path)
	if err != nil {
		utils.ErrorMsg(err)
	}
	
	// Change to internal/commands
	toolErr := commands.PrepCloudTool(tool, path, provider, OptVVerbose)
	if toolErr != nil {
		utils.ErrorMsg(toolErr)
	}
}
