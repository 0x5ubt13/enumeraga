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
	//TODO: change to goroutine????
	runTool("scoutsuite", provider, fmt.Sprintf("%sscoutsuite/", providerDir))
	runTool("prowler", provider, fmt.Sprintf("%sprowler/", providerDir))
	runTool("cloudfox", provider, fmt.Sprintf("%scloud_fox/", providerDir))
	// commands.Pmapper()
	// commands.Steampipe()
	// commands.Powerpipe()
	// if GCP:
	// commands.GCPwn()
	// if AWS:
	// commands.Pacu()???

	os.Exit(0)
}

func runTool(tool, provider, path string) {
	err := commands.RunToolInVirtualEnv([]string{tool, path}, provider)
	if err != nil {
		utils.ErrorMsg(err)
	}
}
