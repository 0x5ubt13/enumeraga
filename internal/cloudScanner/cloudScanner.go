package cloudScanner

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/config"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

func Run(cfg *config.CloudConfig, OptVVerbose *bool) {
	providerDir := fmt.Sprintf("%s/%s/", utils.BaseDir, cfg.Provider)
	_, err := utils.CustomMkdir(providerDir)
	if err != nil {
		utils.ErrorMsg(err)
	}
	fmt.Println(utils.Debug("[?] Debug -> providerDir = ", providerDir))

	// Launch cloud scanning tools sequentially to avoid rate limiting from cloud providers.
	// Add more tools here, then complete the switch case in commands.PrepCloudTool().
	// Order matters: provider-specific inventory tools run first so later tools (e.g. cloudfox)
	// can rely on project/account context already being established.
	switch cfg.Provider {
	case "gcp":
		// 1. Raw inventory first — answers "what can these creds access?" before deeper scans
		runTool("gcp_scanner", cfg, fmt.Sprintf("%sgcp_scanner/", providerDir), OptVVerbose)
		// 2. Compliance and misconfiguration checks
		runTool("scoutsuite", cfg, fmt.Sprintf("%sscoutsuite/", providerDir), OptVVerbose)
		runTool("prowler", cfg, fmt.Sprintf("%sprowler/", providerDir), OptVVerbose)
		// 3. Deeper enumeration once project context is known
		runTool("cloudfox", cfg, fmt.Sprintf("%scloud_fox/", providerDir), OptVVerbose)
	case "k8s":
		runTool("kubenumerate", cfg, fmt.Sprintf("%skubenumerate/", providerDir), OptVVerbose)
	case "azure":
		// 1. monkey365 first — broad Azure + M365 inventory (IAM, Entra ID, subscriptions)
		//    before deeper compliance tools run so project/subscription context is clear.
		runTool("monkey365", cfg, fmt.Sprintf("%smonkey365/", providerDir), OptVVerbose)
		// 2. Compliance and misconfiguration checks
		runTool("scoutsuite", cfg, fmt.Sprintf("%sscoutsuite/", providerDir), OptVVerbose)
		runTool("prowler", cfg, fmt.Sprintf("%sprowler/", providerDir), OptVVerbose)
		// 3. Deeper enumeration
		runTool("cloudfox", cfg, fmt.Sprintf("%scloud_fox/", providerDir), OptVVerbose)
	default:
		// AWS and other providers
		runTool("scoutsuite", cfg, fmt.Sprintf("%sscoutsuite/", providerDir), OptVVerbose)
		runTool("prowler", cfg, fmt.Sprintf("%sprowler/", providerDir), OptVVerbose)
		runTool("cloudfox", cfg, fmt.Sprintf("%scloud_fox/", providerDir), OptVVerbose)
	}
	// runTool("cloudsplaining", cfg, fmt.Sprintf("%scloud_peass/", providerDir), OptVVerbose) // https://github.com/salesforce/cloudsplaining

	// Tried AWSPeass.py and while it's great, I need to figure out how to run it programatically as it prompts for input from time to time
	// runTool("cloudpeass", cfg, fmt.Sprintf("%scloud_peass/", providerDir), OptVVerbose)

	// commands.Steampipe()

	// commands.Powerpipe()
	// if GCP:
	// commands.GCPwn()
	// if AWS:
	// commands.Pacu()???

	// Leaving pmapper out for now as I can't manage to make conda work inside a container and pmapper needs python 3.8
	// runTool("pmapper", cfg, fmt.Sprintf("%spmapper/", providerDir), OptVVerbose)
}

// runTool runs the specified tool
func runTool(tool string, cfg *config.CloudConfig, path string, OptVVerbose *bool) {
	// Ensure path exists before continuing
	_, err := utils.CustomMkdir(path)
	if err != nil {
		utils.ErrorMsg(err)
	}

	// Change to internal/commands
	toolErr := commands.PrepCloudTool(tool, path, cfg, OptVVerbose)
	if toolErr != nil {
		utils.ErrorMsg(toolErr)
	}
}
