package cloudScanner

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/0x5ubt13/enumeraga/internal/config"
	"os"
	"os/exec"
	"encoding/json"
)

func Run(provider string, OptVVerbose *bool) {
	providerDir := fmt.Sprintf("%s/%s/", utils.BaseDir, provider)
	_, err := utils.CustomMkdir(providerDir)
	if err != nil {
		utils.ErrorMsg(err)
	}
	fmt.Println(utils.Debug("[?] Debug -> providerDir = ", providerDir))

	// Create cloud config to use throughout the cloud scanning tools
	cfg := config.CloudConfig{
		// Tool settings
		PMMapperEnabled:   false,
		ScoutSuiteEnabled: true,
		ProwlerEnabled:    true,
		CloudFoxEnabled:   true,

		// Output settings
		OutputPath:   providerDir,
		ReportFormat: "xlsx", // "xlsx", "json", etc.

		// Provider settings
		Provider:          provider,

		// Runtime settings
		Concurrent:     false,
		InstallMissing: false,
		Verbose:        false,
	}

	switch cfg.Provider {
	// case "aws":
		// Placeholder for AWS config 
	case "azure":
		cmd := exec.Command("az", "account", "show", "--output", "json")
		output, err := cmd.Output()
		if err != nil {
			utils.ErrorMsg(fmt.Errorf("failed to get Azure account information: %v", err))
		}

		type AzureSubscription struct {
			ID 			string `json:"id"`
			Name 		string `json:"name"`
			TenantID 	string `json:"tenantId"`
			TenantName 	string `json:"tenantDisplayName"`
		}
		var sub AzureSubscription
		if err := json.Unmarshal(output, &sub); err != nil {
			utils.ErrorMsg(fmt.Errorf("failed to parse Azure account information: %v", err))
		}
		
		cfg.AzureSubscriptionID = sub.ID
		cfg.AzureSubscriptionName = sub.Name
		cfg.AzureTenantID = sub.TenantID
		cfg.AzureTenantName = sub.TenantName
	// case "gcp":
		// Placeholder for GCP

	// default:
	// 	utils.ErrorMsg(fmt.Errorf("unsupported cloud provider: %s", cfg.Provider))
	}

	// Launch scoutsuite's function inside commands.
	//TODO: think: change to goroutine??? Probs too much smashing the cloud provider??
	runTool("scoutsuite", provider, fmt.Sprintf("%sscoutsuite/", providerDir), OptVVerbose, &cfg)
	runTool("prowler", provider, fmt.Sprintf("%sprowler/", providerDir), OptVVerbose, &cfg)
	runTool("cloudfox", provider, fmt.Sprintf("%scloud_fox/", providerDir), OptVVerbose, &cfg)
	// runTool("cloudsplaining, provider, fmt.Sprintf("%scloud_peass/", providerDir), OptVVerbose, &cfg)") // https://github.com/salesforce/cloudsplaining
	
	// Tried AWSPeass.py and while it's great, I need to figure out how to run it programatically as it prompts for input from time to time
	// runTool("cloudpeass, provider, fmt.Sprintf("%scloud_peass/", providerDir), OptVVerbose)")

	// commands.Steampipe()
	
	// commands.Powerpipe()
	// if GCP:
	// commands.GCPwn()
	// if AWS:
	// commands.Pacu()???

	// Leaving pmapper out for now as I can't manage to make conda work inside a container and pmapper needs python 3.8
	// runTool("pmapper", provider, fmt.Sprintf("%spmapper/", providerDir), OptVVerbose)
	
	os.Exit(0)
}

// runTool runs the specified tool
func runTool(tool, provider, path string, OptVVerbose *bool, cfg *config.CloudConfig) {
	// Ensure path exists before continuing
	_, err := utils.CustomMkdir(path)
	if err != nil {
		utils.ErrorMsg(err)
	}

	// Change to internal/commands
	toolErr := commands.PrepCloudTool(tool, path, provider, OptVVerbose, cfg)
	if toolErr != nil {
		utils.ErrorMsg(toolErr)
	}
}
