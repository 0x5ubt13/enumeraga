package cloudScanner

import (
	"fmt"

	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/config"
	"github.com/0x5ubt13/enumeraga/internal/progress"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

func Run(cfg *config.CloudConfig, OptVVerbose *bool) {
	providerDir := fmt.Sprintf("%s/%s/", utils.BaseDir, cfg.Provider)
	_, err := utils.CustomMkdir(providerDir)
	if err != nil {
		utils.ErrorMsg(err)
	}
	fmt.Println(utils.Debug("[?] Debug -> providerDir = ", providerDir))

	// Auto-detect the GCP project ID once so every tool that needs it can use it.
	if cfg.Provider == "gcp" && cfg.GCPProject == "" {
		if project, err := commands.ResolveGCPProject(cfg); err == nil && project != "" {
			cfg.GCPProject = project
			utils.PrintCustomBiColourMsg("green", "cyan", "[+] Auto-detected GCP project: ", project)
		} else if err != nil {
			utils.ErrorMsg(fmt.Errorf("could not auto-detect GCP project: %w; tools requiring --project may be skipped", err))
		}
	}

	// Register every tool up front so the total is known before the first one
	// starts, then launch them sequentially to avoid rate limiting from cloud
	// providers.
	names := providerTools(cfg.Provider)
	keys := make([]string, len(names))
	for i, name := range names {
		keys[i] = utils.ToolRegistry.RegisterTool(name)
	}
	progress.Active.DiscoveryDone()

	for i, name := range names {
		utils.ToolRegistry.StartTool(keys[i])
		err := runTool(name, cfg, fmt.Sprintf("%s%s/", providerDir, toolDir(name)), OptVVerbose)
		utils.ToolRegistry.CompleteTool(keys[i], err == nil)
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

	// State plainly what was and was not covered. A scan that produced results
	// from some tools and lost others is a partial scan, and presenting it as a
	// clean one is what lets a silent gap reach a report.
	commands.PrintCloudCoverageSummary()
}

// providerTools returns the tools to run for a provider, in run order.
// Add more tools here, then complete the switch case in commands.PrepCloudTool().
// Order matters: provider-specific inventory tools run first so later tools (e.g. cloudfox)
// can rely on project/account context already being established.
func providerTools(provider string) []string {
	switch provider {
	case "gcp":
		return []string{
			// 1. Raw inventory first -- answers "what can these creds access?" before deeper scans
			"gcp_scanner", "gcp_iam_brute",
			// 2. Compliance and misconfiguration checks
			"scoutsuite", "prowler",
			// 3. Deeper enumeration once project context is known
			"cloudfox", "nuclei",
		}
	case "k8s":
		return []string{"kubenumerate"}
	case "azure":
		return []string{
			// 1. monkey365 first -- broad Azure + M365 inventory (IAM, Entra ID, subscriptions)
			//    before deeper compliance tools run so project/subscription context is clear.
			"monkey365",
			// 2. Compliance and misconfiguration checks
			"scoutsuite", "prowler",
			// 3. Deeper enumeration
			"cloudfox", "nuclei",
		}
	case "aws":
		return []string{
			// 1. Broad service enumeration first -- discovers what services/resources exist
			"aws_enumerator",
			// 2. Compliance and misconfiguration checks
			"scoutsuite", "prowler",
			// 3. Deeper enumeration
			// Run pmapper before cloudfox so cloudfox can leverage pmapper's graph data for more efficient enumeration and attack path analysis.
			"pmapper", "cloudfox",
		}
	default:
		// AWS-compatible and other providers
		return []string{"aws_enumerator", "scoutsuite", "prowler", "cloudfox", "nuclei"}
	}
}

// toolDir is the output subdirectory for a tool; it matches the tool name
// except for cloudfox.
func toolDir(tool string) string {
	if tool == "cloudfox" {
		return "cloud_fox"
	}
	return tool
}

// runTool runs the specified tool and returns the error from preparing it.
func runTool(tool string, cfg *config.CloudConfig, path string, OptVVerbose *bool) error {
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
	return toolErr
}
