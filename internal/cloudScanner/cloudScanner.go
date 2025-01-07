package cloudScanner

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"os"
)

func Run() {
	provider := cloudChecks()
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

// cloudChecks works the same than internal/checks but for Cloud enumeration instead
func cloudChecks() string {
	// Cloud check #1: key tools exist in the system
	if !*utils.OptQuiet {
		fmt.Println(utils.Cyan("[*] Checking all tools are installed... "))
	}
	utils.InstallMissingTools('c')

	/* Tools to add:
	- Scoutsuite (https://github.com/nccgroup/scoutsuite)
	- Prowler (https://github.com/prowler-cloud/prowler)
	- CloudFox (https://github.com/BishopFox/cloudfox)
		Note: it'd be good if pmapper was installed alongside cloudfox, with their integration it could also have it generate the default privesc query and images as output
	- Pmapper (https://github.com/nccgroup/PMapper)
	- Steampipe (https://github.com/turbot/steampipe)
	- Powerpipe (https://github.com/turbot/powerpipe)
	- GCPwn (https://github.com/NetSPI/gcpwn)
	- Pacu??
	*/

	// Cloud check #2: args passed
	provider := parseCSP()

	// Cloud check #3: Ensure base output directory is correctly set and exists
	utils.CustomMkdir(*utils.OptOutput)
	if !*utils.OptQuiet {
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Using '", *utils.OptOutput, "' as base directory to save the ", "output ", "files")
	}

	return provider
}

func parseCSP() string {
	providers := []string{"aws", "azure", "gcp", "oci", "aliyun", "digitalocean (do)"}
	var provider string

	switch os.Args[2] {
	case "aws", "amazon":
		provider = "aws"
	case "az", "azure":
		provider = "azure"
	case "gcp", "gcloud", "g":
		provider = "gcp"
	case "ay", "ali", "aliy", "aliyun", "alibaba":
		provider = "aliyun"
	case "oci", "oracle":
		provider = "oci"
	case "do", "digital", "digitalocean":
		provider = "do"
	default:
		utils.ErrorMsg(fmt.Sprintf("%s not detected as a suitable cloud service provider. Please try again by using one of these: %v.", provider, providers))
		os.Exit(1)
	}

	utils.PrintCustomBiColourMsg("green", "yellow", "[+] Using '", provider, "' as provider to launch scans")
	return provider
}
