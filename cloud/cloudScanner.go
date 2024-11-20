package cloudScanner

import (
	"fmt"
	"os"

	"github.com/0x5ubt13/enumeraga/internal/commands"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

func Run() {
	cloudChecks()

	commands.Scoutsuite()

	os.Exit(0)
}

// cloudChecks works the same than internal/checks but for Cloud enumeration instead
func cloudChecks() {
	// Cloud check #1: key tools exist in the system
	if !*utils.OptQuiet {
		fmt.Println(utils.Cyan("[*] Checking all tools are installed... "))
	}
	utils.InstallMissingTools('c')

	/* Tools to add:
		- Prowler (https://github.com/prowler-cloud/prowler)
		- Scoutsuite (https://github.com/nccgroup/scoutsuite)
		- CloudFox (https://github.com/BishopFox/cloudfox)
			Note: it'd be good if pmapper was installed alongside cloudfox, with their integration it could also have it generate the default privesc query and images as output
		- Pmapper (https://github.com/nccgroup/PMapper)
		- Steampipe (https://github.com/turbot/steampipe)
		- Powerpipe (https://github.com/turbot/powerpipe)
	*/

	// Cloud check #2: args passed
	providerArg := os.Args[2]

	utils.PrintCustomBiColourMsg("green", "yellow", "[+] Using '", providerArg, "' as provider to launch scans")
}


