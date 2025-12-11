package cloud

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/cloudScanner"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/pborman/getopt/v2"
	"os"
	"time"
)


// Run launches the main entrypoint for enumeraga cloud
func Run(OptOutput *string, OptHelp, OptQuiet, OptVVerbose *bool) {
	// Timing the execution
	start := time.Now()

	// Cloud flow must end when this Run function finishes
	defer os.Exit(0)

	// Parse optional cloud arguments, getting rid of the `enumeraga cloud` args
	// Keep os.Args[0] as program name for getopt, remove "cloud" subcommand
	os.Args = append(os.Args[:1], os.Args[2:]...)
	getopt.Parse()

	// Assign basedir of OptOutput to avoid cyclic import hell
	utils.BaseDir = *OptOutput

	// Check 0: banner!
	if !*OptQuiet {
		utils.PrintBanner()
	}

	// Check 1: Help flag passed?
	if *OptHelp {
		if !*OptQuiet {
			fmt.Println(utils.Cyan("[*] Help flag detected. Aborting other checks and printing usage.\n"))
		}
		printCloudUsage()
		utils.PrintCloudUsageExamples()
		os.Exit(0)
	}

	// Get remaining args after flag parsing
	remainingArgs := getopt.Args()

	// Check 2: Args passed fine?
	if len(remainingArgs) == 0 {
		utils.ErrorMsg("No arguments were provided.")
		printCloudUsage()
		utils.PrintCloudUsageExamples()
		os.Exit(1)
	}

	// Check 3: Ensure there is a valid CSP target
	provider, err := parseCSP(remainingArgs[0])
	if err != nil {
		utils.ErrorMsg(err)
		os.Exit(1)
	}

	// Check 4: I AM GROOT!!!!
	utils.CheckAdminPrivileges("cloud")

	// Check 5: Ensure base output directory is correctly set and exists
	name, err := utils.CustomMkdir(*OptOutput)
	if err != nil {
		if *OptVVerbose {
			utils.ErrorMsg(err)
		}
	}

	if !*OptQuiet {
		utils.PrintCustomBiColourMsg("green", "yellow", "[+] Using '", name, "' as base directory to save the ", "cloud output ", "files")
	}

	// Checks done
	if !*OptQuiet {
		fmt.Printf("%s%s%s\n\n", utils.Cyan("[*] ---------- "), utils.Green("Checks phase complete"), utils.Cyan(" ----------"))
		fmt.Printf("%s%s%s\n", utils.Cyan("[*] ---------- "), utils.Green("Starting enumeration phase"), utils.Cyan(" ----------"))
	}

	// Scan start: changing into cloudScanner's Run function
	cloudScanner.Run(provider, OptVVerbose)

	// Finish and show elapsed time
	utils.FinishLine(start, utils.Interrupted)

	// Wait for goroutines to finish to terminate the program
	utils.Wg.Wait()
}

// printCloudUsage prints only the cloud-relevant flags, not infra flags
func printCloudUsage() {
	fmt.Println("Usage: enumeraga cloud [OPTIONS] <provider>")
	fmt.Println("\nCloud Providers:")
	fmt.Println("  aws, amazon          Amazon Web Services")
	fmt.Println("  azure, az            Microsoft Azure")
	fmt.Println("  gcp, gcloud, g       Google Cloud Platform")
	fmt.Println("  oci, oracle          Oracle Cloud Infrastructure")
	fmt.Println("  aliyun, alibaba      Alibaba Cloud")
	fmt.Println("  do, digitalocean     DigitalOcean")
	fmt.Println("\nOptions:")
	fmt.Println("  -h, --help           Display this help and exit")
	fmt.Println("  -o, --output DIR     Select a different base folder for output (default: /tmp/enumeraga_output)")
	fmt.Println("  -q, --quiet          Don't print the banner and decrease overall verbosity")
	fmt.Println("  -V, --vv             Flood your terminal with plenty of verbosity!")
	fmt.Println()
}

// parseCSP parses the provider the user wants to enumerate
func parseCSP(provider string) (string, error) {
	possibleProviders := []string{"aws", "azure", "gcp", "oci", "aliyun", "digitalocean (do)"}

	switch provider {
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
		utils.ErrorMsg(fmt.Sprintf("%s not detected as a suitable cloud service provider. Please try again by using one of these: %v.", provider, possibleProviders))
		return "", fmt.Errorf("no suitable cloud service provider parsed")
	}

	utils.PrintCustomBiColourMsg("green", "yellow", "[+] Using '", provider, "' as provider to launch scans")
	return provider, nil
}
