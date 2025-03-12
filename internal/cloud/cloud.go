package cloud

import (
	"fmt"
	"github.com/0x5ubt13/enumeraga/internal/cloudScanner"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/pborman/getopt/v2"
	"os"
	"time"
)

func Run(OptOutput *string, OptHelp, OptQuiet, OptVVerbose *bool) {
	// Timing the execution
	start := time.Now()

	// Cloud flow must end when this Run function finishes
	defer os.Exit(0)

	// Parse optional arguments
	//flag.Parse()
	// Parse optional cloud arguments, getting rid of the `enumeraga cloud` args
	os.Args = os.Args[2:]
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
		getopt.Usage()
		utils.PrintCloudUsageExamples()
		os.Exit(0)
	}

	// Check 2: Args passed fine?
	if len(os.Args) == 0 {
		utils.ErrorMsg("No arguments were provided.")
		fmt.Println(utils.Cyan("[*] Debug -> %v args passed: %v", len(os.Args), os.Args))
		getopt.Usage()
		utils.PrintCloudUsageExamples()
		os.Exit(1)
	}

	// Check 3: Ensure there is a valid CSP target
	provider, err := parseCSP(os.Args[0])
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
