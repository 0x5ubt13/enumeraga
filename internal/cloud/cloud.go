package cloud

import (
	"flag"
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
	// Parse optional cloud arguments, getting rid of the 'infra' arg
	os.Args = os.Args[1:]
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
		flag.Usage()
		utils.PrintCloudUsageExamples()
		os.Exit(0)
	}

	// Check 2: Args passed fine?
	if len(os.Args) == 2 {
		utils.ErrorMsg("No arguments were provided.")
		flag.Usage()
		utils.PrintCloudUsageExamples()
		os.Exit(1)
	}

	// Check 3: Ensure there is a target
	provider := parseCSP()

	// Check 4: Ensure base output directory is correctly set and exists
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
