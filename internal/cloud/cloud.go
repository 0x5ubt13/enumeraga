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

var (
	OptHelp     = flag.Bool("help", false, "Display this help and exit.")
	OptInstall  = flag.Bool("install", false, "Only try to install pre-requisite tools and exit.")
	OptOutput   = flag.String("output", "/tmp/enumeraga_cloud_output", "Select a different base folder for the output.")
	OptQuiet    = flag.Bool("quiet", false, "Don't print the banner and decrease overall verbosity.")
	OptVVerbose = flag.Bool("vv", false, "Flood your terminal with plenty of verbosity!")
)

func Run() {
	// Timing the execution
	start := time.Now()

	// Cloud flow must end when this Run function finishes
	defer os.Exit(0)

	// Parse optional arguments
	flag.Parse()

	// Check 0: banner!
	if !*OptQuiet {
		utils.PrintBanner()
	}

	// Check 1: Args passed fine?
	if len(os.Args) == 2 {
		utils.ErrorMsg("No arguments were provided.")
		getopt.Usage()
		utils.PrintInfraUsageExamples()
		os.Exit(1)
	}

	// Check 2: Help flag passed?
	if *OptHelp {
		if !*OptQuiet {
			fmt.Println(utils.Cyan("[*] Help flag detected. Aborting other checks and printing usage.\n"))
		}
		getopt.Usage()
		utils.PrintInfraUsageExamples()
		os.Exit(0)
	}

	// Check 3: am I groot?!
	// Not needed for cloud I think?
	//if os.Geteuid() != 0 {
	//	utils.ErrorMsg("Please run me as root!")
	//	os.Exit(99)
	//}

	// Check 4: key tools exist in the system
	if !*OptQuiet {
		fmt.Println(utils.Cyan("[*] Checking all cloud tools are installed... "))
	}

	utils.InstallMissingTools('c', OptInstall, OptVVerbose)

	if *OptInstall {
		fmt.Println(utils.Green("[+] All pre-required tools have been installed! You're good to go! Run your first scan with enumeraga cloud <provider>!"))
		os.Exit(0)
	}

	// Check 5: Ensure there is a target
	provider := parseCSP()

	// Check 6: Ensure base output directory is correctly set and exists
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

	cloudScanner.Run(provider)

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
