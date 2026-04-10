package cloud

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/0x5ubt13/enumeraga/internal/cloudScanner"
	"github.com/0x5ubt13/enumeraga/internal/config"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/pborman/getopt/v2"
)

// optCreds is intentionally unexported — it is only read within this package.
// The spec uses OptCreds (uppercase) as a naming suggestion; we keep it lowercase
// since it never needs to be accessed from outside the cloud package.
var optCreds = getopt.StringLong("creds", 'c', "", "Path to credentials file (e.g. GCP service account JSON)")

// Azure service principal flags — used by monkey365 and future Azure tools.
var optAzureTenantID     = getopt.StringLong("tenant", 0, "", "Azure Tenant ID (for service principal auth)")
var optAzureClientID     = getopt.StringLong("client-id", 0, "", "Azure Client ID / App ID (for service principal auth)")
var optAzureClientSecret = getopt.StringLong("client-secret", 0, "", "Azure Client Secret (for service principal auth)")

// GCP IAM brute-force flags
var optGCPIAMBruteEmail = getopt.StringLong("iam-brute-email", 0, "", "Override service account email for gcp-iam-brute (GCP only)")
var optNoIAMBrute       = getopt.BoolLong("no-iam-brute", 0, "Disable gcp-iam-brute permission enumeration (GCP only)")

// optGCPToken accepts a file containing a raw GCP access token (ya29.xxx).
// The token is injected into GOOGLE_OAUTH_ACCESS_TOKEN / CLOUDSDK_AUTH_ACCESS_TOKEN so
// all downstream tools can use it via ADC without needing a service account key file.
var optGCPToken = getopt.StringLong("gcp-token", 0, "", "Path to file containing a raw GCP access token (ya29.xxx)")

// optGCPProject overrides the GCP project ID used by cloud tools.
var optGCPProject = getopt.StringLong("project", 0, "", "GCP project ID (overrides auto-detection from gcloud / env vars)")

// optNucleiURL enables nuclei cloud template scans against the given target URL.
var optNucleiURL = getopt.StringLong("nuclei-url", 0, "", "Target URL for nuclei cloud template scans (omit to skip nuclei)")

// validateCredsFile validates the credentials file path and sets GOOGLE_APPLICATION_CREDENTIALS for GCP.
// Returns nil if credsFile is empty (no-op) or if provider is not GCP (warning only).
func validateCredsFile(provider, credsFile string) error {
	if credsFile == "" {
		return nil
	}
	if provider != "gcp" {
		utils.PrintCustomBiColourMsg("yellow", "cyan", "[!]", " --creds is not yet supported for ", provider, ", ignoring")
		return nil
	}
	if _, err := os.Stat(credsFile); err != nil { //nolint:gosec // path validated above
		return fmt.Errorf("credentials file not found: %s", credsFile)
	}
	data, err := os.ReadFile(credsFile) //nolint:gosec // path validated above
	if err != nil {
		return fmt.Errorf("could not read credentials file: %w", err)
	}
	if !json.Valid(data) {
		return fmt.Errorf("credentials file is not valid JSON: %s", credsFile)
	}
	if err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", credsFile); err != nil {
		return fmt.Errorf("failed to set GOOGLE_APPLICATION_CREDENTIALS: %w", err)
	}
	return nil
}

// gcpAuthPreflight authenticates with a GCP service account before running enumeration tools.
// providerDir must already exist (created by caller).
func gcpAuthPreflight(credsFile, providerDir string) error {
	if !utils.CheckToolExists("gcloud") {
		return fmt.Errorf("gcloud is required for --creds authentication but was not found. Install the Google Cloud SDK")
	}

	logPath := fmt.Sprintf("%sgcloud_auth_login.log", providerDir)
	cmd := exec.Command("gcloud", "auth", "activate-service-account", "--key-file", credsFile)
	output, cmdErr := cmd.CombinedOutput()

	return checkGcpAuthOutput(output, cmdErr, logPath)
}

// checkGcpAuthOutput writes output to logPath, checks exit code first, then verifies the success string.
// Extracted for testability.
func checkGcpAuthOutput(output []byte, cmdErr error, logPath string) error {
	_ = os.WriteFile(logPath, output, 0644) //nolint:gosec // logPath is constructed internally, not user input

	if cmdErr != nil {
		return fmt.Errorf("GCP authentication failed. Check your credentials file and see %s for details", logPath)
	}
	if !strings.Contains(string(output), "Activated service account credentials for:") {
		return fmt.Errorf("GCP authentication failed (unexpected output). Check %s for details", logPath)
	}

	utils.PrintCustomBiColourMsg("green", "cyan", "[+]", " Authenticated with given creds file")
	return nil
}

// knownProviderAliases is the full set of strings parseCSP accepts.
// Used by extractProviderArg to find the provider before flag parsing.
var knownProviderAliases = map[string]bool{
	"aws": true, "amazon": true,
	"az": true, "azure": true,
	"gcp": true, "gcloud": true, "g": true,
	"ay": true, "ali": true, "aliy": true, "aliyun": true, "alibaba": true,
	"oci": true, "oracle": true,
	"do": true, "digital": true, "digitalocean": true,
}

// extractProviderArg pre-scans args for a cloud provider name, removes it from the
// slice, and returns it separately. This allows flags to appear before or after the
// provider name without confusing getopt's POSIX stop-at-first-non-flag behaviour.
func extractProviderArg(args []string) (provider string, filtered []string) {
	filtered = append(filtered, args[0]) // keep program name
	for _, arg := range args[1:] {
		if knownProviderAliases[arg] && provider == "" {
			provider = arg
		} else {
			filtered = append(filtered, arg)
		}
	}
	return
}

// Run launches the main entrypoint for enumeraga cloud
func Run(OptOutput *string, OptHelp, OptQuiet, OptVVerbose *bool) error {
	// Timing the execution
	start := time.Now()

	// Remove "cloud" subcommand, then extract the provider name before flag parsing.
	// pborman/getopt uses POSIX mode (stops at first non-flag arg), so we pull the
	// provider out first to let flags appear anywhere relative to the provider name.
	os.Args = append(os.Args[:1], os.Args[2:]...)
	providerArg, filteredArgs := extractProviderArg(os.Args)
	os.Args = filteredArgs
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
		return utils.ErrHelpRequested
	}

	// Check 2: Provider must have been found in args
	if providerArg == "" {
		utils.ErrorMsg("No arguments were provided.")
		printCloudUsage()
		utils.PrintCloudUsageExamples()
		return fmt.Errorf("no cloud provider specified")
	}

	// Check 3: Ensure there is a valid CSP target
	provider, err := parseCSP(providerArg)
	if err != nil {
		return fmt.Errorf("invalid cloud provider: %w", err)
	}

	// Check 3b: Validate credentials file if provided
	credsFile := *optCreds
	if err := validateCredsFile(provider, credsFile); err != nil {
		utils.ErrorMsg(err)
		return fmt.Errorf("credentials validation failed: %w", err)
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

	// Check 5b: GCP pre-flight authentication
	if provider == "gcp" && credsFile != "" {
		providerDir := fmt.Sprintf("%s/%s/", utils.BaseDir, provider)
		if _, mkErr := utils.CustomMkdir(providerDir); mkErr != nil {
			utils.ErrorMsg(mkErr)
		}
		if err := gcpAuthPreflight(credsFile, providerDir); err != nil {
			utils.ErrorMsg(err)
			return fmt.Errorf("GCP authentication failed: %w", err)
		}
	}

	// Checks done
	if !*OptQuiet {
		fmt.Printf("%s%s%s\n\n", utils.Cyan("[*] ---------- "), utils.Green("Checks phase complete"), utils.Cyan(" ----------"))
		fmt.Printf("%s%s%s\n", utils.Cyan("[*] ---------- "), utils.Green("Starting enumeration phase"), utils.Cyan(" ----------"))
	}

	// If --gcp-token was given, read the raw access token from the file and set it in the
	// environment so that injectTokenADC() and gcp-iam-brute token resolution pick it up.
	if *optGCPToken != "" && credsFile == "" {
		tokenBytes, tokenReadErr := os.ReadFile(*optGCPToken)
		if tokenReadErr != nil {
			utils.ErrorMsg(fmt.Errorf("could not read --gcp-token file: %w", tokenReadErr))
			return fmt.Errorf("gcp-token read failed: %w", tokenReadErr)
		}
		rawToken := strings.TrimSpace(string(tokenBytes))
		_ = os.Setenv("GOOGLE_OAUTH_ACCESS_TOKEN", rawToken)
		_ = os.Setenv("CLOUDSDK_AUTH_ACCESS_TOKEN", rawToken)
	}

	// Inject access token into ADC so Python/Go google-auth tools (prowler, scoutsuite,
	// cloudfox) pick it up via GOOGLE_APPLICATION_CREDENTIALS.
	if credsFile == "" {
		if _, cleanup, adcErr := injectTokenADC(); adcErr != nil {
			utils.ErrorMsg(fmt.Errorf("ADC token injection failed: %w", adcErr))
		} else if cleanup != nil {
			defer cleanup()
			utils.PrintCustomBiColourMsg("green", "cyan", "[+] Injected access token as ADC via local token proxy")
		}
	}

	// Scan start: changing into cloudScanner's Run function
	cfg := config.NewCloudConfig()
	cfg.Provider = provider
	cfg.CredsFile = credsFile
	cfg.AzureTenantID = *optAzureTenantID
	cfg.AzureClientID = *optAzureClientID
	cfg.AzureClientSecret = *optAzureClientSecret
	cfg.GCPIAMBruteEnabled = !*optNoIAMBrute
	cfg.GCPIAMBruteEmail = *optGCPIAMBruteEmail
	cfg.GCPProject = *optGCPProject
	cfg.NucleiTargetURL = *optNucleiURL
	cloudScanner.Run(cfg, OptVVerbose)

	// Finish and show elapsed time
	utils.FinishLine(start, utils.Interrupted)

	// Wait for goroutines to finish to terminate the program
	utils.Wg.Wait()

	return utils.ErrCloudComplete
}

// injectTokenADC sets up a local token proxy so that all ADC-based tools (Python and Go)
// can authenticate using a raw GCP access token from the environment.
//
// How it works:
//  1. A temporary HTTP server is started on localhost. It returns the stolen access token
//     for any OAuth2 token exchange POST, regardless of the JWT assertion presented.
//  2. A real RSA key pair is generated and a service_account ADC JSON is written that
//     points token_uri at the local server.
//  3. GOOGLE_APPLICATION_CREDENTIALS is set to the ADC file.
//
// Tools sign a JWT with the generated key and POST it to our server; the server ignores
// the JWT and returns the real token. This bypasses the invalid_client/invalid_grant
// failures that arise from using fake OAuth2 client credentials.
//
// Returns a cleanup func that stops the server and removes the temp file.
// Returns ("", nil, nil) when no access token is found in the environment.
func injectTokenADC() (string, func(), error) {
	token := strings.TrimSpace(os.Getenv("GOOGLE_OAUTH_ACCESS_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("CLOUDSDK_AUTH_ACCESS_TOKEN"))
	}
	if token == "" {
		return "", nil, nil
	}

	// Start local token server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("failed to start token server: %w", err)
	}
	tokenJSON := fmt.Sprintf(`{"access_token":%q,"expires_in":3600,"token_type":"Bearer"}`, token)
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, tokenJSON)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(listener) //nolint:errcheck // background server, error not actionable
	tokenURI := "http://" + listener.Addr().String() + "/token"

	// Generate RSA key — required for the service_account JWT signing flow
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		srv.Close()
		return "", nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	// Detect project for the ADC JSON (cosmetic — tools read it but don't validate it)
	project := "enumeraga"
	if out, err := exec.Command("gcloud", "config", "get-value", "project").Output(); err == nil {
		if p := strings.TrimSpace(string(out)); p != "" && p != "(unset)" {
			project = p
		}
	}

	type saCredential struct {
		Type         string `json:"type"`
		ProjectID    string `json:"project_id"`
		PrivateKeyID string `json:"private_key_id"`
		PrivateKey   string `json:"private_key"`
		ClientEmail  string `json:"client_email"`
		ClientID     string `json:"client_id"`
		AuthURI      string `json:"auth_uri"`
		TokenURI     string `json:"token_uri"`
	}
	data, err := json.Marshal(saCredential{ //nolint:gosec // G117: synthetic mock credential for GCP ADC test server, not a real secret
		Type:         "service_account",
		ProjectID:    project,
		PrivateKeyID: "enumeraga",
		PrivateKey:   string(keyPEM),
		ClientEmail:  fmt.Sprintf("enumeraga@%s.iam.gserviceaccount.com", project),
		ClientID:     "1",
		AuthURI:      "https://accounts.google.com/o/oauth2/auth",
		TokenURI:     tokenURI,
	})
	if err != nil {
		srv.Close()
		return "", nil, fmt.Errorf("failed to marshal ADC JSON: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "enumeraga-adc-*.json")
	if err != nil {
		srv.Close()
		return "", nil, fmt.Errorf("failed to create ADC temp file: %w", err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name()) //nolint:gosec // G703: path from os.CreateTemp, not user input
		srv.Close()
		return "", nil, fmt.Errorf("failed to write ADC temp file: %w", err)
	}
	tmpFile.Close()

	if err := os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tmpFile.Name()); err != nil {
		os.Remove(tmpFile.Name()) //nolint:gosec // G703: path from os.CreateTemp, not user input
		srv.Close()
		return "", nil, fmt.Errorf("failed to set GOOGLE_APPLICATION_CREDENTIALS: %w", err)
	}

	cleanup := func() {
		srv.Close()
		os.Remove(tmpFile.Name())
	}
	return tmpFile.Name(), cleanup, nil
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
	fmt.Println("  -c, --creds FILE         Path to credentials file (e.g. GCP service account JSON)")
	fmt.Println("      --tenant ID          Azure Tenant ID (service principal auth, used by monkey365)")
	fmt.Println("      --client-id ID       Azure Client/App ID (service principal auth, used by monkey365)")
	fmt.Println("      --client-secret SEC  Azure Client Secret (service principal auth, used by monkey365)")
	fmt.Println("      --iam-brute-email EMAIL  Override service account email for gcp-iam-brute (GCP only)")
	fmt.Println("      --no-iam-brute           Disable gcp-iam-brute permission enumeration (GCP only)")
	fmt.Println("  -h, --help               Display this help and exit")
	fmt.Println("  -o, --output DIR         Select a different base folder for output (default: /tmp/enumeraga_output)")
	fmt.Println("  -q, --quiet              Don't print the banner and decrease overall verbosity")
	fmt.Println("  -V, --vv                 Flood your terminal with plenty of verbosity!")
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
