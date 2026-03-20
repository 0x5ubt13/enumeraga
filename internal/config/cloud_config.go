package config

type CloudConfig struct {
	// Active run settings
	Provider  string // active provider for this single run
	CredsFile string // path to credentials file, empty if not supplied

	// Tool settings
	PMMapperEnabled    bool
	ScoutSuiteEnabled  bool
	ProwlerEnabled     bool
	CloudFoxEnabled    bool
	GCPScannerEnabled  bool
	Monkey365Enabled   bool
	NucleiEnabled      bool
	NucleiTargetURL    string // optional target URL for nuclei cloud template scans; leave empty to skip
	GCPIAMBruteEnabled bool
	GCPIAMBruteEmail   string // overrides auto-detected service account email

	// Output settings
	OutputPath   string
	ReportFormat string // "xlsx", "json", etc.

	// Provider settings
	Providers         []string
	AWSProfile        string
	AzureSubscription string
	AzureTenantID     string
	AzureClientID     string
	AzureClientSecret string
	GCPProject        string

	// Runtime settings
	Concurrent     bool
	InstallMissing bool
	Verbose        bool
}

func NewCloudConfig() *CloudConfig {
	return &CloudConfig{
		PMMapperEnabled:    true,
		ScoutSuiteEnabled:  true,
		ProwlerEnabled:     true,
		CloudFoxEnabled:    true,
		GCPScannerEnabled:  true,
		Monkey365Enabled:   true,
		NucleiEnabled:      true,
		GCPIAMBruteEnabled: true,
		ReportFormat:       "xlsx",
		Concurrent:         true,
		InstallMissing:     true,
	}
}
