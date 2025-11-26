package config

type CloudConfig struct {
	// Tool settings
	PMMapperEnabled   bool
	ScoutSuiteEnabled bool
	ProwlerEnabled    bool
	CloudFoxEnabled   bool

	// Output settings
	OutputPath   string
	ReportFormat string // "xlsx", "json", etc.

	// Provider settings
	Provider              string
	AWSProfile            string
	AzureSubscriptionName string 
	AzureSubscriptionID   string
	AzureTenantName       string
	AzureTenantID		  string
	GCPProject            string

	// Runtime settings
	Concurrent     bool
	InstallMissing bool
	Verbose        bool
}

func NewCloudConfig() *CloudConfig {
	return &CloudConfig{
		PMMapperEnabled:   true,
		ScoutSuiteEnabled: true,
		ProwlerEnabled:    true,
		CloudFoxEnabled:   true,
		ReportFormat:      "xlsx",
		Concurrent:        true,
		InstallMissing:    true,
	}
}
