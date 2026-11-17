package commands

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/config"
)

// isolateHome points HOME at a scratch directory, so ensureScout cannot find
// and repair a real ScoutSuite install while a test runs.
func isolateHome(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
}

// skipRecordedFor returns the not_applicable result recorded for tool, if any.
func skipRecordedFor(tool string) (CloudToolResult, bool) {
	for _, r := range CloudResults() {
		if r.Tool == tool && r.Outcome == OutcomeNotApplicable {
			return r, true
		}
	}
	return CloudToolResult{}, false
}

func TestPrepProwlerAppendsServices(t *testing.T) {
	putStubOnPath(t, "prowler")
	outDir := filepath.Join(t.TempDir(), "prowler out")

	got, err := prepProwler(&config.CloudConfig{Provider: "aws", Services: []string{"ec2", "s3"}}, outDir)
	if err != nil {
		t.Fatalf("prepProwler() error = %v", err)
	}
	want := []string{"prowler", "aws", "-o", outDir, "--service", "ec2", "s3"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepProwler(aws) = %#v, want %#v", got, want)
	}

	// The az-login branch used to return early; the filter must survive it.
	got, err = prepProwler(&config.CloudConfig{
		Provider:          "azure",
		AzureSubscription: "sub-1",
		Services:          []string{"vm"},
	}, outDir)
	if err != nil {
		t.Fatalf("prepProwler() error = %v", err)
	}
	want = []string{"prowler", "azure", "-o", outDir, "--az-cli-auth", "--subscription-ids", "sub-1", "--service", "vm"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepProwler(azure) = %#v, want %#v", got, want)
	}
}

func TestPrepScoutsuiteAppendsMappedServices(t *testing.T) {
	isolateHome(t)
	putStubOnPath(t, "scout")
	reportDir := filepath.Join(t.TempDir(), "scout report")

	got, err := prepScoutsuite(&config.CloudConfig{Provider: "aws", Services: []string{"ec2", "guardduty"}}, reportDir)
	if err != nil {
		t.Fatalf("prepScoutsuite() error = %v", err)
	}
	want := []string{"scout", "aws", "--force", "--no-browser", "--report-dir", reportDir, "--services", "ec2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepScoutsuite() = %#v, want %#v", got, want)
	}
}

func TestScoutAzureCLIArgsCarriesServices(t *testing.T) {
	got := scoutAzureCLIArgs("/r", "sub-1", []string{"virtualmachines", "storageaccounts"})
	want := []string{"scout", "azure", "--cli", "--force", "--no-browser", "--report-dir", "/r",
		"--subscriptions", "sub-1", "--services", "virtualmachines", "storageaccounts"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scoutAzureCLIArgs() = %#v, want %#v", got, want)
	}
}

func TestScoutAzureFileAuthArgsCarriesServices(t *testing.T) {
	got := scoutAzureFileAuthArgs("/auth.json", "/r", "", []string{"virtualmachines"})
	want := []string{"scout", "azure", "--file-auth", "/auth.json", "--force", "--no-browser", "--report-dir", "/r",
		"--services", "virtualmachines"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("scoutAzureFileAuthArgs() = %#v, want %#v", got, want)
	}
}

// ScoutSuite drops names it does not know and, if it is left with none, scans
// nothing while still exiting cleanly. It must therefore not be launched at all
// when no requested service has a ScoutSuite equivalent.
func TestPrepCloudToolSkipsScoutWhenNoServiceMaps(t *testing.T) {
	for _, provider := range []string{"aws", "azure"} {
		t.Run(provider, func(t *testing.T) {
			ResetCloudResults()
			isolateHome(t)
			binDir := t.TempDir()
			argvLog := filepath.Join(t.TempDir(), "argv.log")
			fakeTool(t, binDir, "scout", argvLog, "exit 0")
			t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

			service := map[string]string{"aws": "guardduty", "azure": "aks"}[provider]
			verbose := false
			if err := PrepCloudTool("scoutsuite", t.TempDir()+"/", &config.CloudConfig{
				Provider: provider,
				Services: []string{service},
			}, &verbose); err != nil {
				t.Fatalf("PrepCloudTool() error = %v", err)
			}

			if _, err := os.Stat(argvLog); err == nil {
				t.Errorf("scout was launched with argv %q; it has no equivalent of %s", readArgv(t, argvLog), service)
			}
			r, ok := skipRecordedFor("scoutsuite")
			if !ok {
				t.Fatalf("no not_applicable result recorded for scoutsuite; results = %+v", CloudResults())
			}
			if !strings.Contains(r.Detail, service) {
				t.Errorf("skip reason %q does not name the requested service %q", r.Detail, service)
			}
		})
	}
}

func TestPrepNucleiRestrictsTemplates(t *testing.T) {
	putStubOnPath(t, "nuclei")
	got, err := prepNuclei(&config.CloudConfig{
		Provider:        "azure",
		NucleiEnabled:   true,
		NucleiTargetURL: "https://example.com",
		Services:        []string{"vm", "storage"},
	})
	if err != nil {
		t.Fatalf("prepNuclei() error = %v", err)
	}
	want := []string{"nuclei", "-u", "https://example.com",
		"-t", "cloud/azure/virtualmachines/", "-t", "cloud/azure/storageaccounts/",
		"-silent", "-no-interactivity", "-no-color"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepNuclei() = %#v, want %#v", got, want)
	}
}

func TestPrepCloudToolSkipsNucleiWhenNoTemplateMaps(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "nuclei")
	verbose := false
	if err := PrepCloudTool("nuclei", t.TempDir()+"/", &config.CloudConfig{
		Provider:        "azure",
		NucleiEnabled:   true,
		NucleiTargetURL: "https://example.com",
		Services:        []string{"mysql"},
	}, &verbose); err != nil {
		t.Fatalf("PrepCloudTool() error = %v", err)
	}
	r, ok := skipRecordedFor("nuclei")
	if !ok {
		t.Fatalf("no not_applicable result recorded for nuclei; results = %+v", CloudResults())
	}
	if !strings.Contains(r.Detail, "mysql") {
		t.Errorf("skip reason %q does not name the requested service", r.Detail)
	}
}

// Tools that cannot be limited to services are skipped, with the reason kept,
// rather than run unrestricted.
func TestPrepCloudToolSkipsUnscopedToolsWhenServicesSet(t *testing.T) {
	tests := []struct {
		tool string
		cfg  *config.CloudConfig
	}{
		{"pmapper", &config.CloudConfig{Provider: "aws", Services: []string{"iam"}}},
		{"monkey365", &config.CloudConfig{
			Provider:          "azure",
			Services:          []string{"vm"},
			AzureTenantID:     "t",
			AzureClientID:     "c",
			AzureClientSecret: "s",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			ResetCloudResults()
			t.Setenv("PRINCIPALMAPPER_DATA_DIR", "")
			verbose := false
			if err := PrepCloudTool(tt.tool, t.TempDir()+"/", tt.cfg, &verbose); err != nil {
				t.Fatalf("PrepCloudTool() error = %v", err)
			}
			if _, ok := skipRecordedFor(tt.tool); !ok {
				t.Fatalf("no not_applicable result recorded for %s; results = %+v", tt.tool, CloudResults())
			}
			if tt.cfg.PMapperDir != "" || os.Getenv("PRINCIPALMAPPER_DATA_DIR") != "" {
				t.Errorf("%s was prepared despite being skipped (PMapperDir = %q)", tt.tool, tt.cfg.PMapperDir)
			}
		})
	}
}

func TestCloudfoxServiceRunsAWS(t *testing.T) {
	putStubOnPath(t, "cloudfox")
	outDir := filepath.Join(t.TempDir(), "fox out") + "/"

	got, err := cloudfoxServiceRuns(&config.CloudConfig{
		Provider:   "aws",
		AWSProfile: "lab profile",
		Services:   []string{"ec2"},
	}, outDir)
	if err != nil {
		t.Fatalf("cloudfoxServiceRuns() error = %v", err)
	}
	want := []cloudRun{
		{args: []string{"cloudfox", "aws", "instances", "--outdir", outDir, "--profile", "lab profile", "--skip-admin-check"}, out: "instances.out"},
		{args: []string{"cloudfox", "aws", "elastic-network-interfaces", "--outdir", outDir, "--profile", "lab profile", "--skip-admin-check"}, out: "elastic-network-interfaces.out"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cloudfoxServiceRuns(ec2) = %#v, want %#v", got, want)
	}

	// The admin check simulates IAM policies, so it is only kept when IAM is in scope.
	got, err = cloudfoxServiceRuns(&config.CloudConfig{Provider: "aws", Services: []string{"iam", "ec2"}}, outDir)
	if err != nil {
		t.Fatalf("cloudfoxServiceRuns() error = %v", err)
	}
	for _, r := range got {
		for _, a := range r.args {
			if a == "--skip-admin-check" {
				t.Errorf("%v skips the admin check although iam was requested", r.args)
			}
		}
	}
}

func TestCloudfoxServiceRunsAzureKeepsScope(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "cloudfox")
	outDir := t.TempDir() + "/"

	got, err := cloudfoxServiceRuns(&config.CloudConfig{
		Provider:          "azure",
		AzureSubscription: "sub-1",
		Services:          []string{"vm"},
	}, outDir)
	if err != nil {
		t.Fatalf("cloudfoxServiceRuns() error = %v", err)
	}
	want := []cloudRun{{args: []string{"cloudfox", "azure", "vms", "--outdir", outDir, "--subscription", "sub-1"}, out: "vms.out"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cloudfoxServiceRuns(azure vm) = %#v, want %#v", got, want)
	}

	// Every CloudFox Azure module refuses to run without a scope.
	got, err = cloudfoxServiceRuns(&config.CloudConfig{Provider: "azure", Services: []string{"vm"}}, outDir)
	if err != nil || got != nil {
		t.Fatalf("cloudfoxServiceRuns(no scope) = %#v, %v; want nil, nil", got, err)
	}
	if _, ok := skipRecordedFor("cloudfox"); !ok {
		t.Errorf("no not_applicable result recorded for cloudfox without a scope; results = %+v", CloudResults())
	}
}

func TestPrepCloudToolSkipsCloudfoxWhenNoModuleMaps(t *testing.T) {
	ResetCloudResults()
	binDir := t.TempDir()
	argvLog := filepath.Join(t.TempDir(), "argv.log")
	fakeTool(t, binDir, "cloudfox", argvLog, "exit 0")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	verbose := false
	if err := PrepCloudTool("cloudfox", t.TempDir()+"/", &config.CloudConfig{
		Provider: "aws",
		Services: []string{"rds"},
	}, &verbose); err != nil {
		t.Fatalf("PrepCloudTool() error = %v", err)
	}
	if _, err := os.Stat(argvLog); err == nil {
		t.Errorf("cloudfox was launched with argv %q; no module is limited to rds alone", readArgv(t, argvLog))
	}
	r, ok := skipRecordedFor("cloudfox")
	if !ok {
		t.Fatalf("no not_applicable result recorded for cloudfox; results = %+v", CloudResults())
	}
	if !strings.Contains(r.Detail, "rds") {
		t.Errorf("skip reason %q does not name the requested service", r.Detail)
	}
}

// aws-enumerator exits 1 when given more than 10 services, so longer lists are
// split across runs.
func TestAWSEnumeratorServiceRunsChunks(t *testing.T) {
	putStubOnPath(t, "aws-enumerator")
	services := []string{"acm", "amplify", "apigateway", "appsync", "athena", "autoscaling",
		"backup", "batch", "cloudformation", "cloudfront", "awslambda"}

	got, err := awsEnumeratorServiceRuns(&config.CloudConfig{
		Provider:             "aws",
		AWSEnumeratorEnabled: true,
		AWSProfile:           "lab profile",
		Services:             services,
	})
	if err != nil {
		t.Fatalf("awsEnumeratorServiceRuns() error = %v", err)
	}
	want := []cloudRun{
		{args: []string{"aws-enumerator", "enum", "-services",
			"acm,amplify,apigateway,appsync,athena,autoscaling,backup,batch,cloudformation,cloudfront",
			"-profile", "lab profile"}, out: "output_1.out"},
		{args: []string{"aws-enumerator", "enum", "-services", "lambda", "-profile", "lab profile"}, out: "output_2.out"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("awsEnumeratorServiceRuns() = %#v, want %#v", got, want)
	}

	got, err = awsEnumeratorServiceRuns(&config.CloudConfig{
		Provider:             "aws",
		AWSEnumeratorEnabled: true,
		Services:             []string{"ec2", "vpc"},
	})
	if err != nil {
		t.Fatalf("awsEnumeratorServiceRuns() error = %v", err)
	}
	want = []cloudRun{{args: []string{"aws-enumerator", "enum", "-services", "ec2"}, out: "output.out"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("awsEnumeratorServiceRuns(ec2,vpc) = %#v, want %#v", got, want)
	}
}

func TestAWSEnumeratorServiceRunsSkipsWhenNoServiceMaps(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "aws-enumerator")
	got, err := awsEnumeratorServiceRuns(&config.CloudConfig{
		Provider:             "aws",
		AWSEnumeratorEnabled: true,
		Services:             []string{"vpc"},
	})
	if err != nil || got != nil {
		t.Fatalf("awsEnumeratorServiceRuns(vpc) = %#v, %v; want nil, nil", got, err)
	}
	if _, ok := skipRecordedFor("aws_enumerator"); !ok {
		t.Errorf("no not_applicable result recorded for aws_enumerator; results = %+v", CloudResults())
	}
}
