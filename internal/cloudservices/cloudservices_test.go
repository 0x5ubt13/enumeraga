package cloudservices

import (
	"reflect"
	"strings"
	"testing"
)

func TestResolveCanonicalises(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		in       []string
		want     []string
	}{
		{"case, spaces and duplicates", "aws", []string{" EC2 ", "ec2", "S3"}, []string{"ec2", "s3"}},
		{"scout alias folds into its prowler name", "azure", []string{"virtualmachines", "vm"}, []string{"vm"}},
		{"scout alias on its own", "azure", []string{"StorageAccounts"}, []string{"storage"}},
		{"blank entries are dropped", "aws", []string{"iam", "", " "}, []string{"iam"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Resolve(tt.provider, tt.in)
			if err != nil {
				t.Fatalf("Resolve() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Resolve() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResolveRejectsUnknown(t *testing.T) {
	_, err := Resolve("aws", []string{"ec2", "foo", "bar"})
	if err == nil {
		t.Fatal("Resolve() accepted unknown services")
	}
	msg := err.Error()
	for _, want := range []string{"foo", "bar", "accessanalyzer", "workspaces"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not mention %q", msg, want)
		}
	}
}

// A name valid for one provider is not valid for the other: "vm" is Azure's.
func TestResolveRejectsOtherProvidersNames(t *testing.T) {
	if _, err := Resolve("aws", []string{"vm"}); err == nil {
		t.Error("Resolve(aws, vm) accepted an Azure-only service")
	}
	if _, err := Resolve("azure", []string{"ec2"}); err == nil {
		t.Error("Resolve(azure, ec2) accepted an AWS-only service")
	}
}

func TestResolveRejectsUnsupportedProvider(t *testing.T) {
	for _, provider := range []string{"gcp", "oci", "aliyun", "do", "k8s"} {
		if _, err := Resolve(provider, []string{"compute"}); err == nil {
			t.Errorf("Resolve(%s) accepted --services; only aws and azure support it", provider)
		}
	}
}

// An empty -s value names no services. Running unrestricted would be the
// opposite of what the operator asked for, so it is an error, not a no-op.
func TestResolveRejectsEmptyList(t *testing.T) {
	for _, in := range [][]string{{""}, {" ", ""}} {
		if _, err := Resolve("aws", in); err == nil {
			t.Errorf("Resolve(%q) accepted a list naming no services", in)
		}
	}
}

func TestResolveNilMeansUnrestricted(t *testing.T) {
	for _, provider := range []string{"aws", "azure", "gcp"} {
		got, err := Resolve(provider, nil)
		if err != nil || got != nil {
			t.Errorf("Resolve(%s, nil) = %v, %v; want nil, nil", provider, got, err)
		}
	}
}

func TestScoutAzureNames(t *testing.T) {
	got := Scout("azure", []string{"vm", "storage", "aks", "entra", "iam"})
	want := []string{"virtualmachines", "storageaccounts", "aad", "rbac"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Scout(azure) = %v, want %v", got, want)
	}
}

func TestScoutAWSDropsUnsupported(t *testing.T) {
	got := Scout("aws", []string{"ec2", "guardduty", "awslambda"})
	want := []string{"ec2", "awslambda"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Scout(aws) = %v, want %v", got, want)
	}
}

func TestNucleiTemplatesAzure(t *testing.T) {
	got := NucleiTemplates("azure", []string{"vm", "app", "mysql"})
	want := []string{"cloud/azure/virtualmachines/", "cloud/azure/appservice/", "cloud/azure/functions/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("NucleiTemplates(azure) = %v, want %v", got, want)
	}
	if got := NucleiTemplates("aws", []string{"ec2"}); got != nil {
		t.Errorf("NucleiTemplates(aws) = %v, want nil: nuclei is not run for AWS", got)
	}
}

func TestCloudFoxModulesNeedEveryListedService(t *testing.T) {
	tests := []struct {
		provider string
		in       []string
		want     []string
	}{
		{"aws", []string{"ec2"}, []string{"instances", "elastic-network-interfaces"}},
		{"aws", []string{"rds"}, nil},
		// databases also lists DocumentDB and Neptune clusters, which Prowler files
		// under their own services.
		{"aws", []string{"dynamodb", "rds", "redshift"}, nil},
		{"aws", []string{"dynamodb", "rds", "redshift", "documentdb", "neptune"}, []string{"databases"}},
		{"aws", []string{"ecs"}, nil},
		{"aws", []string{"ecs", "ec2"}, []string{"instances", "elastic-network-interfaces", "ecs-tasks"}},
		{"aws", []string{"iam"}, []string{"principals", "permissions", "role-trusts", "access-keys"}},
		{"azure", []string{"vm"}, []string{"vms"}},
		{"azure", []string{"iam"}, nil},
		{"azure", []string{"entra", "iam"}, []string{"rbac"}},
	}
	for _, tt := range tests {
		got := CloudFoxModules(tt.provider, tt.in)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("CloudFoxModules(%s, %v) = %v, want %v", tt.provider, tt.in, got, tt.want)
		}
	}
}

func TestAWSEnumeratorNames(t *testing.T) {
	got := AWSEnumerator([]string{"awslambda", "ec2", "vpc"})
	want := []string{"lambda", "ec2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AWSEnumerator() = %v, want %v", got, want)
	}
}

// Every tool table must be keyed by canonical names, or a requested service
// would silently fail to reach that tool.
func TestTablesUseCanonicalNames(t *testing.T) {
	check := func(table string, provider string, names []string) {
		for _, n := range names {
			if _, ok := canonical[provider][n]; !ok {
				t.Errorf("%s uses %q, which is not a canonical %s service", table, n, provider)
			}
		}
	}
	for provider, m := range scoutNames {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		check("scoutNames", provider, keys)
	}
	for service := range nucleiAzureDirs {
		check("nucleiAzureDirs", "azure", []string{service})
	}
	for provider, mods := range cloudFoxModules {
		for _, m := range mods {
			check("cloudFoxModules", provider, m.needs)
		}
	}
	keys := make([]string, 0, len(awsEnumeratorNames))
	for k := range awsEnumeratorNames {
		keys = append(keys, k)
	}
	check("awsEnumeratorNames", "aws", keys)
}
