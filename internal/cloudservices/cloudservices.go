// Package cloudservices restricts an enumeraga cloud scan to named services.
//
// Operators name services the way Prowler does, because Prowler covers the most
// of them. Every other tool calls the same service something else, or splits it
// differently, so each tool gets its own conversion here. A tool with no
// equivalent of any requested service gets nothing, and the caller must then
// skip it rather than run it unrestricted: an empty filter means "everything" to
// some tools and "nothing" to others, and neither is what the operator asked for.
//
// The tables were read from the tool versions enumeraga runs: Prowler 5.50.0
// (`prowler <provider> --list-services`), ScoutSuite 5.14.0
// (`scout <provider> --list-services`), CloudFox v2.0.5 (its module sources),
// the nuclei-templates `cloud/azure/` folders, and aws-enumerator at commit
// 9ff6976. Re-check them when any of those is upgraded.
package cloudservices

import (
	"fmt"
	"strings"
)

// prowlerServices is every service Prowler 5.50.0 lists, per provider. These
// are the canonical names --services accepts.
var prowlerServices = map[string][]string{
	"aws": {
		"accessanalyzer", "account", "acm", "acmpca", "amplify", "apigateway", "apigatewayv2",
		"appstream", "appsync", "athena", "autoscaling", "awslambda", "backup", "batch",
		"bedrock", "bedrockagentcore", "cloudformation", "cloudfront", "cloudtrail", "cloudwatch",
		"codeartifact", "codebuild", "codecommit", "codepipeline", "cognito", "config",
		"datapipeline", "datasync", "directconnect", "directoryservice", "dlm", "dms",
		"documentdb", "drs", "dynamodb", "ec2", "ecr", "ecs", "efs", "eks", "elasticache",
		"elasticbeanstalk", "elb", "elbv2", "emr", "eventbridge", "firehose", "fms", "fsx",
		"glacier", "glue", "guardduty", "iam", "inspector2", "kafka", "kinesis", "kms",
		"lightsail", "macie", "memorydb", "mq", "neptune", "networkfirewall", "oam",
		"opensearch", "organizations", "rds", "redshift", "resourceexplorer2", "rolesanywhere",
		"route53", "s3", "sagemaker", "secretsmanager", "securityhub", "servicecatalog", "ses",
		"shield", "sns", "sqs", "ssm", "ssmincidents", "stepfunctions", "storagegateway",
		"transfer", "trustedadvisor", "vpc", "waf", "wafv2", "wellarchitected", "workspaces",
	},
	"azure": {
		"aisearch", "aiservices", "aks", "apim", "app", "appinsights", "containerregistry",
		"cosmosdb", "databricks", "defender", "entra", "iam", "keyvault", "monitor", "mysql",
		"network", "policy", "postgresql", "recovery", "sqlserver", "storage", "vm",
	},
}

// scoutNames converts a canonical service to ScoutSuite's name for it. A
// service absent here has no ScoutSuite equivalent.
var scoutNames = map[string]map[string]string{
	"aws": identity(
		"acm", "awslambda", "cloudformation", "cloudfront", "cloudtrail", "cloudwatch",
		"codebuild", "config", "directconnect", "dynamodb", "ec2", "efs", "elasticache", "elb",
		"elbv2", "emr", "iam", "kms", "rds", "redshift", "route53", "s3", "secretsmanager",
		"ses", "sns", "sqs", "vpc",
	),
	"azure": {
		"app":        "appservice",
		"defender":   "securitycenter",
		"entra":      "aad",
		"iam":        "rbac",
		"keyvault":   "keyvault",
		"monitor":    "loggingmonitoring",
		"mysql":      "mysqldatabase",
		"network":    "network",
		"postgresql": "postgresqldatabase",
		"sqlserver":  "sqldatabase",
		"storage":    "storageaccounts",
		"vm":         "virtualmachines",
	},
}

// aliases accepts ScoutSuite's name wherever it differs from Prowler's, so an
// operator who knows the Azure services by ScoutSuite's names is understood.
var aliases = func() map[string]map[string]string {
	out := make(map[string]map[string]string, len(scoutNames))
	for provider, names := range scoutNames {
		out[provider] = make(map[string]string)
		for canonicalName, scoutName := range names {
			if scoutName != canonicalName {
				out[provider][scoutName] = canonicalName
			}
		}
	}
	return out
}()

// canonical is prowlerServices as sets, for lookup.
var canonical = func() map[string]map[string]struct{} {
	out := make(map[string]map[string]struct{}, len(prowlerServices))
	for provider, names := range prowlerServices {
		out[provider] = make(map[string]struct{}, len(names))
		for _, n := range names {
			out[provider][n] = struct{}{}
		}
	}
	return out
}()

// nucleiAzureDirs converts a canonical Azure service to the nuclei-templates
// folders under cloud/azure/ that cover it. Nuclei has no service flag; its
// cloud templates are filed one folder per service instead. Nuclei is not run
// for AWS, so there is no AWS table.
var nucleiAzureDirs = map[string][]string{
	"aisearch":   {"search"},
	"aiservices": {"aiservices"},
	"aks":        {"aks"},
	"apim":       {"apimanagement"},
	"app":        {"appservice", "functions"},
	"cosmosdb":   {"cosmosdb"},
	"defender":   {"securitycenter"},
	"entra":      {"activedirectory"},
	"iam":        {"accesscontrol"},
	"keyvault":   {"keyvault"},
	"monitor":    {"monitor", "activitylog"},
	"network":    {"network"},
	"postgresql": {"postgresql"},
	"sqlserver":  {"sql"},
	"storage":    {"storageaccounts"},
	"vm":         {"virtualmachines"},
}

// cloudFoxModule is one CloudFox command and the services whose inventory it
// lists. Look-ups that only add detail to a resource the module already found
// (the IAM instance profile of an EC2 instance, a VM's NIC and public IP) do
// not count: they enrich the requested service rather than enumerate another.
type cloudFoxModule struct {
	name  string
	needs []string
}

// cloudFoxModules lists the CloudFox commands that can be limited to services,
// in run order. CloudFox has no service flag; a command runs only when every
// service it needs was requested.
var cloudFoxModules = map[string][]cloudFoxModule{
	"aws": {
		{"instances", []string{"ec2"}},
		{"elastic-network-interfaces", []string{"ec2"}},
		{"ecs-tasks", []string{"ecs", "ec2"}},
		{"eks", []string{"eks"}},
		{"ecr", []string{"ecr"}},
		{"lambda", []string{"awslambda"}},
		{"buckets", []string{"s3"}},
		{"filesystems", []string{"efs", "fsx"}},
		// databases also reports the DocumentDB and Neptune clusters that the RDS
		// API returns; Prowler files both under services of their own.
		{"databases", []string{"rds", "redshift", "dynamodb", "documentdb", "neptune"}},
		{"api-gw", []string{"apigateway", "apigatewayv2"}},
		{"cloudformation", []string{"cloudformation"}},
		{"codebuild", []string{"codebuild"}},
		{"secrets", []string{"secretsmanager", "ssm"}},
		{"sns", []string{"sns"}},
		{"sqs", []string{"sqs"}},
		{"route53", []string{"route53"}},
		{"orgs", []string{"organizations"}},
		{"ds", []string{"directoryservice"}},
		{"principals", []string{"iam"}},
		{"permissions", []string{"iam"}},
		{"role-trusts", []string{"iam"}},
		{"access-keys", []string{"iam"}},
	},
	"azure": {
		{"vms", []string{"vm"}},
		{"storage", []string{"storage"}},
		// rbac resolves role assignments against a listing of every Entra user.
		{"rbac", []string{"iam", "entra"}},
	},
}

// awsEnumeratorNames converts a canonical AWS service to aws-enumerator's name.
var awsEnumeratorNames = func() map[string]string {
	out := identity(
		"acm", "amplify", "apigateway", "appsync", "athena", "autoscaling", "backup", "batch",
		"cloudformation", "cloudfront", "cloudtrail", "codebuild", "codecommit", "codepipeline",
		"datapipeline", "datasync", "directconnect", "dlm", "dynamodb", "ec2", "ecr", "ecs",
		"eks", "elasticache", "elasticbeanstalk", "firehose", "fms", "fsx", "glue", "guardduty",
		"iam", "kafka", "kinesis", "kms", "lightsail", "macie", "mq", "organizations", "rds",
		"redshift", "route53", "s3", "sagemaker", "secretsmanager", "securityhub",
		"servicecatalog", "shield", "sns", "sqs", "ssm", "storagegateway", "transfer", "waf",
		"workspaces",
	)
	out["awslambda"] = "lambda"
	return out
}()

func identity(names ...string) map[string]string {
	m := make(map[string]string, len(names))
	for _, n := range names {
		m[n] = n
	}
	return m
}

// Resolve validates the services named for a provider and returns them as
// canonical names, lower-cased, de-duplicated and in the order given.
//
// No names means no restriction, and returns nil. Names given for a provider
// other than aws or azure, a list that names nothing, and any name the provider
// does not have are errors: each would otherwise run a scan other than the one
// asked for.
func Resolve(provider string, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	known, ok := canonical[provider]
	if !ok {
		return nil, fmt.Errorf("--services is supported for aws and azure only, not %q", provider)
	}

	var out, unknown []string
	seen := make(map[string]bool, len(names))
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if c, isAlias := aliases[provider][name]; isAlias {
			name = c
		}
		if _, valid := known[name]; !valid {
			unknown = append(unknown, strings.TrimSpace(raw))
			continue
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}

	if len(unknown) > 0 {
		msg := fmt.Sprintf("unknown %s service(s): %s. Valid names (Prowler's): %s",
			provider, strings.Join(unknown, ", "), strings.Join(prowlerServices[provider], ", "))
		if provider == "azure" {
			msg += ". ScoutSuite's Azure names (e.g. virtualmachines) are accepted too"
		}
		return nil, fmt.Errorf("%s", msg)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--services was given but names no services")
	}
	return out, nil
}

// Scout returns ScoutSuite's names for the services it covers, in order.
func Scout(provider string, services []string) []string {
	var out []string
	for _, s := range services {
		if name, ok := scoutNames[provider][s]; ok {
			out = append(out, name)
		}
	}
	return out
}

// NucleiTemplates returns the nuclei template paths covering the services, in
// order. It returns nil for AWS, which enumeraga does not run nuclei against.
func NucleiTemplates(provider string, services []string) []string {
	if provider != "azure" {
		return nil
	}
	var out []string
	for _, s := range services {
		for _, dir := range nucleiAzureDirs[s] {
			out = append(out, "cloud/azure/"+dir+"/")
		}
	}
	return out
}

// CloudFoxModules returns the CloudFox commands whose every needed service was
// requested, in run order.
func CloudFoxModules(provider string, services []string) []string {
	requested := make(map[string]bool, len(services))
	for _, s := range services {
		requested[s] = true
	}
	var out []string
	for _, m := range cloudFoxModules[provider] {
		covered := true
		for _, need := range m.needs {
			if !requested[need] {
				covered = false
				break
			}
		}
		if covered {
			out = append(out, m.name)
		}
	}
	return out
}

// AWSEnumerator returns aws-enumerator's names for the AWS services it covers,
// in order.
func AWSEnumerator(services []string) []string {
	var out []string
	for _, s := range services {
		if name, ok := awsEnumeratorNames[s]; ok {
			out = append(out, name)
		}
	}
	return out
}
