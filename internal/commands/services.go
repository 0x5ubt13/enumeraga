package commands

import (
	"fmt"
	"slices"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/cloudservices"
	"github.com/0x5ubt13/enumeraga/internal/config"
	"github.com/0x5ubt13/enumeraga/internal/utils"
)

// cloudRun is one launch of a cloud tool: its argument vector and the file,
// within the tool's output directory, that its output is captured to. Most
// tools launch once; CloudFox and aws-enumerator may launch several times when
// services are restricted.
type cloudRun struct {
	args []string
	out  string
}

// awsEnumeratorMaxServices is the most services aws-enumerator accepts in one
// run; it exits 1 when given more.
const awsEnumeratorMaxServices = 10

// servicesScopedTools are the cloud tools that can be limited to --services.
// Every other tool is skipped when services are restricted: run unrestricted, it
// would reach services the operator left out.
var servicesScopedTools = map[string]bool{
	"scoutsuite":     true,
	"prowler":        true,
	"cloudfox":       true,
	"nuclei":         true,
	"aws_enumerator": true,
}

// unscopedReason explains why a tool cannot honour --services.
func unscopedReason(tool string) string {
	switch tool {
	case "pmapper":
		return "--services is set and PMapper cannot be limited to it: it always reads IAM " +
			"and the resource policies of S3, SNS, SQS, KMS and Secrets Manager"
	case "monkey365":
		return "--services is set and monkey365's collection is not mapped to services, so it would run unrestricted"
	default:
		return "--services is set and this tool cannot be limited to services"
	}
}

// noEquivalentReason explains a tool skipped because none of the requested
// services exists in it.
func noEquivalentReason(tool string, services []string) string {
	return fmt.Sprintf("--services is set and %s has no equivalent of any requested service (%s)",
		tool, strings.Join(services, ", "))
}

// skipCloudTool prints why a tool is not being run and records it, so the
// coverage summary shows the gap rather than passing over it.
func skipCloudTool(tool, reason string) {
	utils.PrintCustomBiColourMsg("yellow", "cyan", "[!] Skipping ", tool, ": ", reason)
	RecordCloudSkip(tool, reason)
}

// appendListFlag appends flag followed by values, or nothing when values is
// empty. Prowler and ScoutSuite take their service lists as separate arguments.
func appendListFlag(args []string, flag string, values []string) []string {
	if len(values) == 0 {
		return args
	}
	return append(append(args, flag), values...)
}

// scoutServices converts --services to ScoutSuite's names. skip is true, and the
// skip already recorded, when services were requested but none exists in
// ScoutSuite: launched without a filter it would scan every service instead.
func scoutServices(cfg *config.CloudConfig) (services []string, skip bool) {
	services = cloudservices.Scout(cfg.Provider, cfg.Services)
	if len(cfg.Services) > 0 && len(services) == 0 {
		skipCloudTool("scoutsuite", noEquivalentReason("ScoutSuite", cfg.Services))
		return nil, true
	}
	return services, false
}

// cloudfoxServiceRuns returns one CloudFox run per command that keeps within
// the requested services. CloudFox has no service flag, so the commands are the
// filter; see cloudservices.CloudFoxModules for which command needs what.
func cloudfoxServiceRuns(cfg *config.CloudConfig, filePath string) ([]cloudRun, error) {
	modules := cloudservices.CloudFoxModules(cfg.Provider, cfg.Services)
	if len(modules) == 0 {
		skipCloudTool("cloudfox", fmt.Sprintf(
			"--services is set and no CloudFox command keeps within the requested services (%s)",
			strings.Join(cfg.Services, ", ")))
		return nil, nil
	}

	var flags []string
	switch cfg.Provider {
	case "aws":
		if cfg.AWSProfile != "" {
			flags = append(flags, "--profile", cfg.AWSProfile)
		}
		// The admin check simulates IAM policies for every role it meets, which
		// is IAM enumeration: keep it only when IAM is in scope.
		if !slices.Contains(cfg.Services, "iam") {
			flags = append(flags, "--skip-admin-check")
		}
	case "azure":
		flags = cloudfoxAzureScope(cfg)
		if flags == nil {
			skipCloudTool("cloudfox", cloudfoxAzureScopeReason)
			return nil, nil
		}
	}

	binary, err := cloudfoxBinary()
	if err != nil {
		return nil, err
	}
	runs := make([]cloudRun, 0, len(modules))
	for _, m := range modules {
		args := append([]string{binary, cfg.Provider, m, "--outdir", filePath}, flags...)
		runs = append(runs, cloudRun{args: args, out: m + ".out"})
	}
	return runs, nil
}

// awsEnumeratorServiceRuns returns aws-enumerator runs covering the requested
// services, at most awsEnumeratorMaxServices per run. aws-enumerator appends to
// its results directory rather than replacing it, so the runs accumulate.
func awsEnumeratorServiceRuns(cfg *config.CloudConfig) ([]cloudRun, error) {
	names := cloudservices.AWSEnumerator(cfg.Services)
	if len(names) == 0 {
		skipCloudTool("aws_enumerator", noEquivalentReason("aws-enumerator", cfg.Services))
		return nil, nil
	}
	if ready, err := awsEnumeratorReady(cfg); !ready {
		return nil, err
	}

	chunks := slices.Collect(slices.Chunk(names, awsEnumeratorMaxServices))
	runs := make([]cloudRun, 0, len(chunks))
	for i, chunk := range chunks {
		args := []string{"aws-enumerator", "enum", "-services", strings.Join(chunk, ",")}
		if cfg.AWSProfile != "" {
			args = append(args, "-profile", cfg.AWSProfile)
		}
		out := "output.out"
		if len(chunks) > 1 {
			out = fmt.Sprintf("output_%d.out", i+1)
		}
		runs = append(runs, cloudRun{args: args, out: out})
	}
	return runs, nil
}
