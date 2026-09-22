package commands

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/config"
)

// The invocation that shipped was "cloudfox azure inventory --outdir <dir>".
// cloudfox refuses that -- its Azure modules need a scope -- and then exits 0, so
// the scan reported success while enumerating nothing at all.
func TestPrepCloudfoxAzureScopesToTheSubscription(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "cloudfox")
	outDir := t.TempDir()

	got, err := prepCloudfox(&config.CloudConfig{
		Provider:          "azure",
		AzureSubscription: "sub with spaces",
	}, outDir)
	if err != nil {
		t.Fatalf("prepCloudfox() error = %v", err)
	}

	want := []string{"cloudfox", "azure", "inventory", "--outdir", outDir, "--subscription", "sub with spaces"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepCloudfox() = %#v, want %#v", got, want)
	}
}

// The exact command the failing scan emitted must never be produced again.
func TestPrepCloudfoxAzureNeverEmitsTheUnscopedCommand(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "cloudfox")
	outDir := t.TempDir()

	for _, cfg := range []*config.CloudConfig{
		{Provider: "azure", AzureSubscription: "sub-id"},
		{Provider: "azure", AzureTenantID: "tenant-id"},
		{Provider: "azure"},
	} {
		got, err := prepCloudfox(cfg, outDir)
		if err != nil {
			t.Fatalf("prepCloudfox() error = %v", err)
		}
		if got == nil {
			continue // the explicit skip, asserted separately
		}
		joined := strings.Join(got, " ")
		if !strings.Contains(joined, "--subscription") && !strings.Contains(joined, "--tenant") {
			t.Errorf("prepCloudfox() = %q, which cloudfox rejects: an Azure module needs --subscription or --tenant", joined)
		}
	}
}

// A tenant is accepted when no subscription was given, because cloudfox supports
// either scope.
func TestPrepCloudfoxAzureFallsBackToTheTenant(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "cloudfox")
	outDir := t.TempDir()

	got, err := prepCloudfox(&config.CloudConfig{
		Provider:      "azure",
		AzureTenantID: "tenant-id",
	}, outDir)
	if err != nil {
		t.Fatalf("prepCloudfox() error = %v", err)
	}

	want := []string{"cloudfox", "azure", "inventory", "--outdir", outDir, "--tenant", "tenant-id"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("prepCloudfox() = %#v, want %#v", got, want)
	}
}

// The subscription is preferred: it is the narrower scope, and an engagement is
// scoped to a subscription rather than to the whole tenant.
func TestPrepCloudfoxAzurePrefersSubscriptionOverTenant(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "cloudfox")
	outDir := t.TempDir()

	got, err := prepCloudfox(&config.CloudConfig{
		Provider:          "azure",
		AzureSubscription: "sub-id",
		AzureTenantID:     "tenant-id",
	}, outDir)
	if err != nil {
		t.Fatalf("prepCloudfox() error = %v", err)
	}

	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "--subscription sub-id") {
		t.Errorf("prepCloudfox() = %q, want the subscription scope", joined)
	}
	if strings.Contains(joined, "--tenant") {
		t.Errorf("prepCloudfox() = %q, want the tenant omitted when a subscription is known", joined)
	}
}

// With no scope at all, skipping explicitly beats emitting a command that is
// known to be rejected.
func TestPrepCloudfoxAzureSkipsExplicitlyWithoutAScope(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "cloudfox")

	got, err := prepCloudfox(&config.CloudConfig{Provider: "azure"}, t.TempDir())
	if err != nil {
		t.Fatalf("prepCloudfox() error = %v", err)
	}
	if got != nil {
		t.Fatalf("prepCloudfox() = %#v, want no command when no scope is available", got)
	}

	results := CloudResults()
	if len(results) != 1 {
		t.Fatalf("recorded %d results, want 1 explicit skip", len(results))
	}
	if results[0].Outcome != OutcomeNotApplicable {
		t.Errorf("outcome = %q, want %q", results[0].Outcome, OutcomeNotApplicable)
	}
	if !strings.Contains(results[0].Detail, "subscription") {
		t.Errorf("skip reason = %q, want it to name the missing scope", results[0].Detail)
	}
	if results[0].FullCoverage() {
		t.Error("a skipped tool must not count as full coverage")
	}
}

// The output-directory contract is unchanged, including paths with spaces.
func TestPrepCloudfoxAzureKeepsSpacedOutdirAsOneArgument(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "cloudfox")
	outDir := t.TempDir() + "/fox out"

	got, err := prepCloudfox(&config.CloudConfig{Provider: "azure", AzureSubscription: "s"}, outDir)
	if err != nil {
		t.Fatalf("prepCloudfox() error = %v", err)
	}
	for i, arg := range got {
		if arg == "--outdir" {
			if got[i+1] != outDir {
				t.Errorf("--outdir = %q, want the directory as a single argument %q", got[i+1], outDir)
			}
			return
		}
	}
	t.Error("--outdir missing; the output directory contract was dropped")
}

// A client secret must never reach a command line, whatever else changes.
func TestPrepCloudfoxAzureKeepsSecretsOffTheCommandLine(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "cloudfox")

	const secret = "s3cr3t-client-secret"
	got, err := prepCloudfox(&config.CloudConfig{
		Provider:          "azure",
		AzureSubscription: "sub-id",
		AzureTenantID:     "tenant-id",
		AzureClientID:     "client-id",
		AzureClientSecret: secret,
	}, t.TempDir())
	if err != nil {
		t.Fatalf("prepCloudfox() error = %v", err)
	}
	if strings.Contains(strings.Join(got, " "), secret) {
		t.Errorf("prepCloudfox() leaked the client secret into argv: %#v", got)
	}
}

func TestClassifyCloudToolExit(t *testing.T) {
	tests := []struct {
		name     string
		binary   string
		exitCode int
		output   string
		want     CloudToolOutcome
	}{
		{
			name:     "a clean run is completed",
			binary:   "prowler",
			exitCode: 0,
			want:     OutcomeCompleted,
		},
		{
			name:     "prowler exit 3 means checks failed, not that prowler did",
			binary:   "prowler",
			exitCode: 3,
			want:     OutcomeFindings,
		},
		{
			name:     "scoutsuite exit 200 is a completed run with limited coverage",
			binary:   "scout",
			exitCode: 200,
			want:     OutcomePartial,
		},
		{
			name:     "scoutsuite exit 109 never produced a report, so it failed",
			binary:   "scout",
			exitCode: 109,
			want:     OutcomeFailed,
		},
		{
			name:     "cloudfox rejecting its command line is an invalid invocation despite exit 0",
			binary:   "cloudfox",
			exitCode: 0,
			output:   "Please enter a valid input with a valid flag. Use --help for info.\n",
			want:     OutcomeInvalidInvocation,
		},
		{
			name:     "an unknown flag is an invalid invocation",
			binary:   "cloudfox",
			exitCode: 0,
			output:   "Error: unknown flag: --outdir\n",
			want:     OutcomeInvalidInvocation,
		},
		{
			name:     "a missing binary is unavailable, not a scan failure",
			binary:   "cloudfox",
			exitCode: 127,
			want:     OutcomeUnavailable,
		},
		{
			name:     "an unrecognised non-zero exit is a failure",
			binary:   "cloudfox",
			exitCode: 2,
			want:     OutcomeFailed,
		},
		{
			name:     "prowler findings classification survives an absolute binary path",
			binary:   "/usr/local/bin/prowler",
			exitCode: 3,
			want:     OutcomeFindings,
		},
		{
			name:     "no exit status at all is a failure, not a zero exit",
			binary:   "scout",
			exitCode: -1,
			want:     OutcomeFailed,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, detail := classifyCloudToolExit(tc.binary, tc.exitCode, tc.output)
			if got != tc.want {
				t.Errorf("classifyCloudToolExit(%q, %d) = %q, want %q", tc.binary, tc.exitCode, got, tc.want)
			}
			if detail == "" {
				t.Error("classification produced no reason; the reason is what an operator acts on")
			}
		})
	}
}

// Findings are full coverage: prowler looked at everything and reported problems.
// A permission-limited run is not, because some checks were never made.
func TestFullCoverageDistinguishesFindingsFromLimitedCoverage(t *testing.T) {
	if !(CloudToolResult{Outcome: OutcomeFindings}).FullCoverage() {
		t.Error("a scanner that completed and found problems is still full coverage")
	}
	if (CloudToolResult{Outcome: OutcomePartial}).FullCoverage() {
		t.Error("a permission-limited run must not count as full coverage")
	}
	if (CloudToolResult{Outcome: OutcomeInvalidInvocation}).FullCoverage() {
		t.Error("a tool that never ran must not count as full coverage")
	}
}

// The summary is the operator-facing answer to "did this scan cover everything?".
func TestCloudCoverageSummaryNamesPartialCoverage(t *testing.T) {
	summary := CloudCoverageSummary([]CloudToolResult{
		{Tool: "scout", Outcome: OutcomePartial, ExitCode: 200, Detail: "permission-limited"},
		{Tool: "prowler", Outcome: OutcomeFindings, ExitCode: 3, Detail: "found failing checks"},
		{Tool: "cloudfox", Outcome: OutcomeInvalidInvocation, ExitCode: 0, Detail: "rejected its command line"},
	})

	if !strings.Contains(summary, "PARTIAL COVERAGE") {
		t.Errorf("summary does not state partial coverage:\n%s", summary)
	}
	for _, tool := range []string{"scout", "cloudfox"} {
		if !strings.Contains(summary, tool) {
			t.Errorf("summary does not name %s as incomplete:\n%s", tool, summary)
		}
	}
	if !strings.Contains(summary, "valid and have been kept") {
		t.Errorf("summary does not say the other tools' results are still valid:\n%s", summary)
	}
}

// A scan where everything completed must not be described as partial, including
// when a scanner exited non-zero because it found problems.
func TestCloudCoverageSummaryReportsFullCoverage(t *testing.T) {
	summary := CloudCoverageSummary([]CloudToolResult{
		{Tool: "prowler", Outcome: OutcomeFindings, ExitCode: 3, Detail: "found failing checks"},
		{Tool: "scout", Outcome: OutcomeCompleted, ExitCode: 0, Detail: "completed"},
	})

	if strings.Contains(summary, "PARTIAL COVERAGE") {
		t.Errorf("findings were misreported as missing coverage:\n%s", summary)
	}
	if !strings.Contains(summary, "Full coverage") {
		t.Errorf("summary does not confirm full coverage:\n%s", summary)
	}
}

// The capture buffer must not grow without bound, and must keep the start of the
// output, where a tool's complaint about its command line appears.
func TestCloudOutputCaptureIsBoundedAndKeepsTheStart(t *testing.T) {
	c := newCloudOutputCapture()
	marker := "Please enter a valid input with a valid flag"
	if _, err := c.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	// Far more than the limit, as a chatty tool would produce.
	flood := strings.Repeat("x", captureLimit*2)
	n, err := c.Write([]byte(flood))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(flood) {
		t.Errorf("Write reported %d of %d bytes; a short write stalls the tool it is draining", n, len(flood))
	}
	if got := len(c.String()); got > captureLimit {
		t.Errorf("capture held %d bytes, want at most %d", got, captureLimit)
	}
	if !hasInvalidInvocationMarker(c.String()) {
		t.Error("the marker was lost; classification depends on the start of the output surviving")
	}
}

// No Azure command line may carry the client secret.
//
// The run record captures argument vectors verbatim and the debug line prints
// them, so a secret placed in argv would be written to disk and to the terminal.
// Azure auth reaches the tools through the environment or a temporary file
// instead, and this asserts that across every Azure argument builder rather than
// trusting each one separately.
func TestAzureCloudCommandsNeverCarryTheClientSecret(t *testing.T) {
	ResetCloudResults()
	putStubOnPath(t, "cloudfox", "prowler", "scout")

	const secret = "s3cr3t-client-secret-value"
	cfg := &config.CloudConfig{
		Provider:          "azure",
		AzureSubscription: "sub-id",
		AzureTenantID:     "tenant-id",
		AzureClientID:     "client-id",
		AzureClientSecret: secret,
	}
	outDir := t.TempDir()

	builders := map[string]func() ([]string, error){
		"prepCloudfox": func() ([]string, error) { return prepCloudfox(cfg, outDir) },
		"prepProwler":  func() ([]string, error) { return prepProwler(cfg, outDir) },
		"scoutAzureCLIArgs": func() ([]string, error) {
			return scoutAzureCLIArgs(outDir, cfg.AzureSubscription), nil
		},
		"scoutAzureFileAuthArgs": func() ([]string, error) {
			return scoutAzureFileAuthArgs(filepath.Join(outDir, "auth.json"), outDir, cfg.AzureSubscription), nil
		},
	}

	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			args, err := build()
			if err != nil {
				t.Skipf("%s unavailable in this environment: %v", name, err)
			}
			for _, arg := range args {
				if strings.Contains(arg, secret) {
					t.Errorf("%s put the client secret on the command line: %#v", name, args)
				}
			}
		})
	}
}
