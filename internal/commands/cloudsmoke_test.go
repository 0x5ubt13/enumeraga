package commands

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/config"
)

// fakeTool installs an executable that records the argument vector it was given
// and then behaves as the script says.
//
// Real cloud scanners are never invoked by the tests: the boundary under test is
// the command enumeraga builds and how it reads what comes back.
func fakeTool(t *testing.T, dir, name, argvLog, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake-tool smoke test uses a shell script")
	}
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$*\" >> " + argvLog + "\n" +
		body + "\n"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil { //nolint:gosec // a test fixture must be executable
		t.Fatalf("writing fake %s: %v", name, err)
	}
}

func readArgv(t *testing.T, argvLog string) string {
	t.Helper()
	data, err := os.ReadFile(argvLog) //nolint:gosec // path is built by the test
	if err != nil {
		t.Fatalf("reading recorded argv: %v", err)
	}
	return string(data)
}

// The fake rejects the old syntax exactly as the real cloudfox does -- printing
// the invalid-flag message and exiting 0 -- and succeeds on the new one. It is
// the regression guard for the defect that was reported.
const fakeCloudfoxBody = `case "$*" in
  *--subscription*|*--tenant*)
    echo "[cloudfox] gathering inventory"
    exit 0
    ;;
  *)
    echo "Please enter a valid input with a valid flag. Use --help for info."
    exit 0
    ;;
esac`

func TestSmokeCloudfoxAzureEmitsAnAcceptedCommand(t *testing.T) {
	ResetCloudResults()
	binDir := t.TempDir()
	outDir := t.TempDir() + string(os.PathSeparator)
	argvLog := filepath.Join(t.TempDir(), "argv.log")

	fakeTool(t, binDir, "cloudfox", argvLog, fakeCloudfoxBody)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	verbose := false
	if err := PrepCloudTool("cloudfox", outDir, &config.CloudConfig{
		Provider:          "azure",
		AzureSubscription: "00000000-1111-2222-3333-444444444444",
	}, &verbose); err != nil {
		t.Fatalf("PrepCloudTool() error = %v", err)
	}

	argv := readArgv(t, argvLog)
	if !strings.Contains(argv, "--subscription 00000000-1111-2222-3333-444444444444") {
		t.Errorf("cloudfox was not given the subscription scope; argv = %q", argv)
	}
	if !strings.Contains(argv, "azure inventory") {
		t.Errorf("cloudfox was not asked for an azure inventory; argv = %q", argv)
	}

	results := CloudResults()
	if len(results) != 1 {
		t.Fatalf("recorded %d results, want 1", len(results))
	}
	if results[0].Outcome != OutcomeCompleted {
		t.Errorf("outcome = %q (%s), want %q", results[0].Outcome, results[0].Detail, OutcomeCompleted)
	}
}

// The old command line must be classified as an invalid invocation even though
// cloudfox exits 0. Without the marker check this reads as a clean scan, which is
// how the broken Azure call went unnoticed in the first place.
func TestSmokeRejectedCommandLineIsNotReportedAsSuccess(t *testing.T) {
	ResetCloudResults()
	binDir := t.TempDir()
	outDir := t.TempDir() + string(os.PathSeparator)
	argvLog := filepath.Join(t.TempDir(), "argv.log")

	fakeTool(t, binDir, "cloudfox", argvLog, fakeCloudfoxBody)
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	verbose := false
	// Reproduce the shipped argument vector directly, bypassing the prep function.
	result := runCloudTool(
		[]string{"cloudfox", "azure", "inventory", "--outdir", outDir},
		filepath.Join(outDir, "output.out"), &verbose)

	if result.Outcome != OutcomeInvalidInvocation {
		t.Errorf("outcome = %q, want %q: cloudfox exits 0 when it rejects its flags, so the exit code alone must not decide this",
			result.Outcome, OutcomeInvalidInvocation)
	}
	if result.FullCoverage() {
		t.Error("a rejected command line must not count as coverage")
	}
}

// Prowler exits 3 when checks failed. Its reports are already written, so the run
// is complete and the artefacts must be kept.
func TestSmokeProwlerFindingsExitKeepsItsReports(t *testing.T) {
	ResetCloudResults()
	binDir := t.TempDir()
	outDir := t.TempDir() + string(os.PathSeparator)
	argvLog := filepath.Join(t.TempDir(), "argv.log")
	report := filepath.Join(outDir, "prowler-report.json")

	fakeTool(t, binDir, "prowler", argvLog,
		"echo '{\"findings\": 1}' > "+report+"\necho 'prowler done'\nexit 3")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	verbose := false
	result := runCloudTool([]string{"prowler", "azure"}, filepath.Join(outDir, "output.out"), &verbose)

	if result.Outcome != OutcomeFindings {
		t.Errorf("outcome = %q, want %q: exit 3 means checks failed, not that prowler crashed", result.Outcome, OutcomeFindings)
	}
	if result.ExitCode != 3 {
		t.Errorf("exit code = %d, want 3 recorded verbatim", result.ExitCode)
	}
	if !result.FullCoverage() {
		t.Error("prowler looked at everything and reported problems; that is full coverage")
	}
	if _, err := os.Stat(report); err != nil {
		t.Errorf("prowler's report was not preserved: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "output.out")); err != nil {
		t.Errorf("prowler's captured output was not preserved: %v", err)
	}
}

// ScoutSuite exits 200 when it saved its report but handled errors on the way --
// the Azure AuthorizationFailed case. That is partial coverage, and the underlying
// errors must survive in the artefact rather than being flattened into a failure.
func TestSmokeScoutPermissionErrorsSurviveAsPartialCoverage(t *testing.T) {
	ResetCloudResults()
	binDir := t.TempDir()
	outDir := t.TempDir() + string(os.PathSeparator)
	argvLog := filepath.Join(t.TempDir(), "argv.log")

	const authError = "AuthorizationFailed: the client does not have authorization to perform action " +
		"'Microsoft.Web/sites/config/list/action'"
	fakeTool(t, binDir, "scout", argvLog,
		"echo \""+authError+"\" >&2\necho 'Saving HTML report'\nexit 200")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	verbose := false
	outputFile := filepath.Join(outDir, "output.out")
	result := runCloudTool([]string{"scout", "azure"}, outputFile, &verbose)

	if result.Outcome != OutcomePartial {
		t.Errorf("outcome = %q, want %q", result.Outcome, OutcomePartial)
	}
	if result.ExitCode != 200 {
		t.Errorf("exit code = %d, want 200 preserved", result.ExitCode)
	}
	if result.FullCoverage() {
		t.Error("a permission-limited ScoutSuite run is not full coverage")
	}
	if !strings.Contains(result.Detail, "permission") {
		t.Errorf("detail = %q, want it to explain the coverage limitation", result.Detail)
	}

	// The underlying Azure error must remain readable in the artefact. stderr was
	// previously shown on the terminal but never written to the output file.
	saved, err := os.ReadFile(outputFile) //nolint:gosec // path is built by the test
	if err != nil {
		t.Fatalf("reading scout output: %v", err)
	}
	if !strings.Contains(string(saved), "AuthorizationFailed") {
		t.Errorf("the Azure authorisation error was lost from the artefact:\n%s", saved)
	}
	if !strings.Contains(string(saved), "Microsoft.Web/sites/config/list/action") {
		t.Errorf("the denied action was lost from the artefact:\n%s", saved)
	}
}

// A tool that fails must not stop the ones after it: the cloud scanners are
// independent, and a cloudfox failure that suppressed nuclei would turn one
// defect into a lost scan.
func TestSmokeAFailingToolDoesNotStopLaterTools(t *testing.T) {
	ResetCloudResults()
	binDir := t.TempDir()
	argvLog := filepath.Join(t.TempDir(), "argv.log")

	fakeTool(t, binDir, "cloudfox", argvLog, "echo 'Please enter a valid input with a valid flag. Use --help for info.'\nexit 0")
	fakeTool(t, binDir, "prowler", argvLog, "echo 'prowler ran'\nexit 3")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	verbose := false
	base := t.TempDir()
	foxDir := filepath.Join(base, "fox") + string(os.PathSeparator)
	prowlerDir := filepath.Join(base, "prowler") + string(os.PathSeparator)

	cfg := &config.CloudConfig{Provider: "azure", AzureSubscription: "sub-id"}

	if err := PrepCloudTool("cloudfox", foxDir, cfg, &verbose); err != nil {
		t.Fatalf("cloudfox PrepCloudTool() error = %v", err)
	}
	if err := PrepCloudTool("prowler", prowlerDir, cfg, &verbose); err != nil {
		t.Fatalf("prowler PrepCloudTool() error = %v", err)
	}

	results := CloudResults()
	if len(results) != 2 {
		t.Fatalf("recorded %d results, want both tools recorded", len(results))
	}

	byTool := map[string]CloudToolResult{}
	for _, r := range results {
		byTool[r.Tool] = r
	}
	if byTool["cloudfox"].Outcome != OutcomeInvalidInvocation {
		t.Errorf("cloudfox outcome = %q, want %q", byTool["cloudfox"].Outcome, OutcomeInvalidInvocation)
	}
	if byTool["prowler"].Outcome != OutcomeFindings {
		t.Errorf("prowler outcome = %q, want %q: it must still run after cloudfox failed", byTool["prowler"].Outcome, OutcomeFindings)
	}

	summary := CloudCoverageSummary(results)
	if !strings.Contains(summary, "PARTIAL COVERAGE") {
		t.Errorf("a scan that lost cloudfox must not read as fully successful:\n%s", summary)
	}
	if !strings.Contains(summary, "cloudfox") {
		t.Errorf("the summary must name the tool that failed:\n%s", summary)
	}
	if strings.Contains(summary, "! prowler") {
		t.Errorf("prowler completed with findings and must not be listed as incomplete:\n%s", summary)
	}
}
