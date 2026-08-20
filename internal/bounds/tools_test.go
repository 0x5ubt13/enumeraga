package bounds

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestApplyRateFlaggedTools(t *testing.T) {
	b := &Bounds{Rate: 5}

	tests := []struct {
		name     string
		args     []string
		wantFlag string
		wantVal  string
	}{
		{name: "nmap max-rate", args: []string{"nmap", "-p", "80"}, wantFlag: "--max-rate", wantVal: "5"},
		{name: "ffuf rate", args: []string{"ffuf", "-u", "http://x"}, wantFlag: "-rate", wantVal: "5"},
		{name: "nikto pause in seconds", args: []string{"nikto", "-host", "x"}, wantFlag: "-Pause", wantVal: "1"},
		{name: "onesixtyone wait in millis", args: []string{"onesixtyone", "x"}, wantFlag: "-w", wantVal: "200"},
		{name: "fping interval in millis", args: []string{"fping", "-asgq", "x"}, wantFlag: "-i", wantVal: "200"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := b.ApplyRate(tt.args)
			if got.Skip {
				t.Fatalf("ApplyRate(%v) skipped a rate-flagged tool", tt.args)
			}
			if got.Class != RateFlagged {
				t.Errorf("ApplyRate(%v).Class = %v, want RateFlagged", tt.args, got.Class)
			}
			assertFlag(t, got.Args, tt.wantFlag, tt.wantVal)
		})
	}
}

func TestApplyRateThreadsOnlyUsesMinOfRateAndConcurrency(t *testing.T) {
	// Rate 5, concurrency 2: the thread count must be the lower of the two, so a
	// caller asking for a concurrency of 2 never gets 5 concurrent connections.
	b := &Bounds{Rate: 5, Concurrency: 2}

	got := b.ApplyRate([]string{"gobuster", "dir", "-u", "http://x"})
	if got.Class != RateThreadsOnly {
		t.Errorf("gobuster Class = %v, want RateThreadsOnly", got.Class)
	}
	assertFlag(t, got.Args, "-t", "2")

	// With no concurrency cap, the rate is the only ceiling available.
	got = (&Bounds{Rate: 3}).ApplyRate([]string{"wpscan", "--url", "http://x"})
	assertFlag(t, got.Args, "--max-threads", "3")
}

func TestApplyRateSingleRequestToolsRunUnmodified(t *testing.T) {
	b := &Bounds{Rate: 5}
	args := []string{"ldapsearch", "-x", "-H", "ldap://x"}

	got := b.ApplyRate(args)
	if got.Skip {
		t.Fatal("ApplyRate skipped a single-request tool")
	}
	if got.Class != RateSingleRequest {
		t.Errorf("Class = %v, want RateSingleRequest", got.Class)
	}
	if len(got.Args) != len(args) {
		t.Errorf("ApplyRate modified a single-request tool: %v", got.Args)
	}
}

func TestApplyRateSkipsUnthrottledTools(t *testing.T) {
	b := &Bounds{Rate: 5}

	got := b.ApplyRate([]string{"cmseek", "-u", "http://x"})
	if !got.Skip {
		t.Fatal("ApplyRate did not skip an unthrottled tool under a rate cap")
	}
	if got.Reason == "" {
		t.Error("ApplyRate skipped a tool without giving a reason")
	}
	if got.Class != RateUnthrottled {
		t.Errorf("Class = %v, want RateUnthrottled", got.Class)
	}
}

func TestApplyRateRunsUnthrottledToolsWhenOverridden(t *testing.T) {
	b := &Bounds{Rate: 5, AllowUnthrottledTools: true}

	got := b.ApplyRate([]string{"cmseek", "-u", "http://x"})
	if got.Skip {
		t.Error("ApplyRate skipped an unthrottled tool despite AllowUnthrottledTools")
	}
}

func TestApplyRateIsInertWithoutARateCap(t *testing.T) {
	// Without --rate nothing is skipped and nothing is rewritten, so existing
	// behaviour is untouched for callers who pass no bounds at all.
	b := &Bounds{}

	got := b.ApplyRate([]string{"cmseek", "-u", "http://x"})
	if got.Skip {
		t.Error("ApplyRate skipped a tool with no rate cap in force")
	}
	got = b.ApplyRate([]string{"ffuf", "-u", "http://x"})
	if len(got.Args) != 3 {
		t.Errorf("ApplyRate rewrote arguments with no rate cap in force: %v", got.Args)
	}
}

func TestUnknownToolIsTreatedAsUnthrottled(t *testing.T) {
	// Failing closed: a newly added tool is skipped and reported under --rate
	// rather than quietly running uncapped.
	if IsClassified("some-brand-new-scanner") {
		t.Fatal("test fixture is actually in the table; pick another name")
	}
	got := (&Bounds{Rate: 5}).ApplyRate([]string{"some-brand-new-scanner"})
	if !got.Skip {
		t.Error("an unclassified tool was not skipped under a rate cap")
	}
}

func TestGentlePresetPreservesExistingArgs(t *testing.T) {
	// Folding gentle mode into the shared code path must not change what gentle
	// mode does. whatweb in particular takes -a (an aggression level), not the
	// --max-threads the generic mapping would choose.
	b := GentlePreset()

	tests := []struct {
		args     []string
		wantFlag string
		wantVal  string
	}{
		{args: []string{"ffuf", "-u", "http://x"}, wantFlag: "-rate", wantVal: "50"},
		{args: []string{"ffuf", "-u", "http://x"}, wantFlag: "-t", wantVal: "2"},
		{args: []string{"dirsearch", "-u", "http://x"}, wantFlag: "-t", wantVal: "2"},
		{args: []string{"gobuster", "dir"}, wantFlag: "-t", wantVal: "5"},
		{args: []string{"hydra", "-L", "u"}, wantFlag: "-t", wantVal: "2"},
		{args: []string{"wpscan", "--url", "http://x"}, wantFlag: "--max-threads", wantVal: "1"},
		{args: []string{"whatweb", "http://x"}, wantFlag: "-a", wantVal: "1"},
	}

	for _, tt := range tests {
		t.Run(tt.args[0]+tt.wantFlag, func(t *testing.T) {
			got := b.ApplyRate(tt.args)
			if got.Skip {
				t.Fatalf("gentle preset skipped %q", tt.args[0])
			}
			assertFlag(t, got.Args, tt.wantFlag, tt.wantVal)
		})
	}
}

func TestGentlePresetDoesNotSkipUnthrottledTools(t *testing.T) {
	// Gentle mode has never skipped anything and must not start.
	got := GentlePreset().ApplyRate([]string{"cmseek", "-u", "http://x"})
	if got.Skip {
		t.Error("gentle preset skipped a tool; gentle mode must not change coverage")
	}
}

// variableToolSpellings names the argument slices whose first element is a
// variable rather than a literal, and every tool name that variable can hold.
//
// This is an explicit, reviewed exception list, not a way round the check: an
// unlisted variable fails the test, and every spelling listed still has to appear
// in the capability table. testssl is the one such site — the Kali package
// installs the binary as 'testssl.sh' and a manual install as 'testssl', and the
// launch site picks whichever exists — so both spellings are classified.
var variableToolSpellings = map[string][]string{
	"testssl": {"testssl", "testssl.sh"},
}

// TestEveryLaunchedToolIsClassified walks the source tree for the argument
// slices that launch external tools and asserts each tool has an explicit table
// entry. Without this, a tool added later silently falls into the unthrottled
// class and is skipped under --rate, which is safe but surprising.
func TestEveryLaunchedToolIsClassified(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	// Two shapes are recognised: a string literal as the first element, which is
	// the tool name outright, and an identifier, where the name is only known at
	// run time. The identifier form has to be matched too — a launch site written
	// as []string{someTool, ...} would otherwise slip past the check entirely,
	// which is how testssl came to be launched with no table entry at all.
	literalPattern := regexp.MustCompile(`[A-Za-z0-9_]+Args\s*:?=\s*\[\]string\{\s*"([a-zA-Z0-9_.-]+)"`)
	identifierPattern := regexp.MustCompile(`[A-Za-z0-9_]+Args\s*:?=\s*\[\]string\{\s*([a-zA-Z_][A-Za-z0-9_]*)\s*,`)

	var unclassified []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, readErr := os.ReadFile(path) //nolint:gosec // walking a fixed source tree in a test
		if readErr != nil {
			return readErr
		}
		for _, m := range literalPattern.FindAllStringSubmatch(string(data), -1) {
			if !IsClassified(m[1]) {
				unclassified = append(unclassified, m[1]+" (in "+path+")")
			}
		}
		for _, m := range identifierPattern.FindAllStringSubmatch(string(data), -1) {
			spellings, known := variableToolSpellings[m[1]]
			if !known {
				unclassified = append(unclassified, "variable '"+m[1]+"' (in "+path+
					") holds a tool name chosen at run time: add its spellings to variableToolSpellings in this test")
				continue
			}
			for _, spelling := range spellings {
				if !IsClassified(spelling) {
					unclassified = append(unclassified, spelling+" (via variable '"+m[1]+"' in "+path+")")
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking source tree: %v", err)
	}

	if len(unclassified) > 0 {
		t.Errorf("tools launched but absent from the rate capability table in tools.go:\n  %s",
			strings.Join(unclassified, "\n  "))
	}
}

// assertFlag fails unless args contains flag immediately followed by value.
func assertFlag(t *testing.T, args []string, flag, value string) {
	t.Helper()
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			if args[i+1] != value {
				t.Errorf("flag %s = %q, want %q (args: %v)", flag, args[i+1], value, args)
			}
			return
		}
	}
	t.Errorf("flag %s not found in args: %v", flag, args)
}

// TestApplyRateNeverLoosensAnExistingThrottle covers the case a low rate hides:
// when the cap is higher than the value a launch site already passes, applying it
// would raise the tool's throttle and make a bounded run more aggressive than an
// unbounded one. A cap is a ceiling, so the gentler of the two must win.
func TestApplyRateNeverLoosensAnExistingThrottle(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		rate      int
		flag      string
		wantValue string
	}{
		// The real dirsearch launch site carries -t 10; --rate 50 must not raise it.
		{
			name:      "thread count already lower than the cap",
			args:      []string{"dirsearch", "-t", "10", "-u", "http://example.invalid"},
			rate:      50,
			flag:      "-t",
			wantValue: "10",
		},
		// hydra -t 4 from the brute helper, same shape.
		{
			name:      "hydra threads already lower than the cap",
			args:      []string{"hydra", "-t", "4", "-f", "ssh://example.invalid"},
			rate:      50,
			flag:      "-t",
			wantValue: "4",
		},
		// wpscan --max-threads 5 from the WordPress path.
		{
			name:      "wpscan threads already lower than the cap",
			args:      []string{"wpscan", "--url", "http://example.invalid", "--max-threads", "5"},
			rate:      50,
			flag:      "--max-threads",
			wantValue: "5",
		},
		// A cap below the existing value must still bite.
		{
			name:      "cap lower than the existing thread count still applies",
			args:      []string{"dirsearch", "-t", "10", "-u", "http://example.invalid"},
			rate:      3,
			flag:      "-t",
			wantValue: "3",
		},
		// No value present: the derived one is used, as before.
		{
			name:      "no existing thread count",
			args:      []string{"gobuster", "dir", "-u", "http://example.invalid"},
			rate:      4,
			flag:      "-t",
			wantValue: "4",
		},
		// An inter-request delay inverts the comparison: onesixtyone -w 100 is one
		// packet every 100ms, ten a second. A cap of 50/s derives 20ms, which would
		// be four times faster, so the existing 100ms is the value that survives.
		{
			name:      "existing delay is longer than the cap implies",
			args:      []string{"onesixtyone", "-c", "list", "example.invalid", "-w", "100"},
			rate:      50,
			flag:      "-w",
			wantValue: "100",
		},
		// A cap gentler than the existing delay still applies.
		{
			name:      "cap implies a longer delay than the one present",
			args:      []string{"onesixtyone", "-c", "list", "example.invalid", "-w", "100"},
			rate:      2,
			flag:      "-w",
			wantValue: "500",
		},
		// A value that cannot be parsed is ignored rather than trusted.
		{
			name:      "unparseable existing value falls back to the derived one",
			args:      []string{"dirsearch", "-t", "lots", "-u", "http://example.invalid"},
			rate:      7,
			flag:      "-t",
			wantValue: "7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Bounds{Rate: tt.rate}
			result := b.ApplyRate(tt.args)
			if result.Skip {
				t.Fatalf("ApplyRate skipped %q unexpectedly: %s", tt.args[0], result.Reason)
			}
			assertFlag(t, result.Args, tt.flag, tt.wantValue)
		})
	}
}

// TestApplyRateEmptyArgsIsUnclassified verifies the empty-argument guard does not
// return RateFlagged by omission. Class is consumed by the run summary, so a
// zero-valued Class would be reported as rate-capped traffic that never existed.
func TestApplyRateEmptyArgsIsUnclassified(t *testing.T) {
	b := &Bounds{Rate: 5}
	result := b.ApplyRate(nil)

	if result.Class != RateUnclassified {
		t.Errorf("Class = %d, want RateUnclassified (%d)", result.Class, RateUnclassified)
	}
	if note := result.Class.Note(); note != "" {
		t.Errorf("Note() = %q, want an empty string so no note is recorded", note)
	}
}

// TestTestsslIsClassified pins the classification of the one tool launched
// through a variable, in both spellings. Without a table entry it was skipped
// under --rate by accident of the fail-closed default rather than by decision,
// and no summary line told the caller TLS coverage had been dropped.
func TestTestsslIsClassified(t *testing.T) {
	for _, spelling := range []string{"testssl", "testssl.sh"} {
		if !IsClassified(spelling) {
			t.Errorf("%q has no capability table entry", spelling)
		}
		if got := RateFor(spelling).Class; got != RateUnthrottled {
			t.Errorf("RateFor(%q).Class = %d, want RateUnthrottled (%d)", spelling, got, RateUnthrottled)
		}
	}
}
