package common

import (
	"context"
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/bounds"
	"github.com/0x5ubt13/enumeraga/internal/utils"
	"github.com/Ullaakut/nmap/v3"
)

// TestRateOptionsCountsByMode checks the option set produced for each mode. The
// nmap option type is an opaque function, so the count and the absence of a
// panic are what can be asserted here; the values themselves are covered by the
// bounds package tests.
func TestRateOptionsCountsByMode(t *testing.T) {
	originalBounds := bounds.Active
	originalGentle := utils.GentleMode
	defer func() {
		bounds.Active = originalBounds
		utils.GentleMode = originalGentle
	}()

	tests := []struct {
		name   string
		gentle bool
		cfg    bounds.Config
		want   int
	}{
		// Unbounded: just the fallback minimum rate, exactly as before.
		{name: "no bounds", want: 1},
		// A rate cap replaces the minimum rate rather than adding to it.
		{name: "rate only", cfg: bounds.Config{Rate: 5}, want: 1},
		// Rate cap plus a parallelism cap.
		{name: "rate and concurrency", cfg: bounds.Config{Rate: 5, Concurrency: 2}, want: 2},
		// Concurrency alone keeps the minimum rate and adds parallelism.
		{name: "concurrency only", cfg: bounds.Config{Concurrency: 2}, want: 2},
		// Gentle mode keeps its own timing template and scan delay.
		{name: "gentle", gentle: true, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := bounds.Validate(tt.cfg)
			if err != nil {
				t.Fatalf("Validate returned an error: %v", err)
			}
			bounds.Active = b
			utils.GentleMode = tt.gentle

			if got := len(RateOptions(DefaultMinRate)); got != tt.want {
				t.Errorf("len(RateOptions()) = %d, want %d", got, tt.want)
			}
		})
	}
}

// rateFlags returns the nmap command-line flags the given options produce.
//
// nmap.Option is an opaque func, so counting options cannot tell --max-rate from
// --min-rate; comparing code pointers cannot either, because the compiler inlines
// these one-line closure producers and each call site then has its own code
// pointer (verified: two nmap.WithMaxRate calls differ). Applying the options to
// a scanner and reading back Scanner.Args() is what actually distinguishes them,
// and asserts the flag nmap would receive rather than an identity that stands in
// for it.
//
// WithBinaryPath is passed so NewScanner does not need nmap installed to build
// the argument list, keeping the test independent of the host.
func rateFlags(t *testing.T, options []nmap.Option) []string {
	t.Helper()
	scanner, err := nmap.NewScanner(context.Background(),
		append([]nmap.Option{nmap.WithBinaryPath("/nonexistent/nmap")}, options...)...)
	if err != nil {
		t.Fatalf("NewScanner returned an error: %v", err)
	}
	return scanner.Args()
}

// assertFlagValue fails unless args contains flag immediately followed by value.
func assertFlagValue(t *testing.T, args []string, flag, value string) {
	t.Helper()
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			if args[i+1] != value {
				t.Errorf("%s = %q, want %q (args: %v)", flag, args[i+1], value, args)
			}
			return
		}
	}
	t.Errorf("%s not present in nmap args: %v", flag, args)
}

// assertNoFlag fails when args contains flag at all.
func assertNoFlag(t *testing.T, args []string, flag string) {
	t.Helper()
	for _, a := range args {
		if a == flag {
			t.Errorf("%s present in nmap args but should not be: %v", flag, args)
		}
	}
}

// TestRateOptionsProduceTheRightNmapFlags pins the identity of each option, not
// just how many there are. A --max-rate that had been written as --min-rate would
// turn the caller's ceiling into a floor — nmap would be told to send at least
// that many packets a second — while leaving every count-based assertion green.
func TestRateOptionsProduceTheRightNmapFlags(t *testing.T) {
	originalBounds := bounds.Active
	originalGentle := utils.GentleMode
	defer func() {
		bounds.Active = originalBounds
		utils.GentleMode = originalGentle
	}()
	utils.GentleMode = false

	t.Run("rate cap becomes --max-rate and drops --min-rate", func(t *testing.T) {
		b, err := bounds.Validate(bounds.Config{Rate: 5})
		if err != nil {
			t.Fatalf("Validate returned an error: %v", err)
		}
		bounds.Active = b

		args := rateFlags(t, RateOptions(DefaultMinRate))
		assertFlagValue(t, args, "--max-rate", "5")
		assertNoFlag(t, args, "--min-rate")
		assertNoFlag(t, args, "--max-parallelism")
	})

	t.Run("no rate cap keeps the fallback --min-rate", func(t *testing.T) {
		b, err := bounds.Validate(bounds.Config{})
		if err != nil {
			t.Fatalf("Validate returned an error: %v", err)
		}
		bounds.Active = b

		args := rateFlags(t, RateOptions(DefaultMinRate))
		assertFlagValue(t, args, "--min-rate", "500")
		assertNoFlag(t, args, "--max-rate")
	})

	t.Run("concurrency becomes --max-parallelism", func(t *testing.T) {
		b, err := bounds.Validate(bounds.Config{Rate: 5, Concurrency: 2})
		if err != nil {
			t.Fatalf("Validate returned an error: %v", err)
		}
		bounds.Active = b

		args := rateFlags(t, RateOptions(DefaultMinRate))
		assertFlagValue(t, args, "--max-rate", "5")
		assertFlagValue(t, args, "--max-parallelism", "2")
		assertNoFlag(t, args, "--min-rate")
	})
}
