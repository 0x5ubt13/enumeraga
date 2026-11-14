package commands

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/0x5ubt13/enumeraga/internal/config"
	"github.com/0x5ubt13/enumeraga/internal/types"
	"github.com/xuri/excelize/v2"
)

// openGeneratedReport runs generateReport into a temp dir and opens the single
// workbook it wrote.
func openGeneratedReport(t *testing.T, findings []types.Finding) *excelize.File {
	t.Helper()
	dir := t.TempDir()
	if err := generateReport(findings, &config.CloudConfig{OutputPath: dir}); err != nil {
		t.Fatalf("generateReport: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "cloud_security_scan_*.xlsx"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("want exactly one report, got %v (err %v)", matches, err)
	}
	f, err := excelize.OpenFile(matches[0])
	if err != nil {
		t.Fatalf("open report: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestGenerateReportSheets(t *testing.T) {
	findings := []types.Finding{
		{ID: "1", Provider: "aws", Tool: "prowler", Severity: "HIGH", Resource: "s3://bucket", Description: "public bucket"},
		{ID: "2", Provider: "azure", Tool: "scoutsuite", Severity: "LOW", Resource: "vm-1", Description: "no disk encryption"},
	}
	f := openGeneratedReport(t, findings)

	sheets := f.GetSheetList()
	if slices.Contains(sheets, "Sheet1") {
		t.Errorf("default Sheet1 left in report: %v", sheets)
	}
	for _, want := range []string{"Summary", "aws", "azure"} {
		if !slices.Contains(sheets, want) {
			t.Errorf("sheet %q missing: %v", want, sheets)
		}
	}
	for _, s := range sheets {
		rows, err := f.GetRows(s)
		if err != nil {
			t.Fatalf("read sheet %s: %v", s, err)
		}
		if len(rows) < 2 {
			t.Errorf("sheet %s has %d rows, want a header and data", s, len(rows))
		}
	}
	if got := f.GetSheetName(f.GetActiveSheetIndex()); got != "Summary" {
		t.Errorf("active sheet = %q, want Summary", got)
	}
}

func TestGenerateReportNoFindings(t *testing.T) {
	f := openGeneratedReport(t, nil)
	if sheets := f.GetSheetList(); !slices.Equal(sheets, []string{"Summary"}) {
		t.Errorf("sheets = %v, want only Summary", sheets)
	}
}
