package common

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestEveryScannerReachesTheRecordingSeam is the completeness check for the nmap
// half of the run record.
//
// The record's nmap entries are written in one place, HandleScanResult. The
// compiler forces every existing caller to pass a ScanRecord, but it cannot force
// a newly written scan function to call HandleScanResult at all -- and a scan that
// skips it reaches the target unrecorded. The port sweeps were exactly that
// oversight: they bypass runNmapScanAsync and touch the tool tracker nowhere, so
// they were invisible to the summary and would have been invisible here too.
//
// Any function that constructs an nmap.Scanner must therefore also call
// HandleScanResult.
func TestEveryScannerReachesTheRecordingSeam(t *testing.T) {
	root := filepath.Join("..", "..", "scans")
	newScanner := regexp.MustCompile(`nmap\.NewScanner\(`)
	seam := regexp.MustCompile(`HandleScanResult\(`)

	var offenders []string
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
		text := string(data)
		made := len(newScanner.FindAllString(text, -1))
		handled := len(seam.FindAllString(text, -1))
		if made > handled {
			offenders = append(offenders, path+": "+strconv.Itoa(made)+" scanners, "+strconv.Itoa(handled)+" HandleScanResult calls")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking scans: %v", err)
	}
	if len(offenders) > 0 {
		t.Errorf("scan functions bypassing the recording seam:\n  %s", strings.Join(offenders, "\n  "))
	}
}
