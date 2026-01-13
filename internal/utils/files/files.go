package files

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/utils/output"
	"github.com/Ullaakut/nmap/v3"
)

// ReadTargetsFile from the argument path passed to -t; returns targets and count
func ReadTargetsFile(optTarget *string) ([]string, int) {
	data, err := os.ReadFile(*optTarget)
	if err != nil {
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Failed to read targets file: %v", err))
		return nil, 0
	}

	// Get lines
	lines := strings.Split(string(data), "\n")
	// Filter out empty lines
	nonEmptyLines := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			nonEmptyLines = append(nonEmptyLines, trimmedLine)
		}
	}
	return nonEmptyLines, len(nonEmptyLines)
}

// CustomMkdir checks first if it is possible to create new dir, and send custom msg if not.
func CustomMkdir(name string) (string, error) {
	err := os.MkdirAll(name, os.ModePerm)
	if err != nil {
		return "", err
	}
	return name, nil
}

// ProtocolDetected announces protocol, creates base dir and returns its name
func ProtocolDetected(protocol, baseDir string) string {
	output.PrintCustomBiColourMsg("green", "cyan", "[+] '", protocol, "' service detected")

	protocolDir := fmt.Sprintf("%s%s/", baseDir, strings.ToLower(protocol))
	_, err := CustomMkdir(protocolDir)
	if err != nil {
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error creating protocol directory: %v", err))
	}

	return protocolDir
}

// WriteTextToFile writes a text message to a file at the specified path.
// Creates the file if it doesn't exist, overwrites if it does.
func WriteTextToFile(filePath string, message string) error {
	// Open file
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer func(f *os.File) {
		if closeErr := f.Close(); closeErr != nil {
			output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error closing file %s: %v", filePath, closeErr))
		}
	}(f)

	// Write to it
	if _, err := fmt.Fprintln(f, message); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", filePath, err)
	}
	return nil
}

// WritePortsToFile writes discovered open ports to a file and announces the results.
// Returns the ports string and any error encountered.
func WritePortsToFile(filePath string, ports string, host string) (string, error) {
	// Open file
	fileName := fmt.Sprintf("%sopen_ports.txt", filePath)
	f, err := os.Create(fileName)
	if err != nil {
		return "", fmt.Errorf("failed to create ports file %s: %w", fileName, err)
	}
	defer func(f *os.File) {
		if closeErr := f.Close(); closeErr != nil {
			output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error closing file %s: %v", fileName, closeErr))
		}
	}(f)

	// Write to it
	if _, err := fmt.Fprintln(f, ports); err != nil {
		return "", fmt.Errorf("failed to write ports to file %s: %w", fileName, err)
	}
	output.PrintCustomBiColourMsg("green", "yellow", "[+] Successfully written open ports for host '", host, "' to file '", fileName, "'")

	return ports, nil
}

// RemoveDuplicates removes duplicate ports from the comma-separated ports string
func RemoveDuplicates(s string) string {
	parts := strings.Split(s, ",")
	seen := make(map[string]bool)
	result := make([]string, 0)

	for _, part := range parts {
		if !seen[part] {
			seen[part] = true
			result = append(result, part)
		}
	}
	return strings.Join(result, ",")
}

// GetOpenPortsSlice creates a string slice using strconv.FormatUint and append strings to it.
func GetOpenPortsSlice(sweptHostTcp, sweptHostUdp []nmap.Host) []string {
	openPortsSlice := make([]string, 0)

	for _, host := range sweptHostTcp {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			if port.State.String() == "open" {
				text := strconv.FormatUint(uint64(port.ID), 10)
				openPortsSlice = append(openPortsSlice, text)
			}
		}
	}

	// Same than above but for the swept ports running on UDP
	for _, host := range sweptHostUdp {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		for _, port := range host.Ports {
			if port.State.String() == "open" {
				text := strconv.FormatUint(uint64(port.ID), 10)
				openPortsSlice = append(openPortsSlice, text)
			}
		}
	}
	return openPortsSlice
}
