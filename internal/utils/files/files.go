package files

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/0x5ubt13/enumeraga/internal/utils/output"
	"github.com/Ullaakut/nmap/v3"
)

// ReadTargetsFile reads the file at *optTarget and returns non-empty, trimmed lines.
func ReadTargetsFile(optTarget *string) ([]string, int) {
	data, err := os.ReadFile(*optTarget)
	if err != nil {
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Failed to read targets file: %v", err))
		return nil, 0
	}
	// Fields splits on any whitespace and discards empty tokens, replacing split+filter.
	lines := strings.Fields(string(data))
	return lines, len(lines)
}

// CustomMkdir creates name (and any parents) and returns the path or an error.
func CustomMkdir(name string) (string, error) {
	if err := os.MkdirAll(name, os.ModePerm); err != nil {
		return "", err
	}
	return name, nil
}

// ProtocolDetected announces a detected protocol, creates its base directory, and returns the path.
func ProtocolDetected(protocol, baseDir string) string {
	output.PrintCustomBiColourMsg("green", "cyan", "[+] '", protocol, "' service detected")

	protocolDir := fmt.Sprintf("%s%s/", baseDir, strings.ToLower(protocol))
	if _, err := CustomMkdir(protocolDir); err != nil {
		output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error creating protocol directory: %v", err))
	}
	return protocolDir
}

// writeLineTo creates (or truncates) filePath and writes a single line to it.
// The caller receives any error; close errors are printed directly.
func writeLineTo(filePath, line string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", filePath, err)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			output.PrintCustomBiColourMsg("red", "cyan", "[-] Error: ", fmt.Sprintf("Error closing file %s: %v", filePath, closeErr))
		}
	}()
	if _, err := fmt.Fprintln(f, line); err != nil {
		return fmt.Errorf("failed to write to file %s: %w", filePath, err)
	}
	return nil
}

// WriteTextToFile writes a text message to filePath, creating it if absent.
func WriteTextToFile(filePath, message string) error {
	return writeLineTo(filePath, message)
}

// WritePortsToFile writes discovered open ports to filePath and announces the result.
func WritePortsToFile(filePath, ports, host string) (string, error) {
	fileName := fmt.Sprintf("%sopen_ports.txt", filePath)
	if err := writeLineTo(fileName, ports); err != nil {
		return "", err
	}
	output.PrintCustomBiColourMsg("green", "yellow", "[+] Successfully written open ports for host '", host, "' to file '", fileName, "'")
	return ports, nil
}

// RemoveDuplicates removes duplicate tokens from a comma-separated string.
func RemoveDuplicates(s string) string {
	seen := make(map[string]bool)
	result := make([]string, 0)
	for _, part := range strings.Split(s, ",") {
		if !seen[part] {
			seen[part] = true
			result = append(result, part)
		}
	}
	return strings.Join(result, ",")
}

// appendOpenPorts appends the ID of every open port found in hosts to slice.
func appendOpenPorts(slice []string, hosts []nmap.Host) []string {
	for _, host := range hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		for _, port := range host.Ports {
			if port.State.String() == "open" {
				slice = append(slice, strconv.FormatUint(uint64(port.ID), 10))
			}
		}
	}
	return slice
}

// GetOpenPortsSlice returns the IDs of all open ports across TCP and UDP sweep results.
func GetOpenPortsSlice(sweptHostTcp, sweptHostUdp []nmap.Host) []string {
	ports := make([]string, 0)
	ports = appendOpenPorts(ports, sweptHostTcp)
	ports = appendOpenPorts(ports, sweptHostUdp)
	return ports
}
