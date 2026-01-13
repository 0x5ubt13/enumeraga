package network

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ValidateIP checks if the provided string is a valid IPv4 or IPv6 address
func ValidateIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// ResolveHostToIP resolves a hostname or URL to an IP address
// It accepts domain names (example.com), URLs (http://example.com), and already-valid IPs
// Returns the resolved IP address or error if resolution fails
func ResolveHostToIP(host string) (string, error) {
	// First, try to parse as IP address - if it's already an IP, return it
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// Remove common URL schemes if present (http://, https://, etc.)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "ftp://")

	// Remove path components if URL contains them
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}

	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Try to parse again after cleanup - maybe it was a URL with an IP
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// Perform DNS lookup
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname %s: %v", host, err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for hostname: %s", host)
	}

	// Return the first IPv4 address found, or first IPv6 if no IPv4 exists
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	// If no IPv4 found, return first IPv6
	return ips[0].String(), nil
}

// ValidateCIDR checks if the provided string is a valid CIDR notation
func ValidateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR range: %s - %v", cidr, err)
	}
	return nil
}

// ValidatePort checks if the provided port number is valid (1-65535)
func ValidatePort(port string) error {
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port number: %s - not a number", port)
	}
	if portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port number: %d - must be between 1 and 65535", portNum)
	}
	return nil
}

// ValidatePorts checks if the provided comma-separated port list is valid
func ValidatePorts(ports string) error {
	portList := strings.Split(ports, ",")
	for _, port := range portList {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		// Handle port ranges like "1-100"
		if strings.Contains(port, "-") {
			rangeParts := strings.Split(port, "-")
			if len(rangeParts) != 2 {
				return fmt.Errorf("invalid port range format: %s", port)
			}
			if err := ValidatePort(rangeParts[0]); err != nil {
				return err
			}
			if err := ValidatePort(rangeParts[1]); err != nil {
				return err
			}
			start, _ := strconv.Atoi(rangeParts[0])
			end, _ := strconv.Atoi(rangeParts[1])
			if start > end {
				return fmt.Errorf("invalid port range: %s - start port greater than end port", port)
			}
		} else {
			if err := ValidatePort(port); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateFilePath checks if the provided file path exists and is readable
func ValidateFilePath(path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", path)
	}
	if err != nil {
		return fmt.Errorf("error accessing file: %s - %v", path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("path is a directory, not a file: %s", path)
	}
	return nil
}
