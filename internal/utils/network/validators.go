package network

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ValidateIP checks if the provided string is a valid IPv4 or IPv6 address
func ValidateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// ResolveHostToIP resolves a hostname or URL to an IP address.
// Accepts domain names, URLs (any scheme), and already-valid IPs.
func ResolveHostToIP(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	// Strip scheme (http://, https://, ftp://, …)
	if _, after, ok := strings.Cut(host, "://"); ok {
		host = after
	}

	// Strip path and port
	if h, _, ok := strings.Cut(host, "/"); ok {
		host = h
	}
	if h, _, ok := strings.Cut(host, ":"); ok {
		host = h
	}

	// Re-check: might have been a URL containing a bare IP
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("failed to resolve hostname %s: %v", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for hostname: %s", host)
	}

	// Prefer IPv4; fall back to first IPv6
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}
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

// validatePortRange validates a single "start-end" port range token.
func validatePortRange(token string) error {
	parts := strings.SplitN(token, "-", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid port range format: %s", token)
	}
	if err := ValidatePort(parts[0]); err != nil {
		return err
	}
	if err := ValidatePort(parts[1]); err != nil {
		return err
	}
	start, _ := strconv.Atoi(parts[0])
	end, _ := strconv.Atoi(parts[1])
	if start > end {
		return fmt.Errorf("invalid port range: %s - start port greater than end port", token)
	}
	return nil
}

// ValidatePorts checks if the provided comma-separated port list is valid.
// Supports individual ports and ranges (e.g. "80,443,8000-9000").
func ValidatePorts(ports string) error {
	for _, token := range strings.Split(ports, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if strings.Contains(token, "-") {
			if err := validatePortRange(token); err != nil {
				return err
			}
			continue
		}
		if err := ValidatePort(token); err != nil {
			return err
		}
	}
	return nil
}

// ValidateFilePath checks if the provided file path exists and is readable
func ValidateFilePath(path string) error {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
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
