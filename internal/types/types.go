package types

type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

type Finding struct {
	ID          string
	Provider    string
	Tool        string
	Severity    Severity
	Resource    string
	Service     string
	Region      string
	Description string
	Remediation string
	RawData     interface{}
}

type ScanResult struct {
	Provider  string
	Tool      string
	Findings  []Finding
	RawOutput string
	Error     error
}
