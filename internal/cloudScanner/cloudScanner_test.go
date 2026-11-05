package cloudScanner

import (
	"reflect"
	"testing"
)

func TestProviderToolsOrder(t *testing.T) {
	tests := []struct {
		provider string
		want     []string
	}{
		{"gcp", []string{"gcp_scanner", "gcp_iam_brute", "scoutsuite", "prowler", "cloudfox", "nuclei"}},
		{"k8s", []string{"kubenumerate"}},
		{"azure", []string{"monkey365", "scoutsuite", "prowler", "cloudfox", "nuclei"}},
		{"aws", []string{"aws_enumerator", "scoutsuite", "prowler", "pmapper", "cloudfox"}},
		{"oci", []string{"aws_enumerator", "scoutsuite", "prowler", "cloudfox", "nuclei"}},
		{"", []string{"aws_enumerator", "scoutsuite", "prowler", "cloudfox", "nuclei"}},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			if got := providerTools(tt.provider); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("providerTools(%q) = %v, want %v", tt.provider, got, tt.want)
			}
		})
	}
}
