package helpers

import (
	"strings"
	"testing"
)

func TestGetKubeconfigClusterNameDefault(t *testing.T) {
	t.Setenv("KUBEUSER_CLUSTER_NAME", "")

	if got := GetKubeconfigClusterName(); got != DefaultKubeconfigClusterName {
		t.Fatalf("GetKubeconfigClusterName() = %q, want %q", got, DefaultKubeconfigClusterName)
	}
}

func TestGetKubeconfigClusterNameCustom(t *testing.T) {
	t.Setenv("KUBEUSER_CLUSTER_NAME", "production")

	if got := GetKubeconfigClusterName(); got != "production" {
		t.Fatalf("GetKubeconfigClusterName() = %q, want production", got)
	}
}

func TestValidateKubeconfigClusterName(t *testing.T) {
	tests := []struct {
		name        string
		clusterName string
		wantErr     bool
	}{
		// Accepted: DNS-1123 labels.
		{
			name:        "default",
			clusterName: DefaultKubeconfigClusterName,
			wantErr:     false,
		},
		{
			name:        "custom",
			clusterName: "production",
			wantErr:     false,
		},
		{
			name:        "hyphenated region",
			clusterName: "prod-eu-west-1",
			wantErr:     false,
		},
		{
			name:        "single character",
			clusterName: "a",
			wantErr:     false,
		},
		{
			name:        "max length 63",
			clusterName: strings.Repeat("a", 63),
			wantErr:     false,
		},
		// Rejected: violations of the DNS-1123 label rule.
		{
			name:        "empty",
			clusterName: "",
			wantErr:     true,
		},
		{
			name:        "uppercase",
			clusterName: "Production",
			wantErr:     true,
		},
		{
			name:        "all uppercase",
			clusterName: "PROD",
			wantErr:     true,
		},
		{
			name:        "underscore",
			clusterName: "prod_east",
			wantErr:     true,
		},
		{
			name:        "over 63 characters",
			clusterName: strings.Repeat("a", 64),
			wantErr:     true,
		},
		{
			name:        "leading hyphen",
			clusterName: "-prod",
			wantErr:     true,
		},
		{
			name:        "trailing hyphen",
			clusterName: "prod-",
			wantErr:     true,
		},
		{
			name:        "leading whitespace",
			clusterName: " production",
			wantErr:     true,
		},
		{
			name:        "embedded whitespace",
			clusterName: "prod east",
			wantErr:     true,
		},
		{
			name:        "context separator",
			clusterName: "prod@east",
			wantErr:     true,
		},
		{
			name:        "yaml separator",
			clusterName: "prod:east",
			wantErr:     true,
		},
		{
			name:        "dot separator",
			clusterName: "prod.east",
			wantErr:     true,
		},
		{
			name:        "newline",
			clusterName: "prod\neast",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKubeconfigClusterName(tt.clusterName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateKubeconfigClusterName(%q) error = %v, wantErr %v", tt.clusterName, err, tt.wantErr)
			}
		})
	}
}
