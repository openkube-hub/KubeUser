package helpers

import "testing"

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
			name:        "empty",
			clusterName: "",
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
			wantErr:     false,
		},
		{
			name:        "context separator",
			clusterName: "prod@east",
			wantErr:     false,
		},
		{
			name:        "yaml separator",
			clusterName: "prod:east",
			wantErr:     false,
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
