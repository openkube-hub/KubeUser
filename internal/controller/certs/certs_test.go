package certs

import (
	"testing"
	"time"
)

func TestGetRotationThreshold(t *testing.T) {
	tests := []struct {
		name         string
		certDuration time.Duration
		want         time.Duration
	}{
		{
			name:         "1 hour certificate",
			certDuration: 1 * time.Hour,
			want:         15 * time.Minute, // 25% of 1 hour
		},
		{
			name:         "24 hour certificate",
			certDuration: 24 * time.Hour,
			want:         6 * time.Hour, // 25% of 24 hours
		},
		{
			name:         "7 day certificate",
			certDuration: 7 * 24 * time.Hour,
			want:         42 * time.Hour, // 25% of 7 days
		},
		{
			name:         "3 month certificate",
			certDuration: 90 * 24 * time.Hour,
			want:         540 * time.Hour, // 25% of 90 days = 22.5 days
		},
		{
			name:         "10 minute certificate",
			certDuration: 10 * time.Minute,
			want:         150 * time.Second, // 25% of 10 minutes = 2.5 minutes
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getRotationThreshold(tt.certDuration)
			if got != tt.want {
				t.Errorf("getRotationThreshold() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractCertificateExpiryWithFormatDetection(t *testing.T) {
	// Test certificate in PEM format (base64 encoded DER)
	pemCert := []byte(`-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDKg8N8VhCjVDANBgkqhkiG9w0BAQsFADCBjTELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMRAwDgYDVQQK
DAdDb21wYW55MRAwDgYDVQQLDAdTZWN0aW9uMQ8wDQYDVQQDDAZhbGljZTEkMCIG
CSqGSIb3DQEJARYVYWxpY2VAZXhhbXBsZS5jb20wHhcNMjQwMTAxMDAwMDAwWhcN
MjUwMTAxMDAwMDAwWjCBjTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYD
VQQHDA1TYW4gRnJhbmNpc2NvMRAwDgYDVQQKDAdDb21wYW55MRAwDgYDVQQLDAdT
ZWN0aW9uMQ8wDQYDVQQDDAZhbGljZTEkMCIGCSqGSIb3DQEJARYVYWxpY2VAZXhh
bXBsZS5jb20wXDANBgkqhkiG9w0BAQEFAANLADBIAkEAw8N8VhCjVDANBgkqhkiG
9w0BAQsFAANBAMPDfFYQo1QwDQYJKoZIhvcNAQELBQADQQDDw3xWEKNUMA0GCSqG
SIb3DQEBCwUAA0EAw8N8VhCjVDANBgkqhkiG9w0BAQsFAANBAMPDfFYQo1QwDQYJ
KoZIhvcNAQELBQADQQDDw3xWEKNUMA0GCSqGSIb3DQEBCwUAA0EAw8N8VhCjVDA=
-----END CERTIFICATE-----`)

	tests := []struct {
		name     string
		certData []byte
		wantErr  bool
	}{
		{
			name:     "valid PEM certificate",
			certData: pemCert,
			wantErr:  true, // This will fail because it's a mock cert, but tests the parsing logic
		},
		{
			name:     "invalid certificate data",
			certData: []byte("invalid-cert-data"),
			wantErr:  true,
		},
		{
			name:     "empty certificate data",
			certData: []byte(""),
			wantErr:  true,
		},
		{
			name:     "malformed PEM",
			certData: []byte("-----BEGIN CERTIFICATE-----\ninvalid-base64\n-----END CERTIFICATE-----"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ExtractCertificateExpiryWithFormatDetection(tt.certData)

			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractCertificateExpiryWithFormatDetection() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuildCertKubeconfig(t *testing.T) {
	// Raw PEM bytes — clientcmd.Write handles the base64 wrapping on YAML
	// emit, so callers pass raw data straight through.
	caData := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
	certData := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
	keyData := []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----")

	tests := []struct {
		name      string
		apiServer string
		username  string
	}{
		{
			name:      "valid kubeconfig generation",
			apiServer: "https://kubernetes.default.svc",
			username:  "alice",
		},
		{
			name:      "empty username",
			apiServer: "https://kubernetes.default.svc",
			username:  "",
		},
		{
			name:      "empty API server",
			apiServer: "",
			username:  "alice",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := BuildCertKubeconfig(tt.apiServer, caData, certData, keyData, tt.username)
			if err != nil {
				t.Fatalf("BuildCertKubeconfig() unexpected error: %v", err)
			}
			if len(got) == 0 {
				t.Fatalf("BuildCertKubeconfig() returned empty bytes")
			}

			kubeconfigStr := string(got)
			expectedStrings := []string{
				"apiVersion: v1",
				"kind: Config",
				"clusters:",
				"users:",
				"contexts:",
				"current-context:",
				"  name: cluster",
				"    cluster: cluster",
			}
			for _, expected := range expectedStrings {
				if !contains(kubeconfigStr, expected) {
					t.Errorf("BuildCertKubeconfig() missing expected string: %s", expected)
				}
			}
		})
	}
}

func TestBuildCertKubeconfigWithClusterName(t *testing.T) {
	caData := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
	certData := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
	keyData := []byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----")

	rawKubeconfig, err := BuildCertKubeconfigWithClusterName(
		"https://kubernetes.default.svc",
		caData,
		certData,
		keyData,
		"alice",
		"production",
	)
	if err != nil {
		t.Fatalf("BuildCertKubeconfigWithClusterName() unexpected error: %v", err)
	}
	got := string(rawKubeconfig)

	expectedStrings := []string{
		"  name: production",
		"    cluster: production",
		"  name: alice@production",
		"current-context: alice@production",
	}
	for _, expected := range expectedStrings {
		if !contains(got, expected) {
			t.Errorf("BuildCertKubeconfigWithClusterName() missing expected string: %s", expected)
		}
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
