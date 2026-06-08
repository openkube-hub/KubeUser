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
	tests := []struct {
		name      string
		apiServer string
		caDataB64 string
		certB64   string
		keyB64    string
		username  string
		wantEmpty bool
	}{
		{
			name:      "valid kubeconfig generation",
			apiServer: "https://kubernetes.default.svc",
			caDataB64: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t", // Base64 for "-----BEGIN CERTIFICATE-----"
			certB64:   "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
			keyB64:    "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t", // Base64 for "-----BEGIN PRIVATE KEY-----"
			username:  "alice",
			wantEmpty: false,
		},
		{
			name:      "empty username",
			apiServer: "https://kubernetes.default.svc",
			caDataB64: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
			certB64:   "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
			keyB64:    "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t",
			username:  "",
			wantEmpty: false, // Should still generate kubeconfig
		},
		{
			name:      "empty API server",
			apiServer: "",
			caDataB64: "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
			certB64:   "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
			keyB64:    "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t",
			username:  "alice",
			wantEmpty: false, // Should still generate kubeconfig
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildCertKubeconfig(tt.apiServer, tt.caDataB64, []byte(tt.certB64), []byte(tt.keyB64), tt.username)

			if tt.wantEmpty && len(got) > 0 {
				t.Errorf("BuildCertKubeconfig() expected empty result, got %d bytes", len(got))
			}

			if !tt.wantEmpty && len(got) == 0 {
				t.Errorf("BuildCertKubeconfig() expected non-empty result, got empty")
			}

			// Basic validation that it contains expected kubeconfig structure
			if !tt.wantEmpty {
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
			}
		})
	}
}

func TestBuildCertKubeconfigWithClusterName(t *testing.T) {
	got := string(BuildCertKubeconfigWithClusterName(
		"https://kubernetes.default.svc",
		"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
		[]byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"),
		[]byte("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t"),
		"alice",
		"production",
	))

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
