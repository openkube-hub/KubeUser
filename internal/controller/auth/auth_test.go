package auth

import (
	"context"
	"os"
	"testing"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// Helper function to create string pointers for test cases
func stringPtr(s string) *string {
	return &s
}

func TestValidateAuthSpec(t *testing.T) {
	// Save and restore environment variable
	originalMinDuration := os.Getenv("KUBEUSER_MIN_DURATION")
	defer func() {
		if originalMinDuration != "" {
			if err := os.Setenv("KUBEUSER_MIN_DURATION", originalMinDuration); err != nil {
				t.Logf("Failed to restore environment variable: %v", err)
			}
		} else {
			if err := os.Unsetenv("KUBEUSER_MIN_DURATION"); err != nil {
				t.Logf("Failed to unset environment variable: %v", err)
			}
		}
	}()

	// Unset environment variable to test default behavior
	if err := os.Unsetenv("KUBEUSER_MIN_DURATION"); err != nil {
		t.Fatalf("Failed to unset environment variable: %v", err)
	}
	tests := []struct {
		name    string
		user    *authv1alpha1.User
		wantErr bool
	}{
		{
			name: "valid x509 auth - production safe TTL",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						Type: stringPtr(AuthTypeX509),
						TTL:  "720h", // 30 days - production safe
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing auth type - mandatory identity enforcement",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						TTL: "720h",
						// Type is nil - should fail with mandatory identity
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid oidc auth",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						Type: stringPtr(AuthTypeOIDC),
						TTL:  "24h", // ignored for OIDC
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid auth type",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						Type: stringPtr("invalid"),
					},
				},
			},
			wantErr: true,
		},
		{
			name: "negative duration",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						Type: stringPtr(AuthTypeX509),
						TTL:  "-1h",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "duration too short - production hardening enforces 24h minimum",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						Type: stringPtr(AuthTypeX509),
						TTL:  "12h", // Less than 24 hours (production minimum)
					},
				},
			},
			wantErr: true,
		},
		{
			name: "duration too long",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						Type: stringPtr(AuthTypeX509),
						TTL:  "8761h", // More than 1 year (365*24 + 1)
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAuthSpec(tt.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAuthSpec() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetAuthDuration(t *testing.T) {
	tests := []struct {
		name     string
		user     *authv1alpha1.User
		expected time.Duration
	}{
		{
			name: "custom duration - production safe",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						TTL: "720h", // 30 days
					},
				},
			},
			expected: 720 * time.Hour,
		},
		{
			name: "default duration",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{},
				},
			},
			expected: 90 * 24 * time.Hour, // 3 months
		},
		{
			name: "invalid duration falls back to default",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						TTL: "invalid",
					},
				},
			},
			expected: 90 * 24 * time.Hour, // 3 months
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := GetAuthDuration(tt.user)
			if result != tt.expected {
				t.Errorf("GetAuthDuration() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestManager(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = authv1alpha1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	manager := NewManager(client, nil, "", nil) // nil event recorder and metrics for tests, default signer

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-user",
		},
		Spec: authv1alpha1.UserSpec{
			Auth: &authv1alpha1.AuthSpec{
				Type: stringPtr(AuthTypeX509),
				TTL:  "720h", // 30 days - production safe
			},
		},
	}

	ctx := context.Background()

	// Test x509 provider (should work but may fail due to missing dependencies)
	_, _, err := manager.Ensure(ctx, user)
	// We expect this to fail in unit tests due to missing cluster dependencies
	// In integration tests, this would be properly tested
	if err == nil {
		t.Log("X509 ensure succeeded (unexpected in unit test)")
	} else {
		t.Logf("X509 ensure failed as expected in unit test: %v", err)
	}

	// Test OIDC provider (should fail with not implemented)
	user.Spec.Auth.Type = stringPtr(AuthTypeOIDC)
	_, _, err = manager.Ensure(ctx, user)
	if err == nil {
		t.Error("OIDC ensure should fail with not implemented error")
	}
	if err != nil && err.Error() != "OIDC authentication is not yet implemented (stub only)" {
		t.Errorf("Expected OIDC not implemented error, got: %v", err)
	}

	// Test invalid auth type
	user.Spec.Auth.Type = stringPtr("invalid")
	_, err = manager.getProvider(user)
	if err == nil {
		t.Error("Should fail with unsupported auth type")
	}

	// Test missing auth type - mandatory identity enforcement (nil pointer)
	user.Spec.Auth.Type = nil
	_, err = manager.getProvider(user)
	if err == nil {
		t.Error("Should fail with mandatory auth type error")
	}
	if err != nil && err.Error() != "authentication type is mandatory: spec.auth.type must be specified" {
		t.Errorf("Expected mandatory auth type error, got: %v", err)
	}
}
func TestGetMinimumDuration(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected time.Duration
	}{
		{
			name:     "default minimum (no env var) - production hardened to 24h",
			envValue: "",
			expected: 24 * time.Hour,
		},
		{
			name:     "custom minimum via env var for testing",
			envValue: "5m",
			expected: 5 * time.Minute,
		},
		{
			name:     "invalid env var falls back to production default (24h)",
			envValue: "invalid",
			expected: 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				if err := os.Setenv("KUBEUSER_MIN_DURATION", tt.envValue); err != nil {
					t.Fatalf("Failed to set environment variable: %v", err)
				}
			} else {
				if err := os.Unsetenv("KUBEUSER_MIN_DURATION"); err != nil {
					t.Fatalf("Failed to unset environment variable: %v", err)
				}
			}
			defer func() {
				if err := os.Unsetenv("KUBEUSER_MIN_DURATION"); err != nil {
					t.Logf("Failed to cleanup environment variable: %v", err)
				}
			}()

			result := getMinimumDuration()
			if result != tt.expected {
				t.Errorf("getMinimumDuration() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestValidateAuthSpecWithCustomMinimum(t *testing.T) {
	// Test with 5-minute minimum
	if err := os.Setenv("KUBEUSER_MIN_DURATION", "5m"); err != nil {
		t.Fatalf("Failed to set environment variable: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("KUBEUSER_MIN_DURATION"); err != nil {
			t.Logf("Failed to cleanup environment variable: %v", err)
		}
	}()

	tests := []struct {
		name    string
		user    *authv1alpha1.User
		wantErr bool
	}{
		{
			name: "5 minutes should be valid with custom minimum",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						Type: stringPtr(AuthTypeX509),
						TTL:  "5m",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "1 minute should be invalid even with custom minimum",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						Type: stringPtr(AuthTypeX509),
						TTL:  "1m",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAuthSpec(tt.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAuthSpec() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
