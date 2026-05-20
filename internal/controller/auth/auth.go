package auth

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/metrics"
	certv1 "k8s.io/api/certificates/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Auth type constants
const (
	AuthTypeX509 = "x509"
	AuthTypeOIDC = "oidc"
)

// Default values for authentication configuration
const (
	DefaultTTL = "2160h" // 90 days
)

// Provider defines the interface for authentication providers
type Provider interface {
	// Ensure creates or updates authentication credentials for the user
	// Returns (bool, *ctrl.Result, error) where:
	// - bool: true if status fields were changed
	// - *ctrl.Result: non-nil if immediate requeue is needed
	// - error: actual error that should stop reconciliation
	Ensure(ctx context.Context, user *authv1alpha1.User) (bool, *ctrl.Result, error)

	// Revoke removes authentication credentials for the user
	Revoke(ctx context.Context, user *authv1alpha1.User) error
}

// Manager handles routing to appropriate auth providers
type Manager struct {
	client        client.Client
	eventRecorder record.EventRecorder
	x509          Provider
	oidc          Provider
	signerName    string // Configurable signer for managed K8s support
	metrics       *metrics.Recorder
}

// NewManager creates a new auth manager with the provided client, event recorder, optional signer name, and metrics recorder
func NewManager(c client.Client, eventRecorder record.EventRecorder, signerName string, metricsRecorder *metrics.Recorder) *Manager {
	// Default to standard Kubernetes signer if not specified
	if signerName == "" {
		signerName = certv1.KubeAPIServerClientSignerName
	}
	return &Manager{
		client:        c,
		eventRecorder: eventRecorder,
		x509:          NewX509Provider(c, eventRecorder, signerName, metricsRecorder),
		oidc:          NewOIDCProvider(c),
		signerName:    signerName,
		metrics:       metricsRecorder,
	}
}

// Ensure delegates to the appropriate auth provider based on user spec.
// Returns (bool, *ctrl.Result, error) where:
// - bool: true if status fields were changed
// - *ctrl.Result: non-nil if immediate requeue is needed
// - error: actual error that should stop reconciliation
func (m *Manager) Ensure(ctx context.Context, user *authv1alpha1.User) (bool, *ctrl.Result, error) {
	provider, err := m.getProvider(user)
	if err != nil {
		return false, nil, err
	}

	return provider.Ensure(ctx, user)
}

// Revoke delegates to the appropriate auth provider based on user spec
func (m *Manager) Revoke(ctx context.Context, user *authv1alpha1.User) error {
	provider, err := m.getProvider(user)
	if err != nil {
		return err
	}

	return provider.Revoke(ctx, user)
}

// getProvider returns the appropriate auth provider based on user spec
// MANDATORY IDENTITY: Auth type must be explicitly specified (no defaults)
func (m *Manager) getProvider(user *authv1alpha1.User) (Provider, error) {
	// MANDATORY IDENTITY ENFORCEMENT: Auth must be non-nil
	if user.Spec.Auth == nil {
		return nil, fmt.Errorf("authentication section is mandatory: spec.auth must be specified")
	}

	// MANDATORY IDENTITY ENFORCEMENT: Type must be non-nil pointer
	if user.Spec.Auth.Type == nil {
		return nil, fmt.Errorf("authentication type is mandatory: spec.auth.type must be specified")
	}

	authType := *user.Spec.Auth.Type

	// MANDATORY IDENTITY ENFORCEMENT: No defaulting - type must be explicit
	if authType == "" {
		return nil, fmt.Errorf("authentication type is mandatory: spec.auth.type must be specified")
	}

	switch authType {
	case AuthTypeX509:
		return m.x509, nil
	case AuthTypeOIDC:
		return m.oidc, nil
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", authType)
	}
}

// ValidateAuthSpec validates the auth specification for the user
// MANDATORY IDENTITY: Enforces explicit authentication type specification
func ValidateAuthSpec(user *authv1alpha1.User) error {
	// SECURITY: Reject usernames with 'system:' prefix to prevent CN spoofing.
	// Kubernetes reserves the 'system:' prefix for built-in identities (e.g.,
	// system:kube-controller-manager, system:serviceaccount:...). Allowing user
	// resources with this prefix would generate X.509 certificates whose Subject
	// CN matches a privileged identity, enabling privilege escalation via CN
	// spoofing.
	if strings.HasPrefix(user.Name, "system:") {
		return fmt.Errorf("username %q is invalid: the 'system:' prefix is reserved for Kubernetes built-in identities and cannot be used to prevent certificate CN spoofing", user.Name)
	}

	// MANDATORY IDENTITY ENFORCEMENT: Auth must be non-nil
	if user.Spec.Auth == nil {
		return fmt.Errorf("authentication section is mandatory: spec.auth must be specified")
	}

	authSpec := *user.Spec.Auth

	// MANDATORY IDENTITY ENFORCEMENT: Auth type must be explicitly specified (nil pointer check)
	if authSpec.Type == nil || *authSpec.Type == "" {
		return fmt.Errorf("authentication type is mandatory: spec.auth.type must be specified (e.g., 'x509' or 'oidc')")
	}

	authType := *authSpec.Type

	// Validate auth type is supported
	if authType != AuthTypeX509 && authType != AuthTypeOIDC {
		return fmt.Errorf("unsupported auth type: %s, must be '%s' or '%s'", authType, AuthTypeX509, AuthTypeOIDC)
	}

	// Validate TTL for x509
	if authType == AuthTypeX509 {
		if authSpec.TTL != "" {
			duration, err := time.ParseDuration(authSpec.TTL)
			if err != nil {
				return fmt.Errorf("invalid TTL format: %v", err)
			}

			if duration <= 0 {
				return fmt.Errorf("TTL must be positive, got: %v", duration)
			}

			// Enforce minimum duration (configurable for testing)
			minDuration := getMinimumDuration()
			if duration < minDuration {
				return fmt.Errorf("TTL must be at least %v, got: %v", minDuration, duration)
			}

			// Enforce maximum duration (1 year)
			maxDuration := 365 * 24 * time.Hour
			if duration > maxDuration {
				return fmt.Errorf("TTL must not exceed %v, got: %v", maxDuration, duration)
			}
		}
	}

	// For OIDC, TTL is ignored (placeholder)

	return nil
}

// GetAuthDuration returns the parsed duration from auth spec, with defaults
func GetAuthDuration(user *authv1alpha1.User) time.Duration {
	// Default duration is 90 days (2160h)
	defaultDuration := 90 * 24 * time.Hour

	// Defensive check: if Auth is nil, return default
	if user.Spec.Auth == nil {
		return defaultDuration
	}

	authSpec := *user.Spec.Auth

	if authSpec.TTL == "" {
		return defaultDuration
	}

	duration, err := time.ParseDuration(authSpec.TTL)
	if err != nil {
		return defaultDuration
	}

	return duration
}

// getMinimumDuration returns the minimum allowed duration for certificates
// Production minimum: 24 hours (hardcoded to prevent Thundering Herd loops)
// Internal Override: KUBEUSER_MIN_DURATION (for CI/CD and testing only, not documented)
func getMinimumDuration() time.Duration {
	// Internal testing override (not documented in Helm values.yaml)
	if minDurStr := os.Getenv("KUBEUSER_MIN_DURATION"); minDurStr != "" {
		if minDur, err := time.ParseDuration(minDurStr); err == nil {
			return minDur
		}
	}
	// Production minimum is 24 hours to prevent excessive renewal loops
	return 24 * time.Hour
}

// GetSafeAuthSpec returns a nil-safe AuthSpec with defaults applied.
// This is the SINGLE SOURCE OF TRUTH for authentication defaults across the entire system.
// Used by: Webhook (mutation), Controller (reconciliation), and Validation logic.
//
// Logic:
// - If user.Spec.Auth is nil, returns a zero-spec (validation will handle the error)
// - If Type is nil, returns zero-spec (invalid configuration)
// - Applies dynamic defaults from environment variables (Helm bridge):
//   - TTL: KUBEUSER_DEFAULT_TTL (fallback: 2160h = 90 days)
//   - AutoRenew: KUBEUSER_DEFAULT_AUTORENEW (fallback: true)
//
// This ensures the mutating webhook persists the exact same defaults that the controller expects,
// and respects the SRE's Helm values.yaml configuration.
func GetSafeAuthSpec(user *authv1alpha1.User) authv1alpha1.AuthSpec {
	// Return zero-spec if Auth is nil; webhook prevents this in production
	if user.Spec.Auth == nil {
		return authv1alpha1.AuthSpec{}
	}

	spec := *user.Spec.Auth

	// Handle nil Type pointer - return zero-spec to signify invalid configuration
	if spec.Type == nil {
		return authv1alpha1.AuthSpec{}
	}

	// Apply dynamic defaults for secondary fields (Helm bridge)
	if spec.TTL == "" {
		// Read from environment variable (set by Helm values.yaml)
		defaultTTL := os.Getenv("KUBEUSER_DEFAULT_TTL")
		if defaultTTL == "" {
			defaultTTL = DefaultTTL // Fallback to production standard (2160h = 90 days)
		}
		spec.TTL = defaultTTL
	}

	if spec.AutoRenew == nil {
		// Read from environment variable (set by Helm values.yaml)
		defaultAutoRenew := true // Production default
		if autoRenewStr := os.Getenv("KUBEUSER_DEFAULT_AUTORENEW"); autoRenewStr != "" {
			// Parse boolean from string (true/false, 1/0, yes/no)
			switch autoRenewStr {
			case "false", "0", "no", "False", "NO":
				defaultAutoRenew = false
			}
		}
		spec.AutoRenew = &defaultAutoRenew
	}

	return spec
}
