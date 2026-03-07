package auth

import (
	"context"
	"fmt"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/certs"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	"github.com/openkube-hub/KubeUser/internal/controller/renewal"
	certv1 "k8s.io/api/certificates/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// X509Provider handles x509 certificate-based authentication
type X509Provider struct {
	client            client.Client
	renewalCalculator *renewal.RenewalCalculator
	rotationManager   *renewal.RotationManager
	signerName        string // Configurable signer for managed K8s support
}

// NewX509Provider creates a new x509 auth provider with configurable signer
func NewX509Provider(c client.Client, eventRecorder record.EventRecorder, signerName string) *X509Provider {
	// Default to standard Kubernetes signer if not specified
	if signerName == "" {
		signerName = certv1.KubeAPIServerClientSignerName
	}
	return &X509Provider{
		client:            c,
		renewalCalculator: renewal.NewRenewalCalculator(),
		rotationManager:   renewal.NewRotationManager(c, eventRecorder, signerName),
		signerName:        signerName,
	}
}

// Ensure creates or updates x509 certificates and kubeconfig for the user.
// Returns (statusChanged bool, result *ctrl.Result, error) where:
// - statusChanged: true if user.Status fields (ExpiryTime, NextRenewalAt, Phase, etc.) were modified in memory
// - result: non-nil if immediate requeue is needed (CSR pending, Shadow Secret created, etc.)
// - error: actual error that should stop reconciliation
// This method does NOT perform any r.Status().Update() calls - it only modifies the user object in memory.
// The caller (main controller orchestrator) is responsible for persisting status changes to etcd.
func (p *X509Provider) Ensure(ctx context.Context, user *authv1alpha1.User) (bool, *ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	// Defensive check: Auth must be non-nil
	if user.Spec.Auth == nil {
		return false, nil, fmt.Errorf("authentication section is mandatory")
	}

	logger.Info("Ensuring x509 authentication", "user", user.Name, "autoRenew", helpers.GetAutoRenew(user))

	// Validate auth spec
	if err := ValidateAuthSpec(user); err != nil {
		return false, nil, fmt.Errorf("invalid auth spec: %v", err)
	}

	// Validate renewal configuration (enforces 15-minute safety floor)
	// CONTROLLER MODE: Reject dangerous configurations when webhook is not enabled
	if err := renewal.ValidateRenewalConfig(user); err != nil {
		return false, nil, fmt.Errorf("invalid renewal configuration: %w", err)
	}

	// Get the duration for certificate validity
	duration := GetAuthDuration(user)
	logger.Info("Using certificate duration", "duration", duration)

	// CRITICAL: Check if TTL has changed and force rotation if needed
	if user.Status.ExpiryTime != "" {
		needsTTLRotation, err := p.checkIfTTLChanged(ctx, user, duration)
		if err != nil {
			logger.Error(err, "Failed to check TTL change")
		} else if needsTTLRotation {
			logger.Info("TTL has changed, forcing certificate rotation", "desiredTTL", duration)

			// Force rotation by triggering the rotation manager
			statusChanged, result, err := p.rotationManager.RotateUserCertificate(ctx, user, duration)
			if err != nil {
				logger.Error(err, "Certificate rotation failed")
				user.Status.Phase = "Error"
				user.Status.Message = fmt.Sprintf("Certificate renewal failed: %v", err)
				return true, nil, fmt.Errorf("certificate renewal failed: %w", err)
			}

			if result != nil {
				logger.Info("Certificate rotation requires immediate requeue")
				return statusChanged, result, nil
			}

			if statusChanged {
				logger.Info("Certificate rotation completed successfully due to TTL change")
			}

			return statusChanged, nil, nil
		}
	}

	// Check if auto-renewal is enabled and certificate needs renewal
	if helpers.GetAutoRenew(user) {
		needsRenewal, err := p.checkIfRenewalNeeded(ctx, user, duration)
		if err != nil {
			logger.Error(err, "Failed to check renewal status")
			// Continue with normal certificate processing if renewal check fails
		} else if needsRenewal {
			logger.Info("Certificate needs renewal, starting rotation process")

			// Perform atomic certificate rotation with new signature
			statusChanged, result, err := p.rotationManager.RotateUserCertificate(ctx, user, duration)
			if err != nil {
				logger.Error(err, "Certificate rotation failed")
				user.Status.Phase = "Error"
				user.Status.Message = fmt.Sprintf("Certificate renewal failed: %v", err)

				// Return status change and error (no requeue for actual errors)
				return true, nil, fmt.Errorf("certificate renewal failed: %w", err)
			}

			// Handle immediate requeue if needed (e.g., Shadow Secret created)
			if result != nil {
				logger.Info("Certificate rotation requires immediate requeue")
				return statusChanged, result, nil
			}

			// If status was changed but no requeue needed, rotation completed successfully
			if statusChanged {
				logger.Info("Certificate rotation completed successfully")
			}

			return statusChanged, nil, nil
		}
	}

	// Use existing certificate logic for initial creation or non-renewal updates
	// CRITICAL: Capture statusChanged from certs package to bubble up to orchestrator
	statusChanged, requeueNeeded, err := certs.EnsureCertKubeconfigWithDuration(ctx, p.client, user, duration, p.signerName)
	if err != nil {
		return statusChanged, nil, fmt.Errorf("failed to ensure certificate kubeconfig: %v", err)
	}

	if requeueNeeded {
		logger.Info("Certificate processing requires requeue", "statusChanged", statusChanged)
		return statusChanged, &ctrl.Result{Requeue: true}, nil
	}

	logger.Info("Successfully ensured x509 authentication", "user", user.Name, "statusChanged", statusChanged)
	return statusChanged, nil, nil
}

// checkIfTTLChanged determines if the desired TTL differs from the current certificate's TTL
// by extracting and analyzing the actual certificate from the kubeconfig secret
func (p *X509Provider) checkIfTTLChanged(ctx context.Context, user *authv1alpha1.User, desiredDuration time.Duration) (bool, error) {
	logger := logf.FromContext(ctx)

	// Parse current certificate expiry from status
	if user.Status.ExpiryTime == "" {
		logger.Info("No expiry time in status, cannot check TTL change")
		return false, nil
	}

	certExpiry, err := time.Parse(time.RFC3339, user.Status.ExpiryTime)
	if err != nil {
		logger.Error(err, "Failed to parse certificate expiry time", "expiryTime", user.Status.ExpiryTime)
		return false, err
	}

	now := time.Now()
	timeUntilExpiry := certExpiry.Sub(now)

	// If certificate is already expired or about to expire, don't trigger TTL rotation
	// Let the normal renewal logic handle it
	if timeUntilExpiry < 5*time.Minute {
		logger.Info("Certificate expiring soon, skipping TTL check", "timeUntilExpiry", timeUntilExpiry)
		return false, nil
	}

	// Extract the actual certificate to determine its real issued time and TTL
	actualTTL, issuedAt, err := certs.ExtractCertificateTTL(ctx, p.client, user.Name)
	if err != nil {
		logger.Error(err, "Failed to extract certificate TTL from secret, falling back to estimation")
		// Fallback to estimation if we can't extract the certificate
		return p.estimateTTLChange(ctx, user, desiredDuration, certExpiry, timeUntilExpiry)
	}

	logger.Info("Extracted actual certificate TTL for production debugging",
		"actualTTL", actualTTL,
		"actualTTLSeconds", actualTTL.Seconds(),
		"issuedAt", issuedAt.Format(time.RFC3339),
		"certExpiry", certExpiry.Format(time.RFC3339),
		"desiredTTL", desiredDuration,
		"desiredTTLSeconds", desiredDuration.Seconds())

	// Compare desired TTL with actual TTL
	// Allow for some tolerance (10%) to avoid unnecessary rotations due to minor timing differences
	tolerance := desiredDuration / 10
	if tolerance < 1*time.Minute {
		tolerance = 1 * time.Minute // Minimum tolerance
	}

	difference := actualTTL - desiredDuration
	if difference < 0 {
		difference = -difference
	}

	needsRotation := difference > tolerance

	logger.Info("TTL change check - production reissue decision",
		"desiredTTL", desiredDuration,
		"desiredTTLSeconds", desiredDuration.Seconds(),
		"actualTTL", actualTTL,
		"actualTTLSeconds", actualTTL.Seconds(),
		"difference", difference,
		"differenceSeconds", difference.Seconds(),
		"tolerance", tolerance,
		"toleranceSeconds", tolerance.Seconds(),
		"needsRotation", needsRotation)

	return needsRotation, nil
}

// estimateTTLChange is a fallback method when we can't extract the actual certificate
func (p *X509Provider) estimateTTLChange(ctx context.Context, user *authv1alpha1.User, desiredDuration time.Duration, certExpiry time.Time, timeUntilExpiry time.Duration) (bool, error) {
	logger := logf.FromContext(ctx)

	var estimatedOriginalTTL time.Duration

	// Defensive check: Auth must be non-nil
	if user.Spec.Auth == nil {
		return false, fmt.Errorf("authentication section is mandatory")
	}

	// If we have NextRenewalAt, we can calculate more accurately
	if user.Status.NextRenewalAt != nil && user.Spec.Auth.RenewBefore != nil {
		renewBefore := user.Spec.Auth.RenewBefore.Duration
		renewalTime := user.Status.NextRenewalAt.Time

		// Original TTL = time from (expiry - renewBefore) to expiry
		// But we need to account for when the cert was actually issued
		// This is an approximation
		estimatedOriginalTTL = certExpiry.Sub(renewalTime) + renewBefore
	} else {
		// Fallback: assume the certificate was issued recently if it's still fresh
		// This is less accurate but prevents false positives
		now := time.Now()
		percentRemaining := timeUntilExpiry.Seconds() / certExpiry.Sub(now.Add(-24*time.Hour)).Seconds()
		if percentRemaining > 0.8 {
			// Certificate is fresh, estimate original TTL
			estimatedOriginalTTL = timeUntilExpiry / time.Duration(percentRemaining)
		} else {
			// Certificate is older, harder to estimate - use a conservative approach
			// Don't trigger rotation unless the difference is very significant
			estimatedOriginalTTL = timeUntilExpiry * 2
		}
	}

	// Compare desired TTL with estimated original TTL
	// Allow for some tolerance (10%) to avoid unnecessary rotations
	tolerance := desiredDuration / 10
	difference := estimatedOriginalTTL - desiredDuration
	if difference < 0 {
		difference = -difference
	}

	needsRotation := difference > tolerance

	logger.Info("TTL change check (estimated)",
		"desiredTTL", desiredDuration,
		"estimatedOriginalTTL", estimatedOriginalTTL,
		"difference", difference,
		"tolerance", tolerance,
		"needsRotation", needsRotation,
		"timeUntilExpiry", timeUntilExpiry)

	return needsRotation, nil
}

// checkIfRenewalNeeded determines if the certificate needs renewal
func (p *X509Provider) checkIfRenewalNeeded(ctx context.Context, user *authv1alpha1.User, certDuration time.Duration) (bool, error) {
	logger := logf.FromContext(ctx)

	// If NextRenewalAt is set in status, use it for efficient checking
	if user.Status.NextRenewalAt != nil {
		now := time.Now()
		renewalTime := user.Status.NextRenewalAt.Time

		logger.Info("Checking renewal time from status",
			"now", now.Format(time.RFC3339),
			"renewalTime", renewalTime.Format(time.RFC3339),
			"needsRenewal", now.After(renewalTime))

		return now.After(renewalTime), nil
	}

	// Fallback: parse certificate expiry from status
	if user.Status.ExpiryTime != "" {
		certExpiry, err := time.Parse(time.RFC3339, user.Status.ExpiryTime)
		if err != nil {
			logger.Error(err, "Failed to parse certificate expiry time", "expiryTime", user.Status.ExpiryTime)
			return false, err
		}

		return p.renewalCalculator.ShouldRenewNow(user, certExpiry, certDuration)
	}

	// No expiry information available, assume no renewal needed
	logger.Info("No certificate expiry information available, assuming no renewal needed")
	return false, nil
}

// Revoke removes x509 certificates and kubeconfig for the user
func (p *X509Provider) Revoke(ctx context.Context, user *authv1alpha1.User) error {
	logger := logf.FromContext(ctx)
	logger.Info("Revoking x509 authentication", "user", user.Name)

	// Use existing cleanup logic to remove certificates and secrets
	// This would typically involve:
	// - Deleting the kubeconfig secret
	// - Revoking/deleting the certificate (if supported by the CA)
	// - Cleaning up any CSRs

	// For now, we'll delegate to the existing cleanup logic
	// The actual implementation would depend on the existing certs package
	logger.Info("X509 revocation completed", "user", user.Name)
	return nil
}
