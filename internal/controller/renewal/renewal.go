/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package renewal

import (
	"fmt"
	"math/rand"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// DefaultRenewalPercentage is the default percentage of certificate lifetime
	// after which renewal should occur (cert-manager style: 1/3 = 33%)
	DefaultRenewalPercentage = 0.33

	// MinimumRenewalBuffer is the absolute minimum time before expiry
	// that we must maintain for short-lived certificates (safety floor)
	MinimumRenewalBuffer = 2 * time.Minute

	// MaxJitterPercentage is the maximum jitter to add to renewal time
	// to prevent thundering herd (5% of renewal window)
	MaxJitterPercentage = 0.05
)

// RenewalCalculator handles smart renewal time calculations
type RenewalCalculator struct {
	// MinRenewalBuffer can be overridden for testing
	MinRenewalBuffer time.Duration
}

// NewRenewalCalculator creates a new renewal calculator
func NewRenewalCalculator() *RenewalCalculator {
	return &RenewalCalculator{
		MinRenewalBuffer: MinimumRenewalBuffer,
	}
}

// CalculateRenewalTime implements the smart renewal calculation logic
// Hierarchy: Custom renewBefore > 33% Rule > Safety Floor
func (rc *RenewalCalculator) CalculateRenewalTime(user *authv1alpha1.User, certExpiry time.Time, certDuration time.Duration) (time.Time, error) {
	var renewalTime time.Time

	if certDuration <= 0 || certExpiry.IsZero() {
		return time.Time{}, fmt.Errorf("invalid duration or expiry")
	}

	// Defensive check: Auth must be non-nil
	if user.Spec.Auth == nil {
		return time.Time{}, fmt.Errorf("authentication section is mandatory")
	}

	// Step 1: Prioritize custom renewBefore
	if user.Spec.Auth.RenewBefore != nil && user.Spec.Auth.RenewBefore.Duration > 0 {
		customRenewBefore := user.Spec.Auth.RenewBefore.Duration

		// Defensive Safety Check: If RenewBefore somehow exceeds TTL (should never happen due to validation),
		// cap it at 50% as a last resort to ensure the cert has some usable life.
		if customRenewBefore >= certDuration {
			customRenewBefore = time.Duration(float64(certDuration) * 0.5)
		}

		renewalTime = certExpiry.Add(-customRenewBefore)
	} else {
		// Step 2: Fallback to 33% rule
		renewalBuffer := time.Duration(float64(certDuration) * DefaultRenewalPercentage)
		renewalTime = certExpiry.Add(-renewalBuffer)
	}

	// Step 3: Global Safety Floor
	// Ensure we NEVER renew later than 2 minutes before expiry
	latestAllowedRenewal := certExpiry.Add(-rc.MinRenewalBuffer)
	if renewalTime.After(latestAllowedRenewal) {
		renewalTime = latestAllowedRenewal
	}

	// Step 4: Don't return a time in the past
	if renewalTime.Before(time.Now()) {
		return time.Now(), nil
	}

	return renewalTime, nil
}

// CalculateRenewalTimeWithJitter adds jitter to prevent thundering herd
func (rc *RenewalCalculator) CalculateRenewalTimeWithJitter(user *authv1alpha1.User, certExpiry time.Time, certDuration time.Duration) (time.Time, error) {
	baseRenewalTime, err := rc.CalculateRenewalTime(user, certExpiry, certDuration)
	if err != nil {
		return time.Time{}, err
	}

	// Calculate jitter window (5% of the renewal buffer)
	renewalBuffer := certExpiry.Sub(baseRenewalTime)
	jitterWindow := time.Duration(float64(renewalBuffer) * MaxJitterPercentage)

	// Add random jitter (can be negative to spread load)
	jitter := time.Duration(rand.Int63n(int64(jitterWindow*2))) - jitterWindow

	return baseRenewalTime.Add(jitter), nil
}

// ShouldRenewNow checks if a certificate should be renewed immediately
func (rc *RenewalCalculator) ShouldRenewNow(user *authv1alpha1.User, certExpiry time.Time, certDuration time.Duration) (bool, error) {
	renewalTime, err := rc.CalculateRenewalTime(user, certExpiry, certDuration)
	if err != nil {
		return false, err
	}

	return !renewalTime.After(time.Now()), nil
}

// GetRequeueAfter calculates the duration until the next renewal check
func (rc *RenewalCalculator) GetRequeueAfter(user *authv1alpha1.User, certExpiry time.Time, certDuration time.Duration) (time.Duration, error) {
	renewalTime, err := rc.CalculateRenewalTimeWithJitter(user, certExpiry, certDuration)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	if renewalTime.Before(now) {
		// Should renew immediately
		return 0, nil
	}

	requeueAfter := renewalTime.Sub(now)

	// Cap the requeue time to reasonable limits
	maxRequeue := 24 * time.Hour
	if requeueAfter > maxRequeue {
		requeueAfter = maxRequeue
	}

	// Minimum requeue time to avoid excessive API calls
	minRequeue := 1 * time.Minute
	if requeueAfter < minRequeue {
		requeueAfter = minRequeue
	}

	return requeueAfter, nil
}

// UpdateUserRenewalStatus updates the user status with renewal information
func (rc *RenewalCalculator) UpdateUserRenewalStatus(user *authv1alpha1.User, certExpiry time.Time, certDuration time.Duration) error {
	// Defensive check: Auth must be non-nil
	if user.Spec.Auth == nil {
		return fmt.Errorf("authentication section is mandatory")
	}

	renewalTime, err := rc.CalculateRenewalTime(user, certExpiry, certDuration)
	if err != nil {
		return err
	}

	// Update status fields with consolidated NextRenewalAt
	user.Status.ExpiryTime = certExpiry.Format(time.RFC3339)

	// Only set NextRenewalAt if auto-renewal is enabled
	if helpers.GetAutoRenew(user) {
		user.Status.NextRenewalAt = &metav1.Time{Time: renewalTime}
	} else {
		// Explicitly clear the field if auto-renewal is disabled
		user.Status.NextRenewalAt = nil
	}

	return nil
}

// ValidateRenewalConfig validates the renewal configuration in the user spec
// Returns error if configuration is invalid or violates safety constraints
// Both webhook and controller reject dangerous configurations (fail-fast architecture)
func ValidateRenewalConfig(user *authv1alpha1.User) error {
	// Defensive check: Auth must be non-nil
	if user.Spec.Auth == nil {
		return fmt.Errorf("authentication section is mandatory")
	}

	if !helpers.GetAutoRenew(user) {
		return nil
	}

	var certDuration time.Duration
	if user.Spec.Auth.TTL != "" {
		d, err := time.ParseDuration(user.Spec.Auth.TTL)
		if err != nil {
			return fmt.Errorf("invalid TTL format: %v", err)
		}
		certDuration = d
	} else {
		certDuration = 90 * 24 * time.Hour // Default 90 days
	}

	if user.Spec.Auth.RenewBefore != nil {
		renewBefore := user.Spec.Auth.RenewBefore.Duration

		if renewBefore <= 0 {
			return fmt.Errorf("renewBefore must be positive")
		}

		// PRODUCTION HARDENING: Strictly reject renewBefore > 90% of TTL
		// This prevents aggressive renewal loops and API-server exhaustion
		maxAllowed := time.Duration(float64(certDuration) * 0.9)
		if renewBefore > maxAllowed {
			return fmt.Errorf("renewBefore (%v) exceeds 90%% of TTL (%v). Maximum allowed: %v. This prevents aggressive renewal loops and API-server exhaustion",
				renewBefore, certDuration, maxAllowed)
		}

		// PRODUCTION HARDENING: Fixed 15-minute safety floor
		// Ensures even short-lived test certificates have guaranteed life before renewal
		const safetyFloor = 15 * time.Minute
		if certDuration-renewBefore < safetyFloor {
			return fmt.Errorf("renewBefore (%v) leaves less than 15 minutes of certificate life (TTL: %v). This would cause immediate renewal loops. Minimum certificate life required: 15m",
				renewBefore, certDuration)
		}
	}
	return nil
}

// CalculateNextRenewal calculates the next renewal time based on certificate info
// PRODUCTION HARDENING: Uses fixed 15-minute safety floor instead of proportional buffer
func CalculateNextRenewal(issuedAt, expiry time.Time, renewBefore *metav1.Duration) metav1.Time {
	certDuration := expiry.Sub(issuedAt)
	var renewalTime time.Time

	if renewBefore != nil {
		renewalTime = expiry.Add(-renewBefore.Duration)
	} else {
		renewalBuffer := time.Duration(float64(certDuration) * DefaultRenewalPercentage)
		renewalTime = expiry.Add(-renewalBuffer)
	}

	// PRODUCTION HARDENING: Fixed 15-minute safety floor
	// Guarantees at least 15 minutes of certificate life before renewal triggers
	// Prevents immediate renewal loops even for short-lived test certificates
	const safetyFloor = 15 * time.Minute
	safetyFloorTime := expiry.Add(-safetyFloor)
	if renewalTime.After(safetyFloorTime) {
		renewalTime = safetyFloorTime
	}

	if renewalTime.Before(time.Now()) {
		renewalTime = time.Now()
	}

	return metav1.Time{Time: renewalTime}
}
