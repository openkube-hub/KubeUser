/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package renewal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"sync/atomic"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/certs"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	"github.com/openkube-hub/KubeUser/internal/controller/metrics"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// RotationState represents the current state of certificate rotation
type RotationState int

const (
	RotationStateIdle RotationState = iota
	RotationStateGeneratingKey
	RotationStateCreatingCSR
	RotationStateApprovingCSR
	RotationStateWaitingForCert
	RotationStateUpdatingSecret
	RotationStateComplete
	RotationStateError
)

// RotationManager handles atomic certificate rotation with forward secrecy
type RotationManager struct {
	client        client.Client
	eventRecorder record.EventRecorder
	signerName    string // Configurable signer for managed K8s support (EKS, GKE, AKS)
	clusterName   string // Configurable kubeconfig cluster name
	metrics       *metrics.Recorder
	// concurrentRotations tracks in-flight rotations owned by this manager
	// instance. Per-instance so parallel tests do not share a global counter.
	concurrentRotations atomic.Int64
}

// NewRotationManager creates a new rotation manager with configurable signer
func NewRotationManager(k8sClient client.Client, eventRecorder record.EventRecorder, signerName, clusterName string, metricsRecorder *metrics.Recorder) *RotationManager {
	// Default to standard Kubernetes signer if not specified
	if signerName == "" {
		signerName = certv1.KubeAPIServerClientSignerName
	}
	if clusterName == "" {
		clusterName = helpers.DefaultKubeconfigClusterName
	}
	return &RotationManager{
		client:        k8sClient,
		eventRecorder: eventRecorder,
		signerName:    signerName,
		clusterName:   clusterName,
		metrics:       metricsRecorder,
	}
}

// RotateUserCertificate performs stateful certificate rotation using Shadow Secret pattern.
// Returns (changed bool, result *ctrl.Result, error) where:
// - changed: true if any status fields were modified and need API persistence
// - result: non-nil if immediate requeue is needed (e.g., Shadow Secret created)
// - error: actual error that should stop reconciliation
func (rm *RotationManager) RotateUserCertificate(ctx context.Context, user *authv1alpha1.User, certDuration time.Duration) (bool, *ctrl.Result, error) {
	start := time.Now()
	logger := logf.FromContext(ctx)
	username := user.Name

	// Track concurrent rotations
	current := rm.concurrentRotations.Add(1)
	if rm.metrics != nil {
		rm.metrics.SetConcurrentRotations(int(current))
		rm.metrics.SetRotationQueueLength(int(current))
	}
	defer func() {
		remaining := rm.concurrentRotations.Add(-1)
		if rm.metrics != nil {
			rm.metrics.ObserveCertRotationDuration(user.Namespace, time.Since(start))
			rm.metrics.SetConcurrentRotations(int(remaining))
			rm.metrics.SetRotationQueueLength(int(remaining))
		}
	}()

	// Step 1: Check for existing Shadow Secret (Source of Truth for rotation state)
	shadowSecret, shadowExists, err := rm.getShadowSecret(ctx, username)
	if err != nil {
		if rm.metrics != nil {
			rm.metrics.RecordRotationError(user.Namespace, username, "shadow_secret_check")
		}
		return false, nil, fmt.Errorf("failed to check shadow secret: %w", err)
	}

	// If Shadow Secret exists, we MUST be in Renewing state regardless of User.Status.Phase
	if shadowExists {
		// Trust check: any resource sitting at the shadow-secret name that this
		// operator did not create is treated as externally planted. Resuming
		// rotation from it would build a CSR against the planted private key and
		// write that key into <user>-kubeconfig on the atomic flip.
		if !helpers.IsOwnedByUser(shadowSecret, user) {
			logger.Error(nil, "Shadow Secret is not owned by this User, refusing to resume rotation from it",
				"shadowSecret", shadowSecret.Name, "userUID", user.UID)
			rm.eventRecorder.Event(user, "Warning", "ShadowSecretUntrusted",
				"Found a shadow secret not owned by this User; deleting it and refusing to resume rotation")
			if rm.metrics != nil {
				rm.metrics.RecordRotationError(user.Namespace, username, "shadow_secret_untrusted")
			}
			if err := rm.deleteShadowSecret(ctx, username); err != nil {
				return false, nil, fmt.Errorf("failed to delete untrusted shadow secret: %w", err)
			}
			return false, nil, fmt.Errorf("shadow secret %s is not owned by user %s (uid=%s); deleted and refusing to resume",
				shadowSecret.Name, username, user.UID)
		}

		logger.Info("Shadow Secret found, ensuring Renewing state", "shadowSecret", shadowSecret.Name)

		// Force status to reflect the rotation state (Shadow Secret as Source of Truth)
		statusChanged := false
		if user.Status.Phase != helpers.PhaseRenewing {
			logger.Info("Forcing Phase to Renewing based on Shadow Secret existence")
			user.Status.Phase = helpers.PhaseRenewing
			user.Status.Message = "Certificate rotation in progress"
			statusChanged = true

			// Emit event for state transition
			rm.eventRecorder.Event(user, "Normal", "RotationResumed", "Resuming certificate rotation from Shadow Secret")
		}

		// Continue with rotation process
		return rm.continueRotationFromShadow(ctx, user, shadowSecret, certDuration, statusChanged)
	}

	// Step 2: No Shadow Secret exists, start new rotation
	logger.Info("Starting new certificate rotation", "user", username)

	// Update status to Renewing with initial rotation step
	user.Status.Phase = helpers.PhaseRenewing
	user.Status.RotationStep = "GeneratingKey"
	user.Status.Message = "Starting certificate renewal"

	// Create Shadow Secret first (this makes rotation atomic)
	err = rm.createShadowSecretForRotation(ctx, user)
	if err != nil {
		return false, nil, fmt.Errorf("failed to create shadow secret: %w", err)
	}

	// Update rotation step after successful Shadow Secret creation
	user.Status.RotationStep = "CreatingCSR"

	// Emit event for rotation start
	rm.eventRecorder.Event(user, "Normal", "RotationStarted", "Certificate rotation initiated")

	logger.Info("Shadow Secret created, status updated to Renewing", "phase", user.Status.Phase, "rotationStep", user.Status.RotationStep)

	// Return immediate requeue to ensure status is persisted before continuing
	return true, &ctrl.Result{Requeue: true}, nil
}

// continueRotationFromShadow continues the rotation process from an existing Shadow Secret
func (rm *RotationManager) continueRotationFromShadow(ctx context.Context, user *authv1alpha1.User, shadowSecret *corev1.Secret, certDuration time.Duration, statusChanged bool) (bool, *ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	username := user.Name

	// Extract rotation metadata from Shadow Secret
	csrName, exists := shadowSecret.Annotations[authv1alpha1.CSRNameAnnotation]
	if !exists {
		logger.Error(nil, "Shadow Secret missing CSR name annotation - non-recoverable, cleaning up", "shadowSecret", shadowSecret.Name)
		rm.eventRecorder.Event(user, "Warning", "RotationCorrupted", "Shadow Secret missing CSR annotation, resetting rotation state")

		// State Machine Recovery: Delete corrupted Shadow Secret to allow fresh rotation
		if err := rm.deleteShadowSecret(ctx, username); err != nil {
			logger.Error(err, "Failed to cleanup corrupted shadow secret")
		}

		return false, nil, fmt.Errorf("shadow secret missing CSR name annotation (cleaned up for recovery)")
	}

	logger.Info("Continuing rotation from Shadow Secret", "csrName", csrName, "currentPhase", user.Status.Phase, "currentRotationStep", user.Status.RotationStep)

	// Ensure Phase is Renewing (Shadow Secret is source of truth)
	if user.Status.Phase != helpers.PhaseRenewing {
		logger.Info("Forcing Phase to Renewing during rotation continuation")
		user.Status.Phase = helpers.PhaseRenewing
		user.Status.Message = "Certificate rotation in progress"
		statusChanged = true
	}

	// Extract private key from Shadow Secret
	keyPEM, exists := shadowSecret.Data["key.pem"]
	if !exists {
		logger.Error(nil, "Shadow Secret missing private key - non-recoverable, cleaning up", "shadowSecret", shadowSecret.Name)
		rm.eventRecorder.Event(user, "Warning", "RotationCorrupted", "Shadow Secret missing private key, resetting rotation state")

		// State Machine Recovery: Delete corrupted Shadow Secret to allow fresh rotation
		if err := rm.deleteShadowSecret(ctx, username); err != nil {
			logger.Error(err, "Failed to cleanup corrupted shadow secret")
		}

		return statusChanged, nil, fmt.Errorf("shadow secret missing private key (cleaned up for recovery)")
	}

	// CRITICAL FIX: Ensure CSR exists before checking approval status
	// This handles the case where Shadow Secret was created but CSR creation was interrupted
	logger.Info("Ensuring CSR exists", "csrName", csrName)
	_, err := rm.ensureCSRExists(ctx, user, csrName, username, keyPEM, certDuration)
	if err != nil {
		rm.eventRecorder.Event(user, "Warning", "CSRCreationFailed", fmt.Sprintf("Failed to ensure CSR %s: %v", csrName, err))
		return statusChanged, nil, fmt.Errorf("failed to ensure CSR exists: %w", err)
	}

	// Update rotation step based on current state
	if user.Status.RotationStep != "WaitingForApproval" {
		user.Status.RotationStep = "WaitingForApproval"
		statusChanged = true
	}

	// Step 3: Check CSR status and approve if needed
	approved, signedCert, err := rm.ensureCSRApprovedAndGetCert(ctx, csrName, username, keyPEM)
	if err != nil {
		rm.eventRecorder.Event(user, "Warning", "CSRApprovalFailed", fmt.Sprintf("Failed to approve CSR %s: %v", csrName, err))
		if rm.metrics != nil {
			rm.metrics.RecordRotationError(user.Namespace, username, "csr_approval")
		}
		return statusChanged, nil, fmt.Errorf("failed to ensure CSR approval: %w", err)
	}

	if !approved {
		logger.Info("CSR not yet approved, requeuing", "csrName", csrName, "statusChanged", statusChanged)
		rm.eventRecorder.Event(user, "Normal", "CSRPending", fmt.Sprintf("Waiting for CSR %s approval", csrName))
		// Return statusChanged=true to ensure Renewing state is persisted before requeue
		return statusChanged, &ctrl.Result{RequeueAfter: 10 * time.Second}, nil
	}

	logger.Info("CSR approved, performing atomic flip", "csrName", csrName)
	rm.eventRecorder.Event(user, "Normal", "CSRApproved", fmt.Sprintf("CSR %s approved, performing atomic secret update", csrName))

	// Update rotation step for atomic flip
	if user.Status.RotationStep != "PerformingAtomicFlip" {
		user.Status.RotationStep = "PerformingAtomicFlip"
		statusChanged = true
	}

	// Step 4: Perform atomic secret update
	err = rm.atomicSecretUpdate(ctx, user, keyPEM, signedCert)
	if err != nil {
		rm.eventRecorder.Event(user, "Warning", "AtomicFlipFailed", fmt.Sprintf("Atomic secret update failed: %v", err))
		rm.recordUniqueAttempt(user, authv1alpha1.RenewalAttempt{
			Timestamp: metav1.Now(),
			Success:   false,
			Message:   fmt.Sprintf("Atomic flip failed: %v", err),
			CSRName:   csrName,
		})
		if rm.metrics != nil {
			rm.metrics.RecordRotationError(user.Namespace, username, "atomic_flip")
			rm.metrics.RecordCertRotation(user.Namespace, username, "failure")
		}
		return statusChanged, nil, err
	}

	logger.Info("Atomic flip completed successfully")
	rm.eventRecorder.Event(user, "Normal", "RotationCompleted", "Certificate rotation completed successfully")

	// Update rotation step for finalization
	if user.Status.RotationStep != "Finalizing" {
		user.Status.RotationStep = "Finalizing"
		statusChanged = true
	}

	// Step 5: Finalize & Cleanup
	_ = rm.cleanupRotationResources(ctx, username, csrName)

	// Update user status after successful rotation
	statusUpdated, err := rm.updateUserStatusAfterRotation(user, signedCert, certDuration)
	if err != nil {
		logger.Error(err, "Failed to update user status after rotation")
		return true, nil, err // Status was changed during rotation, but final update failed
	}

	if statusUpdated {
		statusChanged = true
	}

	rm.recordUniqueAttempt(user, authv1alpha1.RenewalAttempt{
		Timestamp: metav1.Now(),
		Success:   true,
		Message:   "Certificate rotation completed successfully",
		CSRName:   csrName,
	})

	// Record successful rotation metric
	if rm.metrics != nil {
		rm.metrics.RecordCertRotation(user.Namespace, username, "success")
		// Update cert expiry timestamp
		if expiry, err := rm.extractCertificateExpiry(signedCert); err == nil {
			rm.metrics.SetCertExpiry(user.Namespace, username, "client", expiry)
		}
	}

	logger.Info("Rotation completed, status changes ready for persistence", "statusChanged", statusChanged)
	return true, nil, nil // Status was updated successfully
}

// recordUniqueAttempt prevents duplicate log entries and spam
func (rm *RotationManager) recordUniqueAttempt(user *authv1alpha1.User, attempt authv1alpha1.RenewalAttempt) {
	history := user.Status.RenewalHistory

	if len(history) > 0 {
		last := history[len(history)-1]
		// Skip if message and success status are identical to the last entry
		if last.Message == attempt.Message && last.Success == attempt.Success {
			return
		}
	}

	if len(history) >= 10 {
		history = history[1:]
	}

	user.Status.RenewalHistory = append(history, attempt)
}

// generateUniqueCSRName creates a unique CSR name using User UID for true uniqueness
func (rm *RotationManager) generateUniqueCSRName(username, userUID string) string {
	// Use User UID for true uniqueness across the cluster
	// This ensures no collisions even if users are recreated with same name
	return fmt.Sprintf("%s-renewal-%s", username, userUID[:8])
}

// getShadowSecret retrieves the shadow secret if it exists
func (rm *RotationManager) getShadowSecret(ctx context.Context, username string) (*corev1.Secret, bool, error) {
	shadowSecretName := fmt.Sprintf("%s-rotation-temp", username)
	userNamespace := helpers.GetKubeUserNamespace()

	shadowSecret := &corev1.Secret{}
	err := rm.client.Get(ctx, types.NamespacedName{
		Name:      shadowSecretName,
		Namespace: userNamespace,
	}, shadowSecret)

	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("failed to get shadow secret: %w", err)
	}

	return shadowSecret, true, nil
}

// createShadowSecretForRotation creates a shadow secret with generated key and CSR name for rotation
func (rm *RotationManager) createShadowSecretForRotation(ctx context.Context, user *authv1alpha1.User) error {
	username := user.Name
	userUID := string(user.UID)

	// Generate new private key
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(newPrivateKey),
	})

	// Generate unique CSR name
	csrName := rm.generateUniqueCSRName(username, userUID)

	// Create shadow secret with generated key and CSR name
	shadowSecretName := fmt.Sprintf("%s-rotation-temp", username)
	userNamespace := helpers.GetKubeUserNamespace()

	shadowSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      shadowSecretName,
			Namespace: userNamespace,
			Labels: map[string]string{
				authv1alpha1.UserLabel:     username,
				authv1alpha1.RotationLabel: "true",
				authv1alpha1.ShadowLabel:   "true",
			},
			Annotations: map[string]string{
				authv1alpha1.CSRNameAnnotation: csrName,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					// Hardcoded: cache-returned objects have empty TypeMeta and GC ignores refs with empty APIVersion/Kind.
					APIVersion:         authv1alpha1.GroupVersion.String(),
					Kind:               "User",
					Name:               user.Name,
					UID:                user.UID,
					Controller:         &[]bool{true}[0],
					BlockOwnerDeletion: &[]bool{true}[0],
				},
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"key.pem": keyPEM,
		},
	}

	return rm.client.Create(ctx, shadowSecret)
}

// deleteShadowSecret removes the shadow secret
func (rm *RotationManager) deleteShadowSecret(ctx context.Context, username string) error {
	shadowSecretName := fmt.Sprintf("%s-rotation-temp", username)
	userNamespace := helpers.GetKubeUserNamespace()

	shadowSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      shadowSecretName,
			Namespace: userNamespace,
		},
	}

	err := rm.client.Delete(ctx, shadowSecret)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to delete shadow secret: %w", err)
	}

	return nil
}

// ensureCSRExists creates CSR if it doesn't exist, returns existing one otherwise.
// A pre-existing CSR under this deterministic name is validated against the
// shadow-secret key before reuse; a mismatch (attacker-planted CSR under our
// name — see #114) triggers delete-and-recreate so the operator only ever
// signs a request bound to its own key.
func (rm *RotationManager) ensureCSRExists(ctx context.Context, user *authv1alpha1.User, csrName, username string, keyPEM []byte, certDuration time.Duration) (*certv1.CertificateSigningRequest, error) {
	logger := logf.FromContext(ctx)

	// Try to get existing CSR first
	var existingCSR certv1.CertificateSigningRequest
	err := rm.client.Get(ctx, types.NamespacedName{Name: csrName}, &existingCSR)
	if err == nil {
		if valErr := rm.validateCSRForApproval(&existingCSR, username, keyPEM); valErr != nil {
			logger.Info("Existing CSR failed operator validation, replacing", "csrName", csrName, "reason", valErr.Error())
			if delErr := rm.client.Delete(ctx, &existingCSR); delErr != nil && !apierrors.IsNotFound(delErr) {
				return nil, fmt.Errorf("failed to delete untrusted CSR %s: %w", csrName, delErr)
			}
			// Fall through to recreate a CSR bound to the shadow-secret key.
		} else {
			logger.Info("Found existing CSR", "csrName", csrName)
			return &existingCSR, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to check for existing CSR: %w", err)
	}

	// Create CSR from stored key
	logger.Info("Creating new CSR from stored key", "csrName", csrName)
	csrPEM, err := rm.createCSRFromKey(username, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR from stored key: %w", err)
	}

	expirationSeconds := int32(certDuration.Seconds())
	newCSR := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
			Labels: map[string]string{
				authv1alpha1.UserLabel:     username,
				authv1alpha1.RenewalLabel:  "true",
				authv1alpha1.RotationLabel: "true",
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					// Hardcoded: cache-returned objects have empty TypeMeta and GC ignores refs with empty APIVersion/Kind.
					APIVersion:         authv1alpha1.GroupVersion.String(),
					Kind:               "User",
					Name:               user.Name,
					UID:                user.UID,
					Controller:         &[]bool{false}[0], // Not a controller reference to avoid conflicts
					BlockOwnerDeletion: &[]bool{true}[0],
				},
			},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:           csrPEM,
			Usages:            []certv1.KeyUsage{certv1.UsageClientAuth},
			SignerName:        rm.signerName, // Use configurable signer for managed K8s support
			ExpirationSeconds: &expirationSeconds,
		},
	}

	err = rm.client.Create(ctx, newCSR)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	logger.Info("Created new CSR", "csrName", csrName)
	return newCSR, nil
}

// ensureCSRApproved approves the CSR if not already approved
func (rm *RotationManager) ensureCSRApproved(ctx context.Context, csr *certv1.CertificateSigningRequest, expectedUsername string, expectedKeyPEM []byte) (bool, error) {
	logger := logf.FromContext(ctx)

	// Check if already approved
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certv1.CertificateApproved && condition.Status == corev1.ConditionTrue {
			return true, nil
		}
		if condition.Type == certv1.CertificateDenied && condition.Status == corev1.ConditionTrue {
			return false, fmt.Errorf("CSR was denied: %s", condition.Message)
		}
	}

	// Validate CSR before approval for security
	if err := rm.validateCSRForApproval(csr, expectedUsername, expectedKeyPEM); err != nil {
		logger.Error(err, "CSR validation failed", "csrName", csr.Name)
		return false, fmt.Errorf("CSR validation failed: %w", err)
	}

	// Approve the CSR
	logger.Info("Auto-approving validated CSR", "csrName", csr.Name)

	// Get fresh copy of CSR to avoid conflicts
	freshCSR := &certv1.CertificateSigningRequest{}
	err := rm.client.Get(ctx, types.NamespacedName{Name: csr.Name}, freshCSR)
	if err != nil {
		return false, fmt.Errorf("failed to get fresh CSR for approval: %w", err)
	}

	freshCSR.Status.Conditions = append(freshCSR.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:           certv1.CertificateApproved,
		Status:         corev1.ConditionTrue,
		Reason:         "AutoApprovedByKubeUser",
		Message:        "Approved by kubeuser-operator for certificate renewal",
		LastUpdateTime: metav1.Now(),
	})

	// CSR approval goes through the signer which may be slow; bound this subresource write
	// so a stalled signer does not consume the full reconcile budget.
	approvalCtx, approvalCancel := context.WithTimeout(ctx, 30*time.Second)
	defer approvalCancel()

	err = rm.client.SubResource("approval").Update(approvalCtx, freshCSR)
	if err != nil {
		return false, fmt.Errorf("failed to approve CSR: %w", err)
	}

	logger.Info("CSR approved successfully", "csrName", csr.Name)
	return false, nil // Just approved, need to wait for certificate
}

// ensureCSRApprovedAndGetCert checks CSR status, approves if needed, and returns signed certificate
func (rm *RotationManager) ensureCSRApprovedAndGetCert(ctx context.Context, csrName, expectedUsername string, expectedKeyPEM []byte) (bool, []byte, error) {
	logger := logf.FromContext(ctx)

	// Get the CSR
	csr := &certv1.CertificateSigningRequest{}
	err := rm.client.Get(ctx, types.NamespacedName{Name: csrName}, csr)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get CSR: %w", err)
	}

	// Check if already approved and has certificate
	approved := false
	for _, condition := range csr.Status.Conditions {
		if condition.Type == certv1.CertificateApproved && condition.Status == corev1.ConditionTrue {
			approved = true
			break
		}
		if condition.Type == certv1.CertificateDenied && condition.Status == corev1.ConditionTrue {
			return false, nil, fmt.Errorf("CSR was denied: %s", condition.Message)
		}
	}

	// If not approved, approve it
	if !approved {
		_, err := rm.ensureCSRApproved(ctx, csr, expectedUsername, expectedKeyPEM)
		if err != nil {
			return false, nil, err
		}
		// Just approved, need to wait for certificate
		return false, nil, nil
	}

	// Check if certificate is available
	if len(csr.Status.Certificate) == 0 {
		logger.Info("CSR approved but certificate not yet available", "csrName", csrName)
		return false, nil, nil
	}

	logger.Info("CSR approved and certificate available", "csrName", csrName)
	return true, csr.Status.Certificate, nil
}

// cleanupRotationResources removes shadow secret and CSR after successful rotation
func (rm *RotationManager) cleanupRotationResources(ctx context.Context, username, csrName string) error {
	logger := logf.FromContext(ctx)

	// Delete shadow secret
	if err := rm.deleteShadowSecret(ctx, username); err != nil {
		logger.Error(err, "Failed to delete shadow secret", "username", username)
		return fmt.Errorf("failed to delete shadow secret: %w", err)
	}

	// Delete CSR
	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{Name: csrName},
	}

	err := rm.client.Delete(ctx, csr)
	if err != nil && !apierrors.IsNotFound(err) {
		logger.Error(err, "Failed to delete CSR", "csrName", csrName)
		return fmt.Errorf("failed to delete CSR: %w", err)
	}

	logger.Info("Cleanup completed successfully", "username", username, "csrName", csrName)
	return nil
}

// createCSRFromKey creates a CSR from the given private key
func (rm *RotationManager) createCSRFromKey(username string, keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: username,
		},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	}), nil
}

// atomicSecretUpdate performs zero-downtime secret update with rollback capability
func (rm *RotationManager) atomicSecretUpdate(ctx context.Context, user *authv1alpha1.User, newKeyPEM, signedCert []byte) error {
	// Bound the entire atomic flip (2 Get + 2 CreateOrUpdate + 1 rollback path).
	// All calls are simple etcd writes that should never need more than 30s.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	logger := logf.FromContext(ctx)
	username := user.Name
	userNamespace := helpers.GetKubeUserNamespace()

	// Get cluster CA and API server info
	caData, err := rm.getClusterCA(ctx)
	if err != nil {
		return fmt.Errorf("failed to get cluster CA: %w", err)
	}

	apiServer := rm.getAPIServerURL()

	// Build new kubeconfig before touching either target secret; if serialization
	// fails we abort here instead of half-writing the shadow-flip.
	newKubeconfig, err := rm.buildKubeconfig(apiServer, caData, signedCert, newKeyPEM, username)
	if err != nil {
		return fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	// Backup existing secrets for rollback
	keySecretName := fmt.Sprintf("%s-key", username)
	cfgSecretName := fmt.Sprintf("%s-kubeconfig", username)

	var oldKeySecret, oldCfgSecret *corev1.Secret

	// Backup key secret
	oldKeySecret = &corev1.Secret{}
	err = rm.client.Get(ctx, types.NamespacedName{Name: keySecretName, Namespace: userNamespace}, oldKeySecret)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to backup key secret: %w", err)
	}
	if apierrors.IsNotFound(err) {
		oldKeySecret = nil // No existing secret to backup
	}

	// Backup kubeconfig secret
	oldCfgSecret = &corev1.Secret{}
	err = rm.client.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: userNamespace}, oldCfgSecret)
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to backup kubeconfig secret: %w", err)
	}
	if apierrors.IsNotFound(err) {
		oldCfgSecret = nil // No existing secret to backup
	}

	// Update key secret first with ResourceVersion checking. Owner refs are set
	// so ensurePrivateKey's trust check on the next reconcile recognizes this
	// secret as operator-created rather than treating it as externally planted.
	keySecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      keySecretName,
			Namespace: userNamespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         authv1alpha1.GroupVersion.String(),
					Kind:               "User",
					Name:               user.Name,
					UID:                user.UID,
					Controller:         &[]bool{true}[0],
					BlockOwnerDeletion: &[]bool{true}[0],
				},
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"key.pem": newKeyPEM,
		},
	}

	// If we have an existing secret, preserve its ResourceVersion for concurrency safety
	if oldKeySecret != nil {
		keySecret.ResourceVersion = oldKeySecret.ResourceVersion
	}

	err = helpers.CreateOrUpdate(ctx, rm.client, keySecret)
	if err != nil {
		return fmt.Errorf("failed to update key secret: %w", err)
	}

	// Update kubeconfig secret with rollback on failure and ResourceVersion checking
	cfgSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfgSecretName,
			Namespace: userNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"config": newKubeconfig,
		},
	}

	// If we have an existing secret, preserve its ResourceVersion for concurrency safety
	if oldCfgSecret != nil {
		cfgSecret.ResourceVersion = oldCfgSecret.ResourceVersion
	}

	err = helpers.CreateOrUpdate(ctx, rm.client, cfgSecret)
	if err != nil {
		// Rollback key secret on kubeconfig update failure
		logger.Error(err, "Failed to update kubeconfig secret, rolling back key secret")
		if oldKeySecret != nil {
			if rollbackErr := helpers.CreateOrUpdate(ctx, rm.client, oldKeySecret); rollbackErr != nil {
				logger.Error(rollbackErr, "Failed to rollback key secret")
			}
		}
		return fmt.Errorf("failed to update kubeconfig secret: %w", err)
	}

	logger.Info("Atomic secret update completed successfully", "user", username)
	return nil
}

// updateUserStatusAfterRotation updates user status fields in memory with new certificate information.
// Returns (bool, error) where bool indicates if any status fields were changed.
// This is a pure in-memory mutator that performs no API writes.
func (rm *RotationManager) updateUserStatusAfterRotation(user *authv1alpha1.User, signedCert []byte, _ time.Duration) (bool, error) {
	// Defensive check: Auth must be non-nil
	if user.Spec.Auth == nil {
		return false, fmt.Errorf("authentication section is mandatory")
	}

	certExpiry, err := rm.extractCertificateExpiry(signedCert)
	if err != nil {
		return false, err
	}

	// Track changes for idempotent updates
	changed := false

	// 1. Set ExpiryTime (Always show this so user knows when cert dies)
	newExpiryTime := certExpiry.Format(time.RFC3339)
	if user.Status.ExpiryTime != newExpiryTime {
		user.Status.ExpiryTime = newExpiryTime
		changed = true
	}

	// 2. Conditional Renewal Logic
	var newNextRenewalAt *metav1.Time
	if helpers.GetAutoRenew(user) {
		// Calculate when the next rotation would trigger
		renewalTime := CalculateNextRenewal(time.Now(), certExpiry, user.Spec.Auth.RenewBefore)
		newNextRenewalAt = &renewalTime
	} else {
		// Explicitly clear the field if auto-renewal is disabled
		newNextRenewalAt = nil
	}

	// Compare NextRenewalAt using pointer-safe comparison
	if !helpers.SemanticTimePtrMatch(user.Status.NextRenewalAt, newNextRenewalAt) {
		user.Status.NextRenewalAt = newNextRenewalAt
		changed = true
	}

	// 3. Update Phase and clear RotationStep
	if user.Status.Phase != helpers.PhaseActive {
		user.Status.Phase = helpers.PhaseActive
		changed = true
	}

	if user.Status.RotationStep != "" {
		user.Status.RotationStep = ""
		changed = true
	}

	// 4. Update conditions properly (Deduplicating by Type)
	now := metav1.Now()

	// Helper to ensure we don't duplicate conditions or grow the list infinitely
	updateCondition := func(condType string, status metav1.ConditionStatus, reason, message string) bool {
		newCond := metav1.Condition{
			Type:               condType,
			Status:             status,
			Reason:             reason,
			Message:            message,
			LastTransitionTime: now,
			ObservedGeneration: user.Generation,
		}

		for i, c := range user.Status.Conditions {
			if c.Type == condType {
				// Check if condition actually changed
				if c.Status != status || c.Reason != reason || c.Message != message {
					user.Status.Conditions[i] = newCond
					return true
				}
				return false // Condition unchanged
			}
		}

		// Condition not found, add new one
		user.Status.Conditions = append(user.Status.Conditions, newCond)
		return true
	}

	// Update status conditions
	if updateCondition("Ready", metav1.ConditionTrue, "UserProvisioned", "Certificate is valid and active") {
		changed = true
	}
	if updateCondition("Renewing", metav1.ConditionFalse, "RenewalComplete", "Latest renewal cycle finished successfully") {
		changed = true
	}

	return changed, nil
}

// Helper methods

// IsRotationInProgress checks if a rotation is currently in progress for a user
func (rm *RotationManager) IsRotationInProgress(ctx context.Context, username string) (bool, string, error) {
	shadowSecret, exists, err := rm.getShadowSecret(ctx, username)
	if err != nil {
		return false, "", fmt.Errorf("failed to check rotation progress: %w", err)
	}

	if !exists {
		return false, "", nil
	}

	csrName := shadowSecret.Annotations[authv1alpha1.CSRNameAnnotation]
	return true, csrName, nil
}

// GetRotationRequeueDelay returns appropriate requeue delay based on certificate duration
func (rm *RotationManager) GetRotationRequeueDelay(certDuration time.Duration) time.Duration {
	// For short-TTL certificates (< 1 hour), use aggressive requeuing
	if certDuration < time.Hour {
		return 10 * time.Second
	}

	// For medium-TTL certificates (< 24 hours), use moderate requeuing
	if certDuration < 24*time.Hour {
		return 30 * time.Second
	}

	// For long-TTL certificates, use conservative requeuing
	return 2 * time.Minute
}

func (rm *RotationManager) getClusterCA(ctx context.Context) ([]byte, error) {
	return certs.GetClusterCA(ctx, rm.client)
}

func (rm *RotationManager) getAPIServerURL() string {
	// Use the existing logic
	return certs.GetAPIServerURL()
}

func (rm *RotationManager) buildKubeconfig(apiServer string, caData, signedCert, keyPEM []byte, username string) ([]byte, error) {
	return certs.BuildCertKubeconfigWithClusterName(apiServer, caData, signedCert, keyPEM, username, rm.clusterName)
}

func (rm *RotationManager) extractCertificateExpiry(certData []byte) (time.Time, error) {
	// Use the existing implementation from certs package
	return certs.ExtractCertificateExpiryWithFormatDetection(certData)
}

// validateCSRForApproval validates a CSR before auto-approval for security.
// expectedUsername and expectedKeyPEM come from the caller (the shadow secret's
// key and the User the operator is rotating), not from the CSR itself — a CSR
// pre-planted by an attacker under the deterministic name would otherwise be
// self-attesting and pass the CN/label checks trivially (see #114).
func (rm *RotationManager) validateCSRForApproval(csr *certv1.CertificateSigningRequest, expectedUsername string, expectedKeyPEM []byte) error {
	// Validate signer name matches configured signer (supports managed K8s)
	if csr.Spec.SignerName != rm.signerName {
		return fmt.Errorf("invalid signer name: %s (expected: %s)", csr.Spec.SignerName, rm.signerName)
	}

	// Validate usages
	expectedUsages := []certv1.KeyUsage{certv1.UsageClientAuth}
	if len(csr.Spec.Usages) != len(expectedUsages) {
		return fmt.Errorf("invalid usages count: expected %d, got %d", len(expectedUsages), len(csr.Spec.Usages))
	}

	for i, usage := range csr.Spec.Usages {
		if usage != expectedUsages[i] {
			return fmt.Errorf("invalid usage at index %d: expected %s, got %s", i, expectedUsages[i], usage)
		}
	}

	// Validate labels
	if csr.Labels == nil {
		return fmt.Errorf("missing required labels")
	}

	if csr.Labels[authv1alpha1.RenewalLabel] != "true" {
		return fmt.Errorf("missing or invalid renewal label")
	}

	if csr.Labels[authv1alpha1.RotationLabel] != "true" {
		return fmt.Errorf("missing or invalid rotation label")
	}

	// Validate CSR content
	block, _ := pem.Decode(csr.Spec.Request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("invalid CSR PEM format")
	}

	csrReq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Validate common name matches the user the operator is rotating.
	if csrReq.Subject.CommonName != expectedUsername {
		return fmt.Errorf("CSR common name %s doesn't match expected user %s", csrReq.Subject.CommonName, expectedUsername)
	}

	// Subject.Organization becomes the Groups claim on the issued cert; the
	// operator never sets one, so any value here is an attempted group injection.
	if len(csrReq.Subject.Organization) > 0 {
		return fmt.Errorf("CSR Subject.Organization %v is not permitted (operator never sets groups)", csrReq.Subject.Organization)
	}

	// Anti-impersonation: the CSR's public key must match the operator-held
	// private key. Without this, an attacker with `create` on CSRs can pre-plant
	// a request under the deterministic name and receive a signed cert bound to
	// their own key.
	if err := helpers.VerifyCSRMatchesKey(csr.Spec.Request, expectedKeyPEM); err != nil {
		return err
	}

	return nil
}
