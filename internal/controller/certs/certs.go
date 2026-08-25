/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package certs

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	inClusterCAPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

func EnsureCertKubeconfig(ctx context.Context, r client.Client, user *authv1alpha1.User) (bool, bool, error) {
	// Use default duration (3 months) and default signer
	defaultDuration := 90 * 24 * time.Hour
	defaultSigner := certv1.KubeAPIServerClientSignerName
	return EnsureCertKubeconfigWithDuration(ctx, r, user, defaultDuration, defaultSigner, helpers.DefaultKubeconfigClusterName)
}

// EnsureCertKubeconfigWithDuration ensures certificate kubeconfig with custom duration and configurable signer.
// Returns (statusChanged bool, requeueNeeded bool, error) where:
// - statusChanged: true if user.Status.ExpiryTime or user.Status.NextRenewalAt were modified in memory
// - requeueNeeded: true if the controller needs to requeue (CSR pending, approval needed, etc.)
// - error: any execution error
// This function does NOT perform any r.Status().Update() calls - it only modifies the user object in memory.
// The caller (orchestrator) is responsible for persisting status changes to etcd.
func EnsureCertKubeconfigWithDuration(ctx context.Context, r client.Client, user *authv1alpha1.User, duration time.Duration, signerName, clusterName string) (bool, bool, error) {
	// Default to standard Kubernetes signer if not specified
	if signerName == "" {
		signerName = certv1.KubeAPIServerClientSignerName
	}
	if clusterName == "" {
		clusterName = helpers.DefaultKubeconfigClusterName
	}

	username := user.Name
	userNamespace := helpers.GetKubeUserNamespace()
	keySecretName := fmt.Sprintf("%s-key", username)
	cfgSecretName := fmt.Sprintf("%s-kubeconfig", username)
	csrName := fmt.Sprintf("%s-csr", username)

	// Stage 1: Verify namespace exists
	if err := ensureNamespace(ctx, r, userNamespace); err != nil {
		return false, false, err
	}

	// Stage 2: Handle certificate rotation if needed
	if err := handleCertificateRotation(ctx, r, cfgSecretName, csrName, username, duration); err != nil {
		return false, false, err
	}

	// Stage 3: Ensure private key exists
	keyPEM, err := ensurePrivateKey(ctx, r, user, keySecretName, userNamespace)
	if err != nil {
		return false, false, fmt.Errorf("failed to ensure private key: %w", err)
	}

	// Stage 4: Check if kubeconfig already exists (early return)
	if kubeconfigExists(ctx, r, cfgSecretName, userNamespace) {
		return false, false, nil
	}

	// Stage 5: Ensure signed certificate (handles CSR lifecycle)
	signedCert, requeue, err := ensureSignedCertificate(ctx, r, user, csrName, keyPEM, duration, signerName)
	if err != nil {
		return false, false, fmt.Errorf("failed to ensure signed certificate: %w", err)
	}
	if requeue {
		return false, true, nil
	}

	// Stage 6: Calculate certificate metadata (expiry, renewal time)
	statusChanged, err := calculateCertificateMetadata(ctx, user, signedCert)
	if err != nil {
		return false, false, fmt.Errorf("failed to calculate certificate metadata: %w", err)
	}

	// Stage 7: Persist kubeconfig secret
	if err := persistKubeconfig(ctx, r, user, signedCert, keyPEM, clusterName); err != nil {
		return false, false, fmt.Errorf("failed to persist kubeconfig: %w", err)
	}

	return statusChanged, false, nil
}

// handleCertificateRotation checks if certificate needs rotation and cleans up resources if needed
func handleCertificateRotation(ctx context.Context, r client.Client, cfgSecretName, csrName, username string, duration time.Duration) error {
	rotationThreshold := getRotationThreshold(duration)
	needsRotation, err := checkCertificateRotation(ctx, r, cfgSecretName, rotationThreshold)
	if err != nil {
		return fmt.Errorf("failed to check certificate rotation: %w", err)
	}

	if !needsRotation {
		return nil
	}

	logger := logf.FromContext(ctx)
	logger.Info("Certificate needs rotation, cleaning up existing resources", "user", username)
	if err := cleanupCertificateResources(ctx, r, cfgSecretName, csrName); err != nil {
		return fmt.Errorf("failed to cleanup certificate resources: %w", err)
	}

	return nil
}

// kubeconfigExists checks if a kubeconfig secret already exists
func kubeconfigExists(ctx context.Context, r client.Client, cfgSecretName, namespace string) bool {
	var existingCfg corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: namespace}, &existingCfg)
	return err == nil
}

// ensureNamespace verifies that the target namespace exists
func ensureNamespace(ctx context.Context, r client.Client, namespace string) error {
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: namespace}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			return fmt.Errorf("target namespace '%s' does not exist - please create it before deploying KubeUser or use Helm with --create-namespace", namespace)
		}
		return fmt.Errorf("failed to verify namespace '%s': %w", namespace, err)
	}
	return nil
}

// ensurePrivateKey loads an existing private key or generates a new 2048-bit RSA key and persists it.
// An existing key Secret is only reused when its OwnerReferences confirm this
// User created it; otherwise it is refused rather than silently used or
// overwritten, since either behaviour would allow a caller with `create` on
// Secrets in the operator namespace to pre-plant key material that ends up
// authenticating the target User.
func ensurePrivateKey(ctx context.Context, r client.Client, user *authv1alpha1.User, name, namespace string) ([]byte, error) {
	logger := logf.FromContext(ctx)

	var keySecret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, &keySecret)

	if err == nil {
		if !helpers.IsOwnedByUser(&keySecret, user) {
			return nil, fmt.Errorf("key secret %s/%s is not owned by user %s (uid=%s); refusing to reuse potentially planted key material",
				namespace, name, user.Name, user.UID)
		}
		keyPEM := keySecret.Data["key.pem"]
		if keyPEM == nil {
			return nil, fmt.Errorf("key secret exists but key.pem data is missing")
		}
		logger.Info("Using existing private key", "secret", name)
		return keyPEM, nil
	}

	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get key secret: %w", err)
	}

	// Generate new key
	logger.Info("Generating new private key", "secret", name)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})

	keySecret = corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
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
		Data: map[string][]byte{"key.pem": keyPEM},
	}

	if err := r.Create(ctx, &keySecret); err != nil {
		return nil, fmt.Errorf("failed to create key secret: %w", err)
	}

	logger.Info("Successfully created private key secret", "secret", name)
	return keyPEM, nil
}

// ensureSignedCertificate handles the entire CSR lifecycle:
// - Check for existing CSR
// - Create CSR if missing
// - Auto-approve CSR if not approved
// - Wait for signed certificate
// Returns (signedCert []byte, requeue bool, error)
func ensureSignedCertificate(ctx context.Context, r client.Client, user *authv1alpha1.User, csrName string, keyPEM []byte, duration time.Duration, signerName string) ([]byte, bool, error) {
	username := user.Name

	// Generate CSR from private key
	csrPEM, err := csrFromKey(username, keyPEM)
	if err != nil {
		return nil, false, fmt.Errorf("failed to generate CSR from key: %w", err)
	}

	// Get or create CSR
	csr, err := getOrCreateCSR(ctx, r, csrName, username, csrPEM, keyPEM, duration, signerName)
	if err != nil {
		return nil, false, err
	}
	if csr == nil {
		// CSR was just created, requeue
		return nil, true, nil
	}

	// Approve CSR if needed
	if needsApproval(csr) {
		if err := approveCSR(ctx, r, csr, csrName, username, keyPEM, signerName); err != nil {
			return nil, false, err
		}
		return nil, true, nil
	}

	// Wait for certificate if not ready
	if len(csr.Status.Certificate) == 0 {
		logger := logf.FromContext(ctx)
		logger.Info("Waiting for certificate to be issued", "csr", csrName)
		return nil, true, nil
	}

	logger := logf.FromContext(ctx)
	logger.Info("Certificate issued successfully", "csr", csrName, "certLength", len(csr.Status.Certificate))
	return csr.Status.Certificate, false, nil
}

// getOrCreateCSR retrieves an existing CSR or creates a new one.
// If a CSR already exists under the deterministic name, it is validated against
// the operator's stored private key and expected spec; a mismatch (which would
// indicate an attacker pre-planted a CSR to be signed under our name) triggers
// delete-and-recreate rather than reuse.
// Returns (csr, error) where csr is nil if a new CSR was just created.
func getOrCreateCSR(ctx context.Context, r client.Client, csrName, username string, csrPEM, keyPEM []byte, duration time.Duration, signerName string) (*certv1.CertificateSigningRequest, error) {
	logger := logf.FromContext(ctx)

	var csr certv1.CertificateSigningRequest
	err := r.Get(ctx, types.NamespacedName{Name: csrName}, &csr)

	if err == nil {
		if valErr := validateOperatorCSR(&csr, username, signerName, keyPEM); valErr != nil {
			logger.Info("Existing CSR failed operator validation, replacing", "csr", csrName, "reason", valErr.Error())
			if delErr := r.Delete(ctx, &csr); delErr != nil && !apierrors.IsNotFound(delErr) {
				return nil, fmt.Errorf("failed to delete untrusted CSR %s: %w", csrName, delErr)
			}
			// Fall through to create a fresh CSR bound to the operator's key.
		} else {
			return &csr, nil
		}
	} else if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get CSR: %w", err)
	}

	// Create new CSR
	logger.Info("Creating new CSR", "csr", csrName, "user", username)
	expirationSeconds := int32(duration.Seconds())

	newCSR := certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:   csrName,
			Labels: map[string]string{authv1alpha1.UserLabel: username},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:           csrPEM,
			Usages:            []certv1.KeyUsage{certv1.UsageClientAuth},
			SignerName:        signerName,
			ExpirationSeconds: &expirationSeconds,
		},
	}

	if err := r.Create(ctx, &newCSR); err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	logger.Info("CSR created, requeuing for approval", "csr", csrName)
	return nil, nil
}

// validateOperatorCSR checks that a CSR is one the operator would have created
// for this user: expected signer, ClientAuth-only usages, CommonName == user,
// no Subject.Organization, and — critically — a public key matching the
// operator-held private key. Any failure means the CSR is not trustworthy for
// auto-approval.
func validateOperatorCSR(csr *certv1.CertificateSigningRequest, username, signerName string, keyPEM []byte) error {
	if csr.Spec.SignerName != signerName {
		return fmt.Errorf("signer %q does not match expected %q", csr.Spec.SignerName, signerName)
	}
	if len(csr.Spec.Usages) != 1 || csr.Spec.Usages[0] != certv1.UsageClientAuth {
		return fmt.Errorf("usages %v do not match expected [%s]", csr.Spec.Usages, certv1.UsageClientAuth)
	}
	block, _ := pem.Decode(csr.Spec.Request)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return errors.New("invalid CSR PEM in Spec.Request")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}
	if req.Subject.CommonName != username {
		return fmt.Errorf("CommonName %q does not match user %q", req.Subject.CommonName, username)
	}
	if len(req.Subject.Organization) > 0 {
		return fmt.Errorf("Subject.Organization %v is not permitted (operator never sets groups)", req.Subject.Organization)
	}
	if err := helpers.VerifyCSRMatchesKey(csr.Spec.Request, keyPEM); err != nil {
		return err
	}
	return nil
}

// needsApproval checks if a CSR needs approval
func needsApproval(csr *certv1.CertificateSigningRequest) bool {
	for _, c := range csr.Status.Conditions {
		if c.Type == certv1.CertificateApproved && c.Status == corev1.ConditionTrue {
			return false
		}
	}
	return true
}

// approveCSR auto-approves a CSR after validating it belongs to the operator.
// The validation guards against approving a pre-planted attacker CSR (see #114):
// the request must use the expected signer, ClientAuth-only usages, match the
// user's CommonName with no Subject.Organization, and — critically — its
// public key must match the operator-held private key.
func approveCSR(ctx context.Context, r client.Client, csr *certv1.CertificateSigningRequest, csrName, username string, keyPEM []byte, signerName string) error {
	logger := logf.FromContext(ctx)

	if err := validateOperatorCSR(csr, username, signerName, keyPEM); err != nil {
		return fmt.Errorf("refusing to approve CSR %s: %w", csrName, err)
	}

	logger.Info("Auto-approving validated CSR", "csr", csrName)

	csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:           certv1.CertificateApproved,
		Status:         corev1.ConditionTrue,
		Reason:         "AutoApproved",
		Message:        "Approved by kubeuser-operator",
		LastUpdateTime: metav1.Now(),
	})

	// CSR approval goes through the signer which may be slow under load; bound this
	// subresource write independently so a stalled signer does not consume the full reconcile budget.
	approvalCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := r.SubResource("approval").Update(approvalCtx, csr); err != nil {
		return fmt.Errorf("failed to approve CSR: %w", err)
	}

	logger.Info("CSR approved, requeuing for certificate issuance", "csr", csrName)
	return nil
}

// calculateCertificateMetadata extracts certificate expiry time and calculates NextRenewalAt
// Updates user.Status fields in memory (does not persist to etcd)
// Returns (statusChanged bool, error)
func calculateCertificateMetadata(ctx context.Context, user *authv1alpha1.User, certData []byte) (bool, error) {
	logger := logf.FromContext(ctx)

	// Extract certificate expiry time
	logger.Info("Extracting certificate expiry", "certLength", len(certData))
	certExpiryTime, err := extractCertificateExpiryWithFormatDetection(certData)
	if err != nil {
		return false, fmt.Errorf("failed to extract certificate expiry: %w", err)
	}
	logger.Info("Successfully extracted certificate expiry", "expiry", certExpiryTime)

	// SEMANTIC PROTECTION: Only set statusChanged = true if values actually differ
	statusChanged := false

	// Capture old values for semantic comparison
	oldExpiryTime := user.Status.ExpiryTime
	oldNextRenewalAt := user.Status.NextRenewalAt

	// Update ExpiryTime
	newExpiryTime := certExpiryTime.Format(time.RFC3339)
	if oldExpiryTime != newExpiryTime {
		user.Status.ExpiryTime = newExpiryTime
		statusChanged = true
		logger.Info("ExpiryTime changed", "old", oldExpiryTime, "new", newExpiryTime)
	}

	// Calculate renewal time using proper renewal logic that respects RenewBefore
	issuedAt := time.Now() // Certificate was just issued

	// Only set NextRenewalAt if auto-renewal is enabled
	var newNextRenewalAt *metav1.Time
	autoRenew := user.Spec.Auth != nil && user.Spec.Auth.AutoRenew != nil && *user.Spec.Auth.AutoRenew
	if autoRenew {
		var renewBefore *metav1.Duration
		if user.Spec.Auth != nil {
			renewBefore = user.Spec.Auth.RenewBefore
		}

		nextRenewal := calculateNextRenewal(issuedAt, certExpiryTime, renewBefore)
		newNextRenewalAt = &nextRenewal

		logger.Info("Certificate times calculated",
			"expiry", certExpiryTime.Format(time.RFC3339),
			"nextRenewalAt", nextRenewal.Format(time.RFC3339),
			"renewBefore", renewBefore)
	} else {
		// Explicitly clear the field if auto-renewal is disabled
		newNextRenewalAt = nil

		logger.Info("Certificate times calculated",
			"expiry", certExpiryTime.Format(time.RFC3339),
			"nextRenewalAt", "disabled (autoRenew=false)")
	}

	// Update NextRenewalAt if changed (semantic comparison)
	if !helpers.SemanticTimePtrMatch(oldNextRenewalAt, newNextRenewalAt) {
		user.Status.NextRenewalAt = newNextRenewalAt
		statusChanged = true

		oldStr := "nil"
		if oldNextRenewalAt != nil {
			oldStr = oldNextRenewalAt.Format(time.RFC3339)
		}
		newStr := "nil"
		if newNextRenewalAt != nil {
			newStr = newNextRenewalAt.Format(time.RFC3339)
		}
		logger.Info("NextRenewalAt changed", "old", oldStr, "new", newStr)
	}

	return statusChanged, nil
}

// persistKubeconfig gathers CA data, API URL, and builds/saves the final kubeconfig secret
func persistKubeconfig(ctx context.Context, r client.Client, user *authv1alpha1.User, certPEM, keyPEM []byte, clusterName string) error {
	logger := logf.FromContext(ctx)
	username := user.Name
	userNamespace := helpers.GetKubeUserNamespace()
	cfgSecretName := fmt.Sprintf("%s-kubeconfig", username)

	// Get cluster CA certificate
	caData, err := getClusterCA(ctx, r)
	if err != nil {
		return fmt.Errorf("failed to get cluster CA: %w", err)
	}

	// Get API server URL
	apiServer := os.Getenv("KUBERNETES_API_SERVER")
	if apiServer == "" {
		apiServer = "https://kubernetes.default.svc"
	}

	// Build kubeconfig
	kcfg, err := buildCertKubeconfig(apiServer, caData, certPEM, keyPEM, username, clusterName)
	if err != nil {
		return fmt.Errorf("failed to build kubeconfig: %w", err)
	}

	// Create or update kubeconfig secret
	cfgSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfgSecretName,
			Namespace: userNamespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"config": kcfg},
	}

	if err := helpers.CreateOrUpdate(ctx, r, cfgSecret); err != nil {
		return fmt.Errorf("failed to create/update kubeconfig secret: %w", err)
	}

	logger.Info("Successfully persisted kubeconfig", "secret", cfgSecretName)
	return nil
}

func csrFromKey(username string, keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("decode key failed")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	csrTemplate := x509.CertificateRequest{Subject: pkix.Name{CommonName: username}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// getClusterCA returns the cluster CA certificate as raw PEM bytes. It first
// looks at the in-cluster service-account CA and falls back to the
// kube-root-ca.crt ConfigMap for out-of-cluster runs (e.g. `make run`).
func getClusterCA(ctx context.Context, r client.Client) ([]byte, error) {
	if data, err := os.ReadFile(filepath.Clean(inClusterCAPath)); err == nil && len(data) > 0 {
		return data, nil
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kube-root-ca.crt"}, &cm); err == nil {
		if crt, ok := cm.Data["ca.crt"]; ok {
			return []byte(crt), nil
		}
	}
	return nil, errors.New("CA not found")
}

// buildCertKubeconfig serializes a kubeconfig for the given user via
// clientcmd. All byte inputs are raw PEM; clientcmd handles the base64
// encoding on YAML emission itself, so no pre-encoding is required.
func buildCertKubeconfig(apiServer string, caData, certData, keyData []byte, username, clusterName string) ([]byte, error) {
	if clusterName == "" {
		clusterName = helpers.DefaultKubeconfigClusterName
	}
	contextName := fmt.Sprintf("%s@%s", username, clusterName)
	kubeconfig, err := clientcmd.Write(clientcmdapi.Config{
		Kind:       "Config",
		APIVersion: "v1",
		Clusters: map[string]*clientcmdapi.Cluster{
			clusterName: {
				Server:                   apiServer,
				CertificateAuthorityData: caData,
			},
		},
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			username: {
				ClientCertificateData: certData,
				ClientKeyData:         keyData,
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			contextName: {
				Cluster:   clusterName,
				AuthInfo:  username,
				Namespace: "default",
			},
		},
		CurrentContext: contextName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to serialize kubeconfig for user %q: %w", username, err)
	}
	return kubeconfig, nil
}

// extractCertificateExpiryWithFormatDetection tries multiple formats to extract certificate expiry
func extractCertificateExpiryWithFormatDetection(certData []byte) (time.Time, error) {
	// Method 1: Try as base64-encoded PEM (most likely)
	if certTime, err := tryBase64PEM(certData); err == nil {
		return certTime, nil
	}

	// Method 2: Try as raw PEM (less likely)
	if certTime, err := tryRawPEM(certData); err == nil {
		return certTime, nil
	}

	// Method 3: Try as raw DER (least likely)
	if certTime, err := tryRawDER(certData); err == nil {
		return certTime, nil
	}

	return time.Time{}, errors.New("unable to parse certificate in any known format")
}

// tryBase64PEM tries to parse as base64-encoded PEM
func tryBase64PEM(certData []byte) (time.Time, error) {
	// Decode base64
	certPEM, err := base64.StdEncoding.DecodeString(string(certData))
	if err != nil {
		return time.Time{}, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Decode PEM to get DER
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, errors.New("PEM decode failed")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate parse failed: %w", err)
	}

	return cert.NotAfter, nil
}

// tryRawPEM tries to parse as raw PEM data
func tryRawPEM(certData []byte) (time.Time, error) {
	// Decode PEM to get DER
	block, _ := pem.Decode(certData)
	if block == nil {
		return time.Time{}, errors.New("PEM decode failed")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate parse failed: %w", err)
	}

	return cert.NotAfter, nil
}

// tryRawDER tries to parse as raw DER data
func tryRawDER(certData []byte) (time.Time, error) {
	// Parse certificate directly
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate parse failed: %w", err)
	}

	return cert.NotAfter, nil
}

// checkCertificateRotation checks if a certificate needs rotation based on expiry
func checkCertificateRotation(ctx context.Context, r client.Client, cfgSecretName string, rotationThreshold time.Duration) (bool, error) {
	userNamespace := helpers.GetKubeUserNamespace()
	var existingCfg corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: userNamespace}, &existingCfg); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil // No existing certificate, no rotation needed
		}
		return false, err
	}

	// Extract certificate from kubeconfig
	kubeconfigData := existingCfg.Data["config"]
	if kubeconfigData == nil {
		return false, nil // No kubeconfig data, needs recreation
	}

	// Parse kubeconfig to extract client certificate
	certData, err := extractClientCertFromKubeconfig(kubeconfigData)
	if err != nil {
		return false, fmt.Errorf("failed to extract certificate from kubeconfig: %w", err)
	}

	// Check certificate expiry
	certExpiry, err := extractCertificateExpiryWithFormatDetection(certData)
	if err != nil {
		return false, fmt.Errorf("failed to extract certificate expiry: %w", err)
	}

	// Check if certificate is expiring soon
	timeUntilExpiry := time.Until(certExpiry)
	return timeUntilExpiry < rotationThreshold, nil
}

// extractClientCertFromKubeconfig extracts client certificate data from kubeconfig YAML
func extractClientCertFromKubeconfig(kubeconfigData []byte) ([]byte, error) {
	// Simple regex approach to extract client-certificate-data
	// In a production environment, you might want to use a proper YAML parser
	lines := strings.Split(string(kubeconfigData), "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "client-certificate-data:") {
			parts := strings.SplitN(trimmedLine, ":", 2)
			if len(parts) == 2 {
				certData := strings.TrimSpace(parts[1])
				// Return the base64 encoded certificate data as bytes
				return []byte(certData), nil
			}
		}
	}
	return nil, errors.New("client certificate data not found in kubeconfig")
}

// cleanupCertificateResources removes existing certificate resources for rotation
func cleanupCertificateResources(ctx context.Context, r client.Client, cfgSecretName, csrName string) error {
	logger := logf.FromContext(ctx)
	userNamespace := helpers.GetKubeUserNamespace()

	// Delete kubeconfig secret
	kubeconfigSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: userNamespace}, kubeconfigSecret); err == nil {
		logger.Info("Deleting kubeconfig secret for rotation", "secret", cfgSecretName)
		if err := r.Delete(ctx, kubeconfigSecret); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete kubeconfig secret: %w", err)
		}
	}

	// Delete existing CSR
	existingCSR := &certv1.CertificateSigningRequest{}
	if err := r.Get(ctx, types.NamespacedName{Name: csrName}, existingCSR); err == nil {
		logger.Info("Deleting existing CSR for rotation", "csr", csrName)
		if err := r.Delete(ctx, existingCSR); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete existing CSR: %w", err)
		}
	}

	// Optionally generate new private key for better security
	// For now, we'll reuse the existing key to maintain consistency
	// In a future enhancement, you might want to rotate keys as well

	return nil
}

// getRotationThreshold returns the rotation threshold for certificates
// Can be overridden with KUBEUSER_ROTATION_THRESHOLD environment variable
// Default: rotate when remaining lifetime ≤ 25% of original TTL
func getRotationThreshold(certDuration time.Duration) time.Duration {
	if thresholdStr := os.Getenv("KUBEUSER_ROTATION_THRESHOLD"); thresholdStr != "" {
		if threshold, err := time.ParseDuration(thresholdStr); err == nil {
			return threshold
		}
	}

	// Default: rotate when 25% of lifetime remains (75% consumed)
	// This means certificates rotate when they have 20-30% of their lifetime left
	return certDuration / 4 // 25% of original duration
}

// GetClusterCA returns the cluster CA certificate as raw PEM bytes (exported for renewal package).
func GetClusterCA(ctx context.Context, r client.Client) ([]byte, error) {
	return getClusterCA(ctx, r)
}

// GetAPIServerURL gets the API server URL (exported for renewal package)
func GetAPIServerURL() string {
	apiServer := os.Getenv("KUBERNETES_API_SERVER")
	if apiServer == "" {
		apiServer = "https://kubernetes.default.svc"
	}
	return apiServer
}

// BuildCertKubeconfig builds a kubeconfig with certificate authentication
// using the default cluster name (exported for renewal package).
func BuildCertKubeconfig(apiServer string, caData, signedCert, keyPEM []byte, username string) ([]byte, error) {
	return BuildCertKubeconfigWithClusterName(apiServer, caData, signedCert, keyPEM, username, helpers.DefaultKubeconfigClusterName)
}

// BuildCertKubeconfigWithClusterName builds a kubeconfig with a configurable cluster name.
func BuildCertKubeconfigWithClusterName(apiServer string, caData, signedCert, keyPEM []byte, username, clusterName string) ([]byte, error) {
	return buildCertKubeconfig(apiServer, caData, signedCert, keyPEM, username, clusterName)
}

// ExtractCertificateExpiryWithFormatDetection extracts certificate expiry (exported for renewal package)
func ExtractCertificateExpiryWithFormatDetection(certData []byte) (time.Time, error) {
	return extractCertificateExpiryWithFormatDetection(certData)
}

// ExtractCertificateTTL extracts the actual TTL and issued time from the user's certificate
// by reading the kubeconfig secret and parsing the certificate
func ExtractCertificateTTL(ctx context.Context, r client.Client, username string) (time.Duration, time.Time, error) {
	logger := logf.FromContext(ctx)
	userNamespace := helpers.GetKubeUserNamespace()
	cfgSecretName := fmt.Sprintf("%s-kubeconfig", username)

	// Get the kubeconfig secret
	var kubeconfigSecret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: userNamespace}, &kubeconfigSecret)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("failed to get kubeconfig secret: %w", err)
	}

	// Extract certificate from kubeconfig
	kubeconfigData := kubeconfigSecret.Data["config"]
	if kubeconfigData == nil {
		return 0, time.Time{}, fmt.Errorf("kubeconfig data not found in secret")
	}

	certData, err := extractClientCertFromKubeconfig(kubeconfigData)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("failed to extract certificate from kubeconfig: %w", err)
	}

	// Parse the certificate to get NotBefore and NotAfter
	cert, err := parseCertificateFromData(certData)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Calculate actual TTL
	actualTTL := cert.NotAfter.Sub(cert.NotBefore)
	issuedAt := cert.NotBefore

	logger.Info("Extracted certificate TTL",
		"username", username,
		"issuedAt", issuedAt.Format(time.RFC3339),
		"expiresAt", cert.NotAfter.Format(time.RFC3339),
		"actualTTL", actualTTL)

	return actualTTL, issuedAt, nil
}

// parseCertificateFromData parses a certificate from various formats (base64, PEM, DER)
func parseCertificateFromData(certData []byte) (*x509.Certificate, error) {
	// Try base64-encoded PEM first (most common in kubeconfig)
	decoded, err := base64.StdEncoding.DecodeString(string(certData))
	if err == nil {
		// Successfully decoded base64, now try to parse as PEM
		block, _ := pem.Decode(decoded)
		if block != nil && block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				return cert, nil
			}
		}
	}

	// Try direct PEM
	block, _ := pem.Decode(certData)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			return cert, nil
		}
	}

	// Try direct DER
	cert, err := x509.ParseCertificate(certData)
	if err == nil {
		return cert, nil
	}

	return nil, fmt.Errorf("failed to parse certificate from any known format")
}

// calculateNextRenewal calculates the next renewal time based on certificate info
// This is a local implementation to avoid import cycles with the renewal package
func calculateNextRenewal(issuedAt, expiry time.Time, renewBefore *metav1.Duration) metav1.Time {
	const (
		// DefaultRenewalPercentage is the default percentage of certificate lifetime
		// after which renewal should occur (cert-manager style: 1/3 = 33%)
		DefaultRenewalPercentage = 0.33
		// MinimumRenewalBuffer is the absolute minimum time before expiry
		MinimumRenewalBuffer = 2 * time.Minute
	)

	var renewalTime time.Time

	certDuration := expiry.Sub(issuedAt)

	if renewBefore != nil {
		// Use custom renewBefore setting
		renewalTime = expiry.Add(-renewBefore.Duration)
	} else {
		// Use 1/3 rule (cert-manager standard)
		renewalBuffer := time.Duration(float64(certDuration) * DefaultRenewalPercentage)
		renewalTime = expiry.Add(-renewalBuffer)
	}

	// Safety floor: ensure at least 2 minutes before expiry
	safetyFloorTime := expiry.Add(-MinimumRenewalBuffer)
	if renewalTime.After(safetyFloorTime) {
		renewalTime = safetyFloorTime
	}

	// Ensure renewal time is not in the past
	now := time.Now()
	if renewalTime.Before(now) {
		renewalTime = now
	}

	return metav1.Time{Time: renewalTime}
}
