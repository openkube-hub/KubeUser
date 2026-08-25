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
	"strings"
	"testing"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func genKeyPEM(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}), key
}

func genCSRPEM(t *testing.T, key *rsa.PrivateKey, cn string, org []string) []byte {
	t.Helper()
	tmpl := x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn, Organization: org},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestValidateCSRForApproval_RejectsKeyMismatch is the regression guard for
// issue #114 on the renewal path. The pre-fix validator inspected signer,
// usages, labels, and CN, but never verified that the CSR's public key came
// from the operator's shadow-secret key. A CSR that satisfies every metadata
// check but is signed with an attacker's key must be rejected.
func TestValidateCSRForApproval_RejectsKeyMismatch(t *testing.T) {
	rm := NewRotationManager(nil, nil, certv1.KubeAPIServerClientSignerName, "", nil)

	operatorKeyPEM, _ := genKeyPEM(t)
	_, attackerKey := genKeyPEM(t)

	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "alice-renewal-12345678",
			Labels: map[string]string{
				authv1alpha1.UserLabel:     "alice",
				authv1alpha1.RenewalLabel:  "true",
				authv1alpha1.RotationLabel: "true",
			},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			SignerName: certv1.KubeAPIServerClientSignerName,
			Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
			Request:    genCSRPEM(t, attackerKey, "alice", nil),
		},
	}

	err := rm.validateCSRForApproval(csr, "alice", operatorKeyPEM)
	if err == nil {
		t.Fatalf("validateCSRForApproval accepted a CSR whose public key differs from the operator-held key — #114 regression (attacker can impersonate any managed user)")
	}
	if !strings.Contains(err.Error(), "public key") {
		t.Fatalf("expected error to reference public-key mismatch, got: %v", err)
	}
}

// TestValidateCSRForApproval_RejectsSubjectOrganization guards the
// group-injection vector: Subject.Organization becomes the Groups claim on the
// issued cert, and the operator never sets one, so any value is an attacker's
// attempt at privilege escalation.
func TestValidateCSRForApproval_RejectsSubjectOrganization(t *testing.T) {
	rm := NewRotationManager(nil, nil, certv1.KubeAPIServerClientSignerName, "", nil)

	operatorKeyPEM, operatorKey := genKeyPEM(t)

	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "alice-renewal-12345678",
			Labels: map[string]string{
				authv1alpha1.UserLabel:     "alice",
				authv1alpha1.RenewalLabel:  "true",
				authv1alpha1.RotationLabel: "true",
			},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			SignerName: certv1.KubeAPIServerClientSignerName,
			Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
			Request:    genCSRPEM(t, operatorKey, "alice", []string{"sudoers"}),
		},
	}

	err := rm.validateCSRForApproval(csr, "alice", operatorKeyPEM)
	if err == nil {
		t.Fatalf("validateCSRForApproval accepted a CSR carrying Subject.Organization — attacker group-injection")
	}
	if !strings.Contains(err.Error(), "Organization") {
		t.Fatalf("expected error to reference Subject.Organization, got: %v", err)
	}
}

// TestValidateCSRForApproval_UsesCallerSuppliedUsernameNotLabels pins the
// invariant that the "expected" user comes from the operator's caller, not
// from CSR labels the attacker controls. Pre-fix the validator derived the
// expected username from csr.Labels[UserLabel], which an attacker who pre-plants
// a CSR trivially controls.
func TestValidateCSRForApproval_UsesCallerSuppliedUsernameNotLabels(t *testing.T) {
	rm := NewRotationManager(nil, nil, certv1.KubeAPIServerClientSignerName, "", nil)

	operatorKeyPEM, operatorKey := genKeyPEM(t)

	// CSR whose labels claim "victim" but whose Subject.CommonName is "victim"
	// — the operator is actually rotating "someone-else", so the CN check
	// against the caller-supplied username must fail even though labels agree
	// with the CSR.
	csr := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: "someone-else-renewal-12345678",
			Labels: map[string]string{
				authv1alpha1.UserLabel:     "victim",
				authv1alpha1.RenewalLabel:  "true",
				authv1alpha1.RotationLabel: "true",
			},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			SignerName: certv1.KubeAPIServerClientSignerName,
			Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
			Request:    genCSRPEM(t, operatorKey, "victim", nil),
		},
	}

	err := rm.validateCSRForApproval(csr, "someone-else", operatorKeyPEM)
	if err == nil {
		t.Fatalf("validateCSRForApproval trusted CSR-supplied labels for expected username instead of the caller's — attacker relabels the pre-planted CSR to whatever passes the CN check")
	}
	if !strings.Contains(err.Error(), "common name") {
		t.Fatalf("expected error to reference CN mismatch, got: %v", err)
	}
}

// TestEnsureCSRExists_ReplacesAttackerPreplantedCSR exercises the full "found
// existing CSR" branch of the renewal path with a fake client and asserts the
// pre-planted attacker CSR is deleted and replaced with one bound to the
// shadow-secret key.
func TestEnsureCSRExists_ReplacesAttackerPreplantedCSR(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1 scheme: %v", err)
	}
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatalf("certv1 scheme: %v", err)
	}

	operatorKeyPEM, operatorKey := genKeyPEM(t)
	_, attackerKey := genKeyPEM(t)

	const (
		username = "valid-user"
	)

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: username, UID: "a287d57b-1234-1234-1234-123456789012"},
	}

	rm := NewRotationManager(nil, nil, certv1.KubeAPIServerClientSignerName, "", nil)
	csrName := rm.generateUniqueCSRName(user.Name, string(user.UID))

	// Attacker pre-plants a CSR that satisfies every metadata check the
	// pre-fix validator ran (signer, usages, labels, CN) but is signed with
	// their own key.
	preplanted := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: csrName,
			Labels: map[string]string{
				authv1alpha1.UserLabel:     username,
				authv1alpha1.RenewalLabel:  "true",
				authv1alpha1.RotationLabel: "true",
			},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			SignerName: certv1.KubeAPIServerClientSignerName,
			Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
			Request:    genCSRPEM(t, attackerKey, username, nil),
		},
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(preplanted).Build()
	rm.client = cli

	if _, err := rm.ensureCSRExists(context.Background(), user, csrName, username, operatorKeyPEM, time.Hour); err != nil {
		t.Fatalf("ensureCSRExists: %v", err)
	}

	stored := &certv1.CertificateSigningRequest{}
	if err := cli.Get(context.Background(), types.NamespacedName{Name: csrName}, stored); err != nil {
		t.Fatalf("get replacement CSR: %v", err)
	}
	block, _ := pem.Decode(stored.Spec.Request)
	if block == nil {
		t.Fatalf("replacement CSR has invalid PEM")
	}
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse replacement CSR: %v", err)
	}
	pub, ok := req.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected replacement CSR key type %T", req.PublicKey)
	}
	if pub.Equal(&attackerKey.PublicKey) {
		t.Fatalf("replacement CSR is still bound to the attacker's public key — #114 regression")
	}
	if !pub.Equal(&operatorKey.PublicKey) {
		t.Fatalf("replacement CSR is not bound to the operator's public key")
	}
}
