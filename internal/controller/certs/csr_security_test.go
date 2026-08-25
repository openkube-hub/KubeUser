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
	"encoding/pem"
	"strings"
	"testing"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	certv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// makeKeyPEM returns a PKCS#1-encoded RSA private key PEM.
func makeKeyPEM(t *testing.T) ([]byte, *rsa.PrivateKey) {
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

// makeCSRPEM returns a CSR PEM signed by key with the given Subject fields.
func makeCSRPEM(t *testing.T, key *rsa.PrivateKey, subject pkix.Name) []byte {
	t.Helper()
	tmpl := x509.CertificateRequest{Subject: subject}
	der, err := x509.CreateCertificateRequest(rand.Reader, &tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func newSchemeWithCSR(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatalf("certv1 scheme: %v", err)
	}
	return scheme
}

// TestGetOrCreateCSR_ReplacesAttackerPreplantedCSR is the regression guard for
// issue #114: an attacker with `create` on CSRs pre-plants a CSR under the
// operator's deterministic name, bound to an attacker-controlled key, hoping
// the operator will find it, auto-approve it, and hand back a signed cert that
// authenticates to the API server as the target user. The pre-fix
// getOrCreateCSR returned any pre-existing CSR unchecked; this test enforces
// the "validate against operator key, delete-and-recreate on mismatch" contract.
func TestGetOrCreateCSR_ReplacesAttackerPreplantedCSR(t *testing.T) {
	scheme := newSchemeWithCSR(t)

	// Operator's stored private key.
	operatorKeyPEM, operatorKey := makeKeyPEM(t)
	// Attacker's key, used to sign a CSR under the operator's expected name.
	_, attackerKey := makeKeyPEM(t)

	const (
		username   = "valid-user"
		csrName    = "valid-user-csr"
		signerName = certv1.KubeAPIServerClientSignerName
	)

	attackerCSRPEM := makeCSRPEM(t, attackerKey, pkix.Name{CommonName: username})
	preplanted := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:   csrName,
			Labels: map[string]string{authv1alpha1.UserLabel: username},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:    attackerCSRPEM,
			Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
			SignerName: signerName,
		},
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(preplanted).Build()

	operatorCSRPEM := makeCSRPEM(t, operatorKey, pkix.Name{CommonName: username})
	got, err := getOrCreateCSR(context.Background(), cli, csrName, username, operatorCSRPEM, operatorKeyPEM, time.Hour, signerName)
	if err != nil {
		t.Fatalf("getOrCreateCSR: %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil (indicating the attacker CSR was deleted and a fresh one created for requeue), got a returned CSR — attacker CSR was reused, this is the #114 impersonation bug")
	}

	// Verify the CSR now stored under the deterministic name is bound to the
	// operator's key, not the attacker's.
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
		t.Fatalf("replacement CSR is bound to the attacker's public key — #114 regression")
	}
	if !pub.Equal(&operatorKey.PublicKey) {
		t.Fatalf("replacement CSR is not bound to the operator's public key")
	}
}

// TestApproveCSR_RefusesCSRThatDoesNotMatchOperatorKey is the second-line
// defence against #114: even if a pre-planted attacker CSR slips past
// getOrCreateCSR (e.g. via a race), the approver itself must refuse to sign
// anything whose public key does not match the operator-held private key.
func TestApproveCSR_RefusesCSRThatDoesNotMatchOperatorKey(t *testing.T) {
	scheme := newSchemeWithCSR(t)

	operatorKeyPEM, _ := makeKeyPEM(t)
	_, attackerKey := makeKeyPEM(t)

	const (
		username   = "valid-user"
		csrName    = "valid-user-csr"
		signerName = certv1.KubeAPIServerClientSignerName
	)

	attackerCSR := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:   csrName,
			Labels: map[string]string{authv1alpha1.UserLabel: username},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:    makeCSRPEM(t, attackerKey, pkix.Name{CommonName: username}),
			Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
			SignerName: signerName,
		},
	}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(attackerCSR).Build()

	err := approveCSR(context.Background(), cli, attackerCSR, csrName, username, operatorKeyPEM, signerName)
	if err == nil {
		t.Fatalf("approveCSR accepted an attacker CSR — #114 regression (approver signed a request whose key was not the operator's)")
	}
	if !strings.Contains(err.Error(), "public key") {
		t.Fatalf("expected error to reference public-key mismatch, got: %v", err)
	}
}

// TestApproveCSR_RefusesUnexpectedSubjectOrganization guards the group-injection
// vector: an attacker CSR carrying Subject.Organization becomes the Groups
// claim on the issued cert. The operator never sets one, so any non-empty
// Organization must be rejected.
func TestApproveCSR_RefusesUnexpectedSubjectOrganization(t *testing.T) {
	scheme := newSchemeWithCSR(t)

	operatorKeyPEM, operatorKey := makeKeyPEM(t)

	const (
		username   = "valid-user"
		csrName    = "valid-user-csr"
		signerName = certv1.KubeAPIServerClientSignerName
	)

	// CSR signed by the operator's own key but carrying a group claim.
	orgCSR := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name:   csrName,
			Labels: map[string]string{authv1alpha1.UserLabel: username},
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:    makeCSRPEM(t, operatorKey, pkix.Name{CommonName: username, Organization: []string{"sudoers"}}),
			Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
			SignerName: signerName,
		},
	}
	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(orgCSR).Build()

	err := approveCSR(context.Background(), cli, orgCSR, csrName, username, operatorKeyPEM, signerName)
	if err == nil {
		t.Fatalf("approveCSR accepted a CSR carrying Subject.Organization — attacker group-injection would be signed")
	}
	if !strings.Contains(err.Error(), "Organization") {
		t.Fatalf("expected error to reference Subject.Organization, got: %v", err)
	}
}
