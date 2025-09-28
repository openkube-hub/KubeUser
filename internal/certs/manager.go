/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package certs

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	// CertificateValidityDuration is how long the certificates are valid for
	CertificateValidityDuration = 365 * 24 * time.Hour // 1 year

	// RenewalThreshold is when to renew certificates (90 days before expiry)
	RenewalThreshold = 90 * 24 * time.Hour

	// DefaultCertDir is the default directory for storing certificates
	// For local development, use project folder; for production, use /tmp
	DefaultCertDir = "./certs"
)

// Manager handles certificate generation and management
type Manager struct {
	CertDir  string
	CertName string
	KeyName  string

	// Service information for certificate generation
	ServiceName      string
	ServiceNamespace string
}

// NewManager creates a new certificate manager
func NewManager(certDir, certName, keyName, serviceName, serviceNamespace string) *Manager {
	if certDir == "" {
		// Use project folder for local dev, /tmp for production
		if _, err := os.Stat("./go.mod"); err == nil {
			// We're in project directory (local development)
			certDir = DefaultCertDir
		} else {
			// We're likely in a container (production)
			certDir = "/tmp/k8s-webhook-server/serving-certs"
		}
	}
	if certName == "" {
		certName = "tls.crt"
	}
	if keyName == "" {
		keyName = "tls.key"
	}
	if serviceName == "" {
		serviceName = "webhook-service"
	}
	if serviceNamespace == "" {
		serviceNamespace = "system"
	}

	return &Manager{
		CertDir:          certDir,
		CertName:         certName,
		KeyName:          keyName,
		ServiceName:      serviceName,
		ServiceNamespace: serviceNamespace,
	}
}

// EnsureCertificates ensures valid certificates exist, creating them if necessary
func (m *Manager) EnsureCertificates() error {
	logger := log.Log.WithName("cert-manager")

	certPath := filepath.Join(m.CertDir, m.CertName)
	keyPath := filepath.Join(m.CertDir, m.KeyName)

	// Check if certificates exist and are still valid
	if m.certificatesValid(certPath) {
		logger.Info("Valid certificates found", "certPath", certPath)
		return nil
	}

	logger.Info("Generating new certificates", "certDir", m.CertDir)

	// Create certificate directory if it doesn't exist
	if err := os.MkdirAll(m.CertDir, 0755); err != nil {
		return fmt.Errorf("failed to create certificate directory: %w", err)
	}

	// Generate new certificates
	if err := m.generateCertificates(certPath, keyPath); err != nil {
		return fmt.Errorf("failed to generate certificates: %w", err)
	}

	logger.Info("Successfully generated new certificates")
	return nil
}

// certificatesValid checks if existing certificates are valid and not expiring soon
func (m *Manager) certificatesValid(certPath string) bool {
	// Check if certificate file exists
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return false
	}

	// Parse certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	// Check if certificate is expiring soon
	timeUntilExpiry := cert.NotAfter.Sub(time.Now())
	if timeUntilExpiry < RenewalThreshold {
		return false
	}

	return true
}

// generateCertificates creates new self-signed certificates
func (m *Manager) generateCertificates(certPath, keyPath string) error {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"KubeUser Controller"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(CertificateValidityDuration),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add Subject Alternative Names
	serviceFQDN := fmt.Sprintf("%s.%s.svc", m.ServiceName, m.ServiceNamespace)
	serviceClusterFQDN := fmt.Sprintf("%s.%s.svc.cluster.local", m.ServiceName, m.ServiceNamespace)

	template.DNSNames = []string{
		m.ServiceName,
		serviceFQDN,
		serviceClusterFQDN,
		"localhost",
	}

	template.IPAddresses = []net.IP{
		net.IPv4(127, 0, 0, 1),
		net.IPv6loopback,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate to file
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key to file
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// SetupWithManager sets up certificate management with the controller manager
func (m *Manager) SetupWithManager(mgr ctrl.Manager) error {
	// Ensure certificates exist before starting
	if err := m.EnsureCertificates(); err != nil {
		return fmt.Errorf("failed to ensure certificates: %w", err)
	}

	// Add a runnable that periodically checks and renews certificates
	return mgr.Add(&CertificateRenewer{manager: m})
}

// CertificateRenewer is a runnable that periodically checks and renews certificates
type CertificateRenewer struct {
	manager *Manager
}

// Start implements the Runnable interface
func (r *CertificateRenewer) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("cert-renewer")

	// Check certificates every hour
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := r.manager.EnsureCertificates(); err != nil {
				logger.Error(err, "Failed to ensure certificates during renewal check")
			}
		}
	}
}

// NeedLeaderElection implements the LeaderElectionRunnable interface
func (r *CertificateRenewer) NeedLeaderElection() bool {
	return false // Certificate renewal doesn't need leader election
}

// Ensure CertificateRenewer implements the necessary interfaces
var _ manager.Runnable = &CertificateRenewer{}
var _ manager.LeaderElectionRunnable = &CertificateRenewer{}
