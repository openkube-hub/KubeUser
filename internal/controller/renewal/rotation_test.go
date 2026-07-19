package renewal

import (
	"context"
	"strings"
	"testing"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRotationManager_generateUniqueCSRName(t *testing.T) {
	rm := NewRotationManager(nil, nil, "", "", nil)

	tests := []struct {
		name     string
		username string
		userUID  string
		want     string
	}{
		{
			name:     "normal case",
			username: "alice",
			userUID:  "12345678-1234-1234-1234-123456789012",
			want:     "alice-renewal-12345678",
		},
		{
			name:     "short UID",
			username: "bob",
			userUID:  "abcd1234",
			want:     "bob-renewal-abcd1234",
		},
		{
			name:     "long username",
			username: "very-long-username",
			userUID:  "87654321-4321-4321-4321-210987654321",
			want:     "very-long-username-renewal-87654321",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rm.generateUniqueCSRName(tt.username, tt.userUID)
			if got != tt.want {
				t.Errorf("generateUniqueCSRName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRotationManagerBuildKubeconfigUsesConfiguredClusterName(t *testing.T) {
	rm := NewRotationManager(nil, nil, "", "production", nil)

	got := string(rm.buildKubeconfig(
		"https://kubernetes.default.svc",
		"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
		[]byte("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"),
		[]byte("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t"),
		"alice",
	))

	expectedStrings := []string{
		"  name: production",
		"    cluster: production",
		"  name: alice@production",
		"current-context: alice@production",
	}
	for _, expected := range expectedStrings {
		if !strings.Contains(got, expected) {
			t.Fatalf("buildKubeconfig() missing expected string %q in:\n%s", expected, got)
		}
	}
}

func TestRotationManager_IsRotationInProgress(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)

	tests := []struct {
		name           string
		username       string
		shadowSecret   *corev1.Secret
		wantInProgress bool
		wantCSRName    string
		wantErr        bool
	}{
		{
			name:           "no rotation in progress",
			username:       "alice",
			shadowSecret:   nil,
			wantInProgress: false,
			wantCSRName:    "",
			wantErr:        false,
		},
		{
			name:     "rotation in progress",
			username: "bob",
			shadowSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "bob-rotation-temp",
					Namespace: "kubeuser",
					Labels: map[string]string{
						"auth.openkube.io/user":     "bob",
						"auth.openkube.io/rotation": "true",
						"auth.openkube.io/shadow":   "true",
					},
					Annotations: map[string]string{
						authv1alpha1.CSRNameAnnotation: "bob-renewal-12345678",
					},
				},
				Data: map[string][]byte{
					"key.pem": []byte("fake-key"),
				},
			},
			wantInProgress: true,
			wantCSRName:    "bob-renewal-12345678",
			wantErr:        false,
		},
		{
			name:     "corrupted shadow secret",
			username: "charlie",
			shadowSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "charlie-rotation-temp",
					Namespace: "kubeuser",
					Labels: map[string]string{
						"auth.openkube.io/user":     "charlie",
						"auth.openkube.io/rotation": "true",
						"auth.openkube.io/shadow":   "true",
					},
				},
				Data: map[string][]byte{
					"key.pem": []byte("fake-key"),
					// Missing csr.name
				},
			},
			wantInProgress: true,
			wantCSRName:    "", // Empty due to corruption
			wantErr:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var objects []runtime.Object
			if tt.shadowSecret != nil {
				objects = append(objects, tt.shadowSecret)
			}

			client := fake.NewClientBuilder().
				WithScheme(scheme).
				WithRuntimeObjects(objects...).
				Build()

			rm := NewRotationManager(client, nil, "", "", nil)

			gotInProgress, gotCSRName, err := rm.IsRotationInProgress(context.TODO(), tt.username)

			if (err != nil) != tt.wantErr {
				t.Errorf("IsRotationInProgress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if gotInProgress != tt.wantInProgress {
				t.Errorf("IsRotationInProgress() inProgress = %v, want %v", gotInProgress, tt.wantInProgress)
			}

			if gotCSRName != tt.wantCSRName {
				t.Errorf("IsRotationInProgress() csrName = %v, want %v", gotCSRName, tt.wantCSRName)
			}
		})
	}
}

func TestRotationManager_GetRotationRequeueDelay(t *testing.T) {
	rm := NewRotationManager(nil, nil, "", "", nil)

	tests := []struct {
		name         string
		certDuration time.Duration
		want         time.Duration
	}{
		{
			name:         "short-lived certificate",
			certDuration: 30 * time.Minute,
			want:         10 * time.Second,
		},
		{
			name:         "medium-lived certificate",
			certDuration: 12 * time.Hour,
			want:         30 * time.Second,
		},
		{
			name:         "long-lived certificate",
			certDuration: 7 * 24 * time.Hour, // 7 days
			want:         2 * time.Minute,
		},
		{
			name:         "very long-lived certificate",
			certDuration: 365 * 24 * time.Hour, // 1 year
			want:         2 * time.Minute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rm.GetRotationRequeueDelay(tt.certDuration)
			if got != tt.want {
				t.Errorf("GetRotationRequeueDelay() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRotationManager_recordUniqueAttempt_Basic(t *testing.T) {
	rm := NewRotationManager(nil, nil, "", "", nil)

	// Test basic functionality - adding first attempt
	user := &authv1alpha1.User{
		Status: authv1alpha1.UserStatus{
			RenewalHistory: []authv1alpha1.RenewalAttempt{},
		},
	}

	attempt := authv1alpha1.RenewalAttempt{
		Timestamp: metav1.Now(),
		Success:   true,
		Message:   "Test attempt",
		CSRName:   "test-csr",
	}

	rm.recordUniqueAttempt(user, attempt)

	if len(user.Status.RenewalHistory) != 1 {
		t.Errorf("Expected 1 attempt in history, got %d", len(user.Status.RenewalHistory))
	}

	if user.Status.RenewalHistory[0].Message != "Test attempt" {
		t.Errorf("Expected message 'Test attempt', got %s", user.Status.RenewalHistory[0].Message)
	}
}

func TestRotationManager_validateCSRForApproval(t *testing.T) {
	rm := NewRotationManager(nil, nil, "", "", nil)

	tests := []struct {
		name    string
		csr     *certv1.CertificateSigningRequest
		wantErr bool
	}{
		{
			name: "valid CSR",
			csr: &certv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "alice-renewal-12345678",
					Labels: map[string]string{
						"auth.openkube.io/user":     "alice",
						"auth.openkube.io/renewal":  "true",
						"auth.openkube.io/rotation": "true",
					},
				},
				Spec: certv1.CertificateSigningRequestSpec{
					SignerName: certv1.KubeAPIServerClientSignerName,
					Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
					// Skip CSR content validation for this test - focus on metadata validation
					Request: []byte("fake-csr-content"),
				},
			},
			wantErr: true, // Will fail on CSR content parsing, but that's expected
		},
		{
			name: "invalid signer name",
			csr: &certv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "alice-renewal-12345678",
					Labels: map[string]string{
						"auth.openkube.io/user":     "alice",
						"auth.openkube.io/renewal":  "true",
						"auth.openkube.io/rotation": "true",
					},
				},
				Spec: certv1.CertificateSigningRequestSpec{
					SignerName: "invalid-signer",
					Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
					Request:    []byte("-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKYWxpY2UudGVzdDCCASIwDQYJKoZIhvcN\n-----END CERTIFICATE REQUEST-----"),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid usage",
			csr: &certv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "alice-renewal-12345678",
					Labels: map[string]string{
						"auth.openkube.io/user":     "alice",
						"auth.openkube.io/renewal":  "true",
						"auth.openkube.io/rotation": "true",
					},
				},
				Spec: certv1.CertificateSigningRequestSpec{
					SignerName: certv1.KubeAPIServerClientSignerName,
					Usages:     []certv1.KeyUsage{certv1.UsageServerAuth}, // Wrong usage
					Request:    []byte("-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKYWxpY2UudGVzdDCCASIwDQYJKoZIhvcN\n-----END CERTIFICATE REQUEST-----"),
				},
			},
			wantErr: true,
		},
		{
			name: "missing renewal label",
			csr: &certv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "alice-renewal-12345678",
					Labels: map[string]string{
						"auth.openkube.io/user":     "alice",
						"auth.openkube.io/rotation": "true",
						// Missing renewal label
					},
				},
				Spec: certv1.CertificateSigningRequestSpec{
					SignerName: certv1.KubeAPIServerClientSignerName,
					Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
					Request:    []byte("-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKYWxpY2UudGVzdDCCASIwDQYJKoZIhvcN\n-----END CERTIFICATE REQUEST-----"),
				},
			},
			wantErr: true,
		},
		{
			name: "missing rotation label",
			csr: &certv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "alice-renewal-12345678",
					Labels: map[string]string{
						"auth.openkube.io/user":    "alice",
						"auth.openkube.io/renewal": "true",
						// Missing rotation label
					},
				},
				Spec: certv1.CertificateSigningRequestSpec{
					SignerName: certv1.KubeAPIServerClientSignerName,
					Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
					Request:    []byte("-----BEGIN CERTIFICATE REQUEST-----\nMIICWjCCAUICAQAwFTETMBEGA1UEAwwKYWxpY2UudGVzdDCCASIwDQYJKoZIhvcN\n-----END CERTIFICATE REQUEST-----"),
				},
			},
			wantErr: true,
		},
		{
			name: "invalid CSR format",
			csr: &certv1.CertificateSigningRequest{
				ObjectMeta: metav1.ObjectMeta{
					Name: "alice-renewal-12345678",
					Labels: map[string]string{
						"auth.openkube.io/user":     "alice",
						"auth.openkube.io/renewal":  "true",
						"auth.openkube.io/rotation": "true",
					},
				},
				Spec: certv1.CertificateSigningRequestSpec{
					SignerName: certv1.KubeAPIServerClientSignerName,
					Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
					Request:    []byte("invalid-csr-data"),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rm.validateCSRForApproval(tt.csr)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateCSRForApproval() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRotationManager_IsRotationInProgress_RoundTripsCSRName is the regression
// guard for the silent CSR-name drift bug. createShadowSecretForRotation writes
// the CSR name to annotations; IsRotationInProgress must read from the same
// place. The test deliberately uses both production code paths — any future
// asymmetry in field or key fails the assertion loudly.
func TestRotationManager_IsRotationInProgress_RoundTripsCSRName(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	rm := NewRotationManager(cli, nil, "kubernetes.io/kube-apiserver-client", "", nil)

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "alice",
			UID:  "12345678-1234-1234-1234-123456789012",
		},
	}

	// Production WRITE path.
	if err := rm.createShadowSecretForRotation(context.Background(), user); err != nil {
		t.Fatalf("createShadowSecretForRotation: %v", err)
	}

	// Production READ path.
	inProgress, csrName, err := rm.IsRotationInProgress(context.Background(), user.Name)
	if err != nil {
		t.Fatalf("IsRotationInProgress: %v", err)
	}
	if !inProgress {
		t.Fatalf("expected rotation in progress = true, got false")
	}
	if csrName == "" {
		t.Fatalf("CSR name came back empty — writer and reader are using different field or key")
	}
	// generateUniqueCSRName is deterministic for (alice, 12345678-...).
	if want := "alice-renewal-12345678"; csrName != want {
		t.Errorf("CSR name round trip = %q, want %q", csrName, want)
	}
}
