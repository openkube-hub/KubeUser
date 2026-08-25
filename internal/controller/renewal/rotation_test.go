package renewal

import (
	"context"
	"strings"
	"testing"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

// TestRotationManager_concurrentRotationsIsPerInstance pins the invariant that
// each RotationManager owns its own in-flight counter. When the counter was a
// package-level var, parallel tests observed each other's increments and one
// manager's metric reading reflected the sum across every manager in the
// process rather than its own workload.
func TestRotationManager_concurrentRotationsIsPerInstance(t *testing.T) {
	rmA := NewRotationManager(nil, nil, "", "", nil)
	rmB := NewRotationManager(nil, nil, "", "", nil)

	rmA.concurrentRotations.Add(1)
	rmA.concurrentRotations.Add(1)

	if got := rmA.concurrentRotations.Load(); got != 2 {
		t.Errorf("rmA.concurrentRotations = %d, want 2", got)
	}
	if got := rmB.concurrentRotations.Load(); got != 0 {
		t.Errorf("rmB.concurrentRotations = %d, want 0; counter leaked between RotationManager instances", got)
	}

	rmB.concurrentRotations.Add(5)
	if got := rmA.concurrentRotations.Load(); got != 2 {
		t.Errorf("rmA.concurrentRotations = %d after mutating rmB, want 2; counter leaked between RotationManager instances", got)
	}
	if got := rmB.concurrentRotations.Load(); got != 5 {
		t.Errorf("rmB.concurrentRotations = %d, want 5", got)
	}
}

func TestRotationManagerBuildKubeconfigUsesConfiguredClusterName(t *testing.T) {
	rm := NewRotationManager(nil, nil, "", "production", nil)

	rawKubeconfig, err := rm.buildKubeconfig(
		"https://kubernetes.default.svc",
		[]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"),
		[]byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"),
		[]byte("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"),
		"alice",
	)
	if err != nil {
		t.Fatalf("buildKubeconfig() unexpected error: %v", err)
	}
	got := string(rawKubeconfig)

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
			err := rm.validateCSRForApproval(tt.csr, "alice", nil)

			if (err != nil) != tt.wantErr {
				t.Errorf("validateCSRForApproval() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestRotationManager_ShadowSecretHasValidOwnerReference is the regression guard
// for the silent GC-orphan bug. The cache-backed client strips TypeMeta on
// returned objects, so reading user.APIVersion/user.Kind at runtime yields
// empty strings — and Kubernetes GC ignores OwnerReferences with an empty
// APIVersion or Kind. Any future regression to `user.APIVersion`/`user.Kind`
// here silently orphans the shadow secret (which contains a private key) when
// the User is deleted with the finalizer removed manually.
func TestRotationManager_ShadowSecretHasValidOwnerReference(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("scheme: %v", err)
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	rm := NewRotationManager(cli, nil, "kubernetes.io/kube-apiserver-client", "", nil)

	// Mimic the reconciler: the User comes from the informer cache with empty
	// TypeMeta, exactly the condition that triggered the original bug.
	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "alice",
			UID:  "12345678-1234-1234-1234-123456789012",
		},
	}

	if err := rm.createShadowSecretForRotation(context.Background(), user); err != nil {
		t.Fatalf("createShadowSecretForRotation: %v", err)
	}

	got := &corev1.Secret{}
	if err := cli.Get(context.Background(), client.ObjectKey{Name: "alice-rotation-temp", Namespace: "kubeuser"}, got); err != nil {
		t.Fatalf("get shadow secret: %v", err)
	}

	if len(got.OwnerReferences) != 1 {
		t.Fatalf("expected exactly 1 OwnerReference, got %d", len(got.OwnerReferences))
	}
	ref := got.OwnerReferences[0]
	if ref.APIVersion != authv1alpha1.GroupVersion.String() {
		t.Errorf("OwnerReference.APIVersion = %q, want %q — empty or wrong APIVersion causes GC to skip this ref", ref.APIVersion, authv1alpha1.GroupVersion.String())
	}
	if ref.Kind != "User" {
		t.Errorf("OwnerReference.Kind = %q, want %q — empty or wrong Kind causes GC to skip this ref", ref.Kind, "User")
	}
	if ref.Name != user.Name {
		t.Errorf("OwnerReference.Name = %q, want %q", ref.Name, user.Name)
	}
	if ref.UID != user.UID {
		t.Errorf("OwnerReference.UID = %q, want %q", ref.UID, user.UID)
	}
	if ref.Controller == nil || !*ref.Controller {
		t.Errorf("OwnerReference.Controller = %v, want *true", ref.Controller)
	}
	if ref.BlockOwnerDeletion == nil || !*ref.BlockOwnerDeletion {
		t.Errorf("OwnerReference.BlockOwnerDeletion = %v, want *true", ref.BlockOwnerDeletion)
	}
}

// TestRotationManager_CSRHasValidOwnerReference is the regression guard for the
// silent GC-orphan bug on renewal CSRs. See the shadow secret variant above for
// the full explanation. This second test exists because the two OwnerReference
// blocks are separate literals in the source and can regress independently.
func TestRotationManager_CSRHasValidOwnerReference(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1 scheme: %v", err)
	}
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatalf("certv1 scheme: %v", err)
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	rm := NewRotationManager(cli, nil, "kubernetes.io/kube-apiserver-client", "", nil)

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "alice",
			UID:  "12345678-1234-1234-1234-123456789012",
		},
	}

	// Seed the shadow secret so we can reuse its key for the CSR path.
	if err := rm.createShadowSecretForRotation(context.Background(), user); err != nil {
		t.Fatalf("createShadowSecretForRotation: %v", err)
	}
	shadow := &corev1.Secret{}
	if err := cli.Get(context.Background(), client.ObjectKey{Name: "alice-rotation-temp", Namespace: "kubeuser"}, shadow); err != nil {
		t.Fatalf("get shadow secret: %v", err)
	}

	csrName := rm.generateUniqueCSRName(user.Name, string(user.UID))
	got, err := rm.ensureCSRExists(context.Background(), user, csrName, user.Name, shadow.Data["key.pem"], time.Hour)
	if err != nil {
		t.Fatalf("ensureCSRExists: %v", err)
	}
	// Also re-read from the client so we assert what the API actually persisted, not just what we constructed.
	if err := cli.Get(context.Background(), client.ObjectKey{Name: csrName}, got); err != nil {
		t.Fatalf("get csr: %v", err)
	}

	if len(got.OwnerReferences) != 1 {
		t.Fatalf("expected exactly 1 OwnerReference, got %d", len(got.OwnerReferences))
	}
	ref := got.OwnerReferences[0]
	if ref.APIVersion != authv1alpha1.GroupVersion.String() {
		t.Errorf("OwnerReference.APIVersion = %q, want %q — empty or wrong APIVersion causes GC to skip this ref", ref.APIVersion, authv1alpha1.GroupVersion.String())
	}
	if ref.Kind != "User" {
		t.Errorf("OwnerReference.Kind = %q, want %q — empty or wrong Kind causes GC to skip this ref", ref.Kind, "User")
	}
	if ref.Name != user.Name {
		t.Errorf("OwnerReference.Name = %q, want %q", ref.Name, user.Name)
	}
	if ref.UID != user.UID {
		t.Errorf("OwnerReference.UID = %q, want %q", ref.UID, user.UID)
	}
	// The CSR ref is deliberately non-controller (per rotation.go comment) but
	// must still block foreground deletion so orphaned certs cannot outlive the User.
	if ref.BlockOwnerDeletion == nil || !*ref.BlockOwnerDeletion {
		t.Errorf("OwnerReference.BlockOwnerDeletion = %v, want *true", ref.BlockOwnerDeletion)
	}
}

// TestRotationManager_RotateUserCertificate_RejectsUnownedShadowSecret is the
// regression guard for CVE-class issue #115: RotateUserCertificate previously
// treated any Secret sitting at `<user>-rotation-temp` as prior operator state
// and resumed the rotation from its `key.pem`. A caller with `create` on
// Secrets in the operator namespace could plant their own private key, wait for
// any legitimate rotation trigger, and the operator would build a CSR against
// the planted key and write that key into `<user>-kubeconfig` on the atomic
// flip — silently authenticating the target User with attacker-held key
// material. This test drives the exact pre-plant scenario and asserts the
// operator refuses to resume, deletes the impostor, and does not create a CSR.
func TestRotationManager_RotateUserCertificate_RejectsUnownedShadowSecret(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1 scheme: %v", err)
	}
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatalf("certv1 scheme: %v", err)
	}

	// Impostor shadow secret with attacker key and no OwnerReference back to
	// the target User. This is the exact shape reproduced on the live cluster
	// in the issue's PoC (labels + csr-name annotation to look legitimate).
	impostor := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alice-rotation-temp",
			Namespace: "kubeuser",
			Labels: map[string]string{
				authv1alpha1.UserLabel:     "alice",
				authv1alpha1.RotationLabel: "true",
				authv1alpha1.ShadowLabel:   "true",
			},
			Annotations: map[string]string{
				authv1alpha1.CSRNameAnnotation: "alice-attacker-csr",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"key.pem": []byte("attacker-controlled-key-material")},
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(impostor).Build()
	recorder := record.NewFakeRecorder(10)
	rm := NewRotationManager(cli, recorder, "kubernetes.io/kube-apiserver-client", "", nil)

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alice",
			Namespace: "kubeuser",
			UID:       "12345678-1234-1234-1234-123456789012",
		},
	}

	_, _, err := rm.RotateUserCertificate(context.Background(), user, time.Hour)
	if err == nil {
		t.Fatal("RotateUserCertificate accepted an unowned shadow secret — attacker key would be used for the next CSR and written into the user's kubeconfig")
	}
	if !strings.Contains(err.Error(), "not owned by user") {
		t.Errorf("error = %v, want it to mention the ownership refusal", err)
	}

	// The impostor must be removed so a follow-up reconcile starts a clean
	// rotation instead of loop-refusing forever.
	got := &corev1.Secret{}
	getErr := cli.Get(context.Background(), client.ObjectKey{Name: "alice-rotation-temp", Namespace: "kubeuser"}, got)
	if !apierrors.IsNotFound(getErr) {
		t.Errorf("impostor shadow secret still present after refusal (get err = %v); operator would keep tripping the same trust check", getErr)
	}

	// No CSR must have been created — reaching CSR creation means the attacker
	// key already flowed into a public-key artefact ready for signer approval.
	csrList := &certv1.CertificateSigningRequestList{}
	if err := cli.List(context.Background(), csrList); err != nil {
		t.Fatalf("list CSRs: %v", err)
	}
	if len(csrList.Items) != 0 {
		t.Errorf("expected 0 CSRs after refusing untrusted shadow, got %d: %+v", len(csrList.Items), csrList.Items)
	}

	// Operator visibility: an event must fire so cluster admins can catch this in audits.
	select {
	case ev := <-recorder.Events:
		if !strings.Contains(ev, "ShadowSecretUntrusted") {
			t.Errorf("event %q does not name the trust-check reason", ev)
		}
	default:
		t.Error("no event emitted for refusal — this attack must be observable to operators")
	}
}

// TestRotationManager_RotateUserCertificate_AcceptsOwnedShadowSecret is the
// symmetric guard: the trust check must not falsely reject shadow secrets the
// operator itself created. A false positive here would break every in-progress
// rotation, effectively DoSing the operator.
func TestRotationManager_RotateUserCertificate_AcceptsOwnedShadowSecret(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1 scheme: %v", err)
	}
	if err := certv1.AddToScheme(scheme); err != nil {
		t.Fatalf("certv1 scheme: %v", err)
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).Build()
	recorder := record.NewFakeRecorder(10)
	rm := NewRotationManager(cli, recorder, "kubernetes.io/kube-apiserver-client", "", nil)

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alice",
			Namespace: "kubeuser",
			UID:       "12345678-1234-1234-1234-123456789012",
		},
	}

	// Production WRITE path — creates a shadow secret owned by this User.
	if err := rm.createShadowSecretForRotation(context.Background(), user); err != nil {
		t.Fatalf("createShadowSecretForRotation: %v", err)
	}

	// Second call should treat the operator-created secret as trusted and
	// progress past the trust check. It will still fail further down
	// (e.g. approval subresource is not implemented by the fake client), but
	// the error must NOT be the ownership refusal.
	_, _, err := rm.RotateUserCertificate(context.Background(), user, time.Hour)
	if err != nil && strings.Contains(err.Error(), "not owned by user") {
		t.Fatalf("operator-created shadow secret was refused as untrusted: %v", err)
	}

	// The trusted shadow secret must survive — deleting it here would abort a
	// legitimate in-progress rotation.
	got := &corev1.Secret{}
	if err := cli.Get(context.Background(), client.ObjectKey{Name: "alice-rotation-temp", Namespace: "kubeuser"}, got); err != nil {
		t.Fatalf("legitimate shadow secret was deleted by trust check: %v", err)
	}
}

// TestRotationManager_AtomicSecretUpdate_KeySecretCarriesOwnerReference guards
// the second half of the fix: rotation writes the new private key back to
// `<user>-key` via atomicSecretUpdate; if that write drops the OwnerReference
// then ensurePrivateKey's trust check refuses the same key on the next
// initial-issuance-style reconcile and the operator wedges. The invariant is
// therefore "rotation-time key writes must be adoptable by the read path".
func TestRotationManager_AtomicSecretUpdate_KeySecretCarriesOwnerReference(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("corev1 scheme: %v", err)
	}

	// Seed the CA ConfigMap so getClusterCA succeeds in the test env.
	caCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "kube-root-ca.crt", Namespace: "default"},
		Data:       map[string]string{"ca.crt": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"},
	}

	cli := fake.NewClientBuilder().WithScheme(scheme).WithObjects(caCM).Build()
	rm := NewRotationManager(cli, record.NewFakeRecorder(10), "kubernetes.io/kube-apiserver-client", "", nil)

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alice",
			Namespace: "kubeuser",
			UID:       "12345678-1234-1234-1234-123456789012",
		},
	}

	newKeyPEM := []byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----")
	signedCert := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")

	if err := rm.atomicSecretUpdate(context.Background(), user, newKeyPEM, signedCert); err != nil {
		t.Fatalf("atomicSecretUpdate: %v", err)
	}

	got := &corev1.Secret{}
	if err := cli.Get(context.Background(), client.ObjectKey{Name: "alice-key", Namespace: "kubeuser"}, got); err != nil {
		t.Fatalf("get key secret: %v", err)
	}
	if len(got.OwnerReferences) != 1 {
		t.Fatalf("key secret OwnerReferences count = %d, want 1 — without an owner ref the read-side trust check would refuse this key on next reconcile", len(got.OwnerReferences))
	}
	ref := got.OwnerReferences[0]
	if !helpers.IsOwnedByUser(got, user) {
		t.Errorf("key secret OwnerReference = (Kind=%q, UID=%q), want the shared IsOwnedByUser check to accept it", ref.Kind, ref.UID)
	}
	if ref.APIVersion != authv1alpha1.GroupVersion.String() {
		t.Errorf("key secret OwnerReference.APIVersion = %q, want %q (empty APIVersion causes GC to skip the ref)", ref.APIVersion, authv1alpha1.GroupVersion.String())
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
