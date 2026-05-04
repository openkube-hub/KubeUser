package cleanup

import (
	"context"
	"testing"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, certv1.AddToScheme, rbacv1.AddToScheme, authv1alpha1.AddToScheme,
	} {
		if err := add(s); err != nil {
			t.Fatalf("scheme: %v", err)
		}
	}
	return s
}

// Regression test for issue #53: rotation artifacts must be deleted by the
// finalizer, not left to garbage collection.
func TestCleanupUserResources_DeletesRotationArtifacts(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	user := &authv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: "alice", UID: "uid-123"}}
	shadow := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "alice-rotation-temp", Namespace: "kubeuser",
		Labels: map[string]string{"auth.openkube.io/user": "alice"},
	}}
	renewalCSR := &certv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{
		Name:   "alice-renewal-uid12345",
		Labels: map[string]string{"auth.openkube.io/user": "alice"},
	}}
	// Resource for a different user must survive — proves the selector is correct.
	otherShadow := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "bob-rotation-temp", Namespace: "kubeuser",
		Labels: map[string]string{"auth.openkube.io/user": "bob"},
	}}

	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(user, shadow, renewalCSR, otherShadow).
		Build()

	CleanupUserResources(context.Background(), cli, user)

	mustNotFound := func(name string, obj client.Object) {
		t.Helper()
		err := cli.Get(context.Background(), client.ObjectKeyFromObject(obj), obj)
		if !apierrors.IsNotFound(err) {
			t.Errorf("%s: expected NotFound, got %v", name, err)
		}
	}
	mustExist := func(name string, obj client.Object) {
		t.Helper()
		if err := cli.Get(context.Background(), client.ObjectKeyFromObject(obj), obj); err != nil {
			t.Errorf("%s: expected to still exist, got %v", name, err)
		}
	}

	mustNotFound("shadow secret", &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-rotation-temp", Namespace: "kubeuser"}})
	mustNotFound("renewal csr", &certv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: "alice-renewal-uid12345"}})
	mustExist("bob's shadow secret (different user, must survive)",
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bob-rotation-temp", Namespace: "kubeuser"}})
}
