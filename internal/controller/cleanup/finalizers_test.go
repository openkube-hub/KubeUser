package cleanup

import (
	"context"
	"errors"
	"strings"
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
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
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

	aliceKey := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-key", Namespace: "kubeuser"}}
	aliceKubeconfig := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-kubeconfig", Namespace: "kubeuser"}}
	bobKey := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bob-key", Namespace: "kubeuser"}}

	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(user, shadow, renewalCSR, otherShadow, aliceKey, aliceKubeconfig, bobKey).
		Build()

	if err := CleanupUserResources(context.Background(), cli, user); err != nil {
		t.Fatalf("CleanupUserResources returned unexpected error: %v", err)
	}

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
	mustNotFound("alice-key", &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-key", Namespace: "kubeuser"}})
	mustNotFound("alice-kubeconfig", &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-kubeconfig", Namespace: "kubeuser"}})
	mustExist("bob-key (different user, must survive)",
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bob-key", Namespace: "kubeuser"}})
	mustExist("bob's shadow secret (different user, must survive)",
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "bob-rotation-temp", Namespace: "kubeuser"}})
}

// Regression test for issue #54: partial cleanup failures must surface as an
// error so the caller can retain the finalizer and requeue. Silently swallowing
// errors here previously caused permanent resource leaks — the finalizer would
// be stripped even when Secrets, CSRs, or RoleBindings failed to delete.
func TestCleanupUserResources_PropagatesDeletionErrors(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	user := &authv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: "alice", UID: "uid-123"}}

	injected := errors.New("simulated API failure")

	tests := []struct {
		name         string
		objects      []client.Object
		funcs        interceptor.Funcs
		wantContains string
	}{
		{
			name: "fixed secret delete fails",
			objects: []client.Object{
				user,
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-key", Namespace: "kubeuser"}},
			},
			funcs: interceptor.Funcs{
				Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					if s, ok := obj.(*corev1.Secret); ok && s.Name == "alice-key" {
						return injected
					}
					return c.Delete(ctx, obj, opts...)
				},
			},
			wantContains: "delete Secret kubeuser/alice-key",
		},
		{
			name: "labelled secret list fails",
			objects: []client.Object{
				user,
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{
					Name: "alice-rotation-temp", Namespace: "kubeuser",
					Labels: map[string]string{"auth.openkube.io/user": "alice"},
				}},
			},
			funcs: interceptor.Funcs{
				List: func(ctx context.Context, c client.WithWatch, list client.ObjectList, opts ...client.ListOption) error {
					if _, ok := list.(*corev1.SecretList); ok {
						return injected
					}
					return c.List(ctx, list, opts...)
				},
			},
			wantContains: "list labelled Secrets",
		},
		{
			name: "csr delete fails",
			objects: []client.Object{
				user,
				&certv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{
					Name:   "alice-renewal-uid12345",
					Labels: map[string]string{"auth.openkube.io/user": "alice"},
				}},
			},
			funcs: interceptor.Funcs{
				Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					if _, ok := obj.(*certv1.CertificateSigningRequest); ok {
						return injected
					}
					return c.Delete(ctx, obj, opts...)
				},
			},
			wantContains: "delete CSR alice-renewal-uid12345",
		},
		{
			name: "rolebinding delete fails",
			objects: []client.Object{
				user,
				&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{
					Name: "alice-rb", Namespace: "team-a",
					Labels: map[string]string{"auth.openkube.io/user": "alice"},
				}},
			},
			funcs: interceptor.Funcs{
				Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					if _, ok := obj.(*rbacv1.RoleBinding); ok {
						return injected
					}
					return c.Delete(ctx, obj, opts...)
				},
			},
			wantContains: "delete RoleBinding team-a/alice-rb",
		},
		{
			name: "clusterrolebinding delete fails",
			objects: []client.Object{
				user,
				&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{
					Name:   "alice-crb",
					Labels: map[string]string{"auth.openkube.io/user": "alice"},
				}},
			},
			funcs: interceptor.Funcs{
				Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
					if _, ok := obj.(*rbacv1.ClusterRoleBinding); ok {
						return injected
					}
					return c.Delete(ctx, obj, opts...)
				},
			},
			wantContains: "delete ClusterRoleBinding alice-crb",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cli := fake.NewClientBuilder().
				WithScheme(newScheme(t)).
				WithObjects(tc.objects...).
				WithInterceptorFuncs(tc.funcs).
				Build()

			err := CleanupUserResources(context.Background(), cli, user)
			if err == nil {
				t.Fatalf("issue #54 regression: expected error from CleanupUserResources when %q, got nil — finalizer would be stripped and resources leaked", tc.name)
			}
			if !errors.Is(err, injected) {
				t.Errorf("expected error chain to wrap the injected failure via %%w, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantContains) {
				t.Errorf("expected error to name the failing resource (%q), got %q", tc.wantContains, err.Error())
			}
		})
	}
}

// Aggregation test: multiple simultaneous failures must all surface, so
// operators see the full blast radius of a cleanup that could not complete.
func TestCleanupUserResources_AggregatesMultipleErrors(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	user := &authv1alpha1.User{ObjectMeta: metav1.ObjectMeta{Name: "alice", UID: "uid-123"}}
	objects := []client.Object{
		user,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-key", Namespace: "kubeuser"}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{
			Name:   "alice-crb",
			Labels: map[string]string{"auth.openkube.io/user": "alice"},
		}},
	}

	failAll := errors.New("api down")
	cli := fake.NewClientBuilder().
		WithScheme(newScheme(t)).
		WithObjects(objects...).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				return failAll
			},
		}).
		Build()

	err := CleanupUserResources(context.Background(), cli, user)
	if err == nil {
		t.Fatal("expected aggregated error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"alice-key", "alice-crb"} {
		if !strings.Contains(msg, want) {
			t.Errorf("aggregated error should name %q, got %q", want, msg)
		}
	}
}
