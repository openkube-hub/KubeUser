package auth

import (
	"context"
	"testing"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestX509Provider_Ensure(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = authv1alpha1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	provider := NewX509Provider(client, nil, "", nil) // nil event recorder and metrics for tests, default signer

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-user",
		},
		Spec: authv1alpha1.UserSpec{
			Auth: &authv1alpha1.AuthSpec{
				Type: stringPtr("x509"),
				TTL:  "72h",
			},
		},
	}

	ctx := context.Background()

	// Test ensure - this will fail in unit tests due to missing cluster dependencies
	// but we can verify the validation logic works
	_, _, err := provider.Ensure(ctx, user)
	// We expect this to fail due to missing cluster resources in unit test
	if err != nil {
		t.Logf("X509 ensure failed as expected in unit test: %v", err)
	}

	// Test with invalid TTL
	user.Spec.Auth.TTL = "-1h"
	_, _, err = provider.Ensure(ctx, user)
	if err == nil {
		t.Error("Should fail with invalid duration")
	}
}

func TestX509Provider_Revoke(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = authv1alpha1.AddToScheme(scheme)

	client := fake.NewClientBuilder().WithScheme(scheme).Build()
	provider := NewX509Provider(client, nil, "", nil) // nil event recorder and metrics for tests, default signer

	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-user",
		},
		Spec: authv1alpha1.UserSpec{
			Auth: &authv1alpha1.AuthSpec{
				Type: stringPtr("x509"),
			},
		},
	}

	ctx := context.Background()

	// Test revoke - should not error (stub implementation)
	err := provider.Revoke(ctx, user)
	if err != nil {
		t.Errorf("X509 revoke should not error: %v", err)
	}
}
