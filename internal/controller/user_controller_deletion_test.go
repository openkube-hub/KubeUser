/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"errors"
	"testing"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// Regression test for issue #54: when CleanupUserResources fails, handleDeletion
// must retain the finalizer and surface the error, so a later reconcile can
// retry. Pre-fix, the cleanup error was silently discarded and the finalizer
// was always removed, permanently orphaning any resource whose delete failed.
func TestHandleDeletion_KeepsFinalizerWhenCleanupFails(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, certv1.AddToScheme, rbacv1.AddToScheme, authv1alpha1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("scheme: %v", err)
		}
	}

	now := metav1.Now()
	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "alice",
			Namespace:         "default",
			Finalizers:        []string{authv1alpha1.UserFinalizer},
			DeletionTimestamp: &now,
		},
	}
	leaked := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "alice-key", Namespace: "kubeuser"}}

	injected := errors.New("simulated etcd unavailable")
	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user, leaked).
		WithInterceptorFuncs(interceptor.Funcs{
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
				if s, ok := obj.(*corev1.Secret); ok && s.Name == "alice-key" {
					return injected
				}
				return c.Delete(ctx, obj, opts...)
			},
		}).
		Build()

	r := &UserReconciler{Client: cli, Scheme: scheme}

	err := r.handleDeletion(context.Background(), user)
	if err == nil {
		t.Fatal("expected error from handleDeletion when cleanup fails, got nil — finalizer would be stripped and Secret orphaned")
	}
	if !errors.Is(err, injected) {
		t.Errorf("expected error chain to wrap the injected cleanup failure, got %v", err)
	}

	var persisted authv1alpha1.User
	if getErr := cli.Get(context.Background(), types.NamespacedName{Name: "alice", Namespace: "default"}, &persisted); getErr != nil {
		t.Fatalf("get user after failed deletion: %v", getErr)
	}
	found := false
	for _, f := range persisted.Finalizers {
		if f == authv1alpha1.UserFinalizer {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("issue #54 regression: finalizer %q was removed despite cleanup failure — resources would be orphaned; finalizers=%v",
			authv1alpha1.UserFinalizer, persisted.Finalizers)
	}
}

// Companion happy-path spec: when cleanup succeeds, the finalizer is removed
// and the User is fully deleted. This pairs with the failure case above so a
// reader sees both invariants side by side.
func TestHandleDeletion_RemovesFinalizerWhenCleanupSucceeds(t *testing.T) {
	t.Setenv("KUBEUSER_NAMESPACE", "kubeuser")

	scheme := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{
		corev1.AddToScheme, certv1.AddToScheme, rbacv1.AddToScheme, authv1alpha1.AddToScheme,
	} {
		if err := add(scheme); err != nil {
			t.Fatalf("scheme: %v", err)
		}
	}

	now := metav1.Now()
	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "alice",
			Namespace:         "default",
			Finalizers:        []string{authv1alpha1.UserFinalizer},
			DeletionTimestamp: &now,
		},
	}

	cli := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(user).
		Build()

	r := &UserReconciler{Client: cli, Scheme: scheme}

	if err := r.handleDeletion(context.Background(), user); err != nil {
		t.Fatalf("handleDeletion returned unexpected error: %v", err)
	}

	// With finalizer removed and DeletionTimestamp set, the fake client GCs the object.
	err := cli.Get(context.Background(), types.NamespacedName{Name: "alice", Namespace: "default"}, &authv1alpha1.User{})
	if err == nil {
		t.Fatal("expected user to be gone after successful cleanup + finalizer removal")
	}
}
