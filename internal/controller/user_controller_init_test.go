/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package controller

import (
	"context"
	"testing"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/auth"
)

// Regression tests for issue #64: the reconcile paths used to lazily
// initialize AuthManager and RenewalCalculator via `if field == nil { field = New… }`.
// Two concurrent reconcile goroutines could both observe nil and race on the
// assignment. SetupWithManager is the sole owner of both fields, and reconcile
// paths must never mutate them.

func TestReconcileAuthenticationDoesNotLazilyInitializeAuthManager(t *testing.T) {
	r := &UserReconciler{}
	user := &authv1alpha1.User{
		Spec: authv1alpha1.UserSpec{
			Auth: &authv1alpha1.AuthSpec{Type: ptr(auth.AuthTypeX509)},
		},
	}

	// With the racy lazy init removed, reconcileAuthentication must not
	// resurrect AuthManager on the fly. The Ensure call will nil-deref; that
	// panic is expected here — the assertion below is what guards the fix.
	func() {
		defer func() { _ = recover() }()
		_, _, _ = r.reconcileAuthentication(context.Background(), user)
	}()

	if r.AuthManager != nil {
		t.Fatalf("reconcileAuthentication must not lazily initialize AuthManager; SetupWithManager owns this field (issue #64)")
	}
}

func TestCalculateSmartRequeueDoesNotLazilyInitializeRenewalCalculator(t *testing.T) {
	r := &UserReconciler{}
	user := &authv1alpha1.User{
		Spec: authv1alpha1.UserSpec{
			Auth: &authv1alpha1.AuthSpec{Type: ptr(auth.AuthTypeX509)},
		},
	}

	if _, err := r.calculateSmartRequeue(context.Background(), user); err != nil {
		t.Fatalf("calculateSmartRequeue returned unexpected error for a user with no cert info: %v", err)
	}

	if r.RenewalCalculator != nil {
		t.Fatalf("calculateSmartRequeue must not lazily initialize RenewalCalculator; SetupWithManager owns this field (issue #64)")
	}
}

func ptr[T any](v T) *T { return &v }
