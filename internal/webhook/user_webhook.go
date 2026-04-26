/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package webhook

import (
	"context"
	"fmt"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/auth"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// UserWebhook validates and mutates User resources before they are persisted to etcd
type UserWebhook struct {
	client.Client
}

// +kubebuilder:webhook:path=/mutate-auth-openkube-io-v1alpha1-user,mutating=true,failurePolicy=fail,sideEffects=None,groups=auth.openkube.io,resources=users,verbs=create;update,versions=v1alpha1,name=muser.auth.openkube.io,admissionReviewVersions=v1
// +kubebuilder:webhook:path=/validate-auth-openkube-io-v1alpha1-user,mutating=false,failurePolicy=fail,sideEffects=None,groups=auth.openkube.io,resources=users,verbs=create;update,versions=v1alpha1,name=vuser.auth.openkube.io,admissionReviewVersions=v1

// SetupWithManager registers the webhook with the manager
func (w *UserWebhook) SetupWithManager(mgr ctrl.Manager) error {
	w.Client = mgr.GetClient()

	return ctrl.NewWebhookManagedBy(mgr).
		For(&authv1alpha1.User{}).
		WithDefaulter(w).
		WithValidator(w).
		Complete()
}

// Compile-time checks to ensure UserWebhook implements required interfaces
var _ webhook.CustomDefaulter = &UserWebhook{}
var _ webhook.CustomValidator = &UserWebhook{}

// Default implements webhook.CustomDefaulter
// This method is called by the mutating webhook to set default values before validation
// Uses auth.GetSafeAuthSpec as the single source of truth for defaults
func (w *UserWebhook) Default(ctx context.Context, obj runtime.Object) error {
	user, ok := obj.(*authv1alpha1.User)
	if !ok {
		return fmt.Errorf("expected User object, got %T", obj)
	}

	logger := logf.FromContext(ctx).WithName("user-webhook-default")
	logger.Info("Setting defaults for User", "user", user.Name)

	// Don't initialize Auth if it's missing - our mandatory policy requires it to be provided
	if user.Spec.Auth == nil {
		logger.Info("Auth section is nil, skipping defaults (will be rejected by validation)", "user", user.Name)
		return nil
	}

	// Use GetSafeAuthSpec to apply defaults (single source of truth)
	// This ensures webhook and controller use identical default values
	safeAuth := auth.GetSafeAuthSpec(user)

	// Apply defaults back to user.Spec.Auth if they were missing
	if user.Spec.Auth.TTL == "" && safeAuth.TTL != "" {
		user.Spec.Auth.TTL = safeAuth.TTL
		logger.Info("Set default TTL", "user", user.Name, "ttl", safeAuth.TTL)
	}

	if user.Spec.Auth.AutoRenew == nil && safeAuth.AutoRenew != nil {
		user.Spec.Auth.AutoRenew = safeAuth.AutoRenew
		logger.Info("Set default AutoRenew", "user", user.Name, "autoRenew", *safeAuth.AutoRenew)
	}

	return nil
}

// ValidateCreate implements admission.CustomValidator
func (w *UserWebhook) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	user, ok := obj.(*authv1alpha1.User)
	if !ok {
		return nil, fmt.Errorf("expected User object, got %T", obj)
	}

	// Stay well under kube-apiserver's default 10s webhook timeout.
	// Each Get call in validateRoles/validateClusterRoles must complete within this budget.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	logger := logf.FromContext(ctx).WithName("user-webhook-create")
	logger.Info("Validating User creation", "user", user.Name)

	// Validate Role references
	if err := w.validateRoles(ctx, user.Spec.Roles); err != nil {
		return nil, err
	}

	// Validate ClusterRole references
	if err := w.validateClusterRoles(ctx, user.Spec.ClusterRoles); err != nil {
		return nil, err
	}

	// Validate Auth specification
	if err := w.validateAuthSpec(user); err != nil {
		return nil, err
	}

	return nil, nil
}

// ValidateUpdate implements admission.CustomValidator
func (w *UserWebhook) ValidateUpdate(ctx context.Context, oldObj, newObj runtime.Object) (admission.Warnings, error) {
	newUser, ok := newObj.(*authv1alpha1.User)
	if !ok {
		return nil, fmt.Errorf("expected User object, got %T", newObj)
	}

	// Stay well under kube-apiserver's default 10s webhook timeout.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	logger := logf.FromContext(ctx).WithName("user-webhook-update")
	logger.Info("Validating User update", "user", newUser.Name)

	// Skip validation if the user is being deleted
	if newUser.DeletionTimestamp != nil {
		logger.Info("Skipping validation for User being deleted", "user", newUser.Name)
		return nil, nil
	}

	// Validate Role references in the updated spec
	if err := w.validateRoles(ctx, newUser.Spec.Roles); err != nil {
		return nil, err
	}

	// Validate ClusterRole references in the updated spec
	if err := w.validateClusterRoles(ctx, newUser.Spec.ClusterRoles); err != nil {
		return nil, err
	}

	// Validate Auth specification in the updated spec
	if err := w.validateAuthSpec(newUser); err != nil {
		return nil, err
	}

	return nil, nil
}

// ValidateDelete implements admission.CustomValidator
func (w *UserWebhook) ValidateDelete(ctx context.Context, obj runtime.Object) (admission.Warnings, error) {
	// No validation needed for delete operations
	return nil, nil
}

// validateRoles checks that all referenced Roles or ClusterRoles exist in their respective namespaces
func (w *UserWebhook) validateRoles(ctx context.Context, roles []authv1alpha1.RoleSpec) error {
	for _, roleSpec := range roles {
		// Validate that exactly one of ExistingRole or ExistingClusterRole is set
		if roleSpec.ExistingRole == "" && roleSpec.ExistingClusterRole == "" {
			return fmt.Errorf("either existingRole or existingClusterRole must be specified for namespace '%s'",
				roleSpec.Namespace)
		}
		if roleSpec.ExistingRole != "" && roleSpec.ExistingClusterRole != "" {
			return fmt.Errorf("cannot specify both existingRole and existingClusterRole for namespace '%s'",
				roleSpec.Namespace)
		}

		if roleSpec.ExistingRole != "" {
			// Validate namespace-scoped Role
			var role rbacv1.Role
			err := w.Get(ctx, types.NamespacedName{
				Name:      roleSpec.ExistingRole,
				Namespace: roleSpec.Namespace,
			}, &role)

			if err != nil {
				if apierrors.IsNotFound(err) {
					return fmt.Errorf("role '%s' not found in namespace '%s'",
						roleSpec.ExistingRole, roleSpec.Namespace)
				}
				return fmt.Errorf("failed to validate role '%s' in namespace '%s': %w",
					roleSpec.ExistingRole, roleSpec.Namespace, err)
			}
		} else {
			// Validate ClusterRole (will be bound with RoleBinding)
			var clusterRole rbacv1.ClusterRole
			err := w.Get(ctx, types.NamespacedName{
				Name: roleSpec.ExistingClusterRole,
			}, &clusterRole)

			if err != nil {
				if apierrors.IsNotFound(err) {
					return fmt.Errorf("clusterrole '%s' not found",
						roleSpec.ExistingClusterRole)
				}
				return fmt.Errorf("failed to validate clusterrole '%s': %w",
					roleSpec.ExistingClusterRole, err)
			}
		}
	}
	return nil
}

// validateClusterRoles checks that all referenced ClusterRoles exist
func (w *UserWebhook) validateClusterRoles(ctx context.Context, clusterRoles []authv1alpha1.ClusterRoleSpec) error {
	for _, clusterRoleSpec := range clusterRoles {
		var clusterRole rbacv1.ClusterRole
		err := w.Get(ctx, types.NamespacedName{
			Name: clusterRoleSpec.ExistingClusterRole,
		}, &clusterRole)

		if err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("clusterrole '%s' not found",
					clusterRoleSpec.ExistingClusterRole)
			}
			return fmt.Errorf("failed to validate clusterrole '%s': %w",
				clusterRoleSpec.ExistingClusterRole, err)
		}
	}
	return nil
}

// validateAuthSpec validates the auth specification using the auth package validation
// WEBHOOK MODE: Strictly rejects dangerous configurations (Fail-Fast architecture)
// MANDATORY IDENTITY: Enforces explicit authentication type specification
func (w *UserWebhook) validateAuthSpec(user *authv1alpha1.User) error {
	// STAGE 1: Reject if auth section is missing entirely
	if user.Spec.Auth == nil {
		return fmt.Errorf("the auth section is mandatory. Please provide spec.auth.type")
	}

	// STAGE 2: Reject if auth type is not specified (nil pointer check)
	if user.Spec.Auth.Type == nil || *user.Spec.Auth.Type == "" {
		return fmt.Errorf("spec.auth.type is mandatory (e.g., x509)")
	}

	// Use the existing auth package validation (enforces 24h minimum TTL)
	if err := auth.ValidateAuthSpec(user); err != nil {
		return fmt.Errorf("invalid auth specification: %w", err)
	}

	// Get safe auth spec with defaults applied (single source of truth)
	safeAuth := auth.GetSafeAuthSpec(user)

	// CRITICAL: Explicitly reject OIDC at webhook level (not yet implemented)
	// This prevents resources from being created and failing later in the controller
	if safeAuth.Type != nil && *safeAuth.Type == "oidc" {
		return fmt.Errorf("OIDC authentication is not yet implemented. Please use 'x509' for certificate-based authentication")
	}

	// PRODUCTION HARDENING: Strict webhook validation for renewal configuration
	if safeAuth.AutoRenew != nil && *safeAuth.AutoRenew {
		// Parse certificate duration
		var certDuration time.Duration
		if safeAuth.TTL != "" {
			d, err := time.ParseDuration(safeAuth.TTL)
			if err != nil {
				return fmt.Errorf("invalid TTL format: %v", err)
			}
			certDuration = d
		} else {
			certDuration = 90 * 24 * time.Hour // Default 90 days
		}

		// Validate renewBefore if specified
		if safeAuth.RenewBefore != nil {
			renewBefore := safeAuth.RenewBefore.Duration

			if renewBefore <= 0 {
				return fmt.Errorf("renewBefore must be positive, got: %v", renewBefore)
			}

			// WEBHOOK ENFORCEMENT: Strictly reject renewBefore > 90% of TTL
			// This prevents Thundering Herd loops at the CLI level
			maxAllowed := time.Duration(float64(certDuration) * 0.9)
			if renewBefore > maxAllowed {
				return fmt.Errorf("renewBefore (%v) exceeds 90%% of TTL (%v). Maximum allowed: %v. This prevents aggressive renewal loops and API-server exhaustion",
					renewBefore, certDuration, maxAllowed)
			}

			// WEBHOOK ENFORCEMENT: Reject renewBefore that violates 15-minute safety floor
			const safetyFloor = 15 * time.Minute
			if certDuration-renewBefore < safetyFloor {
				return fmt.Errorf("renewBefore (%v) leaves less than 15 minutes of certificate life (TTL: %v). This would cause immediate renewal loops. Minimum certificate life required: 15m",
					renewBefore, certDuration)
			}
		}
	}

	return nil
}
