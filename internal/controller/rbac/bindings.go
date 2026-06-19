/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package rbac

import (
	"context"
	"fmt"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ReconcileRoleBindings ensures the correct RoleBindings exist and removes outdated ones
func ReconcileRoleBindings(ctx context.Context, r client.Client, user *authv1alpha1.User) error {
	username := user.Name
	logger := logf.FromContext(ctx)

	// Get all existing RoleBindings for this user
	var existingRBs rbacv1.RoleBindingList
	if err := r.List(ctx, &existingRBs, client.MatchingLabels{authv1alpha1.UserLabel: username}); err != nil {
		return fmt.Errorf("failed to list existing RoleBindings: %w", err)
	}

	// Create a map of desired RoleBindings (namespace:role -> RoleSpec)
	desiredRBs := make(map[string]authv1alpha1.RoleSpec)
	for _, role := range user.Spec.Roles {
		// Validate that exactly one of ExistingRole or ExistingClusterRole is set
		if role.ExistingRole == "" && role.ExistingClusterRole == "" {
			return fmt.Errorf("either existingRole or existingClusterRole must be specified for namespace %s", role.Namespace)
		}
		if role.ExistingRole != "" && role.ExistingClusterRole != "" {
			return fmt.Errorf("cannot specify both existingRole and existingClusterRole for namespace %s", role.Namespace)
		}

		// Identity of this role entry. Shared with the admission webhook via
		// RoleSpec.BindingKey so both agree on what "duplicate" means.
		key := role.BindingKey()

		// Backstop for the webhook's duplicate check: catches Users that
		// bypassed admission (pre-existing objects, etcd restore). Fail loud
		// rather than silently overwriting (issue #57).
		if _, dup := desiredRBs[key]; dup {
			return fmt.Errorf("duplicate spec.roles entry %q appears more than once", key)
		}

		if role.ExistingRole != "" {
			// Validate that the Role exists
			var roleObj rbacv1.Role
			if err := r.Get(ctx, types.NamespacedName{Name: role.ExistingRole, Namespace: role.Namespace}, &roleObj); err != nil {
				if apierrors.IsNotFound(err) {
					return fmt.Errorf("role %s not found in namespace %s", role.ExistingRole, role.Namespace)
				}
				return fmt.Errorf("failed to get role %s in namespace %s: %w", role.ExistingRole, role.Namespace, err)
			}
		} else {
			// Validate that the ClusterRole exists
			var clusterRoleObj rbacv1.ClusterRole
			if err := r.Get(ctx, types.NamespacedName{Name: role.ExistingClusterRole}, &clusterRoleObj); err != nil {
				if apierrors.IsNotFound(err) {
					return fmt.Errorf("clusterrole %s not found", role.ExistingClusterRole)
				}
				return fmt.Errorf("failed to get clusterrole %s: %w", role.ExistingClusterRole, err)
			}
		}
		desiredRBs[key] = role
	}

	// Create a map of existing RoleBindings for easy lookup
	existingRBMap := make(map[string]*rbacv1.RoleBinding)
	for i := range existingRBs.Items {
		rb := &existingRBs.Items[i]
		key := fmt.Sprintf("%s:%s", rb.Namespace, rb.RoleRef.Name)
		existingRBMap[key] = rb
	}

	// Create or update desired RoleBindings
	for key, roleSpec := range desiredRBs {
		// Determine role name and kind
		var roleName, roleKind string
		if roleSpec.ExistingRole != "" {
			roleName = roleSpec.ExistingRole
			roleKind = "Role"
		} else {
			roleName = roleSpec.ExistingClusterRole
			roleKind = "ClusterRole"
		}

		rbName := fmt.Sprintf("%s-%s-rb", username, roleName)
		desiredRB := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rbName,
				Namespace: roleSpec.Namespace,
				Labels:    map[string]string{authv1alpha1.UserLabel: username},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: authv1alpha1.GroupVersion.String(),
					Kind:       "User",
					Name:       user.Name,
					UID:        user.UID,
					Controller: &[]bool{true}[0],
				}},
			},
			Subjects: []rbacv1.Subject{{
				Kind: "User",
				Name: username,
			}},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     roleKind,
				Name:     roleName,
			},
		}

		if existingRB, exists := existingRBMap[key]; exists {
			// Update existing RoleBinding if it differs
			if !helpers.RoleBindingMatches(existingRB, desiredRB) {
				logger.Info("Updating RoleBinding", "name", rbName, "namespace", roleSpec.Namespace)
				desiredRB.ResourceVersion = existingRB.ResourceVersion
				if err := r.Update(ctx, desiredRB); err != nil {
					return fmt.Errorf("failed to update RoleBinding %s in namespace %s: %w", rbName, roleSpec.Namespace, err)
				}
			}
			// Remove from the map so we know it's been processed
			delete(existingRBMap, key)
		} else {
			// Create new RoleBinding
			logger.Info("Creating RoleBinding", "name", rbName, "namespace", roleSpec.Namespace)
			if err := r.Create(ctx, desiredRB); err != nil {
				return fmt.Errorf("failed to create RoleBinding %s in namespace %s: %w", rbName, roleSpec.Namespace, err)
			}
		}
	}

	// Delete any remaining RoleBindings (these are no longer desired)
	for _, rb := range existingRBMap {
		logger.Info("Deleting outdated RoleBinding", "name", rb.Name, "namespace", rb.Namespace)
		if err := r.Delete(ctx, rb); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete outdated RoleBinding %s in namespace %s: %w", rb.Name, rb.Namespace, err)
		}
	}

	return nil
}

// ReconcileClusterRoleBindings ensures the correct ClusterRoleBindings exist and removes outdated ones
func ReconcileClusterRoleBindings(ctx context.Context, r client.Client, user *authv1alpha1.User) error {
	username := user.Name
	logger := logf.FromContext(ctx)

	// Get all existing ClusterRoleBindings for this user
	var existingCRBs rbacv1.ClusterRoleBindingList
	if err := r.List(ctx, &existingCRBs, client.MatchingLabels{authv1alpha1.UserLabel: username}); err != nil {
		return fmt.Errorf("failed to list existing ClusterRoleBindings: %w", err)
	}

	// Create a map of desired ClusterRoleBindings (clusterRole -> ClusterRoleSpec)
	desiredCRBs := make(map[string]authv1alpha1.ClusterRoleSpec)
	for _, clusterRole := range user.Spec.ClusterRoles {
		// Backstop for the listType=map uniqueness rule: catches objects that
		// bypassed admission. Fail loud rather than silently overwriting.
		if _, dup := desiredCRBs[clusterRole.ExistingClusterRole]; dup {
			return fmt.Errorf("duplicate spec.clusterRoles entry: clusterRole %q appears more than once", clusterRole.ExistingClusterRole)
		}

		// Validate that the ClusterRole exists
		var crObj rbacv1.ClusterRole
		if err := r.Get(ctx, types.NamespacedName{Name: clusterRole.ExistingClusterRole}, &crObj); err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("clusterrole %s not found", clusterRole.ExistingClusterRole)
			}
			return fmt.Errorf("failed to get clusterrole %s: %w", clusterRole.ExistingClusterRole, err)
		}
		desiredCRBs[clusterRole.ExistingClusterRole] = clusterRole
	}

	// Create a map of existing ClusterRoleBindings for easy lookup
	existingCRBMap := make(map[string]*rbacv1.ClusterRoleBinding)
	for i := range existingCRBs.Items {
		crb := &existingCRBs.Items[i]
		existingCRBMap[crb.RoleRef.Name] = crb
	}

	// Create or update desired ClusterRoleBindings
	for clusterRoleName, clusterRoleSpec := range desiredCRBs {
		crbName := fmt.Sprintf("%s-%s-crb", username, clusterRoleName)
		desiredCRB := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   crbName,
				Labels: map[string]string{authv1alpha1.UserLabel: username},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: authv1alpha1.GroupVersion.String(),
					Kind:       "User",
					Name:       user.Name,
					UID:        user.UID,
					Controller: &[]bool{true}[0],
				}},
			},
			Subjects: []rbacv1.Subject{{
				Kind: "User",
				Name: username,
			}},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     clusterRoleSpec.ExistingClusterRole,
			},
		}

		if existingCRB, exists := existingCRBMap[clusterRoleName]; exists {
			// Update existing ClusterRoleBinding if it differs
			if !helpers.ClusterRoleBindingMatches(existingCRB, desiredCRB) {
				logger.Info("Updating ClusterRoleBinding", "name", crbName)
				desiredCRB.ResourceVersion = existingCRB.ResourceVersion
				if err := r.Update(ctx, desiredCRB); err != nil {
					return fmt.Errorf("failed to update ClusterRoleBinding %s: %w", crbName, err)
				}
			}
			// Remove from the map so we know it's been processed
			delete(existingCRBMap, clusterRoleName)
		} else {
			// Create new ClusterRoleBinding
			logger.Info("Creating ClusterRoleBinding", "name", crbName)
			if err := r.Create(ctx, desiredCRB); err != nil {
				return fmt.Errorf("failed to create ClusterRoleBinding %s: %w", crbName, err)
			}
		}
	}

	// Delete any remaining ClusterRoleBindings (these are no longer desired)
	for _, crb := range existingCRBMap {
		logger.Info("Deleting outdated ClusterRoleBinding", "name", crb.Name)
		if err := r.Delete(ctx, crb); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete outdated ClusterRoleBinding %s: %w", crb.Name, err)
		}
	}

	return nil
}
