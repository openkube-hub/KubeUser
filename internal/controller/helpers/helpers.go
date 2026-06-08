/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package helpers

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// Phase constants to avoid goconst issues
	PhaseError    = "Error"
	PhaseExpired  = "Expired"
	PhaseReady    = "Ready"
	PhaseActive   = "Active"
	PhasePending  = "Pending"
	PhaseRenewing = "Renewing"
)

const DefaultKubeconfigClusterName = "cluster"

// GetAutoRenew returns the autoRenew value with default of true if not specified
func GetAutoRenew(user *authv1alpha1.User) bool {
	if user.Spec.Auth == nil {
		return true // Default to true
	}
	if user.Spec.Auth.AutoRenew == nil {
		return true // Default to true
	}
	return *user.Spec.Auth.AutoRenew
}

// GetKubeUserNamespace returns the namespace where all KubeUser resources should be created
func GetKubeUserNamespace() string {
	namespace := os.Getenv("KUBEUSER_NAMESPACE")
	if namespace == "" {
		namespace = "kubeuser" // fallback to default
	}
	return namespace
}

// GetKubeconfigClusterName returns the cluster name used in generated kubeconfigs.
func GetKubeconfigClusterName() string {
	clusterName := os.Getenv("KUBEUSER_CLUSTER_NAME")
	if clusterName == "" {
		return DefaultKubeconfigClusterName
	}
	return clusterName
}

// ValidateKubeconfigClusterName rejects blank names and control characters.
func ValidateKubeconfigClusterName(clusterName string) error {
	if clusterName == "" {
		return fmt.Errorf("cluster name must not be empty")
	}
	if strings.TrimSpace(clusterName) != clusterName {
		return fmt.Errorf("cluster name must not have leading or trailing whitespace")
	}
	for _, r := range clusterName {
		if unicode.IsControl(r) {
			return fmt.Errorf("cluster name %q contains unsupported character %q", clusterName, r)
		}
	}
	return nil
}

func CreateOrUpdate(ctx context.Context, r client.Client, obj client.Object) error {
	key := types.NamespacedName{Name: obj.GetName(), Namespace: obj.GetNamespace()}
	existing := obj.DeepCopyObject().(client.Object)
	err := r.Get(ctx, key, existing)
	if apierrors.IsNotFound(err) {
		return r.Create(ctx, obj)
	} else if err != nil {
		return err
	}
	obj.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, obj)
}

// UpdateUserStatus calculates and updates the user status fields in memory based on current state.
// Returns true if any status field was modified, false if the status was already correct.
// This is a pure in-memory mutator that performs no API writes.
func UpdateUserStatus(ctx context.Context, r client.Client, user *authv1alpha1.User) (bool, error) {
	logger := logf.FromContext(ctx)
	logger.Info("Calculating user status", "name", user.Name, "currentPhase", user.Status.Phase)

	// CRITICAL: Protect the Renewing state from being overwritten
	// When a user is in the Renewing phase, the rotation state machine owns the status
	// and RBAC reconciliation must not interfere with it
	if user.Status.Phase == PhaseRenewing {
		logger.Info("User is in Renewing phase, skipping status update to preserve rotation state")
		return false, nil
	}

	// Track if any changes were made
	changed := false

	// Calculate new phase and message
	var newPhase, newMessage string

	// Check if user certificate has expired (only if ExpiryTime is set)
	if user.Status.ExpiryTime != "" {
		if expiry, err := time.Parse(time.RFC3339, user.Status.ExpiryTime); err == nil {
			if time.Now().After(expiry) {
				newPhase = PhaseExpired
				newMessage = "User certificate has expired"
				logger.Info("User certificate has expired", "expiry", user.Status.ExpiryTime)
			} else {
				// Certificate is still valid, calculate active status message
				// We hardcode PhaseActive to satisfy 'unparam' linter
				newPhase = PhaseActive
				newMessage = calculateActiveStatus(user)
			}
		} else {
			logger.Error(err, "Failed to parse expiry time", "expiryTime", user.Status.ExpiryTime)
			// If we can't parse expiry time, fallback to Active
			newPhase = PhaseActive
			newMessage = calculateActiveStatus(user)
		}
	} else {
		// No expiry time set yet, set user as active
		newPhase = PhaseActive
		newMessage = calculateActiveStatus(user)
	}

	// Semantic comparison: only update if values actually changed
	// Capture old values before assignment for accurate logging
	oldPhase := user.Status.Phase
	oldMessage := user.Status.Message

	if oldPhase != newPhase {
		user.Status.Phase = newPhase
		changed = true
		logger.Info("Phase changed", "oldPhase", oldPhase, "newPhase", newPhase)
	}

	if oldMessage != newMessage {
		user.Status.Message = newMessage
		changed = true
		logger.Info("Message changed", "oldMessage", oldMessage, "newMessage", newMessage)
	}

	// Calculate condition updates
	conditionChanged := updateStatusCondition(user, newPhase, newMessage)
	if conditionChanged {
		changed = true
	}

	if changed {
		logger.Info("Status fields updated in memory", "phase", user.Status.Phase, "message", user.Status.Message)
	} else {
		logger.Info("Status fields unchanged", "phase", user.Status.Phase)
	}

	return changed, nil
}

// calculateActiveStatus determines the descriptive message for an active user based on role assignments.
// The 'phase' return was removed to satisfy 'unparam' linting as it was always "Active".
func calculateActiveStatus(user *authv1alpha1.User) string {
	// Count different types of bindings
	var namespacedRoles, namespacedClusterRoles int
	for _, role := range user.Spec.Roles {
		if role.ExistingRole != "" {
			namespacedRoles++
		} else if role.ExistingClusterRole != "" {
			namespacedClusterRoles++
		}
	}
	clusterWideRoles := len(user.Spec.ClusterRoles)
	totalBindings := namespacedRoles + namespacedClusterRoles + clusterWideRoles

	if totalBindings == 0 {
		return "No role bindings configured"
	}

	// Build detailed message parts
	var parts []string
	if namespacedRoles > 0 {
		parts = append(parts, fmt.Sprintf("%d namespace-scoped Role(s)", namespacedRoles))
	}
	if namespacedClusterRoles > 0 {
		parts = append(parts, fmt.Sprintf("%d ClusterRole(s) bound to namespace(s)", namespacedClusterRoles))
	}
	if clusterWideRoles > 0 {
		parts = append(parts, fmt.Sprintf("%d cluster-wide ClusterRole(s)", clusterWideRoles))
	}

	// Join parts into a human-readable sentence
	switch len(parts) {
	case 1:
		return fmt.Sprintf("%s with %s", PhaseActive, parts[0])
	case 2:
		return fmt.Sprintf("%s with %s and %s", PhaseActive, parts[0], parts[1])
	case 3:
		return fmt.Sprintf("%s with %s, %s, and %s", PhaseActive, parts[0], parts[1], parts[2])
	default:
		return PhaseActive
	}
}

// updateStatusCondition updates the status condition based on the current phase and message.
// Returns true if the condition was changed.
func updateStatusCondition(user *authv1alpha1.User, phase, message string) bool {
	now := metav1.NewTime(time.Now())
	conditionType := PhaseReady
	conditionStatus := metav1.ConditionTrue
	conditionReason := "UserProvisioned"
	conditionMessage := message

	switch phase {
	case PhaseError:
		conditionStatus = metav1.ConditionFalse
		conditionReason = "ProvisioningFailed"
	case PhaseExpired:
		conditionStatus = metav1.ConditionFalse
		conditionReason = "CertificateExpired"
	case PhasePending:
		conditionStatus = metav1.ConditionFalse
		conditionReason = "Provisioning"
	}

	// Find existing condition
	for i, condition := range user.Status.Conditions {
		if condition.Type == conditionType {
			// Check if condition needs updating
			if condition.Status != conditionStatus ||
				condition.Reason != conditionReason ||
				condition.Message != conditionMessage {

				user.Status.Conditions[i].Status = conditionStatus
				user.Status.Conditions[i].Reason = conditionReason
				user.Status.Conditions[i].Message = conditionMessage
				user.Status.Conditions[i].LastTransitionTime = now
				return true
			}
			return false // Condition unchanged
		}
	}

	// Condition not found, add new one
	newCondition := metav1.Condition{
		Type:               conditionType,
		Status:             conditionStatus,
		Reason:             conditionReason,
		Message:            conditionMessage,
		LastTransitionTime: now,
	}
	user.Status.Conditions = append(user.Status.Conditions, newCondition)
	return true
}

// SetActiveStatus sets the user status to active based on role assignments.
// This function is kept for backward compatibility but now uses the pure
// calculateActiveStatus helper which returns only the message string.
func SetActiveStatus(user *authv1alpha1.User) {
	// FIX: Receive only the single message string returned by the helper
	message := calculateActiveStatus(user)

	// Explicitly set the phase to PhaseActive to satisfy linting requirements
	user.Status.Phase = PhaseActive
	user.Status.Message = message
}

// RoleBindingMatches checks if two RoleBindings are functionally equivalent
func RoleBindingMatches(existing, desired *rbacv1.RoleBinding) bool {
	// Check if RoleRef matches
	if existing.RoleRef != desired.RoleRef {
		return false
	}

	// Check if subjects match (we expect exactly one subject)
	if len(existing.Subjects) != 1 || len(desired.Subjects) != 1 {
		return false
	}

	return existing.Subjects[0].Kind == desired.Subjects[0].Kind &&
		existing.Subjects[0].Name == desired.Subjects[0].Name
}

// ClusterRoleBindingMatches checks if two ClusterRoleBindings are functionally equivalent
func ClusterRoleBindingMatches(existing, desired *rbacv1.ClusterRoleBinding) bool {
	// Check if RoleRef matches
	if existing.RoleRef != desired.RoleRef {
		return false
	}

	// Check if subjects match (we expect exactly one subject)
	if len(existing.Subjects) != 1 || len(desired.Subjects) != 1 {
		return false
	}

	return existing.Subjects[0].Kind == desired.Subjects[0].Kind &&
		existing.Subjects[0].Name == desired.Subjects[0].Name
}

func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ContainsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func RemoveString(slice []string, s string) []string {
	var result []string
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}

// SemanticTimePtrMatch compares two *metav1.Time pointers safely, handling nil cases.
// Returns true if both pointers are semantically equal (both nil or both point to equal times).
func SemanticTimePtrMatch(a, b *metav1.Time) bool {
	// Both nil - they match
	if a == nil && b == nil {
		return true
	}

	// One nil, one not - they don't match
	if a == nil || b == nil {
		return false
	}

	// Both non-nil - compare the time values
	return a.Time.Equal(b.Time)
}
