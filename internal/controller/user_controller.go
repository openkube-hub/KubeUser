/*
Copyright 2025.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	kubeUserNamespace = "kubeuser"
	inClusterCAPath   = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	userFinalizer = "auth.openkube.io/finalizer"

	// Phase constants to avoid goconst issues
	PhaseError   = "Error"
	PhaseExpired = "Expired"
	PhaseReady   = "Ready"
)

// UserReconciler reconciles a User object
type UserReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// RBAC rules
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;clusterroles,verbs=get;list;watch
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;create
// +kubebuilder:rbac:groups="",resources=serviceaccounts;secrets;configmaps,verbs=get;list;watch;create;update;patch;delete
// CSR
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=update

// Reconcile main loop
func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("=== START RECONCILE ===", "user", req.Name)

	var user authv1alpha1.User
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		logger.Info("User not found, ignoring", "user", req.Name, "error", err)
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	username := user.Name
	logger.Info("Reconciling User", "name", username, "generation", user.Generation, "resourceVersion", user.ResourceVersion)

	// Ensure initial status is set
	logger.Info("Checking initial status", "currentPhase", user.Status.Phase)
	if user.Status.Phase == "" {
		logger.Info("Setting initial status to Pending")
		user.Status.Phase = "Pending"
		user.Status.Message = "Initializing user resources"
		if err := r.Status().Update(ctx, &user); err != nil {
			logger.Error(err, "Failed to set initial status")
			// Don't return error, continue with reconciliation
		} else {
			logger.Info("Successfully set initial status")
		}
	} else {
		logger.Info("Status already set, skipping initial status", "phase", user.Status.Phase)
	}

	// Handle deletion
	logger.Info("Checking deletion", "deletionTimestamp", user.DeletionTimestamp)
	if !user.DeletionTimestamp.IsZero() {
		logger.Info("User is being deleted, starting cleanup")
		if containsString(user.Finalizers, userFinalizer) {
			logger.Info("Cleaning up user resources")
			r.cleanupUserResources(ctx, &user)
			logger.Info("Removing finalizer")
			user.Finalizers = removeString(user.Finalizers, userFinalizer)
			if err := r.Update(ctx, &user); err != nil {
				logger.Error(err, "Failed to remove finalizer")
				return ctrl.Result{}, err
			}
			logger.Info("Successfully cleaned up and removed finalizer")
		}
		logger.Info("=== END RECONCILE (DELETION) ===")
		return ctrl.Result{}, nil
	}

	// Ensure finalizer
	logger.Info("Checking finalizer", "currentFinalizers", user.Finalizers)
	if !containsString(user.Finalizers, userFinalizer) {
		logger.Info("Adding finalizer", "finalizer", userFinalizer)
		user.Finalizers = append(user.Finalizers, userFinalizer)
		if err := r.Update(ctx, &user); err != nil {
			logger.Error(err, "Failed to add finalizer")
			return ctrl.Result{}, err
		}
		logger.Info("Successfully added finalizer")
	} else {
		logger.Info("Finalizer already exists, skipping")
	}

	// Ensure kubeuser namespace
	logger.Info("Ensuring kubeuser namespace", "namespace", kubeUserNamespace)
	if err := r.ensureNamespace(ctx, kubeUserNamespace); err != nil {
		logger.Error(err, "Failed to ensure kubeuser namespace")
		return ctrl.Result{}, err
	}
	logger.Info("Kubeuser namespace ensured")

	// Ensure ServiceAccount (identity anchor)
	logger.Info("Creating/updating ServiceAccount", "name", username, "namespace", kubeUserNamespace)
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      username,
			Namespace: kubeUserNamespace,
			Labels:    map[string]string{"auth.openkube.io/user": username},
		},
	}
	if err := r.createOrUpdate(ctx, sa); err != nil {
		logger.Error(err, "Failed to create/update ServiceAccount")
		return ctrl.Result{}, err
	}
	logger.Info("ServiceAccount created/updated successfully")

	// === Reconcile RoleBindings ===
	logger.Info("Starting RoleBindings reconciliation", "rolesCount", len(user.Spec.Roles))
	if err := r.reconcileRoleBindings(ctx, &user); err != nil {
		logger.Error(err, "Failed to reconcile RoleBindings")
		user.Status.Phase = PhaseError
		user.Status.Message = fmt.Sprintf("Failed to reconcile RoleBindings: %v", err)
		_ = r.Status().Update(ctx, &user)
		return ctrl.Result{}, err
	}
	logger.Info("RoleBindings reconciliation completed")

	// === Reconcile ClusterRoleBindings ===
	logger.Info("Starting ClusterRoleBindings reconciliation", "clusterRolesCount", len(user.Spec.ClusterRoles))
	if err := r.reconcileClusterRoleBindings(ctx, &user); err != nil {
		logger.Error(err, "Failed to reconcile ClusterRoleBindings")
		user.Status.Phase = PhaseError
		user.Status.Message = fmt.Sprintf("Failed to reconcile ClusterRoleBindings: %v", err)
		_ = r.Status().Update(ctx, &user)
		return ctrl.Result{}, err
	}
	logger.Info("ClusterRoleBindings reconciliation completed")

	// Update status after successful RBAC reconciliation
	logger.Info("*** CALLING updateUserStatus ***")
	if err := r.updateUserStatus(ctx, &user); err != nil {
		logger.Error(err, "Failed to update user status")
		// Don't return error, continue with certificate processing
	} else {
		logger.Info("*** updateUserStatus completed successfully ***")
	}

	// Ensure cert-based kubeconfig
	logger.Info("Starting certificate/kubeconfig processing")
	requeue, err := r.ensureCertKubeconfig(ctx, &user)
	if err != nil {
		logger.Error(err, "Failed to ensure certificate kubeconfig")
		logger.Info("=== END RECONCILE (CERT ERROR) ===")
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if requeue {
		logger.Info("Certificate processing needs requeue")
		logger.Info("=== END RECONCILE (REQUEUE) ===")
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}
	logger.Info("Certificate/kubeconfig processing completed")

	// Requeue if user is close to expiry to handle cleanup
	logger.Info("Checking expiry for requeue", "phase", user.Status.Phase, "expiryTime", user.Status.ExpiryTime)
	if user.Status.Phase == "Active" && user.Status.ExpiryTime != "" {
		if expiryTime, err := time.Parse(time.RFC3339, user.Status.ExpiryTime); err == nil {
			timeUntilExpiry := time.Until(expiryTime)
			logger.Info("Time until expiry", "duration", timeUntilExpiry)
			if timeUntilExpiry <= 0 {
				// User has expired, mark as expired
				logger.Info("User has expired, updating status")
				user.Status.Phase = PhaseExpired
				user.Status.Message = "User access has expired"
				_ = r.Status().Update(ctx, &user)
				logger.Info("=== END RECONCILE (EXPIRED) ===")
				return ctrl.Result{}, nil
			} else if timeUntilExpiry < 24*time.Hour {
				// Requeue to check expiry more frequently
				logger.Info("User expires soon, requeueing in 1 hour")
				logger.Info("=== END RECONCILE (EXPIRY REQUEUE) ===")
				return ctrl.Result{RequeueAfter: time.Hour}, nil
			}
		} else {
			logger.Error(err, "Failed to parse expiry time", "expiryTime", user.Status.ExpiryTime)
		}
	}

	logger.Info("=== END RECONCILE (SUCCESS) ===, requeueing in 30 minutes")
	return ctrl.Result{RequeueAfter: 30 * time.Minute}, nil // Regular reconciliation
}

// SetupWithManager wires the controller
func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&authv1alpha1.User{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&corev1.ServiceAccount{}).
		Owns(&corev1.Secret{}).
		Named("user").
		Complete(r)
}

// --- helpers ---

func (r *UserReconciler) ensureNamespace(ctx context.Context, name string) error {
	var ns corev1.Namespace
	if err := r.Get(ctx, types.NamespacedName{Name: name}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			ns = corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
			return r.Create(ctx, &ns)
		}
		return err
	}
	return nil
}

func (r *UserReconciler) createOrUpdate(ctx context.Context, obj client.Object) error {
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

// cleanupUserResources deletes all resources related to the user.
func (r *UserReconciler) cleanupUserResources(ctx context.Context, user *authv1alpha1.User) {
	username := user.Name

	// Delete fixed resources
	fixed := []client.Object{
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: username, Namespace: kubeUserNamespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-key", username), Namespace: kubeUserNamespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-kubeconfig", username), Namespace: kubeUserNamespace}},
		&certv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-csr", username)}},
	}
	for _, obj := range fixed {
		_ = r.Delete(ctx, obj)
	}

	// Delete RoleBindings across namespaces
	var rbs rbacv1.RoleBindingList
	if err := r.List(ctx, &rbs, client.MatchingLabels{"auth.openkube.io/user": username}); err == nil {
		for _, rb := range rbs.Items {
			_ = r.Delete(ctx, &rb)
		}
	}

	// Delete ClusterRoleBindings
	var crbs rbacv1.ClusterRoleBindingList
	if err := r.List(ctx, &crbs, client.MatchingLabels{"auth.openkube.io/user": username}); err == nil {
		for _, crb := range crbs.Items {
			_ = r.Delete(ctx, &crb)
		}
	}

}

// updateUserStatus calculates and updates the user status based on current state
func (r *UserReconciler) updateUserStatus(ctx context.Context, user *authv1alpha1.User) error {
	logger := logf.FromContext(ctx)
	logger.Info("Updating user status", "name", user.Name)

	// Check if user certificate has expired (only if ExpiryTime is set)
	if user.Status.ExpiryTime != "" {
		if expiry, err := time.Parse(time.RFC3339, user.Status.ExpiryTime); err == nil {
			if time.Now().After(expiry) {
				user.Status.Phase = PhaseExpired
				user.Status.Message = "User certificate has expired"
				logger.Info("User certificate has expired", "expiry", user.Status.ExpiryTime)
			} else {
				// Certificate is still valid, set user as active
				r.setActiveStatus(user)
			}
		} else {
			logger.Error(err, "Failed to parse expiry time", "expiryTime", user.Status.ExpiryTime)
			// If we can't parse expiry time, assume user is active
			r.setActiveStatus(user)
		}
	} else {
		// No expiry time set yet (certificate not issued), set user as active
		r.setActiveStatus(user)
	}

	// Add condition for better status tracking
	now := metav1.NewTime(time.Now())
	conditionType := PhaseReady
	conditionStatus := metav1.ConditionTrue
	conditionReason := "UserProvisioned"
	conditionMessage := user.Status.Message

	switch user.Status.Phase {
	case "Error":
		conditionType = PhaseReady
		conditionStatus = metav1.ConditionFalse
		conditionReason = "ProvisioningFailed"
	case "Expired":
		conditionType = PhaseReady
		conditionStatus = metav1.ConditionFalse
		conditionReason = "CertificateExpired"
	case "Pending":
		conditionType = PhaseReady
		conditionStatus = metav1.ConditionFalse
		conditionReason = "Provisioning"
	}

	// Update or add condition
	updatedConditions := []metav1.Condition{}
	conditionFound := false
	for _, condition := range user.Status.Conditions {
		if condition.Type == conditionType {
			condition.Status = conditionStatus
			condition.Reason = conditionReason
			condition.Message = conditionMessage
			condition.LastTransitionTime = now
			conditionFound = true
		}
		updatedConditions = append(updatedConditions, condition)
	}

	if !conditionFound {
		newCondition := metav1.Condition{
			Type:               conditionType,
			Status:             conditionStatus,
			Reason:             conditionReason,
			Message:            conditionMessage,
			LastTransitionTime: now,
		}
		updatedConditions = append(updatedConditions, newCondition)
	}
	user.Status.Conditions = updatedConditions

	logger.Info("Updating status", "phase", user.Status.Phase, "expiry", user.Status.ExpiryTime, "message", user.Status.Message)
	err := r.Status().Update(ctx, user)
	if err != nil {
		logger.Error(err, "Failed to update user status")
		return err
	}
	logger.Info("Successfully updated user status")
	return nil
}

// setActiveStatus sets the user status to active based on role assignments
func (r *UserReconciler) setActiveStatus(user *authv1alpha1.User) {
	user.Status.Phase = "Active"
	roleCount := len(user.Spec.Roles)
	clusterRoleCount := len(user.Spec.ClusterRoles)
	totalRoles := roleCount + clusterRoleCount

	if totalRoles == 0 {
		user.Status.Message = "User has no assigned roles"
	} else if roleCount > 0 && clusterRoleCount > 0 {
		user.Status.Message = fmt.Sprintf("User provisioned with %d namespace role(s) and %d cluster role(s)", roleCount, clusterRoleCount)
	} else if roleCount > 0 {
		user.Status.Message = fmt.Sprintf("User provisioned with %d namespace role(s)", roleCount)
	} else {
		user.Status.Message = fmt.Sprintf("User provisioned with %d cluster role(s)", clusterRoleCount)
	}
}

// reconcileRoleBindings ensures the correct RoleBindings exist and removes outdated ones
func (r *UserReconciler) reconcileRoleBindings(ctx context.Context, user *authv1alpha1.User) error {
	username := user.Name
	logger := logf.FromContext(ctx)

	// Get all existing RoleBindings for this user
	var existingRBs rbacv1.RoleBindingList
	if err := r.List(ctx, &existingRBs, client.MatchingLabels{"auth.openkube.io/user": username}); err != nil {
		return fmt.Errorf("failed to list existing RoleBindings: %w", err)
	}

	// Create a map of desired RoleBindings (namespace:role -> RoleSpec)
	desiredRBs := make(map[string]authv1alpha1.RoleSpec)
	for _, role := range user.Spec.Roles {
		// Validate that the Role exists
		var roleObj rbacv1.Role
		if err := r.Get(ctx, types.NamespacedName{Name: role.ExistingRole, Namespace: role.Namespace}, &roleObj); err != nil {
			if apierrors.IsNotFound(err) {
				return fmt.Errorf("role %s not found in namespace %s", role.ExistingRole, role.Namespace)
			}
			return fmt.Errorf("failed to get role %s in namespace %s: %w", role.ExistingRole, role.Namespace, err)
		}
		key := fmt.Sprintf("%s:%s", role.Namespace, role.ExistingRole)
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
		rbName := fmt.Sprintf("%s-%s-rb", username, roleSpec.ExistingRole)
		desiredRB := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rbName,
				Namespace: roleSpec.Namespace,
				Labels:    map[string]string{"auth.openkube.io/user": username},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "auth.openkube.io/v1alpha1",
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
				Kind:     "Role",
				Name:     roleSpec.ExistingRole,
			},
		}

		if existingRB, exists := existingRBMap[key]; exists {
			// Update existing RoleBinding if it differs
			if !roleBindingMatches(existingRB, desiredRB) {
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

// reconcileClusterRoleBindings ensures the correct ClusterRoleBindings exist and removes outdated ones
func (r *UserReconciler) reconcileClusterRoleBindings(ctx context.Context, user *authv1alpha1.User) error {
	username := user.Name
	logger := logf.FromContext(ctx)

	// Get all existing ClusterRoleBindings for this user
	var existingCRBs rbacv1.ClusterRoleBindingList
	if err := r.List(ctx, &existingCRBs, client.MatchingLabels{"auth.openkube.io/user": username}); err != nil {
		return fmt.Errorf("failed to list existing ClusterRoleBindings: %w", err)
	}

	// Create a map of desired ClusterRoleBindings (clusterRole -> ClusterRoleSpec)
	desiredCRBs := make(map[string]authv1alpha1.ClusterRoleSpec)
	for _, clusterRole := range user.Spec.ClusterRoles {
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
				Labels: map[string]string{"auth.openkube.io/user": username},
				OwnerReferences: []metav1.OwnerReference{{
					APIVersion: "auth.openkube.io/v1alpha1",
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
			if !clusterRoleBindingMatches(existingCRB, desiredCRB) {
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

// roleBindingMatches checks if two RoleBindings are functionally equivalent
func roleBindingMatches(existing, desired *rbacv1.RoleBinding) bool {
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

// clusterRoleBindingMatches checks if two ClusterRoleBindings are functionally equivalent
func clusterRoleBindingMatches(existing, desired *rbacv1.ClusterRoleBinding) bool {
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

// === Certificate helpers ===

func (r *UserReconciler) ensureCertKubeconfig(ctx context.Context, user *authv1alpha1.User) (bool, error) {
	username := user.Name
	keySecretName := fmt.Sprintf("%s-key", username)
	cfgSecretName := fmt.Sprintf("%s-kubeconfig", username)
	csrName := fmt.Sprintf("%s-csr", username)

	// Check if certificate needs rotation (30 days before expiry)
	rotationThreshold := 30 * 24 * time.Hour
	needsRotation, err := r.checkCertificateRotation(ctx, cfgSecretName, rotationThreshold)
	if err != nil {
		return false, fmt.Errorf("failed to check certificate rotation: %w", err)
	}

	if needsRotation {
		// Clean up existing resources for rotation
		logger := logf.FromContext(ctx)
		logger.Info("Certificate needs rotation, cleaning up existing resources", "user", username)
		if err := r.cleanupCertificateResources(ctx, cfgSecretName, csrName); err != nil {
			return false, fmt.Errorf("failed to cleanup certificate resources: %w", err)
		}
	}

	// 1. Load/create key Secret
	var keySecret corev1.Secret
	err = r.Get(ctx, types.NamespacedName{Name: keySecretName, Namespace: kubeUserNamespace}, &keySecret)
	var keyPEM []byte
	if apierrors.IsNotFound(err) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return false, err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		keySecret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: keySecretName, Namespace: kubeUserNamespace},
			Type:       corev1.SecretTypeOpaque,
			Data:       map[string][]byte{"key.pem": keyPEM},
		}
		if err := r.Create(ctx, &keySecret); err != nil {
			return false, err
		}
	} else if err != nil {
		return false, err
	} else {
		keyPEM = keySecret.Data["key.pem"]
	}

	// 2. If kubeconfig already exists, return
	var existingCfg corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: kubeUserNamespace}, &existingCfg); err == nil {
		return false, nil
	}

	// 3. CSR from key
	csrPEM, err := csrFromKey(username, keyPEM)
	if err != nil {
		return false, err
	}

	// 4. Create/get CSR
	var csr certv1.CertificateSigningRequest
	err = r.Get(ctx, types.NamespacedName{Name: csrName}, &csr)
	if apierrors.IsNotFound(err) {
		csr = certv1.CertificateSigningRequest{
			ObjectMeta: metav1.ObjectMeta{Name: csrName, Labels: map[string]string{"auth.openkube.io/user": username}},
			Spec: certv1.CertificateSigningRequestSpec{
				Request:    csrPEM,
				Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
				SignerName: certv1.KubeAPIServerClientSignerName,
			},
		}
		if err := r.Create(ctx, &csr); err != nil {
			return false, err
		}
		return true, nil
	} else if err != nil {
		return false, err
	}

	// 5. Approve CSR if not approved
	approved := false
	for _, c := range csr.Status.Conditions {
		if c.Type == certv1.CertificateApproved && c.Status == corev1.ConditionTrue {
			approved = true
		}
	}
	if !approved {
		csr.Status.Conditions = append(csr.Status.Conditions, certv1.CertificateSigningRequestCondition{
			Type:           certv1.CertificateApproved,
			Status:         corev1.ConditionTrue,
			Reason:         "AutoApproved",
			Message:        "Approved by kubeuser-operator",
			LastUpdateTime: metav1.Now(),
		})
		if err := r.SubResource("approval").Update(ctx, &csr); err != nil {
			return false, err
		}
		return true, nil
	}

	// 6. Wait for cert
	if len(csr.Status.Certificate) == 0 {
		return true, nil
	}
	signedCert := csr.Status.Certificate

	// 7. Cluster CA
	caDataB64, err := r.getClusterCABase64(ctx)
	if err != nil {
		return false, err
	}

	// 8. API server URL
	apiServer := os.Getenv("KUBERNETES_API_SERVER")
	if apiServer == "" {
		apiServer = "https://kubernetes.default.svc"
	}

	// 9. Kubeconfig
	kcfg := buildCertKubeconfig(apiServer, caDataB64,
		base64.StdEncoding.EncodeToString(signedCert),
		base64.StdEncoding.EncodeToString(keyPEM),
		username)

	// 9.5. Extract certificate expiry time
	logger := logf.FromContext(ctx)
	logger.Info("Extracting certificate expiry", "certLength", len(signedCert))
	logger.Info("Certificate data preview", "first20bytes", string(signedCert[:min(20, len(signedCert))]))

	// Try to extract certificate expiry with proper format detection
	certExpiryTime, err := r.extractCertificateExpiryWithFormatDetection(signedCert)
	if err != nil {
		return false, fmt.Errorf("failed to extract certificate expiry: %w", err)
	}
	logger.Info("Successfully extracted certificate expiry", "expiry", certExpiryTime)

	// Update user status with actual certificate expiry
	user.Status.ExpiryTime = certExpiryTime.Format(time.RFC3339)
	user.Status.CertificateExpiry = "Certificate"
	if err := r.Status().Update(ctx, user); err != nil {
		return false, fmt.Errorf("failed to update user status with certificate expiry: %w", err)
	}

	// 10. Save kubeconfig
	cfgSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: cfgSecretName, Namespace: kubeUserNamespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{"config": kcfg},
	}
	return false, r.createOrUpdate(ctx, cfgSecret)
}

func csrFromKey(username string, keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("decode key failed")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	csrTemplate := x509.CertificateRequest{Subject: pkix.Name{CommonName: username}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func (r *UserReconciler) getClusterCABase64(ctx context.Context) (string, error) {
	if data, err := os.ReadFile(filepath.Clean(inClusterCAPath)); err == nil && len(data) > 0 {
		return base64.StdEncoding.EncodeToString(data), nil
	}
	var cm corev1.ConfigMap
	if err := r.Get(ctx, types.NamespacedName{Namespace: "default", Name: "kube-root-ca.crt"}, &cm); err == nil {
		if crt, ok := cm.Data["ca.crt"]; ok {
			return base64.StdEncoding.EncodeToString([]byte(crt)), nil
		}
	}
	return "", errors.New("CA not found")
}

func buildCertKubeconfig(apiServer, caDataB64, certDataB64, keyDataB64, username string) []byte {
	return []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: %s
    server: %s
  name: cluster
contexts:
- context:
    cluster: cluster
    namespace: default
    user: %s
  name: %s@cluster
current-context: %s@cluster
users:
- name: %s
  user:
    client-certificate-data: %s
    client-key-data: %s
`, caDataB64, apiServer, username, username, username, username, certDataB64, keyDataB64))
}

// extractCertificateExpiryWithFormatDetection tries multiple formats to extract certificate expiry
func (r *UserReconciler) extractCertificateExpiryWithFormatDetection(certData []byte) (time.Time, error) {
	// Method 1: Try as base64-encoded PEM (most likely)
	if certTime, err := r.tryBase64PEM(certData); err == nil {
		return certTime, nil
	}

	// Method 2: Try as raw PEM (less likely)
	if certTime, err := r.tryRawPEM(certData); err == nil {
		return certTime, nil
	}

	// Method 3: Try as raw DER (least likely)
	if certTime, err := r.tryRawDER(certData); err == nil {
		return certTime, nil
	}

	return time.Time{}, errors.New("unable to parse certificate in any known format")
}

// tryBase64PEM tries to parse as base64-encoded PEM
func (r *UserReconciler) tryBase64PEM(certData []byte) (time.Time, error) {
	// Decode base64
	certPEM, err := base64.StdEncoding.DecodeString(string(certData))
	if err != nil {
		return time.Time{}, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Decode PEM to get DER
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return time.Time{}, errors.New("PEM decode failed")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate parse failed: %w", err)
	}

	return cert.NotAfter, nil
}

// tryRawPEM tries to parse as raw PEM data
func (r *UserReconciler) tryRawPEM(certData []byte) (time.Time, error) {
	// Decode PEM to get DER
	block, _ := pem.Decode(certData)
	if block == nil {
		return time.Time{}, errors.New("PEM decode failed")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate parse failed: %w", err)
	}

	return cert.NotAfter, nil
}

// tryRawDER tries to parse as raw DER data
func (r *UserReconciler) tryRawDER(certData []byte) (time.Time, error) {
	// Parse certificate directly
	cert, err := x509.ParseCertificate(certData)
	if err != nil {
		return time.Time{}, fmt.Errorf("certificate parse failed: %w", err)
	}

	return cert.NotAfter, nil
}

// checkCertificateRotation checks if a certificate needs rotation based on expiry
func (r *UserReconciler) checkCertificateRotation(ctx context.Context, cfgSecretName string, rotationThreshold time.Duration) (bool, error) {
	var existingCfg corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: kubeUserNamespace}, &existingCfg); err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil // No existing certificate, no rotation needed
		}
		return false, err
	}

	// Extract certificate from kubeconfig
	kubeconfigData := existingCfg.Data["config"]
	if kubeconfigData == nil {
		return false, nil // No kubeconfig data, needs recreation
	}

	// Parse kubeconfig to extract client certificate
	certData, err := r.extractClientCertFromKubeconfig(kubeconfigData)
	if err != nil {
		return false, fmt.Errorf("failed to extract certificate from kubeconfig: %w", err)
	}

	// Check certificate expiry
	certExpiry, err := r.extractCertificateExpiryWithFormatDetection(certData)
	if err != nil {
		return false, fmt.Errorf("failed to extract certificate expiry: %w", err)
	}

	// Check if certificate is expiring soon
	timeUntilExpiry := time.Until(certExpiry)
	return timeUntilExpiry < rotationThreshold, nil
}

// extractClientCertFromKubeconfig extracts client certificate data from kubeconfig YAML
func (r *UserReconciler) extractClientCertFromKubeconfig(kubeconfigData []byte) ([]byte, error) {
	// Simple regex approach to extract client-certificate-data
	// In a production environment, you might want to use a proper YAML parser
	lines := strings.Split(string(kubeconfigData), "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if strings.HasPrefix(trimmedLine, "client-certificate-data:") {
			parts := strings.SplitN(trimmedLine, ":", 2)
			if len(parts) == 2 {
				certData := strings.TrimSpace(parts[1])
				// Return the base64 encoded certificate data as bytes
				return []byte(certData), nil
			}
		}
	}
	return nil, errors.New("client certificate data not found in kubeconfig")
}

// cleanupCertificateResources removes existing certificate resources for rotation
func (r *UserReconciler) cleanupCertificateResources(ctx context.Context, cfgSecretName, csrName string) error {
	logger := logf.FromContext(ctx)

	// Delete kubeconfig secret
	kubeconfigSecret := &corev1.Secret{}
	if err := r.Get(ctx, types.NamespacedName{Name: cfgSecretName, Namespace: kubeUserNamespace}, kubeconfigSecret); err == nil {
		logger.Info("Deleting kubeconfig secret for rotation", "secret", cfgSecretName)
		if err := r.Delete(ctx, kubeconfigSecret); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete kubeconfig secret: %w", err)
		}
	}

	// Delete existing CSR
	existingCSR := &certv1.CertificateSigningRequest{}
	if err := r.Get(ctx, types.NamespacedName{Name: csrName}, existingCSR); err == nil {
		logger.Info("Deleting existing CSR for rotation", "csr", csrName)
		if err := r.Delete(ctx, existingCSR); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete existing CSR: %w", err)
		}
	}

	// Optionally generate new private key for better security
	// For now, we'll reuse the existing key to maintain consistency
	// In a future enhancement, you might want to rotate keys as well

	return nil
}

// --- utils ---
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
func removeString(slice []string, s string) []string {
	var result []string
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}
