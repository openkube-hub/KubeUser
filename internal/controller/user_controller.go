/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/auth"
	"github.com/openkube-hub/KubeUser/internal/controller/cleanup"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	"github.com/openkube-hub/KubeUser/internal/controller/metrics"
	"github.com/openkube-hub/KubeUser/internal/controller/rbac"
	"github.com/openkube-hub/KubeUser/internal/controller/renewal"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// activeReconcileCount tracks how many reconcile goroutines are running concurrently.
var activeReconcileCount int64

// UserReconciler reconciles a User object
type UserReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	EventRecorder     record.EventRecorder
	AuthManager       *auth.Manager
	RenewalCalculator *renewal.RenewalCalculator
	SignerName        string // Configurable CSR signer for managed K8s support (EKS, GKE, AKS)
	Metrics           *metrics.Recorder
}

// RBAC rules
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users/finalizers,verbs=update
// Core resources
// +kubebuilder:rbac:groups="",resources=configmaps;secrets;serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods;replicasets,verbs=get;list;watch;create;update;patch;delete
// Apps resources
// +kubebuilder:rbac:groups=apps,resources=deployments;replicasets,verbs=get;list;watch;create;update;patch;delete
// RBAC resources with bind permission
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;clusterroles,verbs=get;list;watch;bind
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete;bind
// CSR resources
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=update
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=approve,resourceNames=kubernetes.io/kube-apiserver-client;beta.eks.amazonaws.com/app-client
// Admission resources
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;patch

// Reconcile orchestrates the user reconciliation process as a pure orchestrator.
// It implements an idempotent update pattern to minimize etcd writes and prevent infinite loops.
func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	start := time.Now()
	logger := logf.FromContext(ctx)
	logger.Info("=== START RECONCILE ===", "user", req.Name)

	// Track active reconcile goroutines as a proxy for work queue depth
	active := atomic.AddInt64(&activeReconcileCount, 1)
	if r.Metrics != nil {
		r.Metrics.SetWorkQueueDepth("user", int(active))
	}

	// Track reconciliation result for metrics
	var reconcileResult string
	defer func() {
		remaining := atomic.AddInt64(&activeReconcileCount, -1)
		if r.Metrics != nil {
			r.Metrics.RecordReconciliation("user", reconcileResult, time.Since(start))
			r.Metrics.SetWorkQueueDepth("user", int(remaining))
			r.updateAggregateMetrics(ctx)
		}
	}()

	// 1. Fetch User
	var user authv1alpha1.User
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		logger.Info("User not found, ignoring", "user", req.Name, "error", err)
		reconcileResult = "not_found"
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger.Info("Reconciling User", "name", user.Name, "generation", user.Generation, "resourceVersion", user.ResourceVersion)

	// Track status changes to implement idempotent updates
	statusChanged := false
	var err error // Declare error variable for use throughout the function

	// Initialize status if needed
	if changed := r.ensureInitialStatus(&user); changed {
		statusChanged = true
	}

	// 2. Handle Deletion
	if !user.DeletionTimestamp.IsZero() {
		reconcileResult = "deleted"
		return r.handleDeletion(ctx, &user)
	}

	// Ensure finalizer
	if err := r.ensureFinalizer(ctx, &user); err != nil {
		reconcileResult = "error"
		return ctrl.Result{}, err
	}

	// 3. Run Business Logic
	var needsStatusUpdate bool
	var pendingResult *ctrl.Result
	needsStatusUpdate, pendingResult, err = r.reconcileBusinessLogic(ctx, &user)
	if err != nil {
		// Error occurred, but we still need to update status if it was changed
		statusChanged = true // Ensure error status gets persisted
		// Continue to status update section rather than returning immediately
	} else if needsStatusUpdate {
		statusChanged = true
	}
	// Note: pendingResult is captured but not returned yet - we must persist status first

	// 4. Sync NextRenewalAt (Purge if needed)
	if changed := r.syncStatusFields(ctx, &user); changed {
		statusChanged = true
	}

	// 5. ONE Status Update call (if needed)
	if statusChanged {
		if updateErr := r.Status().Update(ctx, &user); updateErr != nil {
			logger.Error(updateErr, "Failed to update user status")
			return ctrl.Result{RequeueAfter: 5 * time.Second}, updateErr
		}
		logger.Info("Status updated successfully", "phase", user.Status.Phase, "rotationStep", user.Status.RotationStep)
	}

	// Handle any error that occurred during business logic after status update
	if err != nil {
		reconcileResult = "error"
		return r.handleError(ctx, &user, err)
	}

	// 6. Return pending result if one was captured (e.g., immediate requeue for Shadow Secret creation)
	if pendingResult != nil {
		logger.Info("=== END RECONCILE (PENDING REQUEUE) ===", "requeueAfter", pendingResult.RequeueAfter)
		reconcileResult = "requeued"
		return *pendingResult, nil
	}

	// 7. Calculate Requeue
	requeueResult := r.calculateRequeue(ctx, &user)
	logger.Info("=== END RECONCILE ===", "requeueAfter", requeueResult.RequeueAfter, "statusCommitted", statusChanged)
	reconcileResult = "success"

	// Update user sync status metric
	if r.Metrics != nil {
		r.Metrics.SetUserSyncStatus(user.Namespace, user.Name, user.Status.Phase == helpers.PhaseActive)
	}

	return requeueResult, nil
}

// reconcileBusinessLogic consolidates the happy path business logic.
// Returns (needsStatusUpdate bool, result *ctrl.Result, err error).
func (r *UserReconciler) reconcileBusinessLogic(ctx context.Context, user *authv1alpha1.User) (bool, *ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	needsStatusUpdate := false

	// Validate auth specification
	if err := auth.ValidateAuthSpec(user); err != nil {
		logger.Error(err, "Invalid auth specification")
		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Invalid auth specification: %v", err)
		return true, nil, err
	}

	// Reconcile RBAC resources (no side effects)
	rbacNeedsUpdate, err := r.reconcileRBAC(ctx, user)
	if err != nil {
		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Failed to reconcile RBAC: %v", err)
		return true, nil, err
	}
	if rbacNeedsUpdate {
		needsStatusUpdate = true
	}

	// Reconcile authentication credentials
	authChanged, authResult, err := r.reconcileAuthentication(ctx, user)
	if err != nil {
		// Handle specific error cases
		if strings.Contains(err.Error(), "not yet implemented") {
			user.Status.Phase = helpers.PhaseError
			user.Status.Message = fmt.Sprintf("Authentication type not implemented: %v", err)
			return true, nil, err
		}

		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Failed to ensure authentication: %v", err)
		return true, &ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}

	// Handle immediate requeue if needed (e.g., Shadow Secret created)
	if authResult != nil {
		logger.Info("Authentication processing requires immediate requeue")
		return authChanged, authResult, nil
	}

	// Aggregate authentication changes
	if authChanged {
		needsStatusUpdate = true
	}

	return needsStatusUpdate, nil, nil
}

// ensureInitialStatus sets the initial status if not already set.
// Returns true if the status was changed.
func (r *UserReconciler) ensureInitialStatus(user *authv1alpha1.User) bool {
	if user.Status.Phase == "" {
		user.Status.Phase = helpers.PhasePending
		user.Status.Message = "Initializing user resources"
		return true
	}
	return false
}

// handleDeletion manages the user deletion process including cleanup and finalizer removal.
// This function gracefully handles etcd race conditions that occur during concurrent deletion reconciliations.
func (r *UserReconciler) handleDeletion(ctx context.Context, user *authv1alpha1.User) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("User is being deleted, starting cleanup")

	if helpers.ContainsString(user.Finalizers, cleanup.UserFinalizer) {
		// Step 1: Clean up all user resources BEFORE removing finalizer
		// This ensures cleanup is complete even if finalizer removal fails
		logger.Info("Cleaning up user resources")
		cleanup.CleanupUserResources(ctx, r.Client, user)

		// Step 2: Remove finalizer as the absolute last step
		logger.Info("Removing finalizer")
		user.Finalizers = helpers.RemoveString(user.Finalizers, cleanup.UserFinalizer)
		if err := r.Update(ctx, user); err != nil {
			// Handle harmless race conditions that occur during concurrent deletion reconciliations
			// These are expected and should not trigger error alerts in observability systems

			// Case 1: Object already deleted by another reconciliation
			if client.IgnoreNotFound(err) == nil {
				logger.Info("Ignoring harmless race condition: user already deleted, finalizer removal not needed")
				return ctrl.Result{}, nil
			}

			// Case 2: Optimistic concurrency conflict (ResourceVersion mismatch)
			if apierrors.IsConflict(err) {
				logger.Info("Ignoring harmless race condition: conflict removing finalizer, likely already removed by another reconciliation")
				return ctrl.Result{}, nil
			}

			// Case 3: etcd precondition failures (UID mismatch during deletion)
			// These occur when the object is being deleted and etcd's preconditions fail
			errMsg := err.Error()
			if strings.Contains(errMsg, "Precondition failed") || strings.Contains(errMsg, "StorageError") {
				logger.Info("Ignoring harmless race condition: etcd precondition failed during deletion",
					"error", errMsg,
					"reason", "Object is being deleted concurrently")
				return ctrl.Result{}, nil
			}

			// Only log actual errors that need attention
			logger.Error(err, "Failed to remove finalizer - unexpected error")
			return ctrl.Result{}, err
		}
		logger.Info("Successfully cleaned up and removed finalizer")
	}

	logger.Info("=== END RECONCILE (DELETION) ===")
	return ctrl.Result{}, nil
}

// ensureFinalizer adds the user finalizer if not present.
func (r *UserReconciler) ensureFinalizer(ctx context.Context, user *authv1alpha1.User) error {
	logger := logf.FromContext(ctx)

	if !helpers.ContainsString(user.Finalizers, cleanup.UserFinalizer) {
		logger.Info("Adding finalizer", "finalizer", cleanup.UserFinalizer)
		user.Finalizers = append(user.Finalizers, cleanup.UserFinalizer)
		if err := r.Update(ctx, user); err != nil {
			logger.Error(err, "Failed to add finalizer")
			return err
		}
		logger.Info("Successfully added finalizer")
	}
	return nil
}

// reconcileRBAC handles both RoleBindings and ClusterRoleBindings reconciliation.
// Returns true if status needs to be updated, without performing the update itself.
func (r *UserReconciler) reconcileRBAC(ctx context.Context, user *authv1alpha1.User) (bool, error) {
	logger := logf.FromContext(ctx)

	// Reconcile RoleBindings
	logger.Info("Starting RoleBindings reconciliation", "rolesCount", len(user.Spec.Roles))
	if err := rbac.ReconcileRoleBindings(ctx, r.Client, user); err != nil {
		logger.Error(err, "Failed to reconcile RoleBindings")
		return false, fmt.Errorf("failed to reconcile RoleBindings: %w", err)
	}
	logger.Info("RoleBindings reconciliation completed")

	// Reconcile ClusterRoleBindings
	logger.Info("Starting ClusterRoleBindings reconciliation", "clusterRolesCount", len(user.Spec.ClusterRoles))
	if err := rbac.ReconcileClusterRoleBindings(ctx, r.Client, user); err != nil {
		logger.Error(err, "Failed to reconcile ClusterRoleBindings")
		return false, fmt.Errorf("failed to reconcile ClusterRoleBindings: %w", err)
	}
	logger.Info("ClusterRoleBindings reconciliation completed")

	// Update user status fields after successful RBAC reconciliation
	// This does not perform API writes, only updates the in-memory object
	logger.Info("Updating user status fields after RBAC reconciliation")
	statusChanged, err := helpers.UpdateUserStatus(ctx, r.Client, user)
	if err != nil {
		logger.Error(err, "Failed to update user status fields")
		// Don't return error, continue with reconciliation
		return false, nil
	}

	logger.Info("User status fields updated successfully")
	return statusChanged, nil // Return whether status actually changed
}

// reconcileAuthentication manages authentication credentials and handles auth-specific errors.
// reconcileAuthentication manages authentication credentials and handles auth-specific errors.
// Returns (bool, *ctrl.Result, error) where:
// - bool: true if status fields were changed
// - *ctrl.Result: non-nil if immediate requeue is needed
// - error: actual error that should stop reconciliation
func (r *UserReconciler) reconcileAuthentication(ctx context.Context, user *authv1alpha1.User) (bool, *ctrl.Result, error) {
	logger := logf.FromContext(ctx)
	logger.Info("Starting authentication credential processing")

	// Initialize auth manager if needed
	if r.AuthManager == nil {
		r.AuthManager = auth.NewManager(r.Client, r.EventRecorder, r.SignerName, r.Metrics)
	}

	// Capture old values before authentication processing
	oldExpiryTime := user.Status.ExpiryTime
	oldNextRenewalAt := user.Status.NextRenewalAt
	oldPhase := user.Status.Phase
	oldRotationStep := user.Status.RotationStep

	statusChanged, result, err := r.AuthManager.Ensure(ctx, user)
	if err != nil {
		// Don't log expected requeue errors as ERROR level
		if strings.Contains(err.Error(), "requeue needed") {
			logger.Info("Authentication processing needs requeue", "reason", err.Error())
		} else {
			logger.Error(err, "Failed to ensure authentication credentials")
		}

		// Check if status was changed during authentication processing (e.g., Phase set to "Renewing")
		additionalChanges := oldPhase != user.Status.Phase ||
			oldExpiryTime != user.Status.ExpiryTime ||
			oldRotationStep != user.Status.RotationStep ||
			!helpers.SemanticTimePtrMatch(oldNextRenewalAt, user.Status.NextRenewalAt)

		return statusChanged || additionalChanges, result, err
	}

	// Compare old vs new values to detect additional changes
	expiryChanged := oldExpiryTime != user.Status.ExpiryTime
	renewalChanged := !helpers.SemanticTimePtrMatch(oldNextRenewalAt, user.Status.NextRenewalAt)
	phaseChanged := oldPhase != user.Status.Phase
	rotationStepChanged := oldRotationStep != user.Status.RotationStep

	additionalChanges := expiryChanged || renewalChanged || phaseChanged || rotationStepChanged
	totalStatusChanged := statusChanged || additionalChanges

	if totalStatusChanged {
		logger.Info("Authentication processing updated status fields",
			"providerChanged", statusChanged,
			"expiryChanged", expiryChanged,
			"renewalChanged", renewalChanged,
			"phaseChanged", phaseChanged,
			"rotationStepChanged", rotationStepChanged,
			"oldExpiry", oldExpiryTime,
			"newExpiry", user.Status.ExpiryTime,
			"oldPhase", oldPhase,
			"newPhase", user.Status.Phase,
			"oldRotationStep", oldRotationStep,
			"newRotationStep", user.Status.RotationStep)
	}

	logger.Info("Authentication credential processing completed")
	return totalStatusChanged, result, nil
}

// syncStatusFields manages status field synchronization, including NextRenewalAt field management.
// Returns true if any status fields were changed.
// This function implements dynamic renewal recalculation to react to Spec changes.
func (r *UserReconciler) syncStatusFields(ctx context.Context, user *authv1alpha1.User) bool {
	logger := logf.FromContext(ctx)
	changed := false

	// Defensive check: if Auth is nil, cannot sync status fields
	if user.Spec.Auth == nil {
		return false
	}

	// Handle NextRenewalAt field based on autoRenew setting
	// Explicit purging: if autoRenew is disabled, explicitly set NextRenewalAt to nil
	if !helpers.GetAutoRenew(user) && user.Status.NextRenewalAt != nil {
		logger.Info("Auto-renewal disabled, explicitly clearing NextRenewalAt field")
		user.Status.NextRenewalAt = nil
		changed = true
	} else if helpers.GetAutoRenew(user) && user.Status.ExpiryTime != "" {
		// Auto-renewal is enabled - check if NextRenewalAt needs recalculation
		certExpiry, err := time.Parse(time.RFC3339, user.Status.ExpiryTime)
		if err != nil {
			logger.Error(err, "Failed to parse existing certificate expiry time", "expiryTime", user.Status.ExpiryTime)
			return changed
		}

		// Calculate what NextRenewalAt SHOULD be based on current Spec
		certDuration := auth.GetAuthDuration(user)
		issuedAt := certExpiry.Add(-certDuration) // Approximate issued time

		expectedRenewalTime := renewal.CalculateNextRenewal(issuedAt, certExpiry, user.Spec.Auth.RenewBefore)

		// CRITICAL: Compare expected vs actual NextRenewalAt
		// If they differ, the user changed RenewBefore in the spec - recalculate immediately
		if !helpers.SemanticTimePtrMatch(user.Status.NextRenewalAt, &expectedRenewalTime) {
			oldRenewalTime := "nil"
			if user.Status.NextRenewalAt != nil {
				oldRenewalTime = user.Status.NextRenewalAt.Format(time.RFC3339)
			}

			logger.Info("NextRenewalAt needs recalculation due to Spec change",
				"oldNextRenewalAt", oldRenewalTime,
				"newNextRenewalAt", expectedRenewalTime.Format(time.RFC3339),
				"renewBefore", user.Spec.Auth.RenewBefore,
				"certExpiry", certExpiry.Format(time.RFC3339))

			user.Status.NextRenewalAt = &expectedRenewalTime
			changed = true
		}
	}

	return changed
}

// handleError handles error cases with proper logging but no API writes.
// Status updates are handled by the main Reconcile function's single update point.
func (r *UserReconciler) handleError(ctx context.Context, user *authv1alpha1.User, err error) (ctrl.Result, error) {
	logger := logf.FromContext(ctx)

	// Check if this is a known requeue-only error (not a hard failure)
	if strings.Contains(err.Error(), "requeue needed") {
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	logger.Error(err, "Reconciliation failed", "phase", user.Status.Phase)

	// Return a standard 5s requeue for errors
	return ctrl.Result{RequeueAfter: 5 * time.Second}, err
}

// calculateRequeue determines the optimal requeue strategy based on user state and configuration.
func (r *UserReconciler) calculateRequeue(ctx context.Context, user *authv1alpha1.User) ctrl.Result {
	logger := logf.FromContext(ctx)

	// No requeue for users in terminal states
	if user.Status.Phase == helpers.PhaseError || user.Status.Phase == helpers.PhaseExpired {
		logger.Info("User in terminal state, no requeue needed", "phase", user.Status.Phase)
		return ctrl.Result{}
	}

	// Defensive check: if Auth is nil, use default requeue
	if user.Spec.Auth == nil {
		logger.Info("Auth is nil, using default requeue")
		return ctrl.Result{RequeueAfter: 30 * time.Minute}
	}

	// Smart requeue for auto-renewal enabled users
	if helpers.GetAutoRenew(user) && user.Status.Phase == helpers.PhaseActive {
		requeueAfter, err := r.calculateSmartRequeue(ctx, user)
		if err != nil {
			logger.Error(err, "Failed to calculate smart requeue, using default")
			return ctrl.Result{RequeueAfter: 30 * time.Minute}
		}
		logger.Info("Smart requeue calculated", "requeueAfter", requeueAfter)
		return ctrl.Result{RequeueAfter: requeueAfter}
	}

	// Legacy expiry-based requeue for non-auto-renewal users
	if user.Status.Phase == helpers.PhaseActive && user.Status.ExpiryTime != "" {
		if expiryTime, err := time.Parse(time.RFC3339, user.Status.ExpiryTime); err == nil {
			timeUntilExpiry := time.Until(expiryTime)
			logger.Info("Time until expiry", "duration", timeUntilExpiry)

			if timeUntilExpiry <= 0 {
				// User has expired - this should trigger a status update in the next reconciliation
				logger.Info("User has expired, will be marked as expired in next reconciliation")
				// Don't modify status here - let the next reconciliation handle it properly
				return ctrl.Result{Requeue: true} // Immediate requeue to handle expiry
			} else if timeUntilExpiry < 24*time.Hour {
				// Requeue to check expiry more frequently
				logger.Info("User expires soon, requeueing in 1 hour")
				return ctrl.Result{RequeueAfter: time.Hour}
			}
		} else {
			logger.Error(err, "Failed to parse expiry time", "expiryTime", user.Status.ExpiryTime)
		}
	}

	// Default requeue for active users
	logger.Info("Using default requeue interval")
	return ctrl.Result{RequeueAfter: 30 * time.Minute}
}

// calculateSmartRequeue calculates the optimal requeue time for auto-renewal.
// It uses NextRenewalAt from status when available for efficiency, with jitter to prevent thundering herd.
func (r *UserReconciler) calculateSmartRequeue(ctx context.Context, user *authv1alpha1.User) (time.Duration, error) {
	logger := logf.FromContext(ctx)

	// Defensive check: if Auth is nil, use default
	if user.Spec.Auth == nil {
		logger.Info("Auth is nil, using default requeue")
		return 30 * time.Minute, nil
	}

	// Initialize renewal calculator if not already done
	if r.RenewalCalculator == nil {
		r.RenewalCalculator = renewal.NewRenewalCalculator()
	}

	// Get certificate duration
	certDuration := auth.GetAuthDuration(user)

	// Use NextRenewalAt from status if available (most efficient)
	if user.Status.NextRenewalAt != nil {
		now := time.Now()
		renewalTime := user.Status.NextRenewalAt.Time

		if renewalTime.Before(now) {
			// Should renew immediately
			logger.Info("Certificate should renew immediately")
			return 0, nil
		}

		requeueAfter := renewalTime.Sub(now)

		// Add small jitter to prevent thundering herd
		jitter := time.Duration(rand.Int63n(int64(5 * time.Minute)))
		requeueAfter += jitter

		// Cap requeue time to reasonable limits
		if requeueAfter > 24*time.Hour {
			requeueAfter = 24 * time.Hour
		}
		if requeueAfter < 1*time.Minute {
			requeueAfter = 1 * time.Minute
		}

		logger.Info("Smart requeue calculated from NextRenewalAt",
			"renewalTime", renewalTime.Format(time.RFC3339),
			"requeueAfter", requeueAfter,
			"jitter", jitter)

		return requeueAfter, nil
	}

	// Fallback: calculate from certificate expiry
	if user.Status.ExpiryTime != "" {
		certExpiry, err := time.Parse(time.RFC3339, user.Status.ExpiryTime)
		if err != nil {
			return 0, fmt.Errorf("failed to parse certificate expiry: %w", err)
		}

		requeueAfter, err := r.RenewalCalculator.GetRequeueAfter(user, certExpiry, certDuration)
		if err != nil {
			return 0, fmt.Errorf("failed to calculate requeue time: %w", err)
		}

		logger.Info("Smart requeue calculated from certificate expiry",
			"certExpiry", certExpiry.Format(time.RFC3339),
			"requeueAfter", requeueAfter)

		return requeueAfter, nil
	}

	// No certificate information available, use default
	logger.Info("No certificate information available, using default requeue")
	return 30 * time.Minute, nil
}

// updateAggregateMetrics lists all users and updates cluster-wide gauge metrics.
// Called at the end of every reconcile via defer so counts stay current after creates/deletes.
func (r *UserReconciler) updateAggregateMetrics(ctx context.Context) {
	var userList authv1alpha1.UserList
	if err := r.List(ctx, &userList); err != nil {
		return
	}

	now := time.Now()

	// Count users by namespace+phase and track expiry windows
	type nsStats struct {
		phaseCounts map[string]float64
		within24h   int
		within7d    int
	}
	stats := map[string]*nsStats{}

	for _, u := range userList.Items {
		ns := u.Namespace
		if ns == "" {
			ns = "cluster"
		}
		phase := string(u.Status.Phase)
		if phase == "" {
			phase = "unknown"
		}

		if stats[ns] == nil {
			stats[ns] = &nsStats{phaseCounts: map[string]float64{}}
		}
		stats[ns].phaseCounts[phase]++

		if u.Status.ExpiryTime != "" {
			if expiry, err := time.Parse(time.RFC3339, u.Status.ExpiryTime); err == nil {
				until := expiry.Sub(now)
				if until > 0 && until <= 24*time.Hour {
					stats[ns].within24h++
				}
				if until > 0 && until <= 7*24*time.Hour {
					stats[ns].within7d++
				}
			}
		}
	}

	for ns, s := range stats {
		for phase, count := range s.phaseCounts {
			r.Metrics.SetUserCount(ns, phase, count)
		}
		r.Metrics.UpdateExpiryAlerts(ns, s.within24h, s.within7d)
	}
}

// SetupWithManager wires the controller
func (r *UserReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Initialize event recorder if not already set
	if r.EventRecorder == nil {
		r.EventRecorder = mgr.GetEventRecorderFor("user-controller")
	}

	// Default signer name if not specified
	if r.SignerName == "" {
		r.SignerName = "kubernetes.io/kube-apiserver-client"
	}

	// Initialize auth manager with configurable signer
	if r.AuthManager == nil {
		r.AuthManager = auth.NewManager(r.Client, r.EventRecorder, r.SignerName, r.Metrics)
	}

	// Initialize renewal calculator
	if r.RenewalCalculator == nil {
		r.RenewalCalculator = renewal.NewRenewalCalculator()
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&authv1alpha1.User{}).
		Owns(&rbacv1.RoleBinding{}).
		Owns(&rbacv1.ClusterRoleBinding{}).
		Owns(&corev1.Secret{}).
		Named("user").
		Complete(r)
}
