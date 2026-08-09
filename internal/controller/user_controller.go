/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package controller

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
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

// UserReconciler reconciles a User object
type UserReconciler struct {
	client.Client
	Scheme            *runtime.Scheme
	EventRecorder     record.EventRecorder
	AuthManager       *auth.Manager
	RenewalCalculator *renewal.RenewalCalculator
	SignerName        string // Configurable CSR signer for managed K8s support (EKS, GKE, AKS)
	ClusterName       string // Configurable kubeconfig cluster name
	Metrics           *metrics.Recorder
}

// RBAC rules
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=auth.openkube.io,resources=users/finalizers,verbs=update
// Core resources
// +kubebuilder:rbac:groups="",resources=configmaps;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=services,verbs=get;list;watch
// RBAC resources with bind permission
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=roles;clusterroles,verbs=get;list;watch;bind
// +kubebuilder:rbac:groups=rbac.authorization.k8s.io,resources=rolebindings;clusterrolebindings,verbs=get;list;watch;create;update;patch;delete;bind
// CSR resources
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=create;get;list;watch;update;patch;delete
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=update
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=signers,verbs=approve,resourceNames=kubernetes.io/kube-apiserver-client;beta.eks.amazonaws.com/app-client
// Admission resources
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=validatingwebhookconfigurations,verbs=get;patch

// Result label values recorded on the kubeuser_reconciliations_total metric.
const (
	reconcileResultNotFound       = "not_found"
	reconcileResultDeleted        = "deleted"
	reconcileResultError          = "error"
	reconcileResultFinalizerAdded = "finalizer_added"
	reconcileResultConflict       = "conflict"
	reconcileResultRequeued       = "requeued"
	reconcileResultSuccess        = "success"
)

// Reconcile orchestrates the user reconciliation process as a pure orchestrator.
// It implements an idempotent update pattern to minimize etcd writes and prevent infinite loops.
func (r *UserReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// Apply a 2-minute budget for one full reconciliation loop. This covers all API operations
	// including CSR approval, secret writes, and RBAC fan-out, while preventing a single hung
	// API call from blocking the controller-runtime work queue goroutine indefinitely.
	//
	// During manager shutdown the effective budget becomes
	// min(2*time.Minute, GracefulShutdownTimeout). A reconcile that started just before SIGTERM
	// may be cancelled at the shorter drain ceiling rather than the 2-minute budget. The Shadow
	// Secret recovery pattern (renewal/rotation.go:99) resumes from a checkpointed shadow on the
	// next leader, so any cancelled rotation is safely recovered.
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	start := time.Now()
	logger := logf.FromContext(ctx)
	logger.Info("=== START RECONCILE ===", "user", req.Name)

	// Track reconciliation result for metrics
	var reconcileResult string
	defer func() {
		if r.Metrics != nil {
			r.Metrics.RecordReconciliation("user", reconcileResult, time.Since(start))
			r.updateAggregateMetrics()
		}
	}()

	// 1. Fetch User
	var user authv1alpha1.User
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		logger.Info("User not found, ignoring", "user", req.Name, "error", err)
		reconcileResult = reconcileResultNotFound
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
		reconcileResult = reconcileResultDeleted
		return ctrl.Result{}, r.handleDeletion(ctx, &user)
	}

	// Ensure finalizer. When this call performs an API update, the in-memory
	// object must not be reused for further writes in this pass (issue #58):
	// any concurrent mutation landing while business logic runs would make the
	// final Status().Update fail with a conflict, discarding its output. End
	// the pass instead. The successful update produces a watch event that is
	// handed to this controller only after the informer cache has absorbed the
	// update, so the pass that event triggers starts from a fresh Get. A pass
	// triggered earlier by some other queued event can still read the older
	// cache; it then re-attempts the add, conflicts harmlessly on the write,
	// and retries with backoff, never reaching business logic with a stale
	// object. An explicit Requeue here would make that stale re-entry the
	// common case instead of the rare exception, which is why none is set.
	finalizerAdded, err := r.ensureFinalizer(ctx, &user)
	if err != nil {
		reconcileResult = reconcileResultError
		return ctrl.Result{}, err
	}
	if finalizerAdded {
		logger.Info("=== END RECONCILE (FINALIZER ADDED) ===",
			"reason", "watch event from the finalizer update triggers the next pass on a fresh object")
		reconcileResult = reconcileResultFinalizerAdded
		return ctrl.Result{}, nil
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
			// On an optimistic-concurrency conflict the computed status is
			// discarded and recomputed on the next pass. Record what was lost
			// so the discard is visible in logs (issue #58), then requeue in
			// 5 seconds WITHOUT returning the error: conflicts are expected
			// contention, and returning a non-nil error would make
			// controller-runtime ignore the RequeueAfter, retry on its
			// millisecond-scale rate-limiter backoff instead, and double-log
			// the conflict at error level.
			if apierrors.IsConflict(updateErr) {
				logger.Info("Status update conflicted with a concurrent write, discarding computed status and requeueing",
					"discardedPhase", user.Status.Phase,
					"discardedRotationStep", user.Status.RotationStep,
					"discardedMessage", user.Status.Message)
				reconcileResult = reconcileResultConflict
				return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
			}
			logger.Error(updateErr, "Failed to update user status")
			reconcileResult = reconcileResultError
			// Return the error alone: controller-runtime ignores any Result
			// when the error is non-nil and requeues with backoff, so a
			// RequeueAfter here would be dead code.
			return ctrl.Result{}, updateErr
		}
		logger.Info("Status updated successfully", "phase", user.Status.Phase, "rotationStep", user.Status.RotationStep)
	}

	// Handle any error that occurred during business logic after status update
	if err != nil {
		reconcileResult = reconcileResultError
		return r.handleError(ctx, &user, err)
	}

	// 6. Return pending result if one was captured (e.g., immediate requeue for Shadow Secret creation)
	if pendingResult != nil {
		logger.Info("=== END RECONCILE (PENDING REQUEUE) ===", "requeueAfter", pendingResult.RequeueAfter)
		reconcileResult = reconcileResultRequeued
		return *pendingResult, nil
	}

	// 7. Calculate Requeue
	requeueResult := r.calculateRequeue(ctx, &user)
	logger.Info("=== END RECONCILE ===", "requeueAfter", requeueResult.RequeueAfter, "statusCommitted", statusChanged)
	reconcileResult = reconcileResultSuccess

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

	// Reject reserved identity prefixes before any credential work. Defense in
	// depth: the webhook rejects at admission, but a User that landed in etcd
	// without passing the webhook must not be issued a certificate.
	if err := auth.ValidateUserIdentity(user); err != nil {
		logger.Error(err, "Invalid user identity")
		user.Status.Phase = helpers.PhaseError
		user.Status.Message = fmt.Sprintf("Invalid user identity: %v", err)
		return true, nil, err
	}

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
func (r *UserReconciler) handleDeletion(ctx context.Context, user *authv1alpha1.User) error {
	logger := logf.FromContext(ctx)
	logger.Info("User is being deleted, starting cleanup")

	if helpers.ContainsString(user.Finalizers, authv1alpha1.UserFinalizer) {
		// Step 1: Clean up all user resources BEFORE removing finalizer
		// This ensures cleanup is complete even if finalizer removal fails
		logger.Info("Cleaning up user resources")
		cleanup.CleanupUserResources(ctx, r.Client, user)

		// Step 2: Remove finalizer as the absolute last step
		logger.Info("Removing finalizer")
		user.Finalizers = helpers.RemoveString(user.Finalizers, authv1alpha1.UserFinalizer)
		if err := r.Update(ctx, user); err != nil {
			// Handle harmless race conditions that occur during concurrent deletion reconciliations
			// These are expected and should not trigger error alerts in observability systems

			// Case 1: Object already deleted by another reconciliation
			if client.IgnoreNotFound(err) == nil {
				logger.Info("Ignoring harmless race condition: user already deleted, finalizer removal not needed")
				return nil
			}

			// Case 2: Optimistic concurrency conflict (ResourceVersion mismatch)
			if apierrors.IsConflict(err) {
				logger.Info("Ignoring harmless race condition: conflict removing finalizer, likely already removed by another reconciliation")
				return nil
			}

			// Case 3: etcd precondition failures (UID mismatch during deletion)
			// These occur when the object is being deleted and etcd's preconditions fail
			errMsg := err.Error()
			if strings.Contains(errMsg, "Precondition failed") || strings.Contains(errMsg, "StorageError") {
				logger.Info("Ignoring harmless race condition: etcd precondition failed during deletion",
					"error", errMsg,
					"reason", "Object is being deleted concurrently")
				return nil
			}

			// Only log actual errors that need attention
			logger.Error(err, "Failed to remove finalizer - unexpected error")
			return err
		}
		logger.Info("Successfully cleaned up and removed finalizer")
	}

	logger.Info("=== END RECONCILE (DELETION) ===")
	return nil
}

// ensureFinalizer adds the user finalizer if not present.
// It returns true when the finalizer was added by this call, meaning an API
// update was performed and the caller must end the current reconcile pass
// instead of reusing the object for further writes (issue #58).
func (r *UserReconciler) ensureFinalizer(ctx context.Context, user *authv1alpha1.User) (bool, error) {
	logger := logf.FromContext(ctx)

	if helpers.ContainsString(user.Finalizers, authv1alpha1.UserFinalizer) {
		return false, nil
	}

	logger.Info("Adding finalizer", "finalizer", authv1alpha1.UserFinalizer)
	user.Finalizers = append(user.Finalizers, authv1alpha1.UserFinalizer)
	if err := r.Update(ctx, user); err != nil {
		logger.Error(err, "Failed to add finalizer")
		return false, err
	}
	logger.Info("Successfully added finalizer")
	return true, nil
}

// reconcileRBAC handles both RoleBindings and ClusterRoleBindings reconciliation.
// Returns true if status needs to be updated, without performing the update itself.
func (r *UserReconciler) reconcileRBAC(ctx context.Context, user *authv1alpha1.User) (bool, error) {
	logger := logf.FromContext(ctx)

	// Phase-level timeout: List + bounded CRUD across namespaces should complete well within 15s.
	// Derived from the reconcile context so cancellation propagates correctly on shutdown.
	rbacCtx, rbacCancel := context.WithTimeout(ctx, 15*time.Second)
	defer rbacCancel()

	// Reconcile RoleBindings
	logger.Info("Starting RoleBindings reconciliation", "rolesCount", len(user.Spec.Roles))
	if err := rbac.ReconcileRoleBindings(rbacCtx, r.Client, user); err != nil {
		logger.Error(err, "Failed to reconcile RoleBindings")
		return false, fmt.Errorf("failed to reconcile RoleBindings: %w", err)
	}
	logger.Info("RoleBindings reconciliation completed")

	// Reconcile ClusterRoleBindings
	logger.Info("Starting ClusterRoleBindings reconciliation", "clusterRolesCount", len(user.Spec.ClusterRoles))
	if err := rbac.ReconcileClusterRoleBindings(rbacCtx, r.Client, user); err != nil {
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

	// Phase-level timeout covering the full cert/rotation call chain:
	// CSR approval subresource (≤30s) + atomic secret flip (≤30s) + auxiliary Gets ≤ 90s.
	// Each sub-operation within the chain has its own inner bound (CSR: 30s, atomic flip: 30s),
	// so this acts as the outer safety net for the combined auth phase.
	authCtx, authCancel := context.WithTimeout(ctx, 90*time.Second)
	defer authCancel()

	// Initialize auth manager if needed
	if r.AuthManager == nil {
		r.AuthManager = auth.NewManager(r.Client, r.EventRecorder, r.SignerName, r.ClusterName, r.Metrics)
	}

	// Capture old values before authentication processing
	oldExpiryTime := user.Status.ExpiryTime
	oldNextRenewalAt := user.Status.NextRenewalAt
	oldPhase := user.Status.Phase
	oldRotationStep := user.Status.RotationStep

	statusChanged, result, err := r.AuthManager.Ensure(authCtx, user)
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

	// Back off on deadline exceeded to avoid rapid retry storms after a timeout.
	// Do not propagate the error to controller-runtime to suppress noisy stack traces.
	if errors.Is(err, context.DeadlineExceeded) {
		logger.Error(err, "Reconciliation timed out, backing off", "phase", user.Status.Phase)
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
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
func (r *UserReconciler) updateAggregateMetrics() {
	// Use a fresh context independent of the reconcile budget: this is a non-critical
	// background observation and must not fail just because the reconcile context expired.
	metricsCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var userList authv1alpha1.UserList
	if err := r.List(metricsCtx, &userList); err != nil {
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
		phase := u.Status.Phase
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

	r.Metrics.ResetUserCounts()
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
	if r.ClusterName == "" {
		r.ClusterName = helpers.DefaultKubeconfigClusterName
	}

	// Initialize auth manager with configurable signer
	if r.AuthManager == nil {
		r.AuthManager = auth.NewManager(r.Client, r.EventRecorder, r.SignerName, r.ClusterName, r.Metrics)
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
