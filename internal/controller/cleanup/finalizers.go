/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package cleanup

import (
	"context"
	"fmt"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/helpers"
	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	UserFinalizer = "auth.openkube.io/finalizer"

	// userLabel selects all operator-managed resources for a given User.
	userLabel = "auth.openkube.io/user"
)

// CleanupUserResources deletes resources owned by the user. Best-effort:
// per-resource failures are logged but never block finalizer removal.
func CleanupUserResources(ctx context.Context, r client.Client, user *authv1alpha1.User) {
	// Finalizer cleanup must complete promptly to unblock the deletion path.
	// The caller's context may already be bounded; this adds a firm local ceiling.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	logger := logf.FromContext(ctx).WithName("cleanup")
	username := user.Name
	userNamespace := helpers.GetKubeUserNamespace()
	selector := client.MatchingLabels{userLabel: username}

	// Delete fixed-name resources (steady-state secrets and initial CSR).
	fixed := []client.Object{
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-key", username), Namespace: userNamespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-kubeconfig", username), Namespace: userNamespace}},
		&certv1.CertificateSigningRequest{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-csr", username)}},
	}
	for _, obj := range fixed {
		if err := r.Delete(ctx, obj); client.IgnoreNotFound(err) != nil {
			logger.Error(err, "failed to delete fixed resource",
				"kind", fmt.Sprintf("%T", obj), "name", obj.GetName(), "namespace", obj.GetNamespace())
		}
	}

	// Delete user-labelled Secrets in the operator namespace (rotation shadow).
	var secrets corev1.SecretList
	if err := r.List(ctx, &secrets, selector, client.InNamespace(userNamespace)); err != nil {
		logger.Error(err, "failed to list user-labelled secrets", "namespace", userNamespace)
	} else {
		for i := range secrets.Items {
			if err := r.Delete(ctx, &secrets.Items[i]); client.IgnoreNotFound(err) != nil {
				logger.Error(err, "failed to delete labelled secret", "name", secrets.Items[i].Name)
			}
		}
	}

	// Delete user-labelled CSRs cluster-wide; closes the orphan window
	// where a signed renewal cert could outlive the User.
	var csrs certv1.CertificateSigningRequestList
	if err := r.List(ctx, &csrs, selector); err != nil {
		logger.Error(err, "failed to list user-labelled CSRs")
	} else {
		for i := range csrs.Items {
			if err := r.Delete(ctx, &csrs.Items[i]); client.IgnoreNotFound(err) != nil {
				logger.Error(err, "failed to delete labelled CSR", "name", csrs.Items[i].Name)
			}
		}
	}

	// Delete RoleBindings across namespaces.
	var rbs rbacv1.RoleBindingList
	if err := r.List(ctx, &rbs, selector); err != nil {
		logger.Error(err, "failed to list user RoleBindings")
	} else {
		for i := range rbs.Items {
			if err := r.Delete(ctx, &rbs.Items[i]); client.IgnoreNotFound(err) != nil {
				logger.Error(err, "failed to delete RoleBinding",
					"name", rbs.Items[i].Name, "namespace", rbs.Items[i].Namespace)
			}
		}
	}

	// Delete ClusterRoleBindings.
	var crbs rbacv1.ClusterRoleBindingList
	if err := r.List(ctx, &crbs, selector); err != nil {
		logger.Error(err, "failed to list user ClusterRoleBindings")
	} else {
		for i := range crbs.Items {
			if err := r.Delete(ctx, &crbs.Items[i]); client.IgnoreNotFound(err) != nil {
				logger.Error(err, "failed to delete ClusterRoleBinding", "name", crbs.Items[i].Name)
			}
		}
	}
}
