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
)

const (
	UserFinalizer = "auth.openkube.io/finalizer"
)

// CleanupUserResources deletes all resources related to the user.
func CleanupUserResources(ctx context.Context, r client.Client, user *authv1alpha1.User) {
	// Finalizer cleanup must complete promptly to unblock the deletion path.
	// The caller's context may already be bounded; this adds a firm local ceiling.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	username := user.Name
	userNamespace := helpers.GetKubeUserNamespace()

	// Delete fixed resources
	fixed := []client.Object{
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-key", username), Namespace: userNamespace}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("%s-kubeconfig", username), Namespace: userNamespace}},
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
