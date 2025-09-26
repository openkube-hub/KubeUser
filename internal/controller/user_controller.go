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
	defaultExpiry     = 365 * 24 * time.Hour
	inClusterCAPath   = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	userFinalizer = "auth.openkube.io/finalizer"
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

	var user authv1alpha1.User
	if err := r.Get(ctx, req.NamespacedName, &user); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	username := user.Name
	logger.Info("Reconciling User", "name", username)

	// Handle deletion
	if !user.ObjectMeta.DeletionTimestamp.IsZero() {
		if containsString(user.Finalizers, userFinalizer) {
			if err := r.cleanupUserResources(ctx, &user); err != nil {
				return ctrl.Result{}, err
			}
			user.Finalizers = removeString(user.Finalizers, userFinalizer)
			if err := r.Update(ctx, &user); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Ensure finalizer
	if !containsString(user.Finalizers, userFinalizer) {
		user.Finalizers = append(user.Finalizers, userFinalizer)
		if err := r.Update(ctx, &user); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Ensure kubeuser namespace
	if err := r.ensureNamespace(ctx, kubeUserNamespace); err != nil {
		return ctrl.Result{}, err
	}

	// Ensure ServiceAccount (identity anchor)
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      username,
			Namespace: kubeUserNamespace,
			Labels:    map[string]string{"auth.openkube.io/user": username},
		},
	}
	if err := r.createOrUpdate(ctx, sa); err != nil {
		return ctrl.Result{}, err
	}

	// === Reconcile RoleBindings ===
	if err := r.reconcileRoleBindings(ctx, &user); err != nil {
		logger.Error(err, "Failed to reconcile RoleBindings")
		user.Status.Phase = "Error"
		user.Status.Message = fmt.Sprintf("Failed to reconcile RoleBindings: %v", err)
		_ = r.Status().Update(ctx, &user)
		return ctrl.Result{}, err
	}

	// === Reconcile ClusterRoleBindings ===
	if err := r.reconcileClusterRoleBindings(ctx, &user); err != nil {
		logger.Error(err, "Failed to reconcile ClusterRoleBindings")
		user.Status.Phase = "Error"
		user.Status.Message = fmt.Sprintf("Failed to reconcile ClusterRoleBindings: %v", err)
		_ = r.Status().Update(ctx, &user)
		return ctrl.Result{}, err
	}

	// Ensure cert-based kubeconfig
	requeue, err := r.ensureCertKubeconfig(ctx, &user)
	if err != nil {
		return ctrl.Result{RequeueAfter: 5 * time.Second}, nil
	}
	if requeue {
		return ctrl.Result{RequeueAfter: 3 * time.Second}, nil
	}

	// Update status
	expiry := time.Now().Add(defaultExpiry)
	if user.Spec.Expiry != "" {
		if d, err := time.ParseDuration(user.Spec.Expiry); err == nil {
			expiry = time.Now().Add(d)
		}
	}
	user.Status.Phase = "Active"
	user.Status.ExpiryTime = expiry.Format(time.RFC3339)
	user.Status.Message = "User provisioned"
	if err := r.Status().Update(ctx, &user); err != nil {
		logger.Error(err, "status update failed")
	}

	return ctrl.Result{}, nil
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
func (r *UserReconciler) cleanupUserResources(ctx context.Context, user *authv1alpha1.User) error {
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

	return nil
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

	// 1. Load/create key Secret
	var keySecret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Name: keySecretName, Namespace: kubeUserNamespace}, &keySecret)
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

// --- utils ---
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
