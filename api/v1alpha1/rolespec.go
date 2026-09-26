package v1alpha1

// BindingKey returns the uniqueness identity of a role entry: namespace +
// RoleRef kind + the effective role name (whichever of ExistingRole /
// ExistingClusterRole is set). Used by the admission webhook and the
// controller so both agree on what "duplicate" means.
//
// The kind is part of the identity: a namespaced Role and a ClusterRole of the
// same name in the same namespace are two distinct grants, and each now gets
// its own generated RoleBinding name, so they are representable side by side.
func (r RoleSpec) BindingKey() string {
	if r.ExistingRole != "" {
		return r.Namespace + ":Role:" + r.ExistingRole
	}
	return r.Namespace + ":ClusterRole:" + r.ExistingClusterRole
}
