package v1alpha1

// BindingKey returns the uniqueness identity of a role entry:
// namespace + the effective role name (whichever of ExistingRole /
// ExistingClusterRole is set). Used by the admission webhook and the
// controller so both agree on what "duplicate" means.
func (r RoleSpec) BindingKey() string {
	name := r.ExistingRole
	if name == "" {
		name = r.ExistingClusterRole
	}
	return r.Namespace + ":" + name
}
