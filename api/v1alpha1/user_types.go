package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//
// Spec types
//

// RoleSpec defines namespace-scoped access by binding to an existing Role
type RoleSpec struct {
	// Namespace where the RoleBinding will be created
	// +kubebuilder:validation:MinLength=1
	Namespace string `json:"namespace"`

	// ExistingRole is the name of the Role inside that namespace
	// +kubebuilder:validation:MinLength=1
	ExistingRole string `json:"existingRole"`
}

// ClusterRoleSpec defines cluster-wide access by binding to an existing ClusterRole
type ClusterRoleSpec struct {
	// ExistingClusterRole is the name of the ClusterRole to bind
	// +kubebuilder:validation:MinLength=1
	ExistingClusterRole string `json:"existingClusterRole"`
}

// UserSpec defines the desired state of User
type UserSpec struct {
	// Roles is a list of namespace-scoped Role bindings
	// +optional
	Roles []RoleSpec `json:"roles,omitempty"`

	// ClusterRoles is a list of cluster-wide ClusterRole bindings
	// +optional
	ClusterRoles []ClusterRoleSpec `json:"clusterRoles,omitempty"`

	// Expiry specifies how long the access should last (e.g., "7d")
	// Format will be parsed by the controller (e.g., 24h, 7d, 30m)
	// +optional
	Expiry string `json:"expiry,omitempty"`
}

//
// Status types
//

// UserStatus defines the observed state of User
type UserStatus struct {
	// ExpiryTime is the actual calculated expiry timestamp (RFC3339 format)
	// +optional
	ExpiryTime string `json:"expiryTime,omitempty"`

	// Phase is a simple high-level status (Pending, Active, Expired, Error)
	// +optional
	Phase string `json:"phase,omitempty"`

	// Message provides details about the current status
	// +optional
	Message string `json:"message,omitempty"`

	// Conditions follow Kubernetes conventions for detailed status
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

//
// CRD definitions
//

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster

// User is the Schema for the users API
type User struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   UserSpec   `json:"spec"`
	Status UserStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// UserList contains a list of User
type UserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []User `json:"items"`
}

func init() {
	SchemeBuilder.Register(&User{}, &UserList{})
}
