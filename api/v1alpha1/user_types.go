package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

//
// Spec types
//

// RoleSpec defines namespace-scoped access by binding to an existing Role or ClusterRole
type RoleSpec struct {
	// Namespace where the RoleBinding will be created
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Namespace string `json:"namespace"`

	// ExistingRole is the name of the Role inside that namespace
	// Mutually exclusive with ExistingClusterRole
	// +optional
	// +kubebuilder:validation:MaxLength=253
	ExistingRole string `json:"existingRole,omitempty"`

	// ExistingClusterRole is the name of a ClusterRole to bind with a RoleBinding in the namespace
	// Mutually exclusive with ExistingRole
	// +optional
	// +kubebuilder:validation:MaxLength=253
	ExistingClusterRole string `json:"existingClusterRole,omitempty"`
}

// ClusterRoleSpec defines cluster-wide access by binding to an existing ClusterRole
type ClusterRoleSpec struct {
	// ExistingClusterRole is the name of the ClusterRole to bind
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	ExistingClusterRole string `json:"existingClusterRole"`
}

// AuthSpec defines authentication configuration for the user
type AuthSpec struct {
	// Type specifies the authentication method (MANDATORY)
	// +kubebuilder:validation:Enum=x509;oidc
	// +kubebuilder:validation:Required
	Type *string `json:"type"`

	// TTL specifies credential time-to-live (lifetime)
	// For x509: certificate validity period (default: 2160h = 90 days)
	// For oidc: ignored (placeholder for future implementation)
	// +optional
	// +kubebuilder:validation:Pattern=^([0-9]+(\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$
	TTL string `json:"ttl,omitempty"`

	// AutoRenew enables automatic certificate renewal (default: true)
	// +optional
	AutoRenew *bool `json:"autoRenew,omitempty"`

	// RenewBefore specifies when to renew before expiry
	// Overrides the default 33% rule. Must be less than TTL.
	// Examples: "5m", "30d", "720h"
	// +optional
	RenewBefore *metav1.Duration `json:"renewBefore,omitempty"`
}

// UserSpec defines the desired state of User
type UserSpec struct {
	// Auth defines authentication configuration (MANDATORY)
	// +kubebuilder:validation:Required
	Auth *AuthSpec `json:"auth"`

	// Roles is a list of namespace-scoped Role bindings. Uniqueness per
	// (namespace, role) is enforced by the webhook and controller via
	// RoleSpec.BindingKey — a composite key can't be a CRD listMapKey, so it
	// lives in code. MaxItems is a deliberate object-size/DoS bound.
	// +optional
	// +kubebuilder:validation:MaxItems=100
	Roles []RoleSpec `json:"roles,omitempty"`

	// ClusterRoles is a list of cluster-wide ClusterRole bindings. listType=map
	// makes the apiserver enforce uniqueness of existingClusterRole natively
	// (rejected at admission, cannot be bypassed) and enables per-entry
	// server-side apply. MaxItems is a deliberate object-size/DoS bound.
	// +optional
	// +listType=map
	// +listMapKey=existingClusterRole
	// +kubebuilder:validation:MaxItems=100
	ClusterRoles []ClusterRoleSpec `json:"clusterRoles,omitempty"`
}

//
// Status types
//

// UserStatus defines the observed state of User
type UserStatus struct {
	// ExpiryTime is the actual expiry timestamp (RFC3339 format)
	// This comes from the actual certificate NotAfter time when available
	// +optional
	ExpiryTime string `json:"expiryTime,omitempty"`

	// NextRenewalAt is when the certificate will be automatically renewed
	// This consolidates the previous RenewalTime and NextRenewalTime fields
	// +optional
	NextRenewalAt *metav1.Time `json:"nextRenewalAt,omitempty"`

	// Phase is a simple high-level status (Pending, Active, Expired, Error, Renewing)
	// +optional
	Phase string `json:"phase,omitempty"`

	// RotationStep provides granular visibility into certificate rotation progress
	// Values: GeneratingKey, CreatingCSR, WaitingForApproval, PerformingAtomicFlip, Finalizing
	// +optional
	RotationStep string `json:"rotationStep,omitempty"`

	// Message provides details about the current status
	// +optional
	Message string `json:"message,omitempty"`

	// Conditions follow Kubernetes conventions for detailed status
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// RenewalHistory tracks recent renewal attempts for observability
	// +optional
	RenewalHistory []RenewalAttempt `json:"renewalHistory,omitempty"`
}

// RenewalAttempt tracks a single renewal attempt
type RenewalAttempt struct {
	// Timestamp when the renewal was attempted
	Timestamp metav1.Time `json:"timestamp"`

	// Success indicates if the renewal was successful
	Success bool `json:"success"`

	// Message provides details about the renewal attempt
	// +optional
	Message string `json:"message,omitempty"`

	// CSRName is the name of the CSR created for this renewal
	// +optional
	CSRName string `json:"csrName,omitempty"`
}

//
// CRD definitions
//

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase",description="Current phase of the user"
// +kubebuilder:printcolumn:name="AutoRenew",type="boolean",JSONPath=".spec.auth.autoRenew",description="Auto-renewal enabled"
// +kubebuilder:printcolumn:name="Expiry",type="string",JSONPath=".status.expiryTime",description="Certificate expiry time"
// +kubebuilder:printcolumn:name="NextRenewal",type="string",JSONPath=".status.nextRenewalAt",description="Next renewal time"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp",description="Time since the user was created"
// +kubebuilder:printcolumn:name="Message",type="string",JSONPath=".status.message",description="Status message",priority=1

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
