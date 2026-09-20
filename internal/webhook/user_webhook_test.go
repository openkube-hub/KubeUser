package webhook

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func webhookScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{rbacv1.AddToScheme, authv1alpha1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatalf("scheme: %v", err)
		}
	}
	return s
}

func newWebhook(t *testing.T, seed ...client.Object) *UserWebhook {
	t.Helper()
	return &UserWebhook{
		Client: fake.NewClientBuilder().
			WithScheme(webhookScheme(t)).
			WithObjects(seed...).
			Build(),
	}
}

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }
func dur(d time.Duration) *metav1.Duration {
	return &metav1.Duration{Duration: d}
}

// TestValidateRoles covers the webhook's spec.roles contract: mutual-exclusion,
// existence of referenced Role/ClusterRole objects, and duplicate rejection via
// the shared RoleSpec.BindingKey identity. The webhook is the primary
// enforcement layer for this contract (the controller is only a backstop that
// catches Users which bypassed admission), so a regression here would silently
// admit conflicting spec.roles entries.
func TestValidateRoles(t *testing.T) {
	seed := []client.Object{
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "dev"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "dev"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "prod"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "dev"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "shared"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "view"}},
	}

	tests := []struct {
		name         string
		roles        []authv1alpha1.RoleSpec
		wantErr      bool
		wantErrMatch string
	}{
		{
			name: "distinct roles across namespaces",
			roles: []authv1alpha1.RoleSpec{
				{Namespace: "dev", ExistingRole: "a"},
				{Namespace: "dev", ExistingRole: "b"},
				{Namespace: "prod", ExistingRole: "a"},
			},
			wantErr: false,
		},
		{
			name: "distinct Role and ClusterRole references",
			roles: []authv1alpha1.RoleSpec{
				{Namespace: "dev", ExistingRole: "a"},
				{Namespace: "dev", ExistingClusterRole: "view"},
			},
			wantErr: false,
		},
		{
			name: "exact duplicate existingRole rejected",
			roles: []authv1alpha1.RoleSpec{
				{Namespace: "dev", ExistingRole: "a"},
				{Namespace: "dev", ExistingRole: "a"},
			},
			wantErr:      true,
			wantErrMatch: "duplicate role binding",
		},
		{
			name: "exact duplicate existingClusterRole rejected",
			roles: []authv1alpha1.RoleSpec{
				{Namespace: "dev", ExistingClusterRole: "view"},
				{Namespace: "dev", ExistingClusterRole: "view"},
			},
			wantErr:      true,
			wantErrMatch: "duplicate role binding",
		},
		{
			name: "Role and ClusterRole with same namespace:name rejected (case B)",
			roles: []authv1alpha1.RoleSpec{
				{Namespace: "dev", ExistingRole: "shared"},
				{Namespace: "dev", ExistingClusterRole: "shared"},
			},
			wantErr:      true,
			wantErrMatch: "duplicate role binding",
		},
		{
			name: "duplicate detected regardless of order",
			roles: []authv1alpha1.RoleSpec{
				{Namespace: "dev", ExistingRole: "a"},
				{Namespace: "dev", ExistingRole: "b"},
				{Namespace: "dev", ExistingRole: "a"},
			},
			wantErr:      true,
			wantErrMatch: "duplicate role binding",
		},
		{
			name: "both existingRole and existingClusterRole set is rejected",
			roles: []authv1alpha1.RoleSpec{
				{Namespace: "dev", ExistingRole: "a", ExistingClusterRole: "view"},
			},
			wantErr:      true,
			wantErrMatch: "cannot specify both",
		},
		{
			name: "neither existingRole nor existingClusterRole set is rejected",
			roles: []authv1alpha1.RoleSpec{
				{Namespace: "dev"},
			},
			wantErr:      true,
			wantErrMatch: "either existingRole or existingClusterRole",
		},
		{
			name: "referenced Role does not exist",
			roles: []authv1alpha1.RoleSpec{
				{Namespace: "dev", ExistingRole: "missing"},
			},
			wantErr:      true,
			wantErrMatch: "role 'missing' not found in namespace 'dev'",
		},
		{
			name: "referenced ClusterRole (via RoleSpec) does not exist",
			roles: []authv1alpha1.RoleSpec{
				{Namespace: "dev", ExistingClusterRole: "missing"},
			},
			wantErr:      true,
			wantErrMatch: "clusterrole 'missing' not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWebhook(t, seed...)
			err := w.validateRoles(context.Background(), tt.roles)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateRoles() err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.wantErrMatch) {
				t.Fatalf("validateRoles() err = %q, want substring %q", err, tt.wantErrMatch)
			}
		})
	}
}

// TestValidateRoles_BindingKeyContract pins the webhook ↔ controller agreement
// on duplicate identity. Both layers reject duplicates using the same
// RoleSpec.BindingKey (namespace + effective role name), so if this contract
// ever drifts — e.g. someone reintroduces separate dedup keys per Kind — a
// case-B pair that the webhook admits would still be rejected by the
// controller, parking the User in phase=Error. This test breaks CI before
// that regression can ship.
func TestValidateRoles_BindingKeyContract(t *testing.T) {
	roleA := authv1alpha1.RoleSpec{Namespace: "dev", ExistingRole: "shared"}
	roleB := authv1alpha1.RoleSpec{Namespace: "dev", ExistingClusterRole: "shared"}

	if roleA.BindingKey() != roleB.BindingKey() {
		t.Fatalf("BindingKey contract broken: %q vs %q — webhook and controller must dedup on the same identity",
			roleA.BindingKey(), roleB.BindingKey())
	}

	w := newWebhook(t,
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "dev"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "shared"}},
	)
	err := w.validateRoles(context.Background(), []authv1alpha1.RoleSpec{roleA, roleB})
	if err == nil {
		t.Fatalf("expected duplicate rejection for shared BindingKey %q, got nil", roleA.BindingKey())
	}
	if !strings.Contains(err.Error(), "duplicate role binding") {
		t.Fatalf("expected duplicate-binding error, got %v", err)
	}
}

// TestValidateClusterRoles asserts existence checks fire and no duplicate
// detection is performed at the webhook layer: spec.clusterRoles is a
// listType=map keyed on existingClusterRole, so the apiserver rejects
// duplicates natively at admission. Duplicating the check here would either
// diverge from the apiserver's identity semantics or accept objects that
// somehow slipped past the apiserver's map validation.
func TestValidateClusterRoles(t *testing.T) {
	seed := []client.Object{
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "view"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "edit"}},
	}

	tests := []struct {
		name         string
		clusterRoles []authv1alpha1.ClusterRoleSpec
		wantErr      bool
		wantErrMatch string
	}{
		{
			name:         "distinct clusterRoles pass",
			clusterRoles: []authv1alpha1.ClusterRoleSpec{{ExistingClusterRole: "view"}, {ExistingClusterRole: "edit"}},
			wantErr:      false,
		},
		{
			name:         "empty list is a no-op",
			clusterRoles: nil,
			wantErr:      false,
		},
		{
			name:         "missing ClusterRole rejected",
			clusterRoles: []authv1alpha1.ClusterRoleSpec{{ExistingClusterRole: "missing"}},
			wantErr:      true,
			wantErrMatch: "clusterrole 'missing' not found",
		},
		{
			name:         "duplicates are NOT flagged by the webhook (delegated to apiserver listType=map)",
			clusterRoles: []authv1alpha1.ClusterRoleSpec{{ExistingClusterRole: "view"}, {ExistingClusterRole: "view"}},
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWebhook(t, seed...)
			err := w.validateClusterRoles(context.Background(), tt.clusterRoles)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateClusterRoles() err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.wantErrMatch) {
				t.Fatalf("validateClusterRoles() err = %q, want substring %q", err, tt.wantErrMatch)
			}
		})
	}
}

// TestValidateAuthSpec locks the webhook's auth-spec contract: spec.auth.type
// is mandatory, OIDC is rejected until implemented, renewBefore must stay
// under 90% of TTL, and the 15-minute cert-life safety floor is enforced.
// Together these guards prevent Users that would trigger Thundering-Herd
// renewal loops or land in a permanently-erroring reconcile.
func TestValidateAuthSpec(t *testing.T) {
	// Allow small TTLs so the safety-floor case can be exercised without
	// hitting the 24h production minimum in auth.ValidateAuthSpec first.
	original, hadOriginal := os.LookupEnv("KUBEUSER_MIN_DURATION")
	if err := os.Setenv("KUBEUSER_MIN_DURATION", "5m"); err != nil {
		t.Fatalf("set KUBEUSER_MIN_DURATION: %v", err)
	}
	t.Cleanup(func() {
		if hadOriginal {
			_ = os.Setenv("KUBEUSER_MIN_DURATION", original)
		} else {
			_ = os.Unsetenv("KUBEUSER_MIN_DURATION")
		}
	})

	tests := []struct {
		name         string
		user         *authv1alpha1.User
		wantErr      bool
		wantErrMatch string
	}{
		{
			name: "spec.auth nil rejected",
			user: &authv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec:       authv1alpha1.UserSpec{Auth: nil},
			},
			wantErr:      true,
			wantErrMatch: "auth section is mandatory",
		},
		{
			name: "spec.auth.type nil rejected",
			user: &authv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec: authv1alpha1.UserSpec{Auth: &authv1alpha1.AuthSpec{
					Type: nil,
					TTL:  "24h",
				}},
			},
			wantErr:      true,
			wantErrMatch: "spec.auth.type is mandatory",
		},
		{
			name: "spec.auth.type empty string rejected",
			user: &authv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec: authv1alpha1.UserSpec{Auth: &authv1alpha1.AuthSpec{
					Type: strPtr(""),
					TTL:  "24h",
				}},
			},
			wantErr:      true,
			wantErrMatch: "spec.auth.type is mandatory",
		},
		{
			name: "OIDC rejected until implemented",
			user: &authv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec: authv1alpha1.UserSpec{Auth: &authv1alpha1.AuthSpec{
					Type: strPtr("oidc"),
				}},
			},
			wantErr:      true,
			wantErrMatch: "OIDC authentication is not yet implemented",
		},
		{
			name: "valid x509 with default renewal accepted",
			user: &authv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec: authv1alpha1.UserSpec{Auth: &authv1alpha1.AuthSpec{
					Type: strPtr("x509"),
					TTL:  "720h",
				}},
			},
			wantErr: false,
		},
		{
			name: "renewBefore > 90% of TTL rejected",
			user: &authv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec: authv1alpha1.UserSpec{Auth: &authv1alpha1.AuthSpec{
					Type:        strPtr("x509"),
					TTL:         "24h",
					AutoRenew:   boolPtr(true),
					RenewBefore: dur(23 * time.Hour),
				}},
			},
			wantErr:      true,
			wantErrMatch: "exceeds 90% of TTL",
		},
		{
			name: "renewBefore = 90% of TTL accepted (boundary)",
			user: &authv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec: authv1alpha1.UserSpec{Auth: &authv1alpha1.AuthSpec{
					Type:        strPtr("x509"),
					TTL:         "100h",
					AutoRenew:   boolPtr(true),
					RenewBefore: dur(90 * time.Hour),
				}},
			},
			wantErr: false,
		},
		{
			// TTL=60m, renewBefore=54m (exactly 90% of TTL, so the 90% cap
			// passes) leaves only 6m of certificate life — trips the 15m
			// safety floor. This case is only reachable when
			// KUBEUSER_MIN_DURATION lowers the min-TTL floor below 150m,
			// because otherwise the 90% cap always fires first.
			name: "renewBefore leaves <15m of cert life triggers safety floor",
			user: &authv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec: authv1alpha1.UserSpec{Auth: &authv1alpha1.AuthSpec{
					Type:        strPtr("x509"),
					TTL:         "60m",
					AutoRenew:   boolPtr(true),
					RenewBefore: dur(54 * time.Minute),
				}},
			},
			wantErr:      true,
			wantErrMatch: "less than 15 minutes of certificate life",
		},
		{
			name: "negative renewBefore rejected",
			user: &authv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec: authv1alpha1.UserSpec{Auth: &authv1alpha1.AuthSpec{
					Type:        strPtr("x509"),
					TTL:         "24h",
					AutoRenew:   boolPtr(true),
					RenewBefore: dur(-1 * time.Second),
				}},
			},
			wantErr:      true,
			wantErrMatch: "renewBefore must be positive",
		},
		{
			name: "renewBefore ignored when autoRenew=false",
			user: &authv1alpha1.User{
				ObjectMeta: metav1.ObjectMeta{Name: "alice"},
				Spec: authv1alpha1.UserSpec{Auth: &authv1alpha1.AuthSpec{
					Type:        strPtr("x509"),
					TTL:         "24h",
					AutoRenew:   boolPtr(false),
					RenewBefore: dur(23 * time.Hour), // would fail 90% if auto-renew were on
				}},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newWebhook(t)
			err := w.validateAuthSpec(tt.user)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAuthSpec() err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.wantErrMatch) {
				t.Fatalf("validateAuthSpec() err = %q, want substring %q", err, tt.wantErrMatch)
			}
		})
	}
}
