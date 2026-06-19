package rbac

import (
	"context"
	"strings"
	"testing"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func bindingsScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	for _, add := range []func(*runtime.Scheme) error{rbacv1.AddToScheme, authv1alpha1.AddToScheme} {
		if err := add(s); err != nil {
			t.Fatalf("scheme: %v", err)
		}
	}
	return s
}

func testUser(roles []authv1alpha1.RoleSpec, clusterRoles []authv1alpha1.ClusterRoleSpec) *authv1alpha1.User {
	return &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{Name: "alice", UID: "uid-alice"},
		Spec:       authv1alpha1.UserSpec{Roles: roles, ClusterRoles: clusterRoles},
	}
}

func TestReconcileRoleBindings_RejectsDuplicates(t *testing.T) {
	// Referenced roles must exist so the first entry's existence check passes.
	seed := []client.Object{
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "dev"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "dev"}},
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "dev"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "shared"}},
	}

	tests := []struct {
		name      string
		roles     []authv1alpha1.RoleSpec
		wantErr   bool
		wantCount int
	}{
		{
			name:    "exact duplicate role",
			roles:   []authv1alpha1.RoleSpec{{Namespace: "dev", ExistingRole: "a"}, {Namespace: "dev", ExistingRole: "a"}},
			wantErr: true,
		},
		{
			name:    "Role and ClusterRole same name+namespace (case B)",
			roles:   []authv1alpha1.RoleSpec{{Namespace: "dev", ExistingRole: "shared"}, {Namespace: "dev", ExistingClusterRole: "shared"}},
			wantErr: true,
		},
		{
			name:      "distinct roles",
			roles:     []authv1alpha1.RoleSpec{{Namespace: "dev", ExistingRole: "a"}, {Namespace: "dev", ExistingRole: "b"}},
			wantErr:   false,
			wantCount: 2,
		},
		{
			name:    "duplicate regardless of order",
			roles:   []authv1alpha1.RoleSpec{{Namespace: "dev", ExistingRole: "a"}, {Namespace: "dev", ExistingRole: "b"}, {Namespace: "dev", ExistingRole: "a"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli := fake.NewClientBuilder().WithScheme(bindingsScheme(t)).WithObjects(seed...).Build()
			err := ReconcileRoleBindings(context.Background(), cli, testUser(tt.roles, nil))

			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("expected a duplicate error, got: %v", err)
			}
			if !tt.wantErr {
				var rbs rbacv1.RoleBindingList
				if err := cli.List(context.Background(), &rbs, client.MatchingLabels{authv1alpha1.UserLabel: "alice"}); err != nil {
					t.Fatalf("list: %v", err)
				}
				if len(rbs.Items) != tt.wantCount {
					t.Errorf("RoleBindings = %d, want %d", len(rbs.Items), tt.wantCount)
				}
			}
		})
	}
}

func TestReconcileClusterRoleBindings_RejectsDuplicates(t *testing.T) {
	seed := []client.Object{
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "view"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "edit"}},
	}

	tests := []struct {
		name         string
		clusterRoles []authv1alpha1.ClusterRoleSpec
		wantErr      bool
		wantCount    int
	}{
		{
			name:         "duplicate clusterRole",
			clusterRoles: []authv1alpha1.ClusterRoleSpec{{ExistingClusterRole: "view"}, {ExistingClusterRole: "view"}},
			wantErr:      true,
		},
		{
			name:         "distinct clusterRoles",
			clusterRoles: []authv1alpha1.ClusterRoleSpec{{ExistingClusterRole: "view"}, {ExistingClusterRole: "edit"}},
			wantErr:      false,
			wantCount:    2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cli := fake.NewClientBuilder().WithScheme(bindingsScheme(t)).WithObjects(seed...).Build()
			err := ReconcileClusterRoleBindings(context.Background(), cli, testUser(nil, tt.clusterRoles))

			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("expected a duplicate error, got: %v", err)
			}
			if !tt.wantErr {
				var crbs rbacv1.ClusterRoleBindingList
				if err := cli.List(context.Background(), &crbs, client.MatchingLabels{authv1alpha1.UserLabel: "alice"}); err != nil {
					t.Fatalf("list: %v", err)
				}
				if len(crbs.Items) != tt.wantCount {
					t.Errorf("ClusterRoleBindings = %d, want %d", len(crbs.Items), tt.wantCount)
				}
			}
		})
	}
}
