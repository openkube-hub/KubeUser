package rbac

import (
	"context"
	"strings"
	"testing"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
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
			err := ReconcileRoleBindings(context.Background(), cli, nil, testUser(tt.roles, nil))

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

// TestReconcileRoleBindings_RoleRefKindFlipRecreates pins the fix for issue
// #92: when a User flips a role entry between existingRole and
// existingClusterRole (same name, same namespace), the pre-existing
// RoleBinding must be deleted and recreated. RoleRef is immutable in the RBAC
// API, so the pre-fix code path — which matched by namespace:name only and
// fell through to Update — produced a stuck reconcile with the User parked in
// phase=Error.
func TestReconcileRoleBindings_RoleRefKindFlipRecreates(t *testing.T) {
	tests := []struct {
		name        string
		seedRoleRef rbacv1.RoleRef
		roles       []authv1alpha1.RoleSpec
		wantKind    string
		wantName    string
	}{
		{
			name: "Role → ClusterRole flip",
			seedRoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "Role",
				Name:     "shared",
			},
			roles:    []authv1alpha1.RoleSpec{{Namespace: "dev", ExistingClusterRole: "shared"}},
			wantKind: "ClusterRole",
			wantName: "shared",
		},
		{
			name: "ClusterRole → Role flip",
			seedRoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     "shared",
			},
			roles:    []authv1alpha1.RoleSpec{{Namespace: "dev", ExistingRole: "shared"}},
			wantKind: "Role",
			wantName: "shared",
		},
	}

	// Referenced roles must exist so the reconciler's existence check passes
	// for the flipped Kind.
	seed := []client.Object{
		&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "dev"}},
		&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "shared"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			existing := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "alice-shared-rb",
					Namespace: "dev",
					Labels:    map[string]string{authv1alpha1.UserLabel: "alice"},
				},
				Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}},
				RoleRef:  tt.seedRoleRef,
			}
			cli := fake.NewClientBuilder().
				WithScheme(bindingsScheme(t)).
				WithObjects(append(seed, existing)...).
				Build()

			rec := record.NewFakeRecorder(4)
			if err := ReconcileRoleBindings(context.Background(), cli, rec, testUser(tt.roles, nil)); err != nil {
				t.Fatalf("ReconcileRoleBindings() error = %v (issue #92: RoleRef change must be recreated, not updated)", err)
			}

			var got rbacv1.RoleBinding
			if err := cli.Get(context.Background(), types.NamespacedName{Name: "alice-shared-rb", Namespace: "dev"}, &got); err != nil {
				t.Fatalf("expected RoleBinding to be recreated with the new RoleRef, got %v (issue #92)", err)
			}
			if got.RoleRef.Kind != tt.wantKind || got.RoleRef.Name != tt.wantName {
				t.Fatalf("RoleRef = %s/%s, want %s/%s (issue #92: delete-then-create must land the new Kind)",
					got.RoleRef.Kind, got.RoleRef.Name, tt.wantKind, tt.wantName)
			}

			// Confirm the event was emitted so operators see why the binding
			// was recreated (acceptance criterion in issue #92).
			select {
			case ev := <-rec.Events:
				if !strings.Contains(ev, "RoleBindingRecreated") {
					t.Fatalf("expected RoleBindingRecreated event, got %q", ev)
				}
			default:
				t.Fatal("expected a RoleBindingRecreated event to be emitted, none was")
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
