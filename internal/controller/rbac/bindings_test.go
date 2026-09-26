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
	"k8s.io/apimachinery/pkg/util/validation"
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
			// Issue #93 relaxes PR #91's hard rejection: the two entries are
			// distinct grants and now get distinct generated names, so both are
			// representable and both must be created.
			name:      "Role and ClusterRole same name+namespace (case B) coexist",
			roles:     []authv1alpha1.RoleSpec{{Namespace: "dev", ExistingRole: "shared"}, {Namespace: "dev", ExistingClusterRole: "shared"}},
			wantErr:   false,
			wantCount: 2,
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

// TestReconcileRoleBindings_RoleRefKindFlip pins the invariant behind issue
// #92: when a User flips a role entry between existingRole and
// existingClusterRole (same name, same namespace), reconcile must converge on a
// binding carrying the new RoleRef. RoleRef is immutable in the RBAC API, so
// the original bug — matching by namespace:name and falling through to Update —
// produced a stuck reconcile with the User parked in phase=Error.
//
// Since issue #93 the generated name encodes the RoleRef kind, so a flip
// resolves as "create under the new name, reap the old one" rather than
// delete-and-recreate under one name. The end state asserted here is the same.
func TestReconcileRoleBindings_RoleRefKindFlip(t *testing.T) {
	tests := []struct {
		name        string
		seedRoleRef rbacv1.RoleRef
		roles       []authv1alpha1.RoleSpec
		wantKind    string
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
			seedName := roleBindingName("alice", "dev", tt.seedRoleRef.Kind, "shared")
			existing := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      seedName,
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

			if err := ReconcileRoleBindings(context.Background(), cli, record.NewFakeRecorder(4), testUser(tt.roles, nil)); err != nil {
				t.Fatalf("ReconcileRoleBindings() error = %v (issue #92: a RoleRef flip must not stall reconcile)", err)
			}

			var rbs rbacv1.RoleBindingList
			if err := cli.List(context.Background(), &rbs, client.MatchingLabels{authv1alpha1.UserLabel: "alice"}); err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(rbs.Items) != 1 {
				t.Fatalf("RoleBindings = %d, want exactly 1 (issue #92: the pre-flip binding must be reaped)", len(rbs.Items))
			}
			if got := rbs.Items[0].RoleRef.Kind; got != tt.wantKind {
				t.Fatalf("RoleRef.Kind = %q, want %q (issue #92: the flipped Kind must land)", got, tt.wantKind)
			}
			if rbs.Items[0].Name == seedName {
				t.Fatalf("binding kept the pre-flip name %q; the name must track the RoleRef kind (issue #93)", seedName)
			}
		})
	}
}

// TestReconcileRoleBindings_RecreatesOnForeignRoleRef covers the backstop that
// survives issue #93's naming change: if a binding at the generated name somehow
// carries a different RoleRef (hand-edited object, restored etcd snapshot),
// reconcile must delete and recreate it rather than attempt an Update the
// apiserver rejects — and must say why via an event.
func TestReconcileRoleBindings_RecreatesOnForeignRoleRef(t *testing.T) {
	name := roleBindingName("alice", "dev", "Role", "shared")
	existing := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "dev",
			Labels:    map[string]string{authv1alpha1.UserLabel: "alice"},
		},
		Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "tampered",
		},
	}
	cli := fake.NewClientBuilder().
		WithScheme(bindingsScheme(t)).
		WithObjects(
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "dev"}},
			existing,
		).
		Build()

	rec := record.NewFakeRecorder(4)
	roles := []authv1alpha1.RoleSpec{{Namespace: "dev", ExistingRole: "shared"}}
	if err := ReconcileRoleBindings(context.Background(), cli, rec, testUser(roles, nil)); err != nil {
		t.Fatalf("ReconcileRoleBindings() error = %v; a foreign RoleRef must be recreated, not updated", err)
	}

	var got rbacv1.RoleBinding
	if err := cli.Get(context.Background(), types.NamespacedName{Name: name, Namespace: "dev"}, &got); err != nil {
		t.Fatalf("expected the binding to be recreated at %q, got %v", name, err)
	}
	if got.RoleRef.Name != "shared" {
		t.Fatalf("RoleRef.Name = %q, want %q", got.RoleRef.Name, "shared")
	}

	select {
	case ev := <-rec.Events:
		if !strings.Contains(ev, "RoleBindingRecreated") {
			t.Fatalf("expected RoleBindingRecreated event, got %q", ev)
		}
	default:
		t.Fatal("expected a RoleBindingRecreated event to be emitted, none was")
	}
}

// TestReconcileRoleBindings_ColonBearingClusterRole covers binding an upstream
// ClusterRole such as system:basic-user through spec.roles. Contrary to issue
// #93's premise this never failed at Create() — RBAC binding names permit
// colons — but the generated name was not a valid DNS subdomain. This pins that
// such references keep working *and* now produce a well-formed object name.
func TestReconcileRoleBindings_ColonBearingClusterRole(t *testing.T) {
	cli := fake.NewClientBuilder().
		WithScheme(bindingsScheme(t)).
		WithObjects(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "system:basic-user"}}).
		Build()

	roles := []authv1alpha1.RoleSpec{{Namespace: "dev", ExistingClusterRole: "system:basic-user"}}
	if err := ReconcileRoleBindings(context.Background(), cli, nil, testUser(roles, nil)); err != nil {
		t.Fatalf("ReconcileRoleBindings() error = %v (issue #93: a colon-bearing ClusterRole must be bindable)", err)
	}

	var rbs rbacv1.RoleBindingList
	if err := cli.List(context.Background(), &rbs, client.MatchingLabels{authv1alpha1.UserLabel: "alice"}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rbs.Items) != 1 {
		t.Fatalf("RoleBindings = %d, want 1", len(rbs.Items))
	}
	if errs := validation.IsDNS1123Subdomain(rbs.Items[0].Name); len(errs) > 0 {
		t.Fatalf("created RoleBinding %q is not a valid object name: %v (issue #93)", rbs.Items[0].Name, errs)
	}
	if rbs.Items[0].RoleRef.Name != "system:basic-user" {
		t.Errorf("RoleRef.Name = %q, want the reference preserved verbatim", rbs.Items[0].RoleRef.Name)
	}
}

// TestReconcileClusterRoleBindings_ColonBearingClusterRole mirrors the
// RoleBinding case for spec.clusterRoles.
func TestReconcileClusterRoleBindings_ColonBearingClusterRole(t *testing.T) {
	cli := fake.NewClientBuilder().
		WithScheme(bindingsScheme(t)).
		WithObjects(&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "system:node-bootstrapper"}}).
		Build()

	clusterRoles := []authv1alpha1.ClusterRoleSpec{{ExistingClusterRole: "system:node-bootstrapper"}}
	if err := ReconcileClusterRoleBindings(context.Background(), cli, testUser(nil, clusterRoles)); err != nil {
		t.Fatalf("ReconcileClusterRoleBindings() error = %v (issue #93: a colon-bearing ClusterRole must be bindable)", err)
	}

	var crbs rbacv1.ClusterRoleBindingList
	if err := cli.List(context.Background(), &crbs, client.MatchingLabels{authv1alpha1.UserLabel: "alice"}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(crbs.Items) != 1 {
		t.Fatalf("ClusterRoleBindings = %d, want 1", len(crbs.Items))
	}
	if errs := validation.IsDNS1123Subdomain(crbs.Items[0].Name); len(errs) > 0 {
		t.Fatalf("created ClusterRoleBinding %q is not a valid object name: %v (issue #93)", crbs.Items[0].Name, errs)
	}
}

// TestReconcileRoleBindings_CaseBCoexist is the acceptance criterion from issue
// #93 that PR #91 could not meet: a namespaced Role and a ClusterRole of the
// same name, in the same namespace, must land as two separate RoleBindings with
// distinct names and the correct RoleRef kinds.
func TestReconcileRoleBindings_CaseBCoexist(t *testing.T) {
	cli := fake.NewClientBuilder().
		WithScheme(bindingsScheme(t)).
		WithObjects(
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "dev"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "shared"}},
		).
		Build()

	roles := []authv1alpha1.RoleSpec{
		{Namespace: "dev", ExistingRole: "shared"},
		{Namespace: "dev", ExistingClusterRole: "shared"},
	}
	if err := ReconcileRoleBindings(context.Background(), cli, nil, testUser(roles, nil)); err != nil {
		t.Fatalf("ReconcileRoleBindings() error = %v (issue #93: case B must be representable)", err)
	}

	var rbs rbacv1.RoleBindingList
	if err := cli.List(context.Background(), &rbs, client.MatchingLabels{authv1alpha1.UserLabel: "alice"}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rbs.Items) != 2 {
		t.Fatalf("RoleBindings = %d, want 2 — both grants must exist (issue #93)", len(rbs.Items))
	}

	byKind := map[string]string{}
	for _, rb := range rbs.Items {
		byKind[rb.RoleRef.Kind] = rb.Name
	}
	if len(byKind) != 2 {
		t.Fatalf("bindings cover RoleRef kinds %v, want both Role and ClusterRole", byKind)
	}
	if byKind["Role"] == byKind["ClusterRole"] {
		t.Fatalf("both grants landed on one object name %q (issue #93)", byKind["Role"])
	}
}

// TestReconcileRoleBindings_MigratesLegacyName documents and pins the upgrade
// path for issue #93. A binding written under the old "<user>-<role>-rb" scheme
// is not silently kept: reconcile creates the new-scheme binding first and reaps
// the legacy object in the same pass, so the grant is never absent in between.
func TestReconcileRoleBindings_MigratesLegacyName(t *testing.T) {
	legacy := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alice-view-rb",
			Namespace: "dev",
			Labels:    map[string]string{authv1alpha1.UserLabel: "alice"},
		},
		Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     "view",
		},
	}
	legacyCRB := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "alice-edit-crb",
			Labels: map[string]string{authv1alpha1.UserLabel: "alice"},
		},
		Subjects: []rbacv1.Subject{{Kind: "User", Name: "alice"}},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     "edit",
		},
	}
	cli := fake.NewClientBuilder().
		WithScheme(bindingsScheme(t)).
		WithObjects(
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "view", Namespace: "dev"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "edit"}},
			legacy, legacyCRB,
		).
		Build()

	user := testUser(
		[]authv1alpha1.RoleSpec{{Namespace: "dev", ExistingRole: "view"}},
		[]authv1alpha1.ClusterRoleSpec{{ExistingClusterRole: "edit"}},
	)
	if err := ReconcileRoleBindings(context.Background(), cli, nil, user); err != nil {
		t.Fatalf("ReconcileRoleBindings() error = %v", err)
	}
	if err := ReconcileClusterRoleBindings(context.Background(), cli, user); err != nil {
		t.Fatalf("ReconcileClusterRoleBindings() error = %v", err)
	}

	var rbs rbacv1.RoleBindingList
	if err := cli.List(context.Background(), &rbs, client.MatchingLabels{authv1alpha1.UserLabel: "alice"}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rbs.Items) != 1 {
		t.Fatalf("RoleBindings = %d, want exactly 1 — the legacy object must be reaped, not left alongside", len(rbs.Items))
	}
	if want := roleBindingName("alice", "dev", "Role", "view"); rbs.Items[0].Name != want {
		t.Errorf("RoleBinding name = %q, want %q (legacy name must be migrated)", rbs.Items[0].Name, want)
	}

	var crbs rbacv1.ClusterRoleBindingList
	if err := cli.List(context.Background(), &crbs, client.MatchingLabels{authv1alpha1.UserLabel: "alice"}); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(crbs.Items) != 1 {
		t.Fatalf("ClusterRoleBindings = %d, want exactly 1", len(crbs.Items))
	}
	if want := clusterRoleBindingName("alice", "edit"); crbs.Items[0].Name != want {
		t.Errorf("ClusterRoleBinding name = %q, want %q (legacy name must be migrated)", crbs.Items[0].Name, want)
	}
}

// TestReconcileBindingsAreIdempotent guards against the churn failure mode the
// naming change could introduce: a second reconcile pass over an unchanged spec
// must be a no-op, not a delete-and-recreate cycle.
func TestReconcileBindingsAreIdempotent(t *testing.T) {
	cli := fake.NewClientBuilder().
		WithScheme(bindingsScheme(t)).
		WithObjects(
			&rbacv1.Role{ObjectMeta: metav1.ObjectMeta{Name: "view", Namespace: "dev"}},
			&rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "system:basic-user"}},
		).
		Build()

	user := testUser(
		[]authv1alpha1.RoleSpec{{Namespace: "dev", ExistingRole: "view"}},
		[]authv1alpha1.ClusterRoleSpec{{ExistingClusterRole: "system:basic-user"}},
	)

	var firstRB, firstCRB string
	for pass := 1; pass <= 2; pass++ {
		if err := ReconcileRoleBindings(context.Background(), cli, nil, user); err != nil {
			t.Fatalf("pass %d: ReconcileRoleBindings() error = %v", pass, err)
		}
		if err := ReconcileClusterRoleBindings(context.Background(), cli, user); err != nil {
			t.Fatalf("pass %d: ReconcileClusterRoleBindings() error = %v", pass, err)
		}

		var rbs rbacv1.RoleBindingList
		if err := cli.List(context.Background(), &rbs, client.MatchingLabels{authv1alpha1.UserLabel: "alice"}); err != nil {
			t.Fatalf("list: %v", err)
		}
		var crbs rbacv1.ClusterRoleBindingList
		if err := cli.List(context.Background(), &crbs, client.MatchingLabels{authv1alpha1.UserLabel: "alice"}); err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(rbs.Items) != 1 || len(crbs.Items) != 1 {
			t.Fatalf("pass %d: got %d RoleBindings and %d ClusterRoleBindings, want 1 each",
				pass, len(rbs.Items), len(crbs.Items))
		}

		if pass == 1 {
			firstRB, firstCRB = rbs.Items[0].Name, crbs.Items[0].Name
			continue
		}
		if rbs.Items[0].Name != firstRB || crbs.Items[0].Name != firstCRB {
			t.Fatalf("names changed between passes: %q/%q then %q/%q — reconcile would churn bindings forever",
				firstRB, firstCRB, rbs.Items[0].Name, crbs.Items[0].Name)
		}
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
