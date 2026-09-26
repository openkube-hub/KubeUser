package rbac

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

// TestBindingNamesAreValidObjectNames pins the hardening half of issue #93.
//
// Note the apiserver is *more* permissive here than the issue assumed: binding
// names go through ValidateRBACName (path-segment rules), not DNS-1123, so
// "alice-system:basic-user-rb" is in fact accepted — verified against a real
// v1.35 apiserver, which also took underscores, uppercase and a 300-char name.
// The pre-fix format was therefore not producing Create() failures.
//
// It was still producing names that are not valid DNS subdomains and that grow
// without bound. Encoding the RoleRef kind (the actual bug, see
// TestRoleBindingNameDistinguishesIdentity) needs a disambiguating digest
// anyway, so the reference is sanitized and the name capped in the same step.
// This test holds that stricter line: a generated name is always a valid DNS
// subdomain, which keeps it usable anywhere an object name is expected —
// including as a label value, where a colon is not legal.
func TestBindingNamesAreValidObjectNames(t *testing.T) {
	tests := []struct {
		name     string
		username string
		refName  string
	}{
		{name: "plain reference", username: "alice", refName: "view"},
		{name: "colon in upstream ClusterRole", username: "alice", refName: "system:basic-user"},
		{name: "multiple colons", username: "alice", refName: "system:controller:node-controller"},
		{name: "underscore permitted by RBAC names", username: "alice", refName: "my_role"},
		{name: "dot permitted by RBAC names", username: "alice", refName: "team.reader"},
		{name: "uppercase reference", username: "alice", refName: "Admin"},
		{name: "adjacent illegal characters", username: "alice", refName: "a::b"},
		{name: "max-length username", username: strings.Repeat("u", 253), refName: "view"},
		{name: "max-length reference", username: "alice", refName: strings.Repeat("r", 253)},
		{name: "max-length username and reference", username: strings.Repeat("u", 253), refName: strings.Repeat("r", 253)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for label, got := range map[string]string{
				"roleBindingName":        roleBindingName(tt.username, "dev", "ClusterRole", tt.refName),
				"clusterRoleBindingName": clusterRoleBindingName(tt.username, tt.refName),
			} {
				if errs := validation.IsDNS1123Subdomain(got); len(errs) > 0 {
					t.Errorf("%s(%q, %q) = %q, not a valid object name: %v (issue #93)",
						label, tt.username, tt.refName, got, errs)
				}
				if len(got) > maxObjectNameLen {
					t.Errorf("%s(%q, %q) is %d chars, exceeds the %d-char budget",
						label, tt.username, tt.refName, len(got), maxObjectNameLen)
				}
			}
		})
	}
}

// TestRoleBindingNameDistinguishesIdentity guards the second half of issue #93:
// the generated name must encode the full grant identity. Before the fix the
// name was "<user>-<role>-rb", so a namespaced Role and a ClusterRole of the
// same name in the same namespace collided on one object name and could not
// both be represented — which is why PR #91 had to reject the pair outright.
func TestRoleBindingNameDistinguishesIdentity(t *testing.T) {
	base := roleBindingName("alice", "dev", "Role", "shared")

	tests := []struct {
		name string
		got  string
	}{
		{name: "RoleRef kind differs", got: roleBindingName("alice", "dev", "ClusterRole", "shared")},
		{name: "namespace differs", got: roleBindingName("alice", "prod", "Role", "shared")},
		{name: "reference name differs", got: roleBindingName("alice", "dev", "Role", "other")},
		{name: "username differs", got: roleBindingName("bob", "dev", "Role", "shared")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got == base {
				t.Errorf("name collides with %q when %s (issue #93: the name must encode the full identity)", base, tt.name)
			}
		})
	}

	// Sanitizing must not become the collision it is meant to avoid: these two
	// references both sanitize to "alice-a-b-..." and are kept apart only by
	// the digest.
	if a, b := roleBindingName("alice", "dev", "Role", "a:b"), roleBindingName("alice", "dev", "Role", "a.b"); a == b {
		t.Errorf("distinct references collided after sanitizing: %q (issue #93)", a)
	}
}

func TestBindingNamesAreDeterministic(t *testing.T) {
	if a, b := roleBindingName("alice", "dev", "Role", "view"), roleBindingName("alice", "dev", "Role", "view"); a != b {
		t.Fatalf("roleBindingName is not deterministic: %q vs %q — reconcile would churn bindings every pass", a, b)
	}
	if a, b := clusterRoleBindingName("alice", "view"), clusterRoleBindingName("alice", "view"); a != b {
		t.Fatalf("clusterRoleBindingName is not deterministic: %q vs %q", a, b)
	}
}

// TestBindingNamesStayReadable keeps the human-facing half of the chosen scheme
// honest: operators grep these names in kubectl output.
func TestBindingNamesStayReadable(t *testing.T) {
	rb := roleBindingName("alice", "dev", "ClusterRole", "system:basic-user")
	if !strings.HasPrefix(rb, "alice-system-basic-user-") || !strings.HasSuffix(rb, "-rb") {
		t.Errorf("roleBindingName = %q, want an alice-system-basic-user-<digest>-rb shape", rb)
	}

	crb := clusterRoleBindingName("alice", "cluster-admin")
	if !strings.HasPrefix(crb, "alice-cluster-admin-") || !strings.HasSuffix(crb, "-crb") {
		t.Errorf("clusterRoleBindingName = %q, want an alice-cluster-admin-<digest>-crb shape", crb)
	}
}
