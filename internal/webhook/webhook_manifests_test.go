package webhook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"sigs.k8s.io/yaml"
)

// TestWebhookFailurePolicies pins the availability contract from issue #38:
// the mutating webhook must tolerate its own outage (Ignore) because the
// controller re-applies the same defaults via auth.GetSafeAuthSpec on every
// reconcile, while the validating webhook enforces security-critical guards
// (mandatory auth.type, reserved-identity prefix, RBAC-reference existence,
// renewBefore bounds) and must remain Fail. A silent flip of either policy
// would either mask invalid Users past admission or turn a webhook pod
// restart into a cluster-wide User create/update outage.
func TestWebhookFailurePolicies(t *testing.T) {
	path := filepath.Join("..", "..", "config", "webhook", "manifests.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var (
		mutating   *admissionregistrationv1.MutatingWebhookConfiguration
		validating *admissionregistrationv1.ValidatingWebhookConfiguration
	)

	for _, doc := range splitYAMLDocs(string(data)) {
		var meta struct {
			Kind string `json:"kind"`
		}
		if err := yaml.Unmarshal([]byte(doc), &meta); err != nil {
			t.Fatalf("decode kind: %v", err)
		}
		switch meta.Kind {
		case "MutatingWebhookConfiguration":
			mutating = &admissionregistrationv1.MutatingWebhookConfiguration{}
			if err := yaml.Unmarshal([]byte(doc), mutating); err != nil {
				t.Fatalf("decode mutating: %v", err)
			}
		case "ValidatingWebhookConfiguration":
			validating = &admissionregistrationv1.ValidatingWebhookConfiguration{}
			if err := yaml.Unmarshal([]byte(doc), validating); err != nil {
				t.Fatalf("decode validating: %v", err)
			}
		}
	}

	if mutating == nil {
		t.Fatal("MutatingWebhookConfiguration not found in manifests.yaml")
	}
	if validating == nil {
		t.Fatal("ValidatingWebhookConfiguration not found in manifests.yaml")
	}
	if len(mutating.Webhooks) == 0 {
		t.Fatal("MutatingWebhookConfiguration has no webhooks")
	}
	if len(validating.Webhooks) == 0 {
		t.Fatal("ValidatingWebhookConfiguration has no webhooks")
	}

	assertFailurePolicy(t, "mutating", mutating.Webhooks[0].Name, mutating.Webhooks[0].FailurePolicy, admissionregistrationv1.Ignore,
		"defaults are re-applied by the controller via auth.GetSafeAuthSpec; a webhook outage must not block User create/update")
	assertFailurePolicy(t, "validating", validating.Webhooks[0].Name, validating.Webhooks[0].FailurePolicy, admissionregistrationv1.Fail,
		"validating webhook enforces mandatory auth.type, reserved-identity rejection, RBAC-reference existence, and renewBefore bounds — bypassing it admits unsafe Users")
}

func assertFailurePolicy(t *testing.T, kind, name string, got *admissionregistrationv1.FailurePolicyType, want admissionregistrationv1.FailurePolicyType, reason string) {
	t.Helper()
	if got == nil {
		t.Fatalf("%s webhook %q has nil failurePolicy; want %s (%s)", kind, name, want, reason)
	}
	if *got != want {
		t.Fatalf("%s webhook %q failurePolicy = %s; want %s (%s)", kind, name, *got, want, reason)
	}
}

func splitYAMLDocs(s string) []string {
	parts := strings.Split(s, "\n---")
	docs := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" || p == "---" {
			continue
		}
		docs = append(docs, p)
	}
	return docs
}
