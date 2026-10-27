/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"encoding/json"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/auth"
)

// Regression tests for issue #71: the controller caps status.renewalHistory
// at 10 entries, but the CRD schema had no matching bound, so a direct write
// to the status subresource could grow the User object without limit.
var _ = Describe("User status schema (issue #71)", func() {
	ctx := context.Background()

	history := func(n int) []authv1alpha1.RenewalAttempt {
		h := make([]authv1alpha1.RenewalAttempt, n)
		for i := range h {
			h[i] = authv1alpha1.RenewalAttempt{
				Timestamp: metav1.Now(),
				Message:   fmt.Sprintf("attempt-%d", i),
			}
		}
		return h
	}

	It("bounds status.renewalHistory at 10 entries", func() {
		key := types.NamespacedName{Name: "issue71-renewal-history"}
		u := &authv1alpha1.User{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name},
			Spec: authv1alpha1.UserSpec{
				Auth: &authv1alpha1.AuthSpec{Type: &[]string{auth.AuthTypeX509}[0], TTL: "24h"},
			},
		}
		Expect(k8sClient.Create(ctx, u)).To(Succeed())
		DeferCleanup(func() { _ = k8sClient.Delete(ctx, u) })

		By("accepting a history at the cap")
		Expect(k8sClient.Get(ctx, key, u)).To(Succeed())
		u.Status.RenewalHistory = history(10)
		Expect(k8sClient.Status().Update(ctx, u)).To(Succeed())

		By("rejecting a history over the cap")
		Expect(k8sClient.Get(ctx, key, u)).To(Succeed())
		u.Status.RenewalHistory = history(11)
		err := k8sClient.Status().Update(ctx, u)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(),
			"status.renewalHistory with 11 entries must be rejected by the CRD schema (maxItems=10), got: %v", err)
	})
})

// Regression tests for issue #70: mutual exclusion of existingRole and
// existingClusterRole was enforced only by the webhook and the controller, so
// with the webhook unavailable (failurePolicy=Ignore, or bypassed) an invalid
// User could be persisted and every reconcile of its RBAC would fail. The CRD
// now enforces it at admission via a CEL rule.
var _ = Describe("User spec schema: roles[] exclusivity (issue #70)", func() {
	ctx := context.Background()

	userWithRole := func(name string, role authv1alpha1.RoleSpec) *authv1alpha1.User {
		return &authv1alpha1.User{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec: authv1alpha1.UserSpec{
				Auth:  &authv1alpha1.AuthSpec{Type: &[]string{auth.AuthTypeX509}[0], TTL: "24h"},
				Roles: []authv1alpha1.RoleSpec{role},
			},
		}
	}

	DescribeTable("admission of a single roles[] entry",
		func(name string, role authv1alpha1.RoleSpec, wantValid bool) {
			u := userWithRole(name, role)
			err := k8sClient.Create(ctx, u)
			if err == nil {
				DeferCleanup(func() { _ = k8sClient.Delete(ctx, u) })
			}
			if wantValid {
				Expect(err).NotTo(HaveOccurred())
				return
			}
			Expect(apierrors.IsInvalid(err)).To(BeTrue(),
				"roles[] entry %+v must be rejected by the CRD's exactly-one-of rule, got: %v", role, err)
			Expect(err.Error()).To(ContainSubstring("exactly one of existingRole or existingClusterRole must be set"))
		},
		Entry("existingRole only", "issue70-role-only",
			authv1alpha1.RoleSpec{Namespace: "default", ExistingRole: "view"}, true),
		Entry("existingClusterRole only", "issue70-clusterrole-only",
			authv1alpha1.RoleSpec{Namespace: "default", ExistingClusterRole: "view"}, true),
		Entry("both set", "issue70-both",
			authv1alpha1.RoleSpec{Namespace: "default", ExistingRole: "view", ExistingClusterRole: "view"}, false),
		Entry("neither set", "issue70-neither",
			authv1alpha1.RoleSpec{Namespace: "default"}, false),
	)

	// Go's omitempty never sends "", but kubectl apply of `existingRole: ""`
	// does. The webhook and controller treat "" as unset, so the CRD must too.
	It("treats an explicit empty string as unset", func() {
		create := func(name, roleFields string) error {
			var spec map[string]any
			Expect(json.Unmarshal([]byte(`{"auth":{"type":"x509","ttl":"24h"},"roles":[{"namespace":"default",`+roleFields+`}]}`),
				&spec)).To(Succeed())
			u := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
			u.SetGroupVersionKind(authv1alpha1.GroupVersion.WithKind("User"))
			u.SetName(name)
			err := k8sClient.Create(ctx, u)
			if err == nil {
				DeferCleanup(func() { _ = k8sClient.Delete(ctx, u) })
			}
			return err
		}

		Expect(create("issue70-empty-plus-cluster", `"existingRole":"","existingClusterRole":"view"`)).To(Succeed(),
			`existingRole: "" alongside existingClusterRole must be accepted`)

		err := create("issue70-empty-both", `"existingRole":"","existingClusterRole":""`)
		Expect(apierrors.IsInvalid(err)).To(BeTrue(),
			`two explicit empty strings must be rejected as "neither set", got: %v`, err)
	})
})
