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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
