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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	"github.com/openkube-hub/KubeUser/internal/controller/auth"
)

// raceInjectingClient wraps a client.Client and, exactly once, runs a hook
// right after a successful Update of a User object. It reproduces the issue
// #58 race deterministically: a concurrent writer landing immediately after
// the reconciler's finalizer write. It also counts Update calls so tests can
// assert a code path performed no API write at all.
type raceInjectingClient struct {
	client.Client
	afterUserUpdate func()
	fired           bool
	updateCalls     int
}

func (c *raceInjectingClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	c.updateCalls++
	err := c.Client.Update(ctx, obj, opts...)
	if err == nil && !c.fired && c.afterUserUpdate != nil {
		if _, ok := obj.(*authv1alpha1.User); ok {
			c.fired = true
			c.afterUserUpdate()
		}
	}
	return err
}

// statusRaceClient wraps a client.Client and, exactly once, runs a hook right
// BEFORE a status subresource update, so the update is guaranteed to hit an
// optimistic-concurrency conflict.
type statusRaceClient struct {
	client.Client
	beforeStatusUpdate func()
	fired              bool
}

func (c *statusRaceClient) Status() client.SubResourceWriter {
	return &racingStatusWriter{SubResourceWriter: c.Client.Status(), parent: c}
}

type racingStatusWriter struct {
	client.SubResourceWriter
	parent *statusRaceClient
}

func (w *racingStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if !w.parent.fired && w.parent.beforeStatusUpdate != nil {
		w.parent.fired = true
		w.parent.beforeStatusUpdate()
	}
	return w.SubResourceWriter.Update(ctx, obj, opts...)
}

// Regression tests for issue #58: after ensureFinalizer performed an API
// update, the same in-memory object was passed on to business logic and to
// the final Status().Update. A concurrent mutation landing in that window
// made the status update fail with a conflict, silently discarding the
// business logic output. The fix ends the reconcile pass when the finalizer
// was just added, so every write sequence starts from a fresh Get, and
// conflicts on the remaining window are logged and requeued without an error.
var _ = Describe("User finalizer handling (issue #58)", func() {
	ctx := context.Background()

	newUser := func(name string) (*authv1alpha1.User, types.NamespacedName) {
		key := types.NamespacedName{Name: name, Namespace: "default"}
		u := &authv1alpha1.User{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace},
			Spec: authv1alpha1.UserSpec{
				Auth: &authv1alpha1.AuthSpec{
					Type: &[]string{auth.AuthTypeX509}[0],
					TTL:  "24h",
				},
			},
		}
		return u, key
	}

	cleanupUser := func(key types.NamespacedName) {
		u := &authv1alpha1.User{}
		if err := k8sClient.Get(ctx, key, u); err == nil {
			u.Finalizers = nil
			_ = k8sClient.Update(ctx, u)
			_ = k8sClient.Delete(ctx, u)
		}
	}

	// mutateOutOfBand simulates a concurrent writer (kubectl label, GitOps
	// sync) by updating a fresh copy of the User through a separate client
	// path, bumping the server-side resourceVersion.
	mutateOutOfBand := func(key types.NamespacedName, label string) {
		var other authv1alpha1.User
		Expect(k8sClient.Get(ctx, key, &other)).To(Succeed())
		if other.Labels == nil {
			other.Labels = map[string]string{}
		}
		other.Labels[label] = "true"
		Expect(k8sClient.Update(ctx, &other)).To(Succeed())
	}

	It("reports whether the finalizer write was performed, without extra API writes", func() {
		u, key := newUser("issue58-ensure")
		Expect(k8sClient.Create(ctx, u)).To(Succeed())
		DeferCleanup(func() { cleanupUser(key) })

		counting := &raceInjectingClient{Client: k8sClient}
		r := &UserReconciler{Client: counting, Scheme: k8sClient.Scheme()}

		var user authv1alpha1.User
		Expect(k8sClient.Get(ctx, key, &user)).To(Succeed())

		By("first call performs exactly one update and reports it")
		added, err := r.ensureFinalizer(ctx, &user)
		Expect(err).NotTo(HaveOccurred())
		Expect(added).To(BeTrue())
		Expect(counting.updateCalls).To(Equal(1))
		Expect(user.Finalizers).To(ContainElement(authv1alpha1.UserFinalizer))

		By("second call is a no-op and performs zero API writes")
		added, err = r.ensureFinalizer(ctx, &user)
		Expect(err).NotTo(HaveOccurred())
		Expect(added).To(BeFalse())
		Expect(counting.updateCalls).To(Equal(1), "no Update call may be issued when the finalizer is already present")
	})

	It("ends the first reconcile pass after adding the finalizer, without writing status", func() {
		u, key := newUser("issue58-first-pass")
		Expect(k8sClient.Create(ctx, u)).To(Succeed())
		DeferCleanup(func() { cleanupUser(key) })

		r := &UserReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}

		By("first pass persists the finalizer and returns an empty result")
		res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(res.IsZero()).To(BeTrue(), "the watch event from the finalizer update drives the next pass")

		var persisted authv1alpha1.User
		Expect(k8sClient.Get(ctx, key, &persisted)).To(Succeed())
		Expect(persisted.Finalizers).To(ContainElement(authv1alpha1.UserFinalizer))
		Expect(persisted.Status.Phase).To(BeEmpty(), "no status write may share a pass with the finalizer write")

		By("second pass persists the status computed by business logic")
		// In envtest the business logic fails fast (the kubeuser namespace
		// does not exist), so the persisted phase is Error. What this spec
		// pins is the write choreography: pass one persisted nothing to
		// status, pass two did.
		_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, key, &persisted)).To(Succeed())
		Expect(persisted.Status.Phase).NotTo(BeEmpty())
		Expect(persisted.Status.Message).NotTo(BeEmpty())
	})

	It("does not lose status output to a concurrent mutation landing right after the finalizer write", func() {
		u, key := newUser("issue58-regression")
		Expect(k8sClient.Create(ctx, u)).To(Succeed())
		DeferCleanup(func() { cleanupUser(key) })

		// The wrapper injects the concurrent mutation at the exact point the
		// issue describes: immediately after the reconciler's own finalizer
		// Update succeeds, before the pass can do anything else. On the
		// pre-fix code this pass continued into business logic with the now
		// stale object and its Status().Update returned 409, surfacing as a
		// reconcile error. With the fix the pass ends before any further
		// write, so the mutation is harmless.
		racing := &raceInjectingClient{
			Client:          k8sClient,
			afterUserUpdate: func() { mutateOutOfBand(key, "issue58-concurrent-writer") },
		}
		r := &UserReconciler{Client: racing, Scheme: k8sClient.Scheme()}

		By("first pass: finalizer write immediately followed by a concurrent mutation")
		res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred(), "pre-fix code returned the 409 from the stale status update here")
		Expect(res.IsZero()).To(BeTrue())
		Expect(racing.fired).To(BeTrue(), "the concurrent mutation must have been injected")

		var persisted authv1alpha1.User
		Expect(k8sClient.Get(ctx, key, &persisted)).To(Succeed())
		Expect(persisted.Finalizers).To(ContainElement(authv1alpha1.UserFinalizer))
		Expect(persisted.Status.Phase).To(BeEmpty())

		By("second pass starts from a fresh Get and persists status despite the mutation")
		_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, key, &persisted)).To(Succeed())
		Expect(persisted.Status.Phase).NotTo(BeEmpty())
		Expect(persisted.Labels).To(HaveKey("issue58-concurrent-writer"), "the concurrent write must survive untouched")
	})

	It("requeues a conflicted status update in 5 seconds without an error, discarding and recomputing", func() {
		u, key := newUser("issue58-conflict")
		Expect(k8sClient.Create(ctx, u)).To(Succeed())
		DeferCleanup(func() { cleanupUser(key) })

		plain := &UserReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}

		By("first pass with a plain client persists the finalizer")
		_, err := plain.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())

		By("second pass hits a guaranteed conflict on its status update")
		racing := &statusRaceClient{
			Client:             k8sClient,
			beforeStatusUpdate: func() { mutateOutOfBand(key, "issue58-status-race") },
		}
		r := &UserReconciler{Client: racing, Scheme: k8sClient.Scheme()}
		res, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred(), "a status conflict is expected contention, not a reconcile error")
		Expect(res.RequeueAfter.Seconds()).To(BeNumerically("==", 5), "conflicts requeue on a real 5 second cadence")
		Expect(racing.fired).To(BeTrue())

		var persisted authv1alpha1.User
		Expect(k8sClient.Get(ctx, key, &persisted)).To(Succeed())
		Expect(persisted.Status.Phase).To(BeEmpty(), "the conflicted status write must be discarded, not retried blindly")

		By("the requeued pass recomputes and persists the status")
		_, err = r.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, key, &persisted)).To(Succeed())
		Expect(persisted.Status.Phase).NotTo(BeEmpty())
	})
})
