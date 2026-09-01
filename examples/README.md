# Examples

Starter manifests you can `kubectl apply` against a cluster where KubeUser is
installed.

- [`rbac/`](rbac/) — starter `ClusterRole`s (viewer, developer,
  namespace-admin, readonly) that fill gaps left by Kubernetes' built-in
  `view`/`edit`/`admin`/`cluster-admin`.
- [`users/`](users/) — sample `User` CRs demonstrating common patterns
  (minimal, developer, on-call, multi-namespace).

## Quickstart

```bash
kubectl apply -f examples/rbac/
kubectl apply -f examples/users/minimal-viewer.yaml
kubectl wait --for=condition=Ready user/alice-viewer --timeout=60s
kubectl get secret alice-viewer-kubeconfig \
  -o jsonpath='{.data.kubeconfig}' | base64 -d > alice.kubeconfig
```

These manifests are for humans reading the repo. Manifests consumed by
`go test` live under [`../test/`](../test/).
