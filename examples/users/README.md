# Example User manifests

Ready-to-apply `User` CRs showing common patterns. Prerequisite: the target
`Role`/`ClusterRole` must already exist. Use the built-in
`view`/`edit`/`admin`/`cluster-admin` roles or apply the starters in
[`../rbac/`](../rbac/) first.

| File                     | Pattern                                                          |
|--------------------------|------------------------------------------------------------------|
| `minimal-viewer.yaml`    | Simplest possible User — binds the built-in `view` cluster-wide  |
| `developer.yaml`         | Namespaced developer role + cluster-wide viewer                  |
| `production-safe.yaml`   | Short-TTL, auto-renewing cert for on-call use                    |
| `multi-namespace.yaml`   | Different permission tiers across `dev` / `staging` / `prod`     |

## Apply

```bash
kubectl apply -f examples/rbac/                       # once, per cluster
kubectl apply -f examples/users/minimal-viewer.yaml   # per user
```

Wait for the User to reach `Active`, then extract the kubeconfig:

```bash
kubectl wait --for=condition=Ready user/alice-viewer --timeout=60s
kubectl get secret alice-viewer-kubeconfig \
  -o jsonpath='{.data.kubeconfig}' | base64 -d > alice.kubeconfig
kubectl --kubeconfig=alice.kubeconfig get pods -A
```

## Note on namespaces

The `dev` / `staging` / `prod` namespaces referenced by `developer.yaml` and
`multi-namespace.yaml` are not created by these manifests. Create them
yourself, or the controller will keep retrying the RoleBinding reconciliation
until they exist.
