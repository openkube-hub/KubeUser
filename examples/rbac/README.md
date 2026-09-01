# Example RBAC roles

Starter `ClusterRole` manifests for common KubeUser use cases. Apply once,
then reference by name from `User.spec.roles[*].existingClusterRole` or
`User.spec.clusterRoles[*].existingClusterRole`.

```bash
kubectl apply -f examples/rbac/
```

## When to use these vs. Kubernetes built-ins

Kubernetes ships four default `ClusterRole`s that cover the most common
cases — use them directly when they fit:

| Built-in         | Use for                                            |
|------------------|----------------------------------------------------|
| `view`           | Read-only namespaced access (no secrets)           |
| `edit`           | Read/write namespaced access (no RBAC, no secrets) |
| `admin`          | Full namespaced access via RoleBinding             |
| `cluster-admin`  | Full cluster access                                |

The manifests here exist to fill gaps the built-ins leave:

| File                     | Fills gap                                                                       |
|--------------------------|---------------------------------------------------------------------------------|
| `viewer.yaml`            | `view` + `pods/log` + `events` — the "developer read-only" role                 |
| `readonly.yaml`          | Cluster-wide read-only (all resources + nonResourceURLs) — for auditors, SREs   |
| `developer.yaml`         | `edit` + `pods/exec` + `pods/portforward` + reads on `secrets`                  |
| `namespace-admin.yaml`   | `*` on `*` — same idea as `admin`, but with no exceptions carved out            |

## Referencing from a User

Namespace-scoped (creates a `RoleBinding` in `dev`):

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  auth: { type: x509 }
  roles:
    - namespace: dev
      existingClusterRole: kubeuser-developer
```

Cluster-scoped (creates a `ClusterRoleBinding`):

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob
spec:
  auth: { type: x509 }
  clusterRoles:
    - existingClusterRole: kubeuser-readonly
```

See [`../users/`](../users/) for complete `User` manifests.
