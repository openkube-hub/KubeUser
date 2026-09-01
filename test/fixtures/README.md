# Test fixtures

YAML manifests used by developers to exercise the controller and webhook by
hand (or from `hack/smoke-test.sh`). Not consumed by `go test`.

## Layout

| Path                              | Purpose                                                             |
|-----------------------------------|---------------------------------------------------------------------|
| `setup.yaml`                      | Namespaces + prerequisite `Role`s the User fixtures reference       |
| `ttl-scaling.yaml`                | Multiple valid Users at different TTLs to visualize renewal timing  |
| `ttl-boundary-24h.yaml`           | Single User at the 24h minimum TTL boundary (accepted)              |
| `smoke-user.yaml`                 | User `jane` — input for `hack/smoke-test.sh` (initial spec)         |
| `smoke-user-updated.yaml`         | User `jane` — input for `hack/smoke-test.sh` (updated spec)         |
| `invalid/missing-auth.yaml`       | `spec.auth` absent — webhook rejects                                |
| `invalid/missing-auth-type.yaml`  | `spec.auth` present but `type` missing — webhook rejects            |
| `invalid/empty-auth-block.yaml`   | `spec.auth: {}` — webhook rejects (`type` mandatory)                |
| `invalid/ttl-above-maximum.yaml`  | `ttl > 365d` — auth validator rejects                               |
| `invalid/renewbefore-too-large.yaml` | `renewBefore > 90%` of TTL — webhook rejects                     |

## Usage

Apply the setup once, then apply individual fixtures to observe behavior:

```bash
kubectl apply -f test/fixtures/setup.yaml
kubectl apply -f test/fixtures/ttl-scaling.yaml
kubectl apply -f test/fixtures/invalid/missing-auth.yaml  # expect error
```

User-facing sample manifests (for tutorials, docs, real deployments) live
under [`../../examples/`](../../examples/) instead.
