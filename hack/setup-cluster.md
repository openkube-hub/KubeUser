# setup-cluster.sh

Spins up a local KubeUser development environment on [kind](https://kind.sigs.k8s.io/).

## Prerequisites

`kind` `kubectl` `helm` `curl` `docker` `make`

## Usage

```bash
# Full setup: cert-manager + the KubeUser controller (no monitoring stack).
# Reuses the `kubeuser` kind cluster if it is already up and upgrades in place.
./hack/setup-cluster.sh

# Delete the existing cluster first and start fresh
./hack/setup-cluster.sh --recreate

# Same, plus kube-prometheus-stack (Prometheus + Grafana with the KubeUser dashboard)
./hack/setup-cluster.sh --with-monitoring

# Rebuild image + upgrade KubeUser Helm release only (cluster stays up)
./hack/setup-cluster.sh --upgrade-only

# Override the image tag
IMG=ghcr.io/openkube-hub/kubeuser-controller:dev ./hack/setup-cluster.sh
```

## What it does

| Step | Action |
|------|--------|
| 1 | If the `kubeuser` kind cluster is already up, reuse it and switch kubectl to `kind-kubeuser` (with `--recreate`, delete it instead) |
| 2 | Otherwise create it from `hack/kind.yaml` (1 control-plane + 1 worker) |
| 3 | Add/update the `jetstack` (and, with `--with-monitoring`, `prometheus-community`) Helm repos |
| 4 | Install latest cert-manager (required: it issues the webhook and metrics TLS certs) |
| 5 | Install kube-prometheus-stack + the KubeUser Grafana dashboard (only with `--with-monitoring`) |
| 6 | `make docker-build` the controller image |
| 7 | `kind load` the image into the cluster |
| 8 | `helm upgrade --install kubeuser` from `helm/kubeuser/` with metrics enabled (installs, or upgrades an existing release) |
| 9 | Apply `examples/users/minimal-viewer.yaml` and wait for `Active` and its kubeconfig secret |
| 10 | Extract `alice-viewer` kubeconfig → `/tmp/kubeconfig` |
| 11 | Smoke-test: `kubectl get pods -n default` with the generated kubeconfig |

### Flags

| Flag | Effect |
|------|--------|
| `--with-monitoring` | Runs step 5: adds the `prometheus-community` repo and installs kube-prometheus-stack with the KubeUser Grafana dashboard. Off by default, so a plain run gets cert-manager and the KubeUser controller only. |
| `--recreate` | Deletes the existing `kubeuser` kind cluster and builds a fresh one. Without it, an existing cluster is reused. |
| `--upgrade-only` | Skips steps 3–5 (repos, cert-manager, prometheus); rebuilds the image and upgrades the KubeUser release. Requires the cluster to be up; can't be combined with `--recreate`. |

Re-running is safe: every install is `helm upgrade --install`, and the
controller pods carry a `kubeuser.openkube.io/image-hash` annotation, a hash of
the built image's layer digests. The image tag (`latest`) never changes between
builds, so the annotation is what makes helm roll the pods when the code
changed, and leaves them alone on a re-run with an identical image.

The KubeUser `ServiceMonitor` is enabled only when the
`servicemonitors.monitoring.coreos.com` CRD exists on the cluster, i.e. when
kube-prometheus-stack is installed. That way `--upgrade-only` works on a
cluster created with or without `--with-monitoring`.

## Endpoints

| Service | Command |
|---------|---------|
| Grafana (with `--with-monitoring`) | `kubectl -n monitoring port-forward svc/kube-prometheus-stack-grafana 3000:80` → http://localhost:3000 (admin / admin) |
| KubeUser pods | `kubectl -n kubeuser get pods` |
| Generated kubeconfig | `/tmp/kubeconfig` |

## Supporting files

```
hack/
├── kind.yaml                                  # kind cluster config
└── monitoring/
    ├── kube-prometheus-stack-values.yaml      # homelab-tuned Prometheus stack values
    └── kubeuser-dashboard-configmap.yaml      # Grafana dashboard for KubeUser metrics
```
