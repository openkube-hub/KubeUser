# setup-cluster.sh

Spins up a local KubeUser development environment on [kind](https://kind.sigs.k8s.io/).

## Prerequisites

`kind` `kubectl` `helm` `curl` `docker` `make`

## Usage

```bash
# Full setup — tears down any existing cluster and starts fresh
./hack/setup-cluster.sh

# Rebuild image + upgrade KubeUser Helm release only (cluster stays up)
./hack/setup-cluster.sh --upgrade-only

# Override the image tag
IMG=ghcr.io/openkube-hub/kubeuser-controller:dev ./hack/setup-cluster.sh
```

## What it does

| Step | Action |
|------|--------|
| 1 | Delete existing `kubeuser` kind cluster if present |
| 2 | Create cluster from `hack/kind.yaml` (1 control-plane + 1 worker) |
| 3 | Add/update `jetstack` and `prometheus-community` Helm repos |
| 4 | Install latest cert-manager |
| 5 | `make docker-build` + `kind load` the controller image |
| 6 | `helm upgrade --install kubeuser` from `helm/kubeuser/` with metrics enabled |
| 7 | Install kube-prometheus-stack (after KubeUser so the metrics TLS cert exists) |
| 8 | Apply `examples/users/minimal-viewer.yaml` and wait for `Active` |
| 9 | Extract `alice-viewer` kubeconfig → `/tmp/kubeconfig` |
| 10 | Smoke-test: `kubectl get pods -n default` with the generated kubeconfig |

`--upgrade-only` skips steps 1–4 and 7 (cluster, repos, cert-manager, prometheus).

## Endpoints

| Service | Command |
|---------|---------|
| Grafana | `kubectl -n monitoring port-forward svc/kube-prometheus-stack-grafana 3000:80` → http://localhost:3000 (admin / admin) |
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
