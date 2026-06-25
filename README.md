# KubeUser

[![Latest Release](https://img.shields.io/github/v/release/openkube-hub/KubeUser?label=latest%20release&sort=semver)](https://github.com/openkube-hub/KubeUser/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/openkube-hub/KubeUser)](https://goreportcard.com/report/github.com/openkube-hub/KubeUser)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Tests](https://github.com/openkube-hub/KubeUser/actions/workflows/test.yml/badge.svg)](https://github.com/openkube-hub/KubeUser/actions/workflows/test.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/openkube-hub/KubeUser)](./go.mod)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/kubeuser)](https://artifacthub.io/packages/search?repo=kubeuser)

KubeUser is a Kubernetes-native way to manage users, certificates, RBAC, and kubeconfigs declaratively — without running an external identity provider.

---

## Overview

Managing Kubernetes access often means manually creating kubeconfigs, handling certificates, and keeping RBAC in sync. This quickly becomes error-prone, hard to audit, and unfriendly to GitOps workflows.

KubeUser solves this by managing Kubernetes users through declarative custom resources. It automatically generates and rotates certificates, applies RBAC bindings, and produces ready-to-use kubeconfigs using native Kubernetes APIs.

**Designed for** small teams and self-managed clusters that want Kubernetes-native, GitOps-friendly access control without a full IAM or OIDC stack. Not a replacement for enterprise identity providers.

### Architecture

```
   ┌──────────────┐
   │   User CR    │   kubectl apply -f user.yaml
   └──────┬───────┘
          │
          ▼
   ┌──────────────────────────┐
   │   Admission Webhooks     │   TLS via cert-manager
   │   • Mutating  (defaults) │
   │   • Validating (rules)   │
   └──────┬───────────────────┘
          │
          ▼
   ┌──────────────────────────┐
   │     User Controller      │   reconcile loop
   │       (Reconciler)       │
   └──┬─────────┬──────────┬──┘
      │         │          │
      ▼         ▼          ▼
   ┌──────┐ ┌─────────┐ ┌────────────┐
   │ CSR  │ │ Secrets │ │   RBAC     │
   │ API  │ │  key +  │ │  Role &    │
   │      │ │ kubecfg │ │  Cluster   │
   │signed│ │         │ │  Bindings  │
   └──────┘ └─────────┘ └────────────┘
```

---

## Quickstart

Try KubeUser in a few commands on any cluster with a working `kubectl` context:

```bash
# 1. Install cert-manager (required for webhook TLS)
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.yaml
kubectl wait --for=condition=ready pod -l app=cert-manager -n cert-manager --timeout=60s

# 2. Install KubeUser (uses the API server from your current kubeconfig)
helm repo add kubeuser https://openkube-hub.github.io/KubeUser

export KUBERNETES_API_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

helm install kubeuser kubeuser/kubeuser \
  --namespace kubeuser --create-namespace \
  --set env.KUBERNETES_API_SERVER="$KUBERNETES_API_SERVER"

# 3. Create a User
cat <<EOF | kubectl apply -f -
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  auth:
    type: x509
  clusterRoles:
    - existingClusterRole: view
EOF

# 4. Retrieve the kubeconfig and use it
kubectl get secret alice-kubeconfig -n kubeuser \
  -o jsonpath='{.data.config}' | base64 -d > alice.kubeconfig
kubectl --kubeconfig alice.kubeconfig get pods -A
```

For production installs, see [Installation](#installation) below.

---

## Features

#### ✅ Implemented

- [x] **Declarative User CRD** — status tracking, conditions, and finalizers for clean resource lifecycles
- [x] **Automatic Certificate Generation** — seamless integration with the Kubernetes CSR API
- [x] **Stateful Rotation Engine** — resumable, multi-step rotation via the **Shadow Secret** pattern; survives controller restarts
- [x] **Atomic Secret Updates** — zero-downtime credential flip with rollback on failure
- [x] **Dynamic RBAC Reconciliation** — automatic RoleBinding and ClusterRoleBinding management
- [x] **Mutating & Validating Webhooks** — TLS-secured via cert-manager CA injection
- [x] **Managed K8s Support** — configurable CSR signers for EKS, GKE, and vanilla clusters
- [x] **Anti-Thundering-Herd Design** — smart requeue with jitter, 24h TTL floor, 33% renew window, and an idempotent single-status-update reconcile path
- [x] **High Availability** — leader election and multi-replica deployment shipped via Helm
- [x] **Prometheus Metrics & Alerting** — rotation counters, duration histograms, expiry gauges, pre-built Grafana dashboard, and shipped PrometheusRule alerts
- [x] **Kubernetes Events** — structured events surfaced via `kubectl describe user`
- [x] **Status Conditions** — standard `Ready`, `Renewing`, and `AutoRenewal` conditions for declarative status checks
- [x] **kubectl Printer Columns** — `kubectl get users` shows Phase, AutoRenew, Expiry, NextRenewal, Age, and Message

#### 🚧 Planned

- [ ] **Deletion Warning Event** — admission warning and Warning event on User delete clarifying that issued certs remain cryptographically valid until expiry (Kubernetes does not consult CRL/OCSP for client certs)
- [ ] **kubectl Plugin** — `kubectl kubeuser kubeconfig <name>` to replace the manual `kubectl get secret | base64 -d` flow
- [ ] **Audit Log** — immutable record of every certificate issuance and rotation event
- [ ] **Short-Lived Certificates (< 24h)** — sub-24h TTL for ephemeral, zero-trust access
- [ ] **ECDSA Key Support** — configurable key algorithm via `spec.auth.keyAlgorithm`
- [ ] **OpenTelemetry Tracing** — end-to-end traces across reconcile and rotation paths
- [ ] **Example Role Manifests** — a curated folder of well-defined, ready-to-apply `Role`/`ClusterRole` YAMLs for common access patterns (read-only, developer, namespace-admin) that users can reference directly

---

## Security Considerations

**Deleting a User does NOT invalidate issued certificates.**

When deleting a User:
- RBAC bindings are removed immediately (access revoked)
- Secrets are deleted
- Certificates remain cryptographically valid until natural expiry

Plan your TTL accordingly. For short-lived access, use a short `ttl` and `autoRenew: false`.

---

## Installation

### Prerequisites

- Kubernetes v1.28+
- kubectl with cluster-admin permissions
- cert-manager (required for webhook certificates)

#### Install cert-manager

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.19.2/cert-manager.yaml
kubectl wait --for=condition=ready pod -l app=cert-manager -n cert-manager --timeout=60s
```

### Option 1: Helm (Recommended)

```bash
helm repo add kubeuser https://openkube-hub.github.io/KubeUser
helm repo update

export KUBERNETES_API_SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')

helm upgrade --install kubeuser kubeuser/kubeuser \
  --create-namespace \
  --namespace kubeuser \
  --version <version> \
  --set env.KUBERNETES_API_SERVER="$KUBERNETES_API_SERVER"

# Verify
kubectl get pods -n kubeuser
kubectl get certificates -n kubeuser
```

> All resource names are prefixed by the Helm release name. Use `helm search repo kubeuser --versions` to list available versions.

### Option 2: Kustomize

```bash
git clone https://github.com/openkube-hub/KubeUser.git
cd KubeUser
kubectl create namespace kubeuser
kubectl apply -k config/default
kubectl wait --for=condition=ready pod -l control-plane=controller-manager -n kubeuser --timeout=120s
```

### Option 3: Local Development (kind)

```bash
make docker-build
kind load docker-image ghcr.io/openkube-hub/kubeuser-controller:latest --name <cluster-name>
kubectl apply -k config/default
kubectl patch deployment kubeuser-controller-manager -n kubeuser \
  -p '{"spec":{"template":{"spec":{"containers":[{"name":"manager","imagePullPolicy":"Never"}]}}}}'
```

---

## Usage

### How Defaults Work

KubeUser uses a mutating admission webhook to persist defaults into the User spec at creation time:

```yaml
# You submit:
spec:
  auth:
    type: x509

# Webhook persists:
spec:
  auth:
    type: x509
    ttl: "2160h"      # from KUBEUSER_DEFAULT_TTL
    autoRenew: true   # from KUBEUSER_DEFAULT_AUTORENEW
```

Verify applied defaults: `kubectl get user <name> -o yaml`

Customize defaults via Helm:
```bash
helm upgrade --install kubeuser kubeuser/kubeuser \
  --set authDefaults.ttl=720h \
  --set authDefaults.autoRenew=false
```

> **Important:** `authDefaults` changes only apply to users created after the upgrade. Existing users retain their persisted defaults.

### Basic User (Namespace-Scoped Access)

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  auth:
    type: x509        # REQUIRED: currently only 'x509' is supported
    ttl: "72h"        # Optional: default 2160h (90 days)
    autoRenew: false  # Optional: default true
  roles:
    - namespace: "development"
      existingRole: "developer"
    - namespace: "staging"
      existingRole: "viewer"
```

### User with Cluster-wide Access

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob-admin
spec:
  auth:
    type: x509
    ttl: "2160h"
    autoRenew: true
  clusterRoles:
    - existingClusterRole: "cluster-admin"
```

### Mixed Permissions

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: contractor-jane
spec:
  auth:
    type: x509
    ttl: "720h"        # 30 days
    autoRenew: true
    renewBefore: "72h" # Renew 3 days before expiry (overrides 33% rule)
  roles:
    - namespace: "project-x"
      existingRole: "developer"
    - namespace: "monitoring"
      existingClusterRole: "view"  # ClusterRole bound to a specific namespace
  clusterRoles:
    - existingClusterRole: "view"
```

### Retrieve a User's Kubeconfig

```bash
kubectl get secret <username>-kubeconfig -n kubeuser \
  -o jsonpath='{.data.config}' | base64 -d > /tmp/kubeconfig

kubectl --kubeconfig /tmp/kubeconfig get pods -n dev
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.auth` | `AuthSpec` | **Yes** | Authentication configuration |
| `spec.auth.type` | `string` | **Yes** | Auth method — only `x509` is supported |
| `spec.auth.ttl` | `string` | No | Certificate lifetime (default: `2160h`) |
| `spec.auth.autoRenew` | `boolean` | No | Enable automatic renewal (default: `true`) |
| `spec.auth.renewBefore` | `string` | No | Renew this duration before expiry. Cannot exceed 90% of TTL |
| `spec.roles` | `[]RoleSpec` | No | Namespace-scoped role bindings |
| `spec.roles[].namespace` | `string` | Yes | Target namespace |
| `spec.roles[].existingRole` | `string` | Yes (or `existingClusterRole`) | Existing Role in the same namespace |
| `spec.roles[].existingClusterRole` | `string` | Yes (or `existingRole`) | ClusterRole bound into the namespace |
| `spec.clusterRoles` | `[]ClusterRoleSpec` | No | Cluster-wide role bindings |
| `spec.clusterRoles[].existingClusterRole` | `string` | Yes | Existing ClusterRole |

> For each `spec.roles[]` entry, exactly one of `existingRole` or `existingClusterRole` must be set.

---

## Managed Kubernetes Support

KubeUser issues client certificates via the Kubernetes CSR API. The default signer is `kubernetes.io/kube-apiserver-client`, which works on any cluster that permits third-party client-auth CSR signing.

For environments with a custom CA controller (e.g., cert-manager's CA issuer fronting a custom signer), override via Helm:

```bash
helm install kubeuser kubeuser/kubeuser \
  --set signerName="<your-signer-name>" \
  --set rbac.signerResourceNames[0]="<your-signer-name>"
```

To see what signers your cluster already accepts:

```bash
kubectl get csr -o jsonpath='{range .items[*]}{.spec.signerName}{"\n"}{end}' | sort -u
```

---

## Configuration

### Certificate Duration Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Minimum TTL | 24h | Enforced by validating webhook — prevents thundering herd loops |
| Maximum TTL | Bounded by the cluster signing duration (Kubernetes default: `8760h` / 1 year) | Configure `--cluster-signing-duration` on `kube-controller-manager` to allow longer |
| Default TTL | 2160h (90 days) | Applied by mutating webhook; configurable via `authDefaults.ttl` |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KUBERNETES_API_SERVER` | `https://127.0.0.1:6443` | API server address written into generated kubeconfigs |
| `CLUSTER_DOMAIN` | `cluster.local` | Cluster DNS domain |
| `KUBEUSER_DEFAULT_TTL` | `2160h` | Default certificate TTL |
| `KUBEUSER_DEFAULT_AUTORENEW` | `true` | Default auto-renewal behaviour |
| `KUBEUSER_SIGNER_NAME` | `kubernetes.io/kube-apiserver-client` | CSR signer name |

---

## Documentation

- [Certificate Management](docs/certificate-management.md)
- [Auto-Renewal](docs/auto-renewal.md)
- [Webhook Validation](docs/webhook-validation.md)
- [Metrics Reference](docs/metrics.md)
- [Accessing Metrics](docs/accessing-metrics.md)
- [Release Verification](docs/release-verification.md)
- [Troubleshooting](docs/troubleshooting.md)

---

## 🤝 Contributing

We welcome contributions of all kinds — bug reports, features, documentation, and tests.

See **[CONTRIBUTING.md](./CONTRIBUTING.md)** for the full guide: prerequisites, local setup,
code style, commit format, testing, and PR checklist.

---

## 🏛️ Community

| Document | Description |
|----------|-------------|
| [CONTRIBUTING.md](./CONTRIBUTING.md) | How to contribute |
| [GOVERNANCE.md](./GOVERNANCE.md) | Project roles, decision-making, and release process |
| [MAINTAINERS.md](./MAINTAINERS.md) | Current and emeritus maintainers |
| [SECURITY.md](./SECURITY.md) | How to report security vulnerabilities |
| [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) | Community standards |

---

If you find KubeUser useful, please consider giving it a ⭐ on GitHub!
