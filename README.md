# KubeUser

[![Latest Release](https://img.shields.io/github/v/release/openkube-hub/KubeUser?label=latest%20release&sort=semver)](https://github.com/openkube-hub/KubeUser/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/openkube-hub/KubeUser)](https://goreportcard.com/report/github.com/openkube-hub/KubeUser)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)
[![Tests](https://github.com/openkube-hub/KubeUser/actions/workflows/test.yml/badge.svg)](https://github.com/openkube-hub/KubeUser/actions/workflows/test.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/openkube-hub/KubeUser)](./go.mod)

KubeUser is a Kubernetes-native way to manage users, certificates, RBAC, and kubeconfigs declaratively — without running an external identity provider.

---

## Overview

Managing Kubernetes access often means manually creating kubeconfigs, handling certificates, and keeping RBAC in sync. This quickly becomes error-prone, hard to audit, and unfriendly to GitOps workflows.

KubeUser solves this by managing Kubernetes users through declarative custom resources. It automatically generates and rotates certificates, applies RBAC bindings, and produces ready-to-use kubeconfigs using native Kubernetes APIs.

**Designed for** small teams and self-managed clusters that want Kubernetes-native, GitOps-friendly access control without a full IAM or OIDC stack. Not a replacement for enterprise identity providers.

### Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User CRD      │───▶│  User Controller │───▶│  RBAC Resources │
│  (Custom Res.)  │    │  (Reconciler)    │    │ (Roles/Bindings)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │ Certificate &   │
                       │ Kubeconfig Gen  │
                       └─────────────────┘
```

---

## Features

#### ✅ Implemented

- [x] **Declarative User CRD** — status tracking, conditions, and finalizers for clean resource lifecycles
- [x] **Automatic Certificate Generation** — seamless integration with the Kubernetes CSR API
- [x] **Stateful Rotation Engine** — resumable, multi-step rotation via the **Shadow Secret** pattern; survives controller restarts
- [x] **Atomic Secret Updates** — zero-downtime credential flip with rollback on failure
- [x] **Dynamic RBAC Reconciliation** — automatic RoleBinding and ClusterRoleBinding management
- [x] **Production-Grade Webhooks** — TLS-secured mutating and validating webhooks with cert-manager CA injection
- [x] **Managed K8s Support** — configurable CSR signers for EKS, GKE, and vanilla clusters
- [x] **Prometheus Metrics & Alerting** — rotation counters, duration histograms, expiry gauges, pre-built Grafana dashboard, and shipped PrometheusRule alerts
- [x] **Kubernetes-native Observability** — structured events via `kubectl describe user` and standard `Ready`, `Renewing`, `AutoRenewal` status conditions

#### 🚧 Planned

- [ ] **x509 Group Membership** — `O=` field support for RBAC group bindings
- [ ] **Certificate Revocation Notification** — admission warning and event on User deletion
- [ ] **Audit Log** — immutable record of every certificate issuance and rotation event
- [ ] **Short-Lived Certificates (< 24h)** — sub-24h TTL for ephemeral, zero-trust access
- [ ] **ECDSA Key Support** — configurable key algorithm via `spec.auth.keyAlgorithm`
- [ ] **OpenTelemetry Tracing** — end-to-end traces across reconcile and rotation paths
- [ ] **Predefined Role Templates** — curated library for common access patterns

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
| `spec.roles[].existingRole` | `string` | No* | Existing Role in the namespace |
| `spec.roles[].existingClusterRole` | `string` | No* | ClusterRole to bind to the namespace |
| `spec.clusterRoles` | `[]ClusterRoleSpec` | No | Cluster-wide role bindings |
| `spec.clusterRoles[].existingClusterRole` | `string` | Yes | Existing ClusterRole |

*Either `existingRole` or `existingClusterRole` must be specified per role entry.*

---

## Managed Kubernetes Support

**AWS EKS:**
```bash
helm install kubeuser kubeuser/kubeuser \
  --set signerName="beta.eks.amazonaws.com/app-client" \
  --set rbac.signerResourceNames[0]="beta.eks.amazonaws.com/app-client"
```

**GKE / AKS:** Discover your signer name, then configure:
```bash
kubectl get csr -o jsonpath='{.items[0].spec.signerName}'

helm install kubeuser kubeuser/kubeuser \
  --set signerName="<your-signer-name>" \
  --set rbac.signerResourceNames[0]="<your-signer-name>"
```

---

## Configuration

### Certificate Duration Limits

| Limit | Value | Notes |
|-------|-------|-------|
| Minimum TTL | 24h | Enforced by validating webhook — prevents thundering herd loops |
| Maximum TTL | 8760h (1 year) | Based on Kubernetes default `--cluster-signing-duration` |
| Default TTL | 2160h (90 days) | Applied by mutating webhook; configurable via `authDefaults.ttl` |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KUBERNETES_API_SERVER` | `https://kubernetes.default.svc` | API server address written into generated kubeconfigs |
| `CLUSTER_DOMAIN` | `cluster.local` | Cluster DNS domain |
| `KUBEUSER_DEFAULT_TTL` | `2160h` | Default certificate TTL |
| `KUBEUSER_DEFAULT_AUTORENEW` | `true` | Default auto-renewal behaviour |
| `KUBEUSER_SIGNER_NAME` | `kubernetes.io/kube-apiserver-client` | CSR signer name |

---

## Observability

```bash
# View all users with expiry and next renewal
kubectl get users -o custom-columns=NAME:.metadata.name,EXPIRY:.status.expiryTime,NEXT_RENEWAL:.status.nextRenewalAt

# Detailed status and events for a specific user
kubectl describe user <username>

# Check Ready and Renewing conditions
kubectl get user <username> -o json | jq '.status.conditions'
```

For Prometheus metrics, Grafana dashboards, and alerting rules see [docs/metrics.md](docs/metrics.md).

---

## Troubleshooting

### Controller Pod Not Starting

```bash
kubectl get pods -n kubeuser
kubectl logs -n kubeuser deployment/kubeuser-controller-manager
kubectl get events -n kubeuser --sort-by=.lastTimestamp
```

**Common causes:** missing cert-manager, webhook certificate not ready, image pull issues.

### Webhook Certificate Issues

```bash
kubectl get certificates -n kubeuser
kubectl describe certificate kubeuser-webhook-cert -n kubeuser
kubectl logs -n cert-manager deployment/cert-manager
```

### User Creation Fails

```bash
kubectl describe user <username>
kubectl logs -n kubeuser deployment/kubeuser-controller-manager | grep -i error
```

**Common causes:** referenced Role/ClusterRole does not exist, target namespace does not exist, webhook validation failure.

### Certificate Generation Issues

```bash
kubectl get csr -l auth.openkube.io/user=<username>
kubectl describe csr <csr-name>
kubectl auth can-i create certificatesigningrequests \
  --as=system:serviceaccount:kubeuser:kubeuser-controller-manager
```

---

## Documentation

- [Certificate Management](docs/certificate-management.md)
- [Auto-Renewal](docs/auto-renewal.md)
- [Webhook Validation](docs/webhook-validation.md)
- [Metrics Reference](docs/metrics.md)
- [Accessing Metrics](docs/accessing-metrics.md)

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
