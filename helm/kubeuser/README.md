# KubeUser Helm Chart

This Helm chart deploys the KubeUser operator, a Kubernetes-native user management system that automates user authentication and authorization through declarative custom resources.

## Prerequisites

- Kubernetes 1.28+
- Helm 3.0+
- Cluster admin permissions

## Installation

### Quick Start

```bash
# Add the chart repository
helm repo add kubeuser https://openkube-hub.github.io/KubeUser

# Install with automatic namespace creation (recommended)
helm install kubeuser ./helm/kubeuser --create-namespace -n kubeuser

# Or install into existing namespace
helm install kubeuser ./helm/kubeuser -n existing-namespace
```

**Important**: 
- Everything (controller + user secrets) goes in the same namespace specified by `-n`
- Use `--create-namespace` for new namespaces or ensure the namespace exists first

### Custom Installation

```bash
# Install with custom configuration and namespace creation
helm install kubeuser ./helm/kubeuser \
  --create-namespace -n kubeuser \
  --set image.tag=v0.2.0 \
  --set webhook.enabled=true \
  --set metrics.enabled=true

# Install into existing namespace
helm install kubeuser ./helm/kubeuser -n my-existing-namespace
```

## Configuration

### Authentication Defaults Configuration

KubeUser allows SREs to customize default authentication settings via Helm values:

```yaml
authDefaults:
  ttl: "2160h"      # Default certificate lifetime (90 days)
  autoRenew: true   # Default auto-renewal behavior
```

**How It Works:**
1. Helm values are mapped to environment variables in the deployment
2. Controller reads environment variables at startup
3. Mutating webhook applies defaults when User resources are created
4. Defaults are persisted into the User spec (visible in etcd)

**Environment Variable Mapping:**
- `authDefaults.ttl` → `KUBEUSER_DEFAULT_TTL`
- `authDefaults.autoRenew` → `KUBEUSER_DEFAULT_AUTORENEW`
- `signerName` → `KUBEUSER_SIGNER_NAME`
- `clusterName` → `KUBEUSER_CLUSTER_NAME`

**⚠️  Important:** Changes to `authDefaults` only apply to NEW users created after the Helm upgrade. Existing users retain their original defaults (persisted in spec).

### Namespace Configuration

**Important:** The controller creates user resources (secrets, kubeconfigs) in the same namespace where it is deployed.

The `KUBEUSER_NAMESPACE` environment variable is automatically set to `{{ .Release.Namespace }}`, ensuring all user resources are created in the Helm release namespace.

**Recommended Setup:**
```bash
# Install controller and user resources in the same namespace
helm install kubeuser ./helm/kubeuser --create-namespace -n kubeuser
```

This creates:
- Controller deployment in `kubeuser` namespace
- User secrets and kubeconfigs in `kubeuser` namespace
- All resources in one place for easy management

**Alternative Setup (Advanced):**
If you need user resources in a different namespace, you can override the environment variable:

```yaml
# values.yaml
env:
  KUBEUSER_NAMESPACE: "custom-namespace"
```

**Note:** Ensure the target namespace exists before deploying:
```bash
kubectl create namespace custom-namespace
helm install kubeuser ./helm/kubeuser -n kubeuser
```

### Configuration Parameters

The following table lists the configurable parameters and their default values:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Controller image repository | `ghcr.io/openkube-hub/kubeuser-controller` |
| `image.tag` | Controller image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount` | Number of controller replicas | `2` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `webhook.enabled` | Enable webhook server | `true` |
| `webhook.service.port` | Webhook service port | `443` |
| `webhook.mutating.failurePolicy` | Mutating webhook failure policy. Defaults are re-applied by the controller on every reconcile, so `Ignore` avoids turning a webhook-pod restart into a cluster-wide User create/update outage. Setting this to `Fail` reintroduces issue #38. | `Ignore` |
| `webhook.validating.failurePolicy` | Validating webhook failure policy. Enforces mandatory `spec.auth.type`, reserved-identity prefix, RBAC-reference existence, and TTL/renewBefore bounds. Setting this to `Ignore` admits Users the controller cannot safely reconcile. | `Fail` |
| `podDisruptionBudget.enabled` | Create a PodDisruptionBudget for the controller pod that serves the webhooks. | `true` |
| `podDisruptionBudget.minAvailable` | Minimum controller replicas that must stay available during voluntary disruption. Set to `null` if using `maxUnavailable` instead. | `1` |
| `podDisruptionBudget.maxUnavailable` | Maximum controller replicas that may be unavailable during voluntary disruption. Mutually exclusive with `minAvailable`. | `null` |
| `metrics.enabled` | Enable metrics endpoint | `true` |
| `metrics.service.port` | Metrics service port | `8080` |
| `rbac.create` | Create RBAC resources | `true` |
| `crds.install` | Install CustomResourceDefinitions | `true` |
| `env.KUBERNETES_API_SERVER` | API server endpoint written into generated kubeconfigs; override with your reachable URL | `https://127.0.0.1:6443` |
| `env.CLUSTER_DOMAIN` | Kubernetes cluster domain | `cluster.local` |
| `env.KUBEUSER_MIN_DURATION` | Minimum certificate duration (optional) | `10m` |
| `env.KUBEUSER_ROTATION_THRESHOLD` | Certificate rotation threshold (optional) | `25% of TTL` |
| `clusterName` | Cluster and context name written into generated kubeconfigs | `cluster` |
| `commonLabels.environment` | Common environment label | `test` |

## Usage Examples

### Basic User Creation

After installation, create a user with namespace-scoped access:

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  auth:
    type: x509  # REQUIRED: currently only 'x509' is supported
    ttl: "2160h"  # Optional: defaults to 2160h (90 days)
    autoRenew: true  # Optional: defaults to true
  roles:
    # Bind a namespace-scoped Role
    - namespace: "development"
      existingRole: "developer"
    - namespace: "staging"
      existingRole: "viewer"
```

### User with ClusterRole in Specific Namespaces

Bind a ClusterRole with RoleBinding to grant permissions only in specific namespaces:

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob
spec:
  auth:
    type: x509
    ttl: "2160h"
    autoRenew: true
  roles:
    # Bind ClusterRole 'view' with RoleBinding in specific namespaces
    - namespace: "team-a"
      existingClusterRole: "view"
    - namespace: "team-b"
      existingClusterRole: "edit"
```

### User with Cluster-wide Access

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: charlie-admin
spec:
  auth:
    type: x509
    ttl: "2160h"
    autoRenew: true
  clusterRoles:
    # Bind ClusterRole with ClusterRoleBinding for cluster-wide access
    - existingClusterRole: "cluster-admin"
```

### Mixed Permissions

Combine namespace-scoped and cluster-wide permissions:

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: dave
spec:
  auth:
    type: x509
    ttl: "2160h"
    autoRenew: true
  roles:
    # Namespace-scoped Role
    - namespace: "production"
      existingRole: "deployer"
    # ClusterRole bound to specific namespace
    - namespace: "monitoring"
      existingClusterRole: "view"
  clusterRoles:
    # Cluster-wide access
    - existingClusterRole: "cluster-reader"
```

## Upgrading

```bash
# Upgrade to a new version
helm upgrade kubeuser ./helm/kubeuser \
  --set image.tag=v0.3.0

# Upgrade with new values
helm upgrade kubeuser ./helm/kubeuser -f custom-values.yaml
```

## Uninstallation

```bash
# Uninstall the release
helm uninstall kubeuser

# Clean up CRDs (if needed)
kubectl delete crd users.auth.openkube.io
```

## Troubleshooting

### Common Issues

1. **Webhook Certificate Issues**
   ```bash
   # Check webhook certificate secret
   kubectl get secret kubeuser-webhook-certs -n kubeuser
   
   # View webhook logs
   kubectl logs -f deployment/kubeuser-controller-manager -n kubeuser
   ```

2. **RBAC Permission Issues**
   ```bash
   # Verify ClusterRoleBinding
   kubectl get clusterrolebinding | grep kubeuser
   
   # Check service account
   kubectl get serviceaccount -n kubeuser
   ```

3. **CRD Issues**
   ```bash
   # Verify CRD installation
   kubectl get crd users.auth.openkube.io -o yaml
   ```

## Development

### Running Tests

```bash
# Validate chart templates
helm lint ./helm/kubeuser

# Dry run installation
helm install kubeuser ./helm/kubeuser --dry-run --debug

# Template rendering
helm template kubeuser ./helm/kubeuser
```

## Contributing

Please refer to the main project repository for contribution guidelines:
https://github.com/openkube-hub/KubeUser
