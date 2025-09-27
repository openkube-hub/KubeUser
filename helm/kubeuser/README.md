# KubeUser Helm Chart

This Helm chart deploys the KubeUser operator, a Kubernetes-native user management system that automates user authentication and authorization through declarative custom resources.

## Prerequisites

- Kubernetes 1.20+
- Helm 3.0+
- Cluster admin permissions

## Installation

### Quick Start

```bash
# Add the chart repository (if published)
helm repo add kubeuser https://charts.example.com/kubeuser

# Install with default values
helm install kubeuser ./helm/kubeuser

# Install with custom namespace (following user preference)
helm install kubeuser ./helm/kubeuser \
  --set global.namespace=neta-test \
  --set global.environment=test \
  --set global.nameSuffix=-neta-test
```

### Custom Installation

```bash
# Install with custom configuration
helm install kubeuser ./helm/kubeuser \
  --set image.tag=v0.2.0 \
  --set webhook.enabled=true \
  --set metrics.enabled=true \
```

## Configuration

The following table lists the configurable parameters and their default values:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.namespace` | Target namespace for deployment | `neta-test` |
| `global.environment` | Environment label | `test` |
| `global.nameSuffix` | Suffix for namespace name | `-neta-test` |
| `image.repository` | Controller image repository | `kubeuser-controller` |
| `image.tag` | Controller image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `replicaCount` | Number of controller replicas | `1` |
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `128Mi` |
| `resources.requests.cpu` | CPU request | `10m` |
| `resources.requests.memory` | Memory request | `64Mi` |
| `webhook.enabled` | Enable webhook server | `true` |
| `webhook.service.port` | Webhook service port | `443` |
| `metrics.enabled` | Enable metrics endpoint | `true` |
| `metrics.service.port` | Metrics service port | `8080` |
| `rbac.create` | Create RBAC resources | `true` |
| `crds.install` | Install CustomResourceDefinitions | `true` |
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
  roles:
    - namespace: "development"
      existingRole: "developer"
    - namespace: "staging"
      existingRole: "viewer"
  expiry: "30d"
```

### User with Cluster-wide Access

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob-admin
spec:
  clusterRoles:
    - existingClusterRole: "cluster-admin"
  expiry: "7d"
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
   kubectl get secret kubeuser-webhook-certs -n neta-test
   
   # View webhook logs
   kubectl logs -f deployment/kubeuser-controller-manager -n neta-test
   ```

2. **RBAC Permission Issues**
   ```bash
   # Verify ClusterRoleBinding
   kubectl get clusterrolebinding | grep kubeuser
   
   # Check service account
   kubectl get serviceaccount -n neta-test
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