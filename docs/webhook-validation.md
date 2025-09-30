# Webhook Validation for User Resources

## Overview

The KubeUser operator includes an admission webhook that validates User resources before they are persisted to etcd. This prevents the creation of User objects that reference non-existent Roles or ClusterRoles, ensuring RBAC integrity.

## Features

- **Pre-persistence validation**: User resources are validated before being stored in etcd
- **Role existence validation**: Verifies that all referenced Roles exist in their specified namespaces
- **ClusterRole existence validation**: Verifies that all referenced ClusterRoles exist
- **Automated certificate management**: Uses cert-manager to automatically provision and manage webhook TLS certificates
- **Clear error messages**: Provides descriptive error messages when validation fails

## How it Works

1. When a User resource is created or updated, the Kubernetes API server sends an admission review to the webhook
2. The webhook validates that all referenced Roles and ClusterRoles exist
3. If validation passes, the User resource is allowed to be persisted
4. If validation fails, the operation is rejected with a clear error message

## Certificate Management

### Webhook Certificates

The webhook uses cert-manager for automatic certificate provisioning and management:

- **Self-signed issuer**: A self-signed Certificate Authority is created for the webhook
- **Automatic renewal**: cert-manager handles certificate renewal automatically (90 days before expiry)
- **CA injection**: cert-manager automatically injects the CA bundle into the ValidatingAdmissionWebhook configuration
- **RSA 2048-bit keys** with proper key usage for server authentication

### Client Certificates

Client certificates for user authentication are managed through the Kubernetes Certificate Signing Request (CSR) API:

- **Kubernetes CSR API**: Uses the native `kubernetes.io/kube-apiserver-client` signer
- **Automatic approval**: The controller automatically approves CSRs for managed users
- **Certificate rotation**: Certificates are automatically rotated 30 days before expiry
- **Secure storage**: Private keys and certificates are stored as Kubernetes secrets

## Prerequisites

- **cert-manager**: Must be installed in your cluster
  ```bash
  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
  ```

## Configuration

The webhook configuration is located in `config/webhook/` and includes:

- `issuer.yaml`: Self-signed issuer and certificate configuration
- `service.yaml`: Service configuration for the webhook server
- `manifests.yaml`: ValidatingAdmissionWebhook configuration
- `kustomization.yaml`: Kustomize configuration for certificate management

## Validation Examples

### Valid User Resource
```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: jane-doe
spec:
  roles:
    - namespace: default
      existingRole: developer  # This role must exist in the 'default' namespace
  clusterRoles:
    - existingClusterRole: view  # This ClusterRole must exist
```

### Validation Errors

**Missing Role:**
```
error validating User resource: role 'non-existent-role' not found in namespace 'default'
```

**Missing ClusterRole:**
```
error validating User resource: clusterrole 'non-existent-cluster-role' not found
```

## Deployment

The webhook is automatically deployed when you apply the default configuration:

```bash
kubectl apply -k config/default
```

## Troubleshooting

### Webhook Certificate Issues
Check that cert-manager is running and the certificate is ready:
```bash
kubectl get certificates -n kubeuser-system
kubectl get secrets kubeuser-webhook-certs -n kubeuser-system
```

### Client Certificate Issues
Check CSR status and certificate secrets:
```bash
# Check CSRs for a specific user
kubectl get csr -l auth.openkube.io/user=username

# Check user certificate secrets
kubectl get secrets -n kubeuser | grep username

# Check certificate expiry from kubeconfig
kubectl get secret username-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d | grep client-certificate-data | head -1 | awk '{print $2}' | base64 -d | openssl x509 -noout -dates
```

### Certificate Rotation Issues
If certificates are not rotating automatically:
```bash
# Force certificate rotation by deleting the kubeconfig secret
kubectl delete secret username-kubeconfig -n kubeuser

# Trigger reconciliation
kubectl annotate user username kubectl.kubernetes.io/restartedAt="$(date -Iseconds)"
```

### Webhook Logs
Check the controller manager logs for webhook validation events:
```bash
kubectl logs -n kubeuser-system deployment/kubeuser-controller-manager
```

### Testing Validation
Create a User resource that references a non-existent role to test validation:
```bash
cat <<EOF | kubectl apply -f -
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: test-user
spec:
  roles:
    - namespace: default
      existingRole: non-existent-role
EOF
```

This should fail with a validation error message.

## Security Considerations

- The webhook validates RBAC references, preventing the creation of Users with invalid permissions
- Certificate management is handled automatically by cert-manager
- The webhook runs with minimal required permissions
- Validation occurs before persistence, preventing invalid states