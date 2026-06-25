# Certificate Management in KubeUser

KubeUser implements a comprehensive certificate management system that handles both webhook certificates (for admission control) and client certificates (for user authentication). This document provides detailed information about how certificates are created, stored, and managed.

## Overview

KubeUser uses different certificate management approaches:

1. **Webhook Certificates**: Self-managed by the controller (cert-manager optional)
2. **Client Certificates**: Managed via Kubernetes Certificate Signing Request (CSR) API
3. **Certificate Storage**: Secure storage in Kubernetes secrets
4. **Automatic Approval**: Controller-managed CSR approval process

## Client Certificate Management

### Architecture Overview

KubeUser creates client certificates through the Kubernetes CSR API:

- **Private Key Generation**: RSA-2048 private keys generated securely
- **CSR Creation**: Certificate Signing Requests submitted to Kubernetes API
- **Automatic Approval**: Controller validates and approves CSRs for managed users
- **Secure Storage**: Keys and certificates stored as Kubernetes secrets
- **Proper Signer**: Uses `kubernetes.io/kube-apiserver-client` signer

### Implementation Details

```go
// CSR creation with proper signer
csr = certv1.CertificateSigningRequest{
    ObjectMeta: metav1.ObjectMeta{
        Name: csrName, 
        Labels: map[string]string{"auth.openkube.io/user": username}
    },
    Spec: certv1.CertificateSigningRequestSpec{
        Request:           csrPEM,
        Usages:            []certv1.KeyUsage{certv1.UsageClientAuth},
        SignerName:        certv1.KubeAPIServerClientSignerName, // kubernetes.io/kube-apiserver-client
        ExpirationSeconds: &expirationSeconds,
    },
}
```

### Key Features

- **Kubernetes Native**: Uses built-in Kubernetes CSR API
- **Automatic Approval**: Controller automatically approves CSRs for managed users
- **Secure Storage**: Keys and certificates stored as Kubernetes secrets
- **Proper Signer**: Uses `kubernetes.io/kube-apiserver-client` signer for client authentication
- **Certificate Validation**: Validates certificate properties before approval

### Certificate Lifecycle

#### Creation Process

1. **Private Key Generation**:
   - Generate RSA-2048 private key using secure random number generation
   - Store private key in `{username}-key` secret

2. **CSR Creation**:
   - Create Certificate Signing Request from private key
   - Submit CSR to Kubernetes API with proper labels and signer
   - Set appropriate expiration time based on user configuration

3. **Automatic Approval**:
   - Controller validates CSR properties (signer, usage, labels)
   - Auto-approve validated CSRs for managed users
   - Wait for certificate authority to sign the request

4. **Certificate Storage**:
   - Retrieve signed certificate from CSR status
   - Build complete kubeconfig with certificate, key, and cluster CA
   - Store kubeconfig in `{username}-kubeconfig` secret

#### Resource Cleanup

When User resource is deleted:
- All related secrets deleted (`{username}-key`, `{username}-kubeconfig`)
- CSRs cleaned up automatically
- RBAC bindings removed

## Webhook Certificate Management

### Current Implementation

KubeUser uses different webhook certificate approaches depending on the environment:

#### Local Development and Testing
Uses **self-signed certificates** managed internally by the controller:

```yaml
# From config comments:
# No cert-manager needed - certificates are self-managed by the controller
```

The controller generates and manages webhook certificates automatically for local development and testing scenarios.

#### Production Environments
Uses **cert-manager** for proper certificate management:

```yaml
# Self-signed issuer for production
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: kubeuser-webhook-issuer
  namespace: kubeuser
spec:
  selfSigned: {}

# Certificate resource for production
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: kubeuser-webhook-cert
  namespace: kubeuser
spec:
  secretName: kubeuser-webhook-certs
  issuerRef:
    name: kubeuser-webhook-issuer
    kind: Issuer
  commonName: kubeuser-webhook-service.kubeuser.svc.cluster.local
  dnsNames:
  - kubeuser-webhook-service
  - kubeuser-webhook-service.kubeuser
  - kubeuser-webhook-service.kubeuser.svc
  - kubeuser-webhook-service.kubeuser.svc.cluster.local
```

**Note**: cert-manager is required for production deployments to ensure proper certificate lifecycle management and security.

## Security Considerations

### Best Practices Implemented

1. **Strong Cryptography**:
   - RSA 2048-bit keys minimum
   - Proper key usage flags (`clientAuth`)
   - Secure random number generation using `crypto/rand`

2. **Access Control**:
   - Minimal RBAC permissions for controller
   - Secrets stored in dedicated namespace
   - Proper ownership references for garbage collection

3. **Certificate Validation**:
   - Validates CSR properties before approval
   - Ensures proper signer name (`kubernetes.io/kube-apiserver-client`)
   - Verifies certificate usage flags
   - Checks required labels for security

4. **Secure Storage**:
   - Private keys stored separately from certificates
   - Secrets properly labeled for identification
   - Owner references ensure cleanup when users are deleted

### Security Recommendations

1. **Monitor Certificate Health**:
   ```bash
   # Check certificate expiry for all users
   kubectl get users -o custom-columns=NAME:.metadata.name,EXPIRY:.status.expiryTime
   ```

2. **Regular Audits**:
   - Review CSR approval history
   - Verify certificate purposes and usage
   - Check for orphaned certificates or secrets

3. **Access Monitoring**:
   - Monitor CSR creation and approval rates
   - Alert on unusual certificate request patterns
   - Track certificate usage and access patterns

## Configuration

### Certificate Duration

Certificate duration is configured in the User resource:

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  auth:
    type: x509
    ttl: "2160h"  # 3 months (default)
```

### Environment Variables

- **KUBERNETES_API_SERVER**: API server URL for kubeconfig generation (default: `https://127.0.0.1:6443`)
- **KUBEUSER_MIN_DURATION**: Internal testing override for minimum TTL (default: `24h`, not exposed in Helm values.yaml)

## Troubleshooting

### Common Issues

#### 1. CSR Not Approved
```bash
# Check CSR status
kubectl get csr -l auth.openkube.io/user=username

# View CSR details
kubectl describe csr username-csr

# Manual approval if needed (troubleshooting only)
kubectl certificate approve username-csr
```

#### 2. Certificate Creation Failed
```bash
# Check controller logs
kubectl logs -n kubeuser deployment/kubeuser-controller-manager | grep -i cert

# Verify RBAC permissions
kubectl auth can-i create certificatesigningrequests --as=system:serviceaccount:kubeuser:kubeuser-controller-manager

# Check CSR approval permissions
kubectl auth can-i update certificatesigningrequests/approval --as=system:serviceaccount:kubeuser:kubeuser-controller-manager
```

#### 3. Private Key Issues
```bash
# Check private key secret
kubectl get secret username-key -n kubeuser

# Verify key format
kubectl get secret username-key -n kubeuser -o jsonpath='{.data.key\.pem}' | base64 -d | openssl rsa -check -noout
```

#### 4. Certificate Validation Issues
```bash
# Check certificate expiry
kubectl get secret username-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d | \
  grep client-certificate-data | base64 -d | openssl x509 -noout -dates

# Verify certificate chain and properties
kubectl get secret username-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d | \
  grep client-certificate-data | base64 -d | openssl x509 -text -noout
```

### Debug Commands

```bash
# View all certificate-related resources for a user
kubectl get secrets,csr -n kubeuser -l auth.openkube.io/user=username

# Check controller logs for certificate operations
kubectl logs -n kubeuser deployment/kubeuser-controller-manager | grep -E "(cert|csr|key)"

# Verify kubeconfig functionality
kubectl --kubeconfig <(kubectl get secret username-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d) auth can-i get pods

# Test certificate authentication
kubectl --kubeconfig <(kubectl get secret username-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d) get nodes
```

## Prerequisites

1. **Kubernetes Cluster**: v1.28+ with CSR API enabled

2. **RBAC Permissions**: Controller needs CSR management permissions:
   ```yaml
   - apiGroups: ["certificates.k8s.io"]
     resources: ["certificatesigningrequests"]
     verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
   - apiGroups: ["certificates.k8s.io"]
     resources: ["certificatesigningrequests/approval"]
     verbs: ["update"]
   - apiGroups: ["certificates.k8s.io"]
     resources: ["signers"]
     resourceNames: ["kubernetes.io/kube-apiserver-client"]
     verbs: ["approve"]
   ```

3. **Namespace**: Dedicated namespace for storing user secrets and certificates

4. **cert-manager**: Required for production deployments, optional for local development and testing

## Best Practices

1. **Certificate Monitoring**: Set up monitoring for certificate creation and validation
2. **Secret Management**: Include certificate secrets in backup and disaster recovery procedures
3. **Access Control**: Regularly audit access to certificate secrets and CSR resources
4. **Testing**: Validate certificate creation and authentication in test environments
5. **Documentation**: Maintain documentation of certificate management procedures for operations teams

## Related Documentation

- [Auto-Renewal Feature](auto-renewal.md) - Detailed certificate renewal and rotation
- [Webhook Validation](webhook-validation.md) - Details about admission webhook certificates
- [User Management](../README.md) - Overall user management features