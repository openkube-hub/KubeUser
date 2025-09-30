# Certificate Management in KubeUser

KubeUser implements a comprehensive certificate management system that handles both webhook certificates (for admission control) and client certificates (for user authentication). This document provides detailed information about how certificates are managed, rotated, and troubleshooted.

## Overview

KubeUser uses two different certificate management approaches:

1. **Webhook Certificates**: Managed by cert-manager for admission webhook TLS
2. **Client Certificates**: Managed via Kubernetes Certificate Signing Request (CSR) API for user authentication

## Webhook Certificate Management

### Architecture

Webhook certificates are managed by cert-manager using the following components:

```yaml
# Self-signed issuer
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: kubeuser-webhook-issuer
  namespace: kubeuser
spec:
  selfSigned: {}

# Certificate resource
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
  duration: 8760h # 1 year
  renewBefore: 2160h # 90 days
  privateKey:
    algorithm: RSA
    size: 2048
  usages:
  - digital signature
  - key encipherment
  - server auth
```

### Key Features

- **Automatic Renewal**: cert-manager automatically renews certificates 90 days before expiry
- **CA Bundle Injection**: cert-manager automatically injects the CA bundle into webhook configurations
- **Proper SAN Configuration**: Includes all necessary DNS names for service discovery
- **Strong Cryptography**: Uses RSA 2048-bit keys with appropriate key usage

### Monitoring

Check webhook certificate status:
```bash
# Check certificate status
kubectl get certificate -n kubeuser

# Check certificate secret
kubectl get secret kubeuser-webhook-certs -n kubeuser

# View certificate details
kubectl describe certificate kubeuser-webhook-cert -n kubeuser
```

## Client Certificate Management

### Architecture

Client certificates are managed through the Kubernetes CSR API with the following workflow:

1. **Private Key Generation**: RSA 2048-bit private key generated and stored in Kubernetes secret
2. **CSR Creation**: Certificate Signing Request created using Kubernetes CSR API
3. **Automatic Approval**: Controller automatically approves CSRs for managed users
4. **Certificate Storage**: Signed certificate stored in kubeconfig secret
5. **Rotation Monitoring**: Certificates monitored for expiry and rotated automatically

### Implementation Details

```go
// Certificate rotation check (30 days before expiry)
rotationThreshold := 30 * 24 * time.Hour
needsRotation, err := r.checkCertificateRotation(ctx, cfgSecretName, rotationThreshold)

// CSR creation with proper signer
csr = certv1.CertificateSigningRequest{
    ObjectMeta: metav1.ObjectMeta{
        Name: csrName, 
        Labels: map[string]string{"auth.openkube.io/user": username}
    },
    Spec: certv1.CertificateSigningRequestSpec{
        Request:    csrPEM,
        Usages:     []certv1.KeyUsage{certv1.UsageClientAuth},
        SignerName: certv1.KubeAPIServerClientSignerName, // kubernetes.io/kube-apiserver-client
    },
}
```

### Key Features

- **Kubernetes Native**: Uses built-in Kubernetes CSR API
- **Automatic Approval**: Controller automatically approves CSRs for managed users
- **Certificate Rotation**: Automatic rotation 30 days before expiry
- **Secure Storage**: Keys and certificates stored as Kubernetes secrets
- **Proper Signer**: Uses `kubernetes.io/kube-apiserver-client` signer for client authentication

### Certificate Lifecycle

1. **Creation**:
   - Private key generated (RSA 2048-bit)
   - CSR created and submitted to Kubernetes API
   - CSR automatically approved by controller
   - Certificate retrieved and stored in kubeconfig secret

2. **Rotation**:
   - Certificates monitored during reconciliation
   - When certificate is within 30 days of expiry:
     - Existing kubeconfig secret deleted
     - Existing CSR deleted
     - New CSR created (reusing private key for consistency)
     - New certificate issued and stored

3. **Cleanup**:
   - When User resource is deleted:
     - All related secrets deleted
     - CSRs cleaned up
     - RBAC bindings removed

## Security Considerations

### Best Practices Implemented

1. **Strong Cryptography**:
   - RSA 2048-bit keys minimum
   - Proper key usage flags
   - Secure random number generation

2. **Certificate Rotation**:
   - Automatic rotation before expiry
   - Configurable rotation threshold
   - Proper cleanup of old resources

3. **Access Control**:
   - Minimal RBAC permissions for controller
   - Secrets stored in dedicated namespace
   - Proper ownership references

4. **Monitoring and Logging**:
   - Certificate expiry tracking
   - Rotation events logged
   - Status updates in User resources

### Security Recommendations

1. **Monitor Certificate Health**:
   ```bash
   # Check certificate expiry for all users
   kubectl get secrets -n kubeuser | grep kubeconfig | while read secret _; do
     echo "=== $secret ==="
     kubectl get secret $secret -n kubeuser -o jsonpath='{.data.config}' | base64 -d | grep client-certificate-data | head -1 | awk '{print $2}' | base64 -d | openssl x509 -noout -dates
   done
   ```

2. **Set up Monitoring**:
   - Monitor CSR approval rates
   - Alert on failed certificate rotations
   - Track certificate expiry dates

3. **Regular Audits**:
   - Review CSR history
   - Verify certificate purposes
   - Check for orphaned certificates

## Troubleshooting

### Common Issues

#### 1. CSR Not Approved
```bash
# Check CSR status
kubectl get csr -l auth.openkube.io/user=username

# Manual approval if needed
kubectl certificate approve username-csr
```

#### 2. Certificate Not Rotating
```bash
# Force rotation by deleting kubeconfig
kubectl delete secret username-kubeconfig -n kubeuser

# Trigger reconciliation
kubectl patch user username -p '{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"'$(date -Iseconds)'"}}}'
```

#### 3. Webhook Certificate Issues
```bash
# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager

# Check certificate events
kubectl describe certificate kubeuser-webhook-cert -n kubeuser

# Force certificate renewal
kubectl delete certificate kubeuser-webhook-cert -n kubeuser
```

#### 4. Private Key Issues
```bash
# Check private key secret
kubectl get secret username-key -n kubeuser

# Verify key format
kubectl get secret username-key -n kubeuser -o jsonpath='{.data.key\.pem}' | base64 -d | openssl rsa -check -noout
```

### Debug Commands

```bash
# View all certificate-related resources for a user
kubectl get secrets,csr -n kubeuser -l auth.openkube.io/user=username

# Check controller logs for certificate operations
kubectl logs -n kubeuser deployment/kubeuser-controller-manager | grep -i cert

# Verify kubeconfig functionality
kubectl --kubeconfig <(kubectl get secret username-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d) auth can-i get pods

# Check certificate chain
kubectl get secret username-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d | grep client-certificate-data | head -1 | awk '{print $2}' | base64 -d | openssl x509 -text -noout
```

## Configuration

### Rotation Threshold
The default rotation threshold is 30 days before expiry. This can be adjusted by modifying the controller code:

```go
// In ensureCertKubeconfig function
rotationThreshold := 30 * 24 * time.Hour // Adjust as needed
```

### Webhook Certificate Duration
Webhook certificate duration is configurable in Helm values:

```yaml
webhook:
  certManager:
    duration: 8760h # 1 year
    renewBefore: 2160h # 90 days before expiry
```

## Prerequisites

1. **cert-manager**: Required for webhook certificates
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
   ```

2. **RBAC Permissions**: Controller needs CSR management permissions:
   ```yaml
   - apiGroups: ["certificates.k8s.io"]
     resources: ["certificatesigningrequests"]
     verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]
   - apiGroups: ["certificates.k8s.io"]
     resources: ["certificatesigningrequests/approval"]
     verbs: ["update"]
   ```

## Best Practices

1. **Regular Monitoring**: Set up monitoring for certificate expiry and rotation
2. **Backup Strategy**: Include certificate secrets in backup procedures
3. **Testing**: Regularly test certificate rotation in non-production environments
4. **Documentation**: Keep certificate procedures documented for operations team
5. **Compliance**: Ensure certificate management meets organizational security policies

## Related Documentation

- [Webhook Validation](webhook-validation.md) - Details about admission webhook
- [User Management](../README.md) - Overall user management features
- [RBAC Integration](rbac-integration.md) - Role-based access control details