# Auto-Renewal Feature for KubeUser

## Overview

The Auto-Renewal feature provides production-grade automatic certificate renewal for KubeUser with intelligent renewal logic, forward secrecy, and zero-downtime rotation. The system uses a stateful rotation approach with Shadow Secret pattern for atomic certificate updates.

## Key Features

- **Smart Renewal Logic**: Hierarchical renewal calculation (Custom renewBefore > 33% Rule > Safety Floor)
- **Forward Secrecy**: Generates new RSA private keys for each renewal
- **Zero-Downtime**: Atomic secret updates with rollback capability
- **Stateful Rotation**: Shadow Secret pattern ensures resumable operations
- **Thundering Herd Prevention**: Jitter-based requeue scheduling (up to 5 minutes)
- **Short-lived Certificate Support**: Handles certificates as short as 10 minutes
- **Comprehensive Observability**: Status conditions, renewal history, and deterministic CSR naming

## Configuration

### Basic Auto-Renewal

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  auth:
    type: x509        # Default, can be omitted
    ttl: "24h"        # Default is 2160h (3 months)
    autoRenew: true   # Enable auto-renewal (default: false)
```

This configuration uses the default 33% rule: the certificate will be renewed when 33% of its lifetime remains (after 16 hours for a 24-hour certificate).

### Custom Renewal Timing

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob
spec:
  auth:
    type: x509
    ttl: "2h"
    autoRenew: true
    renewBefore: "30m"  # Renew 30 minutes before expiry
```

### Short-lived Certificates

```yaml
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: charlie
spec:
  auth:
    type: x509
    ttl: "24h"         # KubeUser production minimum (24 hours)
    autoRenew: true
    renewBefore: "8h"  # Renew 8 hours before expiry
```

**Note:** 
- **Production Minimum:** KubeUser enforces a 24-hour minimum TTL to prevent Thundering Herd loops
- **Testing Override:** The `KUBEUSER_MIN_DURATION` environment variable can override this for CI/CD (not exposed in Helm)
- **Kubernetes CSR API:** Technical minimum is 3 minutes, but KubeUser enforces 24 hours for operational safety

## Renewal Logic Hierarchy

The system follows this strict hierarchy when determining renewal time:

1. **Custom `renewBefore`**: If specified and valid, renew this duration before expiry
2. **33% Rule**: Default cert-manager behavior (renew when 33% of lifetime remains)
3. **Fixed Safety Floor**: 15-minute minimum buffer to ensure propagation reliability in high-latency clusters

### Validation and Auto-Correction

The system automatically validates aggressive renewal settings:

- **90% Cap**: `renewBefore` cannot exceed 90% of certificate TTL
- **Fixed Safety Floor**: Ensures minimum 15-minute buffer for propagation reliability
- **Strict Validation**: Invalid settings are rejected with clear error messages (fail-fast)
- **Duration Limits**: Enforces 24-hour minimum TTL and 1-year maximum

### Examples

| Certificate TTL | renewBefore | Actual Renewal Time | Logic Used | Notes |
|----------------|-------------|-------------------|------------|-------|
| 24h | (not set) | After 16h | 33% rule | Standard behavior |
| 24h | 6h | After 18h | Custom renewBefore | User override |
| 24h | 1h | After 22h | Custom renewBefore | Short renewal window |
| 72h | (not set) | After 48h | 33% rule | 3-day certificate |
| 72h | 24h | After 48h | Custom renewBefore | 1-day before expiry |

## Status Fields

The User status includes several fields for monitoring renewal:

```yaml
status:
  phase: "Active"
  expiryTime: "2026-01-22T10:30:00Z"
  nextRenewalAt: "2026-01-22T02:30:00Z"  # Only shown when autoRenew: true
  conditions:
  - type: Ready
    status: "True"
    reason: UserProvisioned
    message: Certificate is valid and active
  - type: Renewing
    status: "False"
    reason: RenewalComplete
    message: Latest renewal cycle finished successfully
  renewalHistory:
  - timestamp: "2026-01-21T10:30:00Z"
    success: true
    message: Certificate rotation completed successfully
    csrName: alice-renewal-a1b2c3d4
```

**Important**: The `nextRenewalAt` field only appears when `autoRenew: true`. When auto-renewal is disabled, this field is automatically cleared.

## Stateful Certificate Rotation Process

The rotation uses a Shadow Secret pattern for atomic, resumable operations:

### Phase 1: Initialization
1. **Check Shadow Secret**: Look for existing rotation state (`{username}-rotation-temp`)
2. **Generate New Key**: Create new RSA-2048 private key for forward secrecy
3. **Create Shadow Secret**: Store key and deterministic CSR name
4. **Record Progress**: Log successful state creation

### Phase 2: CSR Management
5. **Create CSR**: Generate CSR with deterministic name (`{username}-renewal-{uid8}`)
6. **Auto-Approve**: Controller validates and approves its own CSRs
7. **Wait for Certificate**: Monitor until signed certificate is available

### Phase 3: Atomic Update
8. **Backup Secrets**: Store current key and kubeconfig for rollback
9. **Update Key Secret**: Replace `{username}-key` with new private key
10. **Update Kubeconfig**: Replace `{username}-kubeconfig` with new certificate
11. **Rollback on Failure**: Restore previous secrets if update fails

### Phase 4: Cleanup
12. **Delete Shadow Secret**: Remove temporary rotation state
13. **Delete CSR**: Clean up certificate signing request
14. **Update Status**: Set new expiry time and next renewal time

## Requeue Strategy

The controller uses intelligent requeue scheduling to minimize API server load:

### Smart Calculation Priority
1. **NextRenewalAt**: Uses pre-calculated renewal time from status (most efficient)
2. **Certificate Expiry**: Calculates from certificate expiry time (fallback)
3. **Default**: 30-minute intervals when no certificate info available

### Jitter and Bounds
- **Jitter**: Adds random delay up to 5 minutes to prevent thundering herd
- **Minimum**: 1 minute (prevents excessive API calls)
- **Maximum**: 24 hours (reasonable upper bound)
- **Immediate**: Requeues immediately when renewal time is reached

### Rotation-Specific Requeuing
During active rotation, requeue intervals are based on certificate duration:
- **Short-lived (< 1 hour)**: 10 seconds (aggressive)
- **Medium-lived (< 24 hours)**: 30 seconds (moderate)
- **Long-lived (≥ 24 hours)**: 2 minutes (conservative)

## Observability

### Status Conditions

The system maintains standard Kubernetes conditions:

- **Ready**: Indicates if the user's certificate is valid and ready
- **Renewing**: Shows if a renewal is currently in progress

### Renewal History

The last 10 renewal attempts are tracked with deduplication:

```yaml
renewalHistory:
- timestamp: "2026-01-21T10:30:00Z"
  success: true
  message: "Initiated rotation: Shadow secret created"
  csrName: "alice-renewal-a1b2c3d4"
- timestamp: "2026-01-21T10:31:00Z"
  success: true
  message: "Certificate rotation completed successfully"
  csrName: "alice-renewal-a1b2c3d4"
```

### Monitoring with kubectl

```bash
# Check user status
kubectl get users alice -o wide

# View detailed status including renewal history
kubectl describe user alice

# Check if NextRenewalAt is set (only when autoRenew: true)
kubectl get user alice -o jsonpath='{.status.nextRenewalAt}'

# Monitor renewal progress
kubectl get user alice -o jsonpath='{.status.renewalHistory[*]}'

# Check for rotation secrets
kubectl get secrets -l auth.openkube.io/rotation=true
```

## Validation Rules

### Certificate Duration
- **Kubernetes CSR Minimum**: 3 minutes (Kubernetes CSR API requirement)
- **KubeUser Minimum**: 10 minutes (enforced for practical usability)
- **Maximum TTL**: 1 year (365 days) - based on Kubernetes controller default `--cluster-signing-duration` flag
- **Default TTL**: 2160h (3 months)

**Note**: The 1-year maximum is the default value set by the Kubernetes controller's `--cluster-signing-duration` flag. This can be changed by cluster administrators, but KubeUser enforces the 1-year limit for consistency and security best practices.

### Renewal Configuration
- `autoRenew`: Boolean (default: false)
- `renewBefore`: Must be positive duration if specified
- `renewBefore`: Cannot exceed 90% of certificate TTL
- `renewBefore`: Must leave at least 15 minutes of certificate life (fixed safety floor)

### Duration Constraints
- **Kubernetes CSR API**: Allows minimum 3 minutes via `expirationSeconds`
- **KubeUser Production Enforcement**: 24-hour minimum for operational safety
- **Testing Override**: `KUBEUSER_MIN_DURATION` environment variable (not exposed in Helm)
- **Maximum Duration**: 1 year (based on default `--cluster-signing-duration` flag)
- **Cluster Administrator Note**: The maximum can be adjusted by changing the Kubernetes controller's `--cluster-signing-duration` flag, but KubeUser maintains the 1-year limit for security consistency

### Validation Behavior
Invalid `renewBefore` values are rejected with clear error messages:
- Settings exceeding 90% of TTL are rejected (prevents aggressive renewal loops)
- Settings leaving less than 15 minutes of certificate life are rejected (safety floor)
- Both webhook and controller enforce these rules (fail-fast architecture)

## Error Handling and Recovery

### Stateful Recovery
- **Shadow Secret**: Rotation state persists across controller restarts
- **Deterministic CSR Names**: Uses User UID for uniqueness and idempotency
- **Resumable Operations**: Can continue from any point in rotation process

### Error Scenarios
- **CSR Creation Failures**: Retries with rotation-specific intervals
- **Approval Failures**: Validates CSR security before auto-approval
- **Certificate Unavailable**: Continues monitoring until available
- **Secret Update Failures**: Atomic rollback to previous state
- **Network Issues**: Uses controller-runtime's built-in retry logic

### Cleanup and Resource Management
- **Automatic Cleanup**: Removes Shadow Secrets and CSRs after successful rotation
- **Owner References**: Ensures proper garbage collection when User is deleted
- **Resource Limits**: Renewal history capped at 10 entries with deduplication

## Performance Considerations

### Efficient Status Checking
- **Primary**: Uses `nextRenewalAt` from status (no certificate parsing needed)
- **Fallback**: Parses certificate expiry only when status unavailable
- **Caching**: Leverages controller-runtime's built-in caching

### Load Distribution
- **Jittered Requeues**: Prevents API server overload during mass renewals
- **Bounded Intervals**: Reasonable limits prevent excessive reconciliation
- **Smart Scheduling**: Different intervals for different certificate durations

### Resource Optimization
- **Deterministic Naming**: Prevents resource accumulation
- **Automatic Cleanup**: Removes temporary resources after completion
- **Owner References**: Proper garbage collection lifecycle

## Migration and Configuration Changes

### Enabling Auto-Renewal
Existing users can enable auto-renewal by adding `autoRenew: true`:
1. Controller calculates renewal time from current certificate expiry
2. Sets `nextRenewalAt` in status for efficient scheduling
3. Begins automatic renewal cycles

### Disabling Auto-Renewal
When `autoRenew` is changed to `false`:
1. `nextRenewalAt` field is immediately cleared from status
2. No further automatic renewals are scheduled
3. Certificate remains valid until natural expiry

### Changing Renewal Settings
- `renewBefore` changes take effect on next renewal calculation
- Invalid settings are auto-corrected with explanatory messages
- Changes are reflected in `nextRenewalAt` field

## Troubleshooting

### Common Issues

1. **NextRenewalAt Not Appearing**
   - Verify `autoRenew: true` is set
   - Check that certificate has valid expiry time
   - Review controller logs for validation errors

2. **Renewal Not Triggering**
   - Check current time vs `nextRenewalAt`
   - Verify controller is running and has proper RBAC
   - Review renewal history for error messages

3. **Rotation Stuck in Progress**
   - Check for Shadow Secret: `kubectl get secrets -l auth.openkube.io/shadow=true`
   - Review CSR status: `kubectl get csr -l auth.openkube.io/rotation=true`
   - Check controller logs for specific errors

### Debug Commands

```bash
# Check controller logs
kubectl logs -n kubeuser-system deployment/kubeuser-controller-manager

# List rotation-related resources
kubectl get secrets -l auth.openkube.io/rotation=true
kubectl get csr -l auth.openkube.io/rotation=true

# Check certificate expiry
kubectl get secret alice-kubeconfig -o jsonpath='{.data.config}' | base64 -d | \
  grep client-certificate-data | base64 -d | openssl x509 -noout -dates

# Monitor renewal status
kubectl get user alice -o jsonpath='{.status}' | jq .
```

## Security Considerations

### Forward Secrecy
- **New Private Keys**: Generated for each renewal (RSA-2048)
- **No Key Reuse**: Previous keys are completely replaced
- **Secure Generation**: Uses crypto/rand for key generation

### Atomic Operations
- **Zero-Downtime**: Secrets updated atomically
- **Rollback Capability**: Failed updates are automatically rolled back
- **No Mismatched Pairs**: Key and certificate always match

### CSR Security
- **Auto-Approval Validation**: Strict validation before approval
- **Label-Based Security**: Only approves CSRs with proper labels
- **Deterministic Names**: Prevents CSR name collisions
- **Cleanup**: CSRs removed after successful rotation

### Audit and Compliance
- **Complete History**: All renewal attempts logged
- **Deterministic Operations**: Reproducible and auditable
- **Owner References**: Clear resource ownership and lifecycle

## Future Enhancements

- **Certificate Authority Rotation**: Support for CA certificate updates
- **External CA Integration**: Support for external certificate authorities  
- **Webhook Notifications**: Configurable webhooks for renewal events
- **Metrics Integration**: Prometheus metrics for renewal monitoring
- **Advanced Scheduling**: More sophisticated renewal timing algorithms