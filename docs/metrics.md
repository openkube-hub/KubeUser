# Prometheus Metrics

KubeUser exposes Prometheus metrics for monitoring certificate operations, user status, and controller performance.

## Metrics Endpoint

Metrics are exposed on the controller's metrics endpoint (default: `:8443/metrics` with TLS).

## Available Metrics

### Certificate Operations

#### `kubeuser_cert_rotations_total`
Counter tracking total certificate rotations.

Labels:
- `namespace`: User namespace
- `user`: User name
- `status`: Rotation status (`success`, `failure`)

#### `kubeuser_cert_rotation_duration_seconds`
Histogram tracking certificate rotation duration.

Labels:
- `namespace`: User namespace

Buckets: 0.1, 0.5, 1, 2, 5, 10, 30 seconds

#### `kubeuser_cert_rotation_errors_total`
Counter tracking certificate rotation errors.

Labels:
- `namespace`: User namespace
- `user`: User name
- `error_type`: Error category (`csr_approval`, `atomic_flip`, `shadow_secret_check`, etc.)

### User Status

#### `kubeuser_users_total`
Gauge tracking total number of managed users.

Labels:
- `namespace`: User namespace
- `status`: User status (`active`, `pending`, `error`, `renewing`)

#### `kubeuser_user_sync_status`
Gauge tracking user sync status (1=synced, 0=pending).

Labels:
- `namespace`: User namespace
- `user`: User name

### Performance Metrics

#### `kubeuser_reconciliations_total`
Counter tracking total reconciliation attempts.

Labels:
- `controller`: Controller name (e.g., `user`)
- `result`: Reconciliation result (`success`, `error`, `requeued`, `deleted`, `not_found`)

#### `kubeuser_reconcile_duration_seconds`
Histogram tracking reconciliation loop duration.

Labels:
- `controller`: Controller name

Buckets: Exponential from 0.001s (2^15 buckets)

#### `kubeuser_workqueue_depth`
Gauge tracking current work queue depth.

Labels:
- `controller`: Controller name

### Thundering Herd Protection

#### `kubeuser_concurrent_rotations`
Gauge tracking number of concurrent certificate rotations.

#### `kubeuser_rotation_queue_length`
Gauge tracking number of pending rotations in queue.

#### `kubeuser_throttled_rotations_total`
Counter tracking rotations throttled to prevent thundering herd.

### Certificate Expiry Tracking

#### `kubeuser_cert_expiry_timestamp_seconds`
Gauge tracking certificate expiry time as Unix timestamp.

Labels:
- `namespace`: User namespace
- `user`: User name
- `cert_type`: Certificate type (e.g., `client`)

#### `kubeuser_certs_expiring_24h`
Gauge tracking number of certificates expiring within 24 hours.

Labels:
- `namespace`: User namespace

#### `kubeuser_certs_expiring_7d`
Gauge tracking number of certificates expiring within 7 days.

Labels:
- `namespace`: User namespace

## Example Queries

### Certificate Rotation Rate
```promql
rate(kubeuser_cert_rotations_total[5m])
```

### Certificate Rotation Success Rate
```promql
sum(rate(kubeuser_cert_rotations_total{status="success"}[5m])) 
/ 
sum(rate(kubeuser_cert_rotations_total[5m]))
```

### Average Rotation Duration
```promql
histogram_quantile(0.95, rate(kubeuser_cert_rotation_duration_seconds_bucket[5m]))
```

### Certificates Expiring Soon
```promql
sum by (namespace) (kubeuser_certs_expiring_24h)
```

### Reconciliation Error Rate
```promql
rate(kubeuser_reconciliations_total{result="error"}[5m])
```

### Controller Performance
```promql
histogram_quantile(0.99, rate(kubeuser_reconcile_duration_seconds_bucket[5m]))
```

## Alerting Rules

Example Prometheus alerting rules:

```yaml
groups:
  - name: kubeuser
    rules:
      - alert: HighCertRotationFailureRate
        expr: |
          sum(rate(kubeuser_cert_rotations_total{status="failure"}[5m])) 
          / 
          sum(rate(kubeuser_cert_rotations_total[5m])) > 0.1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High certificate rotation failure rate"
          description: "{{ $value | humanizePercentage }} of rotations are failing"

      - alert: CertificatesExpiringSoon
        expr: kubeuser_certs_expiring_24h > 0
        for: 1h
        labels:
          severity: critical
        annotations:
          summary: "Certificates expiring within 24 hours"
          description: "{{ $value }} certificates in {{ $labels.namespace }} expire within 24h"

      - alert: SlowReconciliation
        expr: |
          histogram_quantile(0.99, 
            rate(kubeuser_reconcile_duration_seconds_bucket[5m])
          ) > 30
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "Slow reconciliation performance"
          description: "P99 reconciliation time is {{ $value }}s"

      - alert: HighRotationQueueDepth
        expr: kubeuser_rotation_queue_length > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High rotation queue depth"
          description: "{{ $value }} rotations pending in queue"
```

## Grafana Dashboard

A sample Grafana dashboard JSON is available in `config/grafana/dashboard.json` (to be created).

Key panels to include:
- Certificate rotation rate and success rate
- Rotation duration histogram
- Active users by namespace
- Certificates expiring soon
- Reconciliation performance
- Error rates by type
