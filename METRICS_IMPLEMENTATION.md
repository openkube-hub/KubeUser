# Prometheus Metrics Implementation Summary

This document summarizes the Prometheus metrics implementation for KubeUser.

## What Was Implemented

### 1. Metrics Package (`internal/controller/metrics/`)

- **metrics.go**: Defines all Prometheus metrics (counters, gauges, histograms)
- **recorder.go**: Provides a clean API for recording metrics
- **helpers.go**: Error classification utilities for metrics labels
- **Tests**: Full test coverage for metrics functionality

### 2. Metrics Integration

Metrics are integrated throughout the controller:

- **Controller**: Reconciliation timing, success/error rates, user sync status
- **Rotation Manager**: Certificate rotation operations, duration, errors
- **Main**: Metrics recorder initialization and dependency injection

### 3. Metrics Categories

#### Certificate Operations
- `kubeuser_cert_rotations_total` - Total rotations by status
- `kubeuser_cert_rotation_duration_seconds` - Rotation duration histogram
- `kubeuser_cert_rotation_errors_total` - Errors by type

#### User Status
- `kubeuser_users_total` - Total users by status
- `kubeuser_user_sync_status` - Individual user sync status

#### Performance
- `kubeuser_reconciliations_total` - Reconciliation attempts
- `kubeuser_reconcile_duration_seconds` - Reconciliation duration
- `kubeuser_workqueue_depth` - Work queue depth

#### Thundering Herd Protection
- `kubeuser_concurrent_rotations` - Active rotations
- `kubeuser_rotation_queue_length` - Pending rotations
- `kubeuser_throttled_rotations_total` - Throttled operations

#### Certificate Expiry
- `kubeuser_cert_expiry_timestamp_seconds` - Expiry timestamps
- `kubeuser_certs_expiring_24h` - Certs expiring within 24h
- `kubeuser_certs_expiring_7d` - Certs expiring within 7 days

## Files Modified

1. `internal/controller/metrics/metrics.go` - NEW
2. `internal/controller/metrics/recorder.go` - NEW
3. `internal/controller/metrics/helpers.go` - NEW
4. `internal/controller/metrics/recorder_test.go` - NEW
5. `internal/controller/metrics/helpers_test.go` - NEW
6. `internal/controller/user_controller.go` - MODIFIED (added metrics tracking)
7. `internal/controller/renewal/rotation.go` - MODIFIED (added metrics tracking)
8. `internal/controller/auth/auth.go` - MODIFIED (metrics parameter)
9. `internal/controller/auth/x509.go` - MODIFIED (metrics parameter)
10. `cmd/main.go` - MODIFIED (metrics initialization)
11. Test files - MODIFIED (updated function signatures)

## Documentation

1. `docs/metrics.md` - Complete metrics reference with examples
2. `docs/accessing-metrics.md` - Guide for accessing metrics
3. `hack/test-metrics.sh` - Script to test metrics endpoint

## How to Use

### Local Development

```bash
# Terminal 1: Run the controller
make run

# Terminal 2: View metrics
curl -k https://localhost:8443/metrics

# Or use the test script
./hack/test-metrics.sh

# Or watch continuously
watch -n 2 'curl -sk https://localhost:8443/metrics | grep kubeuser'
```

### Production Deployment

```bash
# Deploy with Prometheus monitoring
cd config/default
kustomize edit add resource ../prometheus
make deploy

# Metrics are automatically scraped by Prometheus via ServiceMonitor
```

### Example Queries

```promql
# Certificate rotation rate
rate(kubeuser_cert_rotations_total[5m])

# Success rate
sum(rate(kubeuser_cert_rotations_total{status="success"}[5m])) 
/ sum(rate(kubeuser_cert_rotations_total[5m]))

# P95 rotation duration
histogram_quantile(0.95, rate(kubeuser_cert_rotation_duration_seconds_bucket[5m]))

# Certificates expiring soon
kubeuser_certs_expiring_24h > 0
```

## Testing

All tests pass:
```bash
go test ./internal/controller/metrics/... -v
go test ./internal/controller/... -short
go build ./cmd/main.go
```

## Architecture

The metrics implementation follows these principles:

1. **Separation of Concerns**: Metrics logic is isolated in its own package
2. **Dependency Injection**: Metrics recorder is passed through constructors
3. **Nil-Safe**: All metrics calls check for nil recorder (tests can pass nil)
4. **Minimal Overhead**: Metrics recording is fast and non-blocking
5. **Standard Labels**: Consistent labeling across all metrics

## Next Steps

1. Create Grafana dashboards for visualization
2. Set up alerting rules in Prometheus
3. Add more granular metrics as needed
4. Monitor metrics in production to tune thresholds
