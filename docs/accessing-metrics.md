# Accessing Prometheus Metrics

This guide shows you how to access and view the Prometheus metrics exposed by KubeUser.

## Local Development (make run)

When running the controller locally with `make run`, metrics are exposed on `https://localhost:8443/metrics` by default (with self-signed TLS).

### Option 1: Using curl (Quick Check)

```bash
# Run the controller
make run

# In another terminal, access metrics (skip TLS verification for local dev)
curl -k https://localhost:8443/metrics
```

You should see output like:
```
# HELP kubeuser_cert_rotations_total Total number of certificate rotations
# TYPE kubeuser_cert_rotations_total counter
kubeuser_cert_rotations_total{namespace="default",status="success",user="alice"} 5
...
```

### Option 2: Using kubectl port-forward (Cluster Deployment)

If you've deployed the controller to a cluster:

```bash
# Deploy the controller
make deploy

# Port-forward the metrics service
kubectl port-forward -n kubeuser-system svc/kubeuser-controller-manager-metrics-service 8443:8443

# In another terminal, access metrics
curl -k https://localhost:8443/metrics
```

### Option 3: Prometheus Scraping (Production)

For production monitoring, configure Prometheus to scrape the metrics endpoint.

#### 1. Install Prometheus Operator (if not already installed)

```bash
kubectl apply -f https://raw.githubusercontent.com/prometheus-operator/prometheus-operator/main/bundle.yaml
```

#### 2. Apply the ServiceMonitor

The ServiceMonitor is already configured in `config/prometheus/monitor.yaml`:

```bash
# Enable Prometheus monitoring in kustomization
cd config/default
kustomize edit add resource ../prometheus

# Deploy with Prometheus monitoring
make deploy
```

#### 3. Access Prometheus UI

```bash
# Port-forward to Prometheus
kubectl port-forward -n monitoring svc/prometheus-operated 9090:9090

# Open in browser
open http://localhost:9090
```

## Viewing Metrics

### Using Prometheus UI

1. Navigate to `http://localhost:9090`
2. Go to "Graph" tab
3. Try these example queries:

**Certificate rotation rate:**
```promql
rate(kubeuser_cert_rotations_total[5m])
```

**Success rate:**
```promql
sum(rate(kubeuser_cert_rotations_total{status="success"}[5m])) 
/ 
sum(rate(kubeuser_cert_rotations_total[5m]))
```

**Certificates expiring soon:**
```promql
kubeuser_certs_expiring_24h
```

**P95 rotation duration:**
```promql
histogram_quantile(0.95, rate(kubeuser_cert_rotation_duration_seconds_bucket[5m]))
```

### Using Grafana

1. Install Grafana:
```bash
kubectl apply -f https://raw.githubusercontent.com/grafana/grafana/main/deploy/kubernetes/grafana.yaml
```

2. Port-forward to Grafana:
```bash
kubectl port-forward -n monitoring svc/grafana 3000:3000
```

3. Access Grafana at `http://localhost:3000` (default: admin/admin)

4. Add Prometheus as a data source:
   - Configuration → Data Sources → Add data source
   - Select Prometheus
   - URL: `http://prometheus-operated:9090`
   - Save & Test

5. Import a dashboard or create custom panels using the metrics from `docs/metrics.md`

## Testing Metrics Locally

To generate some metrics for testing:

```bash
# Run the controller
make run

# In another terminal, create a test user
kubectl apply -f config/samples/auth_v1alpha1_user.yaml

# Watch the metrics update
watch -n 2 'curl -sk https://localhost:8443/metrics | grep kubeuser'
```

## Metrics Configuration

### Change Metrics Port

Edit `cmd/main.go` or use the flag:

```bash
go run ./cmd/main.go --metrics-bind-address=:8080 --metrics-secure=false
```

### Disable Metrics

```bash
go run ./cmd/main.go --metrics-bind-address=0
```

### Enable HTTP (No TLS)

For local development only:

```bash
go run ./cmd/main.go --metrics-bind-address=:8080 --metrics-secure=false
```

Then access via:
```bash
curl http://localhost:8080/metrics
```

## Troubleshooting

### "Connection refused"

- Ensure the controller is running: `make run`
- Check the metrics port in the logs: look for "Starting metrics server"
- Verify the port isn't blocked by firewall

### "Certificate verify failed"

Use `-k` flag with curl to skip TLS verification in development:
```bash
curl -k https://localhost:8443/metrics
```

### No metrics showing up

- Create some User resources to generate metrics
- Check controller logs for errors
- Verify metrics are registered: `curl -k https://localhost:8443/metrics | grep kubeuser`

### Prometheus not scraping

- Check ServiceMonitor is created: `kubectl get servicemonitor -n kubeuser-system`
- Verify Prometheus has RBAC permissions to scrape the namespace
- Check Prometheus targets: Prometheus UI → Status → Targets

## Next Steps

- See `docs/metrics.md` for complete metrics reference
- Set up alerting rules for production monitoring
- Create Grafana dashboards for visualization
