# Troubleshooting

Common diagnostic commands for the most frequent failure modes when running
KubeUser. Run these against the namespace where the controller is installed
(`kubeuser` in the examples below — adjust if you used a different release
namespace).

## Controller Pod Not Starting

```bash
kubectl get pods -n kubeuser
kubectl logs -n kubeuser deployment/kubeuser-controller-manager
kubectl get events -n kubeuser --sort-by=.lastTimestamp
```

**Common causes:** missing cert-manager, webhook certificate not ready, image pull issues.

## Webhook Certificate Issues

```bash
kubectl get certificates -n kubeuser
kubectl describe certificate kubeuser-webhook-cert -n kubeuser
kubectl logs -n cert-manager deployment/cert-manager
```

## User Creation Fails

```bash
kubectl describe user <username>
kubectl logs -n kubeuser deployment/kubeuser-controller-manager | grep -i error
```

**Common causes:** referenced Role/ClusterRole does not exist, target namespace does not exist, webhook validation failure.

## Certificate Generation Issues

```bash
kubectl get csr -l auth.openkube.io/user=<username>
kubectl describe csr <csr-name>
kubectl auth can-i create certificatesigningrequests \
  --as=system:serviceaccount:kubeuser:kubeuser-controller-manager
```
