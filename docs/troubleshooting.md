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

## CSR Stuck at `Approved` — No Kubeconfig Secret

**Symptom:** the `User` stays in `Pending`, `<username>-key` exists but
`<username>-kubeconfig` never appears, and the controller logs
`Waiting for certificate to be issued` on every reconcile.

```bash
kubectl get csr -l auth.openkube.io/user=<username>
# CONDITION reads "Approved" and never becomes "Approved,Issued"

kubectl get csr <csr-name> -o jsonpath='{.status.certificate}' | wc -c
# 0 — nothing has been signed
```

This means the cluster approved the request but no signer issued a
certificate. KubeUser cannot resolve this on its own; it keeps requeueing
because the certificate may still arrive.

**Causes, most common first:**

1. **The control plane does not sign `client auth` CSRs.** This is the case on
   Amazon EKS, where client certificate signing is unsupported — there is no
   working configuration. See
   [Cluster Compatibility](cluster-compatibility.md#amazon-eks).
2. **`KUBEUSER_SIGNER_NAME` points at a signer with no controller behind it.**
   The CSR is accepted and approved, then nothing picks it up. Confirm the
   signer is actually implemented by your cluster:
   ```bash
   kubectl get deploy -n kubeuser kubeuser-controller-manager \
     -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="KUBEUSER_SIGNER_NAME")].value}{"\n"}'
   ```
3. **`csrsigning` is unhealthy in `kube-controller-manager`** (self-managed
   control planes). Check its logs and that `--cluster-signing-cert-file` /
   `--cluster-signing-key-file` are set.

Confirm which case you are in with the
[preflight check](cluster-compatibility.md#preflight-check) — it reproduces the
same request without KubeUser in the loop.

## Kubeconfig Issued but `Unauthorized`

The certificate was signed, but by a CA the API server does not trust for
client authentication. This happens with a custom `signerName` whose CA was
never added to the API server's `--client-ca-file`.

```bash
kubectl --kubeconfig <user>.kubeconfig get pods
# error: You must be logged in to the server (Unauthorized)
```

An RBAC `forbidden` error is *not* this problem — it means authentication
succeeded and the user simply lacks permissions; fix `spec.roles` /
`spec.clusterRoles` instead.
