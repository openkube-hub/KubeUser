# Cluster Compatibility

KubeUser issues x509 client certificates through the Kubernetes CSR API. That
places two requirements on the cluster, and neither can be satisfied from
inside the operator:

1. **A signer that issues `client auth` certificates.** KubeUser submits a
   `CertificateSigningRequest` with `usages: ["client auth", "digital
   signature", "key encipherment"]` and
   `signerName: kubernetes.io/kube-apiserver-client` (configurable via
   `KUBEUSER_SIGNER_NAME`). Something in the control plane must sign it —
   upstream that is the `csrsigning` controller in `kube-controller-manager`.
2. **A signing CA the API server trusts for authentication.** The issued
   certificate is only usable if its CA chain is in the API server's
   `--client-ca-file`. The default signer satisfies this by definition. A
   custom signer satisfies it only if its CA was wired into the API server by
   the cluster operator.

A cluster that approves CSRs but never populates `.status.certificate`, or
whose signer uses a CA the API server does not trust for client auth, cannot
be served by KubeUser. The operator will keep the `User` in `Pending`
indefinitely — see
[Troubleshooting](troubleshooting.md#csr-stuck-at-approved--no-kubeconfig-secret).

---

## Compatibility Matrix

| Platform | Status | Notes |
|----------|--------|-------|
| kubeadm (upstream), kind, minikube | ✅ **Verified** | Default signer path; `make test-e2e` runs against kind |
| Kubespray | ✅ **Verified** | Verified end to end; bootstraps with kubeadm, so it inherits the layout below |
| RKE2 | ✅ **Verified** | Verified end to end with the default signer |
| k3s, k0s, Talos, MicroK8s | ✅ **Expected to work** | Follow the kubeadm layout: one cluster CA used for both signing and client auth; not covered by CI |
| Hand-rolled control planes | ⚠️ **Depends on your flags** | See [below](#hand-rolled-control-planes) |
| RKE1 | ⚠️ **Needs configuration** | Signing flags are not set by default; see [below](#hand-rolled-control-planes) |
| **Amazon EKS** | ❌ **Not supported** | The EKS signer refuses `client auth`; see [below](#amazon-eks) |
| GKE, AKS, other managed control planes | ⚠️ **Unverified** | No documented restriction, unlike EKS; run the [preflight check](#preflight-check) — see [Other managed providers](#other-managed-providers) |

"Expected to work" means the distribution uses the upstream signing path and
KubeUser has no platform-specific code for it — not that a maintainer has run
the end-to-end flow there. If you verify (or disprove) one of these, please
open a PR updating this table.

The installer is not what matters; the resulting flags are. kubeadm (and
therefore Kubespray) satisfies both requirements by default, because it points
signing and client auth at the same CA:

```
# kube-controller-manager
--cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt
--cluster-signing-key-file=/etc/kubernetes/pki/ca.key
# kube-apiserver
--client-ca-file=/etc/kubernetes/pki/ca.crt
```

## Hand-rolled Control Planes

If you assembled the control plane yourself rather than through a distribution,
"self-managed" is not a guarantee — the flags you chose decide it, and two
mistakes are easy to make:

| Misconfiguration | Result |
|------------------|--------|
| `kube-controller-manager` has no `--cluster-signing-cert-file` / `--cluster-signing-key-file`, or `csrsigning` is excluded from `--controllers` | CSR is approved and never issued — the same symptom as EKS, a different cause |
| The signing CA differs from the CA in the API server's `--client-ca-file` (common when the client CA is a separate intermediate) | Certificate issues fine, then every request is rejected `Unauthorized` |

Check both before deploying:

```bash
# On a control-plane node
ps aux | grep kube-controller-manager | tr ' ' '\n' | grep cluster-signing
ps aux | grep kube-apiserver | tr ' ' '\n' | grep client-ca-file
# The signing cert and the client CA should be the same file, or the signing
# CA must chain to a CA inside the client-ca-file bundle.
```

Then run the [preflight check](#preflight-check), which proves it end to end.

Distributions can land here too: RKE1 does not set the signing flags by
default (RKE2 does), so CSRs are approved and never issued until the cluster
config adds them:

```yaml
kube-controller:
  extra_args:
    cluster-signing-cert-file: /etc/kubernetes/ssl/kube-ca.pem
    cluster-signing-key-file: /etc/kubernetes/ssl/kube-ca-key.pem
```

---

## Preflight Check

Run this on any cluster before deploying KubeUser. It asks the cluster
directly whether it will issue a client-auth certificate — the exact thing
KubeUser depends on:

```bash
KEY=$(mktemp) CSR=$(mktemp)
openssl req -new -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CSR" \
  -subj "/CN=kubeuser-preflight"

cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: kubeuser-preflight
spec:
  request: $(base64 < "$CSR" | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages: ["client auth", "digital signature", "key encipherment"]
EOF

kubectl certificate approve kubeuser-preflight
sleep 5
kubectl get csr kubeuser-preflight
```

**Pass** — the cluster can run KubeUser:

```
NAME                 SIGNERNAME                                   CONDITION
kubeuser-preflight   kubernetes.io/kube-apiserver-client           Approved,Issued
```

**Fail** — the CSR stays `Approved` with an empty `.status.certificate`, or is
`Denied`/`Failed`. KubeUser cannot issue credentials on this cluster with this
signer.

Clean up:

```bash
kubectl delete csr kubeuser-preflight
rm -f "$KEY" "$CSR"
```

A signer can also issue from a CA the API server does not trust for client
auth, so confirm the certificate actually authenticates:

```bash
kubectl get csr kubeuser-preflight -o jsonpath='{.status.certificate}' \
  | base64 -d > /tmp/preflight.crt
API=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
curl -sk --cert /tmp/preflight.crt --key "$KEY" "$API/apis" \
  -o /dev/null -w '%{http_code}\n'
```

`200` or `403` is a pass — the certificate authenticated (`403` only means the
identity has no RBAC yet). `401` means the signing CA is not in the API
server's `--client-ca-file`.

---

## Amazon EKS

**KubeUser does not work on Amazon EKS**, and no configuration works around it.
EKS exposes no signer that issues client certificates. Its only user-facing
signer, `beta.eks.amazonaws.com/app-serving`, caps usages at
`["key encipherment", "digital signature", "server auth"]`, and the AWS
documentation states plainly:

> Client certificate signing is not supported.

— [Secure workloads with Kubernetes certificates](https://docs.aws.amazon.com/eks/latest/userguide/cert-signing.html)

`kubernetes.io/kube-apiserver-client` exists as an API value but nothing serves
it: CSRs reach `Approved` and are never issued, so the `User` stays in
`Pending` and no kubeconfig secret is ever created. Tracked as
[aws/containers-roadmap#1856](https://github.com/aws/containers-roadmap/issues/1856)
(open since October 2022). For the diagnostic walkthrough, see
[Troubleshooting](troubleshooting.md#csr-stuck-at-approved--no-kubeconfig-secret).

An external CA does not help either: a client certificate only authenticates if
its CA is in the API server's `--client-ca-file`, and EKS does not expose API
server flags. The limitation is in the authentication path, not the issuance
path.

EKS fails because AWS replaced the upstream signer, not because it is managed,
so do not generalize to other providers. One trap: **a provider whose nodes
bootstrap through the CSR API proves nothing about the user-facing signer**,
because kubelets use `kubernetes.io/kube-apiserver-client-kubelet`. Only the
[preflight check](#preflight-check) is evidence.

### What to use on EKS instead

- **EKS access entries** (`aws eks create-access-entry`) — the current,
  recommended path; maps IAM principals to Kubernetes groups.
- **`aws-auth` ConfigMap** — the legacy equivalent, still supported.
- **OIDC provider** — `aws eks associate-identity-provider-config`, for
  non-IAM identities.

---

## Other Managed Providers

No provider other than EKS documents a restriction on client-auth signing.
These are **Unverified** because nobody has run the flow on them, not because
anything is known to block them:

| Provider | Documented restriction | Notes |
|----------|------------------------|-------|
| GKE | None | The cluster root CA signs `certificates.k8s.io` CSRs and is what the API server validates client certificates against ([Cluster trust](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/cluster-trust)). `--no-issue-client-certificate` disables only *legacy* client-cert issuance, not the certificates API |
| AKS | None | With `--disable-local-accounts` and Entra integration, certificate identities run counter to the cluster's auth posture, and rotating cluster certificates to revoke local accounts invalidates KubeUser certificates too |
| DOKS, LKE, Civo, OKE, ACK, Scaleway, OVH | None found | Mostly near-upstream control planes |

Run the [preflight check](#preflight-check): one minute, and authoritative for
your cluster and version.

---

## Custom Signers

If your cluster runs a non-default signer whose CA is in the API server's
`--client-ca-file` (for example a cert-manager CA issuer fronting a custom
signer controller), point KubeUser at it:

```bash
helm install kubeuser kubeuser/kubeuser \
  --set signerName="<your-signer-name>" \
  --set rbac.signerResourceNames[0]="<your-signer-name>"
```

Both values are required: `signerName` selects the signer on the CSR, and
`rbac.signerResourceNames` grants the controller `approve` on that signer.
Setting only the first leaves the controller unable to approve its own CSRs.

To list the signers already in use on the cluster:

```bash
kubectl get csr -o jsonpath='{range .items[*]}{.spec.signerName}{"\n"}{end}' \
  | sort -u
```

Note that a signer appearing in that list is not proof it will sign a
client-auth request for you — run the [preflight check](#preflight-check)
against it by substituting the `signerName` field.
