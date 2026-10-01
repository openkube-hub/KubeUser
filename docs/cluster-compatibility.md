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
indefinitely — see [Symptoms](#symptoms-of-an-incompatible-signer).

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

Distributions can land here too. RKE1, for example, does not set the signing
flags by default; CSRs are approved and never issued until the cluster
configuration enables them:

```yaml
kube-controller:
  extra_args:
    cluster-signing-cert-file: /etc/kubernetes/ssl/kube-ca.pem
    cluster-signing-key-file: /etc/kubernetes/ssl/kube-ca-key.pem
```

(RKE2 is unaffected — it is verified above.)

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

If the check passes, confirm the issued certificate actually authenticates —
a signer can issue from a CA the API server does not trust for client auth:

```bash
kubectl get csr kubeuser-preflight -o jsonpath='{.status.certificate}' \
  | base64 -d > /tmp/preflight.crt
# Build a kubeconfig with /tmp/preflight.crt + "$KEY" and expect
# "Unauthorized" to be absent (RBAC "forbidden" is a pass — it means the
# certificate authenticated).
```

---

## Amazon EKS

**KubeUser does not work on Amazon EKS.** This is a platform limitation, not a
bug in KubeUser, and there is no configuration that works around it.

EKS does not expose a signer that issues client certificates. Its only
user-facing signer is `beta.eks.amazonaws.com/app-serving`, and the AWS
documentation states its permitted key usages are limited to
`["key encipherment", "digital signature", "server auth"]`, adding plainly:

> Client certificate signing is not supported.

— [Secure workloads with Kubernetes certificates](https://docs.aws.amazon.com/eks/latest/userguide/cert-signing.html)

`kubernetes.io/kube-apiserver-client` exists on EKS as an API value, but the
managed control plane runs no signer behind it: CSRs reach `Approved` and are
never issued. This is tracked upstream as
[aws/containers-roadmap#1856](https://github.com/aws/containers-roadmap/issues/1856)
(open since October 2022).

### EKS is an outlier, not the rule for managed Kubernetes

EKS fails because AWS replaced the upstream `csrsigning` behavior with its own
signer that caps usages at `server auth`. That is an EKS-specific decision, not
a property of running a managed control plane, so do not assume GKE, AKS or any
other provider behaves the same way — none of them documents an equivalent
restriction.

One trap is worth naming, because it is how EKS misleads: **a provider whose
nodes bootstrap through the CSR API tells you nothing about the user-facing
signer.** Kubelet certificates use a different signer
(`kubernetes.io/kube-apiserver-client-kubelet`), and a provider can keep that
one working for node bootstrap while leaving `kubernetes.io/kube-apiserver-client`
unserved. Seeing node CSRs reach `Approved,Issued` is not evidence that
KubeUser will work. Only the [preflight check](#preflight-check) is.

### Symptoms of an incompatible signer

What you see on EKS, and on any cluster that fails the preflight check:

```bash
$ kubectl get user alice
NAME    PHASE     AUTORENEW   EXPIRY   NEXTRENEWAL   AGE
alice   Pending   true                               6m

$ kubectl get csr -l auth.openkube.io/user=alice
NAME    SIGNERNAME                            CONDITION
alice   kubernetes.io/kube-apiserver-client   Approved          # never "Approved,Issued"

$ kubectl get secret -n kubeuser | grep alice
alice-key          Opaque   1   6m                              # created
                                                                # alice-kubeconfig never appears
```

Controller logs repeat, by design, until the certificate appears:

```
INFO  Waiting for certificate to be issued   {"csr": "alice"}
```

The `User` stays in `Pending`, the private key secret exists, and the
`<username>-kubeconfig` secret is never created because there is no
certificate to put in it.

Swapping in an external CA does not help either. A client certificate only
authenticates if its CA is in the API server's `--client-ca-file`, and EKS does
not expose API server flags — so a certificate from cert-manager, Vault or AWS
Private CA would be issued successfully and still be rejected as
`Unauthorized`. The limitation is in the authentication path, not the issuance
path.

### What to use on EKS instead

EKS authenticates users through IAM, not x509:

- **EKS access entries** (`aws eks create-access-entry`) — the current,
  recommended path; maps IAM principals to Kubernetes groups/access policies.
- **`aws-auth` ConfigMap** — the legacy equivalent, still supported.
- **OIDC provider** — associate an external IdP with the cluster
  (`aws eks associate-identity-provider-config`) for non-IAM identities.

The same reasoning applies to any managed control plane that does not sign
client-auth CSRs: use the platform's own identity integration.

---

---

## Other Managed Providers

GKE and AKS are marked **Unverified** rather than supported or unsupported,
deliberately:

- **GKE** — the cluster root CA both signs CSRs submitted through
  `certificates.k8s.io` and is what the API server uses to validate client
  certificates, which is the combination KubeUser needs
  ([Cluster trust](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/cluster-trust)).
  Google documents no restriction on client-auth signing, and
  `--no-issue-client-certificate` disables only *legacy* GKE client-certificate
  issuance, not the certificates API. Nothing documented blocks KubeUser, but
  Google does not document the user-facing signer's behavior either.
- **AKS** — no documented restriction on client-auth CSRs. Note separately
  that on clusters with `--disable-local-accounts` and Microsoft Entra
  integration, certificate-based identities run counter to the cluster's
  intended auth posture, and rotating cluster certificates to revoke local
  accounts will invalidate KubeUser-issued certificates too.
- **DOKS, LKE, Civo, OKE, ACK, Scaleway, OVH and similar** — no authoritative
  statement either way. Most run a control plane close to upstream.

In every one of these cases the preflight check answers the question in under a
minute, and the answer is authoritative for *your* cluster and version. Claiming
support without running it is how the EKS claim got into this project's README
in the first place.

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

---

## Where KubeUser Fits

The requirement above — a cluster whose control plane you own, or at least
whose signer behaves like upstream — is also where KubeUser is most useful:

- **Self-managed and bare-metal clusters** (kubeadm, Kubespray, k3s, RKE2,
  Talos), where there is no cloud IAM to inherit identities from.
- **Air-gapped and disconnected environments**, where an external OIDC
  provider is unreachable by design. KubeUser depends on nothing outside the
  cluster: the CSR API, Secrets, and RBAC are all local, so credential
  issuance and rotation keep working with no egress.
- **Edge and on-premise fleets**, where each site runs its own small control
  plane and operating a per-site IdP is disproportionate.
- **Regulated or sovereign deployments** that cannot route authentication
  through a third-party identity service.
- **Lab, CI, and homelab clusters**, where OIDC setup costs more than the
  access it grants.

It is not a replacement for an enterprise identity provider: certificates
cannot be revoked before expiry (Kubernetes does not consult CRL/OCSP for
client certs), so keep TTLs short where that matters.
