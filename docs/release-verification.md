# Release Verification

Every KubeUser release ships two signed artifacts: the controller container
image (signed with **cosign keyless** via GitHub Actions OIDC) and the Helm
chart tarball (signed with **PGP** using `helm package --sign`, surfaced as a
`.prov` file alongside the chart on the chart repository).

This page is for two audiences:

1. **Users** who want to verify a release before installing it.
2. **Release engineers / fork owners** who need to bootstrap signing in a new
   repository.

---

## For users

### Verify the controller image

Cosign keyless signing means there is no long-lived public key — the signature
binds the image digest to the GitHub Actions workflow identity that produced
it. Verification checks the signing certificate's identity (the workflow URL)
and OIDC issuer (GitHub's token endpoint).

```bash
cosign verify \
  --certificate-identity-regexp "^https://github.com/openkube-hub/KubeUser/\.github/workflows/release\.yml@refs/tags/v.*$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/openkube-hub/kubeuser-controller:<version>
```

A successful verification prints the certificate subject and the Rekor
transparency log entry the signature was recorded in.

### Verify the Helm chart

```bash
# 1. Fetch the public signing key into a legacy-format keyring file.
#    Helm's --verify reads a binary keyring (gpg2 stores keys in keybox
#    format by default, which helm cannot read), so we export explicitly.
curl -fsSL https://openkube-hub.github.io/KubeUser/release-key.asc \
  | gpg --dearmor > /tmp/kubeuser-pubring.gpg

# 2. Add the chart repo and pull-with-verify against that keyring.
helm repo add kubeuser https://openkube-hub.github.io/KubeUser
helm repo update
helm pull kubeuser/kubeuser \
  --verify --keyring /tmp/kubeuser-pubring.gpg \
  --version <version>
```

`helm pull --verify` downloads both `kubeuser-<version>.tgz` and the
provenance file `kubeuser-<version>.tgz.prov`, then validates the PGP
signature in the provenance file against the keyring.

Artifact Hub renders the **Signed** badge automatically based on the
`artifacthub.io/signKey` annotation in `Chart.yaml`.

### Verifying against a fork

Forks publish under their own GitHub organisation, so substitute the owner
name in both the cosign identity regex and the public key URL. For
`MuhanedYahya/KubeUser`:

```bash
cosign verify \
  --certificate-identity-regexp "^https://github.com/MuhanedYahya/KubeUser/\.github/workflows/release\.yml@refs/tags/v.*$" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/muhanedyahya/kubeuser-controller:<version>

curl -fsSL https://muhanedyahya.github.io/KubeUser/release-key.asc \
  | gpg --dearmor > /tmp/kubeuser-pubring.gpg
helm repo add kubeuser-fork https://muhanedyahya.github.io/KubeUser
helm repo update
helm pull kubeuser-fork/kubeuser \
  --verify --keyring /tmp/kubeuser-pubring.gpg \
  --version <version>
```

---

## For release engineers (bootstrap)

These steps are needed once per repository to enable signed releases. After
that the release workflow handles signing on every tag push.

### 1. Cosign keyless — no setup required

The image signing job uses GitHub Actions OIDC. The only repository setting
needed is the `id-token: write` permission on the job (already present in
`.github/workflows/release.yml`).

### 2. Generate a PGP signing key

```bash
gpg --full-generate-key
# Choose: RSA and RSA, 4096 bits, no expiration (or set one and rotate),
# real name "KubeUser Release Signing Key", email release@<your-domain>,
# strong passphrase.

# Capture the fingerprint and key ID.
gpg --list-secret-keys --keyid-format=long
```

### 3. Export the private key and add repo secrets

```bash
gpg --armor --export-secret-keys <key-id> > kubeuser-signing.key
```

In GitHub → repo Settings → Secrets and variables → Actions, add:

| Secret name           | Value                                                |
| --------------------- | ---------------------------------------------------- |
| `HELM_GPG_KEY`        | Contents of `kubeuser-signing.key`                   |
| `HELM_GPG_PASSPHRASE` | The passphrase you set when generating the key       |

Delete the `kubeuser-signing.key` file from disk afterwards. The private key
should only exist in the secret manager and in your offline backup.

### 4. Update the `artifacthub.io/signKey` annotation

Edit `helm/kubeuser/Chart.yaml` so the `fingerprint` matches the key you
generated and the `url` points to where the public key will be reachable. For
forks the workflow publishes it automatically at
`https://<owner>.github.io/<repo>/release-key.asc` on each release.

```yaml
annotations:
  artifacthub.io/signKey: |
    fingerprint: ABCDEF0123456789ABCDEF0123456789ABCDEF01
    url: https://muhanedyahya.github.io/KubeUser/release-key.asc
```

### 5. (Optional) Pre-publish the public key

The release workflow publishes the public key to `gh-pages` on the first
release, but you can publish it manually before tagging so Artifact Hub can
fetch it immediately:

```bash
gpg --armor --export <key-id> > release-key.asc
git checkout gh-pages
git add release-key.asc
git commit -m "Publish release signing key"
git push origin gh-pages
git checkout -
```

### 6. Tag a release and verify end-to-end

```bash
git tag v0.1.0 && git push origin v0.1.0
```

Once both jobs finish, run the verification commands from the *For users*
section above against the freshly published artifacts.

### Rotating the signing key

1. Generate a new PGP key (step 2).
2. Update `HELM_GPG_KEY` and `HELM_GPG_PASSPHRASE` secrets (step 3).
3. Update the `artifacthub.io/signKey` annotation with the new fingerprint
   (step 4).
4. Tag the next release. The workflow will publish the new public key to
   `release-key.asc`, overwriting the previous one. Old chart versions remain
   verifiable as long as users keep the old public key imported, so consider
   keeping `release-key-<old-fingerprint>.asc` alongside the new key during a
   transition window.

The cosign keyless signature does not require rotation — each release is bound
to the workflow identity at the time it ran, and Rekor preserves the
transparency log entry indefinitely.
