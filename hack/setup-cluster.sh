#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="kubeuser"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMG="${IMG:-ghcr.io/openkube-hub/kubeuser-controller:latest}"
UPGRADE_ONLY=false
WITH_MONITORING=false
RECREATE=false

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --upgrade-only)    UPGRADE_ONLY=true ;;
    --with-monitoring) WITH_MONITORING=true ;;
    --recreate)        RECREATE=true ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

# ── Dependency check ───────────────────────────────────────────────────────────
for cmd in kind kubectl helm curl docker make; do
  command -v "$cmd" &>/dev/null || die "'$cmd' not found — please install it first."
done

[[ "${UPGRADE_ONLY}" == "true" && "${RECREATE}" == "true" ]] \
  && die "--upgrade-only and --recreate are mutually exclusive."

# ── 1. Reuse or (re)create the kind cluster ───────────────────────────────────
CLUSTER_EXISTS=false
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  CLUSTER_EXISTS=true
fi

if [[ "${CLUSTER_EXISTS}" == "true" && "${RECREATE}" == "true" ]]; then
  warn "--recreate: deleting existing cluster '${CLUSTER_NAME}'."
  kind delete cluster --name "${CLUSTER_NAME}"
  success "Deleted cluster '${CLUSTER_NAME}'."
  CLUSTER_EXISTS=false
fi

if [[ "${CLUSTER_EXISTS}" == "true" ]]; then
  # Point kubectl/helm at the kind cluster explicitly: the current context may
  # belong to a different cluster, and every later step acts on it.
  info "Cluster '${CLUSTER_NAME}' is already up — reusing it (pass --recreate to start fresh)."
  kind export kubeconfig --name "${CLUSTER_NAME}"
  success "kubectl context set to kind-${CLUSTER_NAME}."
elif [[ "${UPGRADE_ONLY}" == "true" ]]; then
  die "--upgrade-only needs a running '${CLUSTER_NAME}' kind cluster — run without it first."
else
  # ── 2. Create new cluster ────────────────────────────────────────────────────
  info "Creating kind cluster '${CLUSTER_NAME}' (1 control-plane + 1 worker)…"
  kind create cluster --config "${SCRIPT_DIR}/kind.yaml"
  success "Cluster '${CLUSTER_NAME}' is up."
fi

if [[ "${UPGRADE_ONLY}" == "false" ]]; then

# ── 3. Helm repos ──────────────────────────────────────────────────────────────
info "Adding / updating Helm repos…"
helm repo add jetstack             https://charts.jetstack.io                            --force-update
if [[ "${WITH_MONITORING}" == "true" ]]; then
  helm repo add prometheus-community https://prometheus-community.github.io/helm-charts  --force-update
fi
helm repo update
success "Helm repos ready."

# ── 4. cert-manager ───────────────────────────────────────────────────────────
CERT_MANAGER_VERSION=$(
  curl -s https://api.github.com/repos/cert-manager/cert-manager/releases/latest \
    | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/'
)
info "Installing cert-manager ${CERT_MANAGER_VERSION}…"

helm upgrade --install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version "${CERT_MANAGER_VERSION}" \
  --set crds.enabled=true \
  --wait \
  --timeout 5m

success "cert-manager ${CERT_MANAGER_VERSION} installed."

# ── 5. kube-prometheus-stack ──────────────────────────────────────────────────
# Opt-in with --with-monitoring.
if [[ "${WITH_MONITORING}" == "true" ]]; then
  # Installed BEFORE the KubeUser chart so the monitoring.coreos.com/v1
  # ServiceMonitor CRD exists when KubeUser's chart renders. Reordering this
  # above the KubeUser install reintroduces the "no matches for kind
  # ServiceMonitor" failure on a fresh cluster.
  info "Creating monitoring namespace and importing dashboard ConfigMap…"
  kubectl create namespace monitoring --dry-run=client -o yaml | kubectl apply -f -
  kubectl apply -f "${SCRIPT_DIR}/monitoring/kubeuser-dashboard-configmap.yaml"

  PROM_CHART_VERSION="82.15.1"
  info "Installing kube-prometheus-stack ${PROM_CHART_VERSION}…"

  helm upgrade --install kube-prometheus-stack \
    prometheus-community/kube-prometheus-stack \
    --namespace monitoring \
    --version "${PROM_CHART_VERSION}" \
    -f "${SCRIPT_DIR}/monitoring/kube-prometheus-stack-values.yaml" \
    --wait \
    --timeout 10m

  success "kube-prometheus-stack ${PROM_CHART_VERSION} installed."
else
  info "Skipping kube-prometheus-stack (pass --with-monitoring to install it)."
fi

fi # --upgrade-only skip end

# ── 6. Build KubeUser image ───────────────────────────────────────────────────
info "Building KubeUser controller image (${IMG})…"
make -C "${REPO_ROOT}" docker-build IMG="${IMG}"
success "Image built."

# ── 7. Load image into kind ───────────────────────────────────────────────────
info "Loading image into kind cluster '${CLUSTER_NAME}'…"
kind load docker-image "${IMG}" --name "${CLUSTER_NAME}"
success "Image loaded."

# ── 8. Install KubeUser Helm chart ────────────────────────────────────────────
API_SERVER=$(kind get kubeconfig --name "${CLUSTER_NAME}" | grep 'server:' | awk '{print $2}')
info "API server: ${API_SERVER}"

# The ServiceMonitor needs the monitoring.coreos.com CRD, which only exists
# when kube-prometheus-stack is installed. Detecting it (rather than keying off
# the flag) keeps --upgrade-only working whether or not the cluster was
# created with --with-monitoring.
SERVICE_MONITOR=false
if kubectl get crd servicemonitors.monitoring.coreos.com &>/dev/null; then
  SERVICE_MONITOR=true
fi

# The tag is reused across builds and pullPolicy is IfNotPresent, so an
# unchanged pod template would leave a re-run on the old binary. Stamping a
# hash of the image's layer digests makes helm roll the pods exactly when the
# image content changed. (.Id is not usable: BuildKit's provenance attestation
# gives every build a new manifest-list digest even when nothing changed.)
if command -v sha256sum &>/dev/null; then SHA256=(sha256sum); else SHA256=(shasum -a 256); fi
IMAGE_HASH=$(docker image inspect --format '{{json .RootFS.Layers}}' "${IMG}" | "${SHA256[@]}" | cut -c1-16)

info "Installing / upgrading KubeUser Helm chart (serviceMonitor=${SERVICE_MONITOR})…"
helm upgrade --install kubeuser "${REPO_ROOT}/helm/kubeuser" \
  --namespace kubeuser \
  --create-namespace \
  --set image.pullPolicy=IfNotPresent \
  --set-string "podAnnotations.kubeuser\\.openkube\\.io/image-hash=${IMAGE_HASH}" \
  --set env.KUBERNETES_API_SERVER="${API_SERVER}" \
  --set metrics.enabled=true \
  --set metrics.certManager.enabled=true \
  --set metrics.serviceMonitor.enabled="${SERVICE_MONITOR}" \
  --wait \
  --timeout 5m
success "KubeUser installed / upgraded."

# ── 9. Apply example user ─────────────────────────────────────────────────────
info "Applying example user from examples/users/minimal-viewer.yaml…"
# helm --wait returns once the pods are Ready, but the webhook Service's
# endpoints can lag behind, so the first admission call may be refused.
# Retry until the webhook answers.
applied=false
for _ in $(seq 1 60); do
  if kubectl apply -f "${REPO_ROOT}/examples/users/minimal-viewer.yaml" 2>/dev/null; then
    applied=true
    break
  fi
  sleep 2
done
[[ "${applied}" == "true" ]] \
  || kubectl apply -f "${REPO_ROOT}/examples/users/minimal-viewer.yaml" \
  || die "could not apply the example user within 120s (is the webhook reachable?)"

info "Waiting for alice-viewer to become Active…"
kubectl wait --for=jsonpath='{.status.phase}'=Active user/alice-viewer --timeout=120s
success "alice-viewer is Active."

# RBAC reconciliation flips .status.phase to Active before the auth pass has
# finished issuing the x509 cert and writing the kubeconfig secret, so waiting
# on phase alone races the secret. Wait explicitly on the secret creation.
info "Waiting for alice-viewer-kubeconfig secret to be created…"
for _ in $(seq 1 60); do
  if kubectl -n kubeuser get secret alice-viewer-kubeconfig &>/dev/null; then
    break
  fi
  sleep 2
done
kubectl -n kubeuser get secret alice-viewer-kubeconfig &>/dev/null \
  || die "alice-viewer-kubeconfig secret was not created within 120s"
success "alice-viewer-kubeconfig secret is ready."

echo ""
info "kubectl get users:"
kubectl get users

echo ""
info "kubectl get user alice-viewer:"
kubectl get user alice-viewer -o yaml

# ── 10. Extract kubeconfig ────────────────────────────────────────────────────
info "Extracting kubeconfig to /tmp/kubeconfig…"
kubectl get secret alice-viewer-kubeconfig \
  --namespace kubeuser \
  -o jsonpath='{.data.config}' \
  | base64 -d > /tmp/kubeconfig
success "Kubeconfig written to /tmp/kubeconfig."

# ── 11. Smoke-test the generated kubeconfig ───────────────────────────────────
info "Listing pods in default namespace using alice-viewer kubeconfig…"
KUBECONFIG=/tmp/kubeconfig kubectl get pods -n default

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Cluster '${CLUSTER_NAME}' is ready.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
if [[ "${SERVICE_MONITOR}" == "true" ]]; then
  echo "  Grafana    → kubectl -n monitoring port-forward svc/kube-prometheus-stack-grafana 3000:80"
  echo "               http://localhost:3000  (admin / admin)"
  echo ""
fi
echo "  KubeUser   → kubectl -n kubeuser get pods"
echo "  Kubeconfig → /tmp/kubeconfig  (alice-viewer)"
echo ""
