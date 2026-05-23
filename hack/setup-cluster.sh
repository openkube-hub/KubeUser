#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="kubeuser"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
IMG="${IMG:-ghcr.io/openkube-hub/kubeuser-controller:latest}"
UPGRADE_ONLY=false

# ── Colours ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

for arg in "$@"; do
  case "$arg" in
    --upgrade-only) UPGRADE_ONLY=true ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

# ── Dependency check ───────────────────────────────────────────────────────────
for cmd in kind kubectl helm curl docker make; do
  command -v "$cmd" &>/dev/null || die "'$cmd' not found — please install it first."
done

if [[ "${UPGRADE_ONLY}" == "false" ]]; then

# ── 1. Tear down existing cluster ──────────────────────────────────────────────
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
  warn "Cluster '${CLUSTER_NAME}' already exists — deleting it."
  kind delete cluster --name "${CLUSTER_NAME}"
  success "Deleted cluster '${CLUSTER_NAME}'."
fi

# ── 2. Create new cluster ──────────────────────────────────────────────────────
info "Creating kind cluster '${CLUSTER_NAME}' (1 control-plane + 1 worker)…"
kind create cluster --config "${SCRIPT_DIR}/kind.yaml"
success "Cluster '${CLUSTER_NAME}' is up."

# ── 3. Helm repos ──────────────────────────────────────────────────────────────
info "Adding / updating Helm repos…"
helm repo add jetstack             https://charts.jetstack.io                            --force-update
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts    --force-update
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

fi # --upgrade-only skip end

# ── 5. Build KubeUser image ───────────────────────────────────────────────────
info "Building KubeUser controller image (${IMG})…"
make -C "${REPO_ROOT}" docker-build IMG="${IMG}"
success "Image built."

# ── 6. Load image into kind ───────────────────────────────────────────────────
info "Loading image into kind cluster '${CLUSTER_NAME}'…"
kind load docker-image "${IMG}" --name "${CLUSTER_NAME}"
success "Image loaded."

# ── 7. Install KubeUser Helm chart ────────────────────────────────────────────
API_SERVER=$(kind get kubeconfig --name "${CLUSTER_NAME}" | grep 'server:' | awk '{print $2}')
info "API server: ${API_SERVER}"

info "Installing KubeUser Helm chart…"
helm upgrade --install kubeuser "${REPO_ROOT}/helm/kubeuser" \
  --namespace kubeuser \
  --create-namespace \
  --set image.pullPolicy=IfNotPresent \
  --set env.KUBERNETES_API_SERVER="${API_SERVER}" \
  --set metrics.enabled=true \
  --set metrics.certManager.enabled=true \
  --set metrics.serviceMonitor.enabled=true \
  --wait \
  --timeout 5m
success "KubeUser installed."

if [[ "${UPGRADE_ONLY}" == "false" ]]; then

# ── 8. kube-prometheus-stack ──────────────────────────────────────────────────
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

fi # --upgrade-only skip end

# ── 9. Apply test user ────────────────────────────────────────────────────────
info "Applying test user from test-examples/valid-user.yaml…"
kubectl apply -f "${REPO_ROOT}/test-examples/valid-user.yaml"

info "Waiting for valid-user to become Active…"
kubectl wait --for=jsonpath='{.status.phase}'=Active user/valid-user --timeout=120s
success "valid-user is Active."

echo ""
info "kubectl get users:"
kubectl get users

echo ""
info "kubectl get user valid-user:"
kubectl get user valid-user -o yaml

# ── 10. Extract kubeconfig ────────────────────────────────────────────────────
info "Extracting kubeconfig to /tmp/kubeconfig…"
kubectl get secret valid-user-kubeconfig \
  --namespace kubeuser \
  -o jsonpath='{.data.config}' \
  | base64 -d > /tmp/kubeconfig
success "Kubeconfig written to /tmp/kubeconfig."

# ── 11. Smoke-test the generated kubeconfig ───────────────────────────────────
info "Listing pods in default namespace using valid-user kubeconfig…"
KUBECONFIG=/tmp/kubeconfig kubectl get pods -n default

# ── Done ───────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  Cluster '${CLUSTER_NAME}' is ready.${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Grafana    → kubectl -n monitoring port-forward svc/kube-prometheus-stack-grafana 3000:80"
echo "               http://localhost:3000  (admin / admin)"
echo ""
echo "  KubeUser   → kubectl -n kubeuser get pods"
echo "  Kubeconfig → /tmp/kubeconfig  (valid-user)"
echo ""
