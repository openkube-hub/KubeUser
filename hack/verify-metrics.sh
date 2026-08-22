#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}KubeUser Metrics Verification${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if metrics endpoint is accessible
echo -e "${YELLOW}1. Checking metrics endpoint...${NC}"
if curl -s --connect-timeout 5 http://localhost:8080/metrics > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Metrics endpoint is accessible at http://localhost:8080/metrics${NC}"
else
    echo -e "${RED}✗ Metrics endpoint not accessible${NC}"
    echo "  Make sure the controller is running with: make run"
    exit 1
fi
echo ""

# Get all metrics
METRICS=$(curl -s http://localhost:8080/metrics)

# Check for KubeUser metrics
echo -e "${YELLOW}2. Checking KubeUser metrics registration...${NC}"

EXPECTED_METRICS=(
    "kubeuser_reconciliations_total"
    "kubeuser_reconcile_duration_seconds"
    "kubeuser_concurrent_rotations"
    "kubeuser_rotation_queue_length"
    "kubeuser_throttled_rotations_total"
    "kubeuser_user_sync_status"
)

MISSING=0
for metric in "${EXPECTED_METRICS[@]}"; do
    if echo "$METRICS" | grep -q "^# HELP $metric"; then
        echo -e "${GREEN}✓ $metric${NC}"
    else
        echo -e "${RED}✗ $metric (not found)${NC}"
        MISSING=$((MISSING + 1))
    fi
done
echo ""

# Check for certificate metrics (may not exist until rotation happens)
echo -e "${YELLOW}3. Checking certificate rotation metrics...${NC}"
CERT_METRICS=(
    "kubeuser_cert_rotations_total"
    "kubeuser_cert_rotation_duration_seconds"
    "kubeuser_cert_rotation_errors_total"
    "kubeuser_cert_expiry_timestamp_seconds"
    "kubeuser_certs_expiring_24h"
    "kubeuser_certs_expiring_7d"
)

CERT_MISSING=0
for metric in "${CERT_METRICS[@]}"; do
    if echo "$METRICS" | grep -q "$metric"; then
        echo -e "${GREEN}✓ $metric${NC}"
    else
        echo -e "${YELLOW}⚠ $metric (will appear after certificate rotation)${NC}"
        CERT_MISSING=$((CERT_MISSING + 1))
    fi
done
echo ""

# Check for user status metrics
echo -e "${YELLOW}4. Checking user status metrics...${NC}"
if echo "$METRICS" | grep -q "kubeuser_users_total"; then
    echo -e "${GREEN}✓ kubeuser_users_total${NC}"
else
    echo -e "${YELLOW}⚠ kubeuser_users_total (will appear after users are created)${NC}"
fi

if echo "$METRICS" | grep -q '^workqueue_depth{[^}]*name="user"'; then
    echo -e "${GREEN}✓ workqueue_depth{name=\"user\"} (controller-runtime built-in)${NC}"
else
    echo -e "${YELLOW}⚠ workqueue_depth{name=\"user\"} (will appear during reconciliation)${NC}"
fi
echo ""

# Show current metric values
echo -e "${YELLOW}5. Current metric values:${NC}"
echo ""
echo -e "${BLUE}Reconciliation Metrics:${NC}"
echo "$METRICS" | grep "^kubeuser_reconciliations_total" | sed 's/^/  /'
echo ""
echo -e "${BLUE}User Sync Status:${NC}"
echo "$METRICS" | grep "^kubeuser_user_sync_status" | sed 's/^/  /' || echo "  (no users synced yet)"
echo ""
echo -e "${BLUE}Rotation Queue:${NC}"
echo "$METRICS" | grep "^kubeuser_concurrent_rotations\|^kubeuser_rotation_queue_length\|^kubeuser_throttled_rotations" | sed 's/^/  /'
echo ""

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Summary:${NC}"
echo -e "${BLUE}========================================${NC}"
if [ $MISSING -eq 0 ]; then
    echo -e "${GREEN}✓ All core metrics are registered and working!${NC}"
else
    echo -e "${RED}✗ $MISSING core metrics are missing${NC}"
    exit 1
fi

if [ $CERT_MISSING -gt 0 ]; then
    echo -e "${YELLOW}⚠ $CERT_MISSING certificate metrics not yet populated${NC}"
    echo -e "${YELLOW}  These will appear after creating a User resource${NC}"
    echo ""
    echo -e "${YELLOW}To generate certificate metrics, run:${NC}"
    echo -e "  kubectl apply -f config/samples/auth_v1alpha1_user.yaml"
fi
echo ""
echo -e "${GREEN}Metrics are working correctly!${NC}"
echo -e "View all metrics: ${BLUE}curl http://localhost:8080/metrics${NC}"
