#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}KubeUser Metrics Test Script${NC}"
echo "================================"
echo ""

# Check if controller is running
echo -e "${YELLOW}Checking if metrics endpoint is accessible...${NC}"
if curl -k -s --connect-timeout 5 https://localhost:8443/metrics > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Metrics endpoint is accessible${NC}"
else
    echo -e "${RED}✗ Metrics endpoint not accessible${NC}"
    echo "  Make sure the controller is running with: make run"
    exit 1
fi

echo ""
echo -e "${YELLOW}Fetching KubeUser metrics...${NC}"
echo ""

# Fetch and display metrics
METRICS=$(curl -k -s https://localhost:8443/metrics | grep "^kubeuser_")

if [ -z "$METRICS" ]; then
    echo -e "${YELLOW}No KubeUser metrics found yet.${NC}"
    echo "This is normal if no User resources have been created."
    echo ""
    echo "To generate metrics, create a User resource:"
    echo "  kubectl apply -f config/samples/auth_v1alpha1_user.yaml"
else
    echo -e "${GREEN}KubeUser Metrics:${NC}"
    echo "$METRICS"
fi

echo ""
echo -e "${YELLOW}Available metric types:${NC}"
curl -k -s https://localhost:8443/metrics | grep "^# HELP kubeuser_" | sed 's/# HELP /  - /'

echo ""
echo -e "${GREEN}Metrics endpoint: https://localhost:8443/metrics${NC}"
echo ""
echo "To continuously monitor metrics, run:"
echo "  watch -n 2 'curl -sk https://localhost:8443/metrics | grep kubeuser'"
