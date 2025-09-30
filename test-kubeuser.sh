#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

wait_for_condition() {
    local description=$1
    local condition=$2
    local timeout=${3:-60}
    
    log_info "Waiting for: $description"
    
    for i in $(seq 1 $timeout); do
        if eval "$condition" >/dev/null 2>&1; then
            log_success "$description - completed"
            return 0
        fi
        sleep 1
        if [ $((i % 10)) -eq 0 ]; then
            log_info "Still waiting for: $description ($i/${timeout}s)"
        fi
    done
    
    log_error "$description - timed out after ${timeout}s"
    return 1
}

# Test functions
test_prerequisites() {
    log_info "=== Testing Prerequisites ==="
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed or not in PATH"
        exit 1
    fi
    
    # Check cluster access
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot access Kubernetes cluster"
        exit 1
    fi
    
    # Check cert-manager
    if ! kubectl get namespace cert-manager >/dev/null 2>&1; then
        log_warning "cert-manager namespace not found"
        log_info "Installing cert-manager..."
        kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml
        wait_for_condition "cert-manager pods to be ready" "kubectl get pods -n cert-manager | grep -E '1/1.*Running'"
    fi
    
    log_success "Prerequisites check completed"
}

test_deployment() {
    log_info "=== Testing KubeUser Deployment ==="
    
    # Check if controller is running
    wait_for_condition "KubeUser controller to be ready" "kubectl get pods -n kubeuser | grep 'kubeuser-controller-manager.*1/1.*Running'" 120
    
    # Check webhook certificate
    wait_for_condition "Webhook certificate to be ready" "kubectl get certificate -n kubeuser kubeuser-webhook-cert -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}' | grep -q True" 60
    
    # Check webhook secret
    if ! kubectl get secret kubeuser-webhook-certs -n kubeuser >/dev/null 2>&1; then
        log_error "Webhook certificate secret not found"
        return 1
    fi
    
    log_success "KubeUser deployment is healthy"
}

test_user_creation() {
    log_info "=== Testing User Creation ==="
    
    # Apply test setup (namespaces and roles)
    log_info "Creating test setup..."
    kubectl apply -f test/test-setup.yaml
    
    # Create test user
    log_info "Creating test user 'jane'..."
    kubectl apply -f test/test-user-jane-1.yaml
    
    # Wait for user to be processed
    wait_for_condition "User 'jane' to be created" "kubectl get user jane >/dev/null 2>&1" 30
    
    # Check user status
    log_info "Checking user status..."
    kubectl get user jane
    kubectl describe user jane
    
    log_success "User creation test completed"
}

test_certificate_generation() {
    log_info "=== Testing Certificate Generation ==="
    
    # Wait for certificate secrets to be created
    wait_for_condition "Private key secret to be created" "kubectl get secret jane-key -n kubeuser >/dev/null 2>&1" 60
    wait_for_condition "Kubeconfig secret to be created" "kubectl get secret jane-kubeconfig -n kubeuser >/dev/null 2>&1" 120
    
    # Check CSR
    log_info "Checking Certificate Signing Request..."
    if kubectl get csr -l auth.openkube.io/user=jane | grep jane-csr; then
        kubectl get csr -l auth.openkube.io/user=jane
        log_success "CSR found and processed"
    else
        log_warning "CSR not found - might have been cleaned up already"
    fi
    
    # Extract and save kubeconfig
    log_info "Extracting kubeconfig for user 'jane'..."
    kubectl get secret jane-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d > /tmp/jane-kubeconfig.yaml
    
    # Verify kubeconfig format
    if grep -q "client-certificate-data" /tmp/jane-kubeconfig.yaml && grep -q "client-key-data" /tmp/jane-kubeconfig.yaml; then
        log_success "Kubeconfig contains certificate data"
    else
        log_error "Kubeconfig is missing certificate data"
        return 1
    fi
    
    # Check certificate expiry
    log_info "Checking certificate expiry..."
    CERT_DATA=$(grep "client-certificate-data:" /tmp/jane-kubeconfig.yaml | head -1 | awk '{print $2}')
    if [ -n "$CERT_DATA" ]; then
        echo "$CERT_DATA" | base64 -d | openssl x509 -noout -subject -issuer -dates || log_warning "Could not parse certificate details"
    fi
    
    log_success "Certificate generation test completed"
}

test_rbac_bindings() {
    log_info "=== Testing RBAC Bindings ==="
    
    # Check RoleBindings
    log_info "Checking RoleBindings..."
    kubectl get rolebindings -n dev | grep jane || log_warning "No RoleBindings found for jane in dev namespace"
    
    # Check ClusterRoleBindings  
    log_info "Checking ClusterRoleBindings..."
    kubectl get clusterrolebindings | grep jane || log_warning "No ClusterRoleBindings found for jane"
    
    # List all bindings for the user
    log_info "All RBAC resources for user 'jane':"
    kubectl get rolebindings,clusterrolebindings --all-namespaces | grep jane || log_warning "No RBAC bindings found"
    
    log_success "RBAC bindings test completed"
}

test_user_access() {
    log_info "=== Testing User Access ==="
    
    # Test authentication
    log_info "Testing authentication with generated kubeconfig..."
    if kubectl --kubeconfig /tmp/jane-kubeconfig.yaml auth can-i get pods 2>/dev/null; then
        log_success "User can authenticate with generated kubeconfig"
    else
        log_error "User authentication failed"
        return 1
    fi
    
    # Test specific permissions
    log_info "Testing specific permissions..."
    
    # Test dev namespace access
    if kubectl --kubeconfig /tmp/jane-kubeconfig.yaml auth can-i get pods -n dev 2>/dev/null; then
        log_success "User has access to pods in dev namespace"
    else
        log_warning "User does not have access to pods in dev namespace"
    fi
    
    # Test cluster-level access
    if kubectl --kubeconfig /tmp/jane-kubeconfig.yaml auth can-i get nodes 2>/dev/null; then
        log_success "User has cluster-level access (from ClusterRole)"
    else
        log_warning "User does not have cluster-level access"
    fi
    
    log_success "User access test completed"
}

test_user_update() {
    log_info "=== Testing User Update ==="
    
    # Update user permissions
    log_info "Updating user permissions..."
    kubectl apply -f test/test-user-jane-2.yaml
    
    # Wait for changes to propagate
    sleep 5
    
    # Check updated bindings
    log_info "Checking updated RBAC bindings..."
    kubectl get rolebindings,clusterrolebindings --all-namespaces | grep jane || log_warning "No RBAC bindings found after update"
    
    log_success "User update test completed"
}

test_certificate_rotation() {
    log_info "=== Testing Certificate Rotation ==="
    
    # Get current certificate expiry
    log_info "Getting current certificate expiry..."
    USER_STATUS=$(kubectl get user jane -o jsonpath='{.status.expiryTime}' 2>/dev/null || echo "")
    if [ -n "$USER_STATUS" ]; then
        log_info "Current certificate expires at: $USER_STATUS"
    fi
    
    # Force certificate rotation by deleting kubeconfig secret
    log_info "Forcing certificate rotation..."
    kubectl delete secret jane-kubeconfig -n kubeuser
    
    # Trigger reconciliation
    kubectl annotate user jane kubectl.kubernetes.io/restartedAt="$(date -Iseconds)" --overwrite
    
    # Wait for new certificate to be generated
    wait_for_condition "New kubeconfig secret to be created" "kubectl get secret jane-kubeconfig -n kubeuser >/dev/null 2>&1" 120
    
    # Verify new kubeconfig works
    log_info "Testing new kubeconfig after rotation..."
    kubectl get secret jane-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d > /tmp/jane-kubeconfig-new.yaml
    
    if kubectl --kubeconfig /tmp/jane-kubeconfig-new.yaml auth can-i get pods >/dev/null 2>&1; then
        log_success "Certificate rotation successful - new kubeconfig works"
    else
        log_error "Certificate rotation failed - new kubeconfig doesn't work"
        return 1
    fi
    
    log_success "Certificate rotation test completed"
}

test_cleanup() {
    log_info "=== Testing Cleanup ==="
    
    # Delete user
    log_info "Deleting user 'jane'..."
    kubectl delete -f test/test-user-jane-1.yaml --ignore-not-found
    
    # Check that resources are cleaned up
    sleep 5
    
    # Check secrets are cleaned up
    if ! kubectl get secret jane-kubeconfig -n kubeuser >/dev/null 2>&1; then
        log_success "User kubeconfig secret cleaned up"
    else
        log_warning "User kubeconfig secret still exists"
    fi
    
    if ! kubectl get secret jane-key -n kubeuser >/dev/null 2>&1; then
        log_success "User private key secret cleaned up"  
    else
        log_warning "User private key secret still exists"
    fi
    
    # Check RBAC bindings are cleaned up
    if ! kubectl get rolebindings,clusterrolebindings --all-namespaces | grep jane >/dev/null 2>&1; then
        log_success "RBAC bindings cleaned up"
    else
        log_warning "Some RBAC bindings still exist"
        kubectl get rolebindings,clusterrolebindings --all-namespaces | grep jane || true
    fi
    
    # Clean up test setup
    kubectl delete -f test/test-setup.yaml --ignore-not-found
    
    log_success "Cleanup test completed"
}

# Main test execution
main() {
    log_info "Starting KubeUser comprehensive test suite..."
    
    # Check if running from project directory
    if [ ! -f "test/test-setup.yaml" ]; then
        log_error "Please run this script from the KubeUser project root directory"
        exit 1
    fi
    
    # Run test suite
    test_prerequisites
    test_deployment
    test_user_creation
    test_certificate_generation
    test_rbac_bindings
    test_user_access
    test_user_update
    test_certificate_rotation
    test_cleanup
    
    log_success "=== All tests completed successfully! ==="
    log_info "Generated kubeconfig files:"
    log_info "  - /tmp/jane-kubeconfig.yaml (original)"
    log_info "  - /tmp/jane-kubeconfig-new.yaml (after rotation)"
}

# Run main function
main "$@"