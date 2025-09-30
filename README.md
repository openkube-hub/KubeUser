# KubeUser

Lightweight Kubernetes-native user management operator that simplifies user authentication and authorization through declarative custom resources.

## 🚀 Project Overview

KubeUser is a Kubernetes operator that automates user management by providing a declarative API for creating and managing user access to Kubernetes clusters. It streamlines the process of granting temporary or permanent access to users through role-based access control (RBAC).

### Why KubeUser?

- **Declarative User Management**: Define users and their permissions using Kubernetes custom resources
- **Temporary Access**: Built-in support for time-limited user access with automatic expiration
- **Certificate-based Authentication**: Automatically generates client certificates and kubeconfig files
- **RBAC Integration**: Seamlessly integrates with existing Kubernetes Role and ClusterRole resources
- **Kubernetes Native**: Built using controller-runtime, following Kubernetes best practices
- **Multi-tenancy Support**: Namespace-scoped and cluster-wide permission management

### Main Use Cases

1. **Developer Onboarding**: Quickly grant new developers access to specific namespaces
2. **Temporary Access**: Provide contractors or external users time-limited cluster access
3. **Audit and Compliance**: Centralized user management with clear access tracking
4. **GitOps Integration**: Manage user permissions through version-controlled YAML files

## 🏗️ Architecture & Features

### Architecture Overview

KubeUser follows the standard Kubernetes operator pattern:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   User CRD      │───▶│  User Controller │───▶│  RBAC Resources │
│  (Custom Res.)  │    │  (Reconciler)    │    │ (Roles/Bindings)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │ Certificate &   │
                       │ Kubeconfig Gen  │
                       └─────────────────┘
```

#### 🚧 Planned Features
- [ ] Reconciliation Loop: Continuous monitoring and enforcement of user permissions
- [X] Finalizers: Proper cleanup of user resources when User objects are deleted
- [X] Certificate Management: Automatic generation of client certificates using Kubernetes CSR API
- [X] Kubeconfig Generation: Creates ready-to-use kubeconfig files stored as secrets
- [X] RBAC Integration: Creates RoleBindings and ClusterRoleBindings based on User spec
- [X] Role Validation: Validates that referenced Roles and ClusterRoles exist
- [ ] Status Reporting: Comprehensive status updates with conditions
- [X] **Webhook validation for User resources**
- [X] **Certificate rotation and renewal** (30 days before expiry)
- [ ] **Templated Roles**: Provide predefined reusable RBAC role templates for common use cases
- [ ] Expiry Support: Time-based access control with configurable expiration
- [ ] High availability: support for multi-replica deployments
- [ ] Metrics Endpoint: Prometheus-compatible metrics on port 8080
- [ ] Health Checks: Liveness and readiness probes for robust deployments
- [ ] Resource Cleanup: Automatic cleanup of associated resources on user deletion
- [ ] User group management
- [ ] Audit logging for user access changes
- [ ] Grafana dashboard for user management metrics

## 📦 Installation Instructions

### Prerequisites

- **Kubernetes cluster** (v1.28+)
- **kubectl** configured to access your cluster with cluster-admin permissions
- **cert-manager** (required for webhook certificates)
- **Docker** (for building images locally)
- **kind** or **minikube** (for local testing)

#### Install cert-manager

KubeUser requires cert-manager for webhook certificate management:

```bash
# Install cert-manager
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Wait for cert-manager to be ready
kubectl wait --for=condition=ready pod -l app=cert-manager -n cert-manager --timeout=60s
```

### Deployment Options

#### Option 1: Using Kustomize (Recommended)

```bash
# Clone the repository
git clone https://github.com/openkube-hub/KubeUser.git
cd KubeUser

# Deploy using kustomize
kubectl apply -k config/default

# Wait for controller to be ready
kubectl wait --for=condition=ready pod -l control-plane=controller-manager -n kubeuser --timeout=120s
```

#### Option 2: Local Development with kind

For local testing and development:

```bash
# Build the Docker image
make docker-build

# Load image into kind cluster
kind load docker-image controller:latest --name <your-cluster-name>

# Deploy with local image
kubectl apply -k config/default

# Update deployment to use local image
kubectl patch deployment kubeuser-controller-manager -n kubeuser -p '{"spec":{"template":{"spec":{"containers":[{"name":"manager","imagePullPolicy":"Never"}]}}}}'
```

### Verification

Verify the installation:

```bash
# Check controller status
kubectl get pods -n kubeuser

# Check webhook certificate
kubectl get certificates -n kubeuser

# Check CRDs
kubectl get crd users.auth.openkube.io
```


## 🚀 Quick Start / Usage

### Basic User Creation

Create a user with namespace-scoped access:

```yaml path=null start=null
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: alice
spec:
  roles:
    - namespace: "development"
      existingRole: "developer"
    - namespace: "staging"
      existingRole: "viewer"
  expiry: "30d"  # Optional: 30 days expiry
```

### User with Cluster-wide Access

```yaml path=null start=null
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: bob-admin
spec:
  clusterRoles:
    - existingClusterRole: "cluster-admin"
  expiry: "7d"  # One week access
```

### Mixed Permissions Example

```yaml path=null start=null
apiVersion: auth.openkube.io/v1alpha1
kind: User
metadata:
  name: contractor-jane
spec:
  roles:
    - namespace: "project-x"
      existingRole: "developer"
    - namespace: "testing"
      existingRole: "tester"
  clusterRoles:
    - existingClusterRole: "view"  # Read-only cluster access
  expiry: "14d"  # Two weeks access
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `spec.roles` | `[]RoleSpec` | No | List of namespace-scoped role bindings |
| `spec.roles[].namespace` | `string` | Yes | Target namespace for the role binding |
| `spec.roles[].existingRole` | `string` | Yes | Name of the existing Role in the namespace |
| `spec.clusterRoles` | `[]ClusterRoleSpec` | No | List of cluster-wide role bindings |
| `spec.clusterRoles[].existingClusterRole` | `string` | Yes | Name of the existing ClusterRole |
| `spec.expiry` | `string` | No | Duration (e.g., "24h", "7d", "30m") after which access expires |

### Managing Users

```bash
# Create sample namespace and role
kubectl create ns dev
kubectl create role developer --verb=get,list,watch --resource=pods -n dev

# Apply user configuration
kubectl apply -f test/test-user.yaml

# Check user status
kubectl get users
kubectl describe user jane

# Get the generated kubeconfig
kubectl get secret jane-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d > ~/tmp/kubeconfig

# Test user access
kubectl --kubeconfig ~/tmp/kubeconfig get pods -n dev

# Delete user (cleans up all associated resources)
kubectl delete user jane
```

### Comprehensive Testing

For thorough testing of all features, use the provided test script:

```bash
# Run the comprehensive test suite
./test-kubeuser.sh
```

This script tests:
- Prerequisites validation
- Controller deployment health
- User creation and RBAC bindings
- Certificate generation and kubeconfig creation
- User access validation
- Certificate rotation
- Resource cleanup

#### Manual Testing Steps

1. **Setup test environment:**
   ```bash
   kubectl apply -f test/test-setup.yaml
   ```

2. **Create a test user:**
   ```bash
   kubectl apply -f test/test-user-jane-1.yaml
   ```

3. **Verify user creation:**
   ```bash
   kubectl get users
   kubectl describe user jane
   ```

4. **Check generated resources:**
   ```bash
   # Check secrets
   kubectl get secrets -n kubeuser | grep jane
   
   # Check RBAC bindings
   kubectl get rolebindings -n dev | grep jane
   kubectl get clusterrolebindings | grep jane
   
   # Check CSR (if still present)
   kubectl get csr -l auth.openkube.io/user=jane
   ```

5. **Test user access:**
   ```bash
   # Extract kubeconfig
   kubectl get secret jane-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d > /tmp/jane.kubeconfig
   
   # Test authentication
   kubectl --kubeconfig /tmp/jane.kubeconfig auth can-i get pods -n dev
   
   # Test actual access
   kubectl --kubeconfig /tmp/jane.kubeconfig get pods -n dev
   ```

## ⚙️ Configuration

### Environment Variables

The operator supports the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KUBERNETES_API_SERVER` | `https://kubernetes.default.svc` | Kubernetes api address |

## 🔧 Troubleshooting

### Common Issues

#### Controller Pod Not Starting

```bash
# Check pod status
kubectl get pods -n kubeuser

# Check pod logs
kubectl logs -n kubeuser deployment/kubeuser-controller-manager

# Check events
kubectl get events -n kubeuser --sort-by=.lastTimestamp
```

**Common causes:**
- Missing cert-manager installation
- Webhook certificate not ready
- Image pull issues (for local development)

#### Webhook Certificate Issues

```bash
# Check certificate status
kubectl get certificates -n kubeuser
kubectl describe certificate kubeuser-webhook-cert -n kubeuser

# Check cert-manager logs
kubectl logs -n cert-manager deployment/cert-manager

# Force certificate recreation
kubectl delete certificate kubeuser-webhook-cert -n kubeuser
kubectl apply -k config/default
```

#### User Creation Fails

```bash
# Check user status
kubectl describe user <username>

# Check controller logs
kubectl logs -n kubeuser deployment/kubeuser-controller-manager | grep -i error

# Check webhook validation
kubectl get validatingwebhookconfiguration kubeuser-validating-webhook-configuration -o yaml
```

**Common causes:**
- Referenced roles don't exist
- RBAC permission issues
- Webhook validation failures

#### Certificate Generation Issues

```bash
# Check CSR status
kubectl get csr -l auth.openkube.io/user=<username>

# Check CSR details
kubectl describe csr <csr-name>

# Check controller RBAC permissions
kubectl auth can-i create certificatesigningrequests --as=system:serviceaccount:kubeuser:kubeuser-controller-manager
```

### Getting Help

For additional support:
1. Check the comprehensive documentation in `docs/`
2. Review logs for specific error messages
3. Ensure all prerequisites are properly installed
4. Verify RBAC permissions are correctly configured

## 📚 Documentation

- [Certificate Management Guide](docs/certificate-management.md) - Comprehensive certificate management details
- [Webhook Validation](docs/webhook-validation.md) - Webhook validation and troubleshooting
- [Test Script](test-kubeuser.sh) - Automated testing script

## 🚀 Quick Reference

### Essential Commands

```bash
# Deploy KubeUser
kubectl apply -k config/default

# Check deployment status
kubectl get pods -n kubeuser
kubectl get certificates -n kubeuser

# Create a user
kubectl apply -f test/test-user-jane-1.yaml

# Get user kubeconfig
kubectl get secret jane-kubeconfig -n kubeuser -o jsonpath='{.data.config}' | base64 -d > jane.kubeconfig

# Test user access
kubectl --kubeconfig jane.kubeconfig auth can-i get pods -n dev

# Clean up
kubectl delete user jane
kubectl delete -k config/default
```

### Key Resources Created

- **Namespace**: `kubeuser`
- **CRD**: `users.auth.openkube.io`
- **Controller**: `kubeuser-controller-manager`
- **Webhook**: `kubeuser-validating-webhook-configuration`
- **Certificates**: `kubeuser-webhook-cert` (managed by cert-manager)

### User Resource Secrets

For each user, the controller creates:
- `<username>-key`: Private key secret
- `<username>-kubeconfig`: Complete kubeconfig file
- CSR: `<username>-csr` (temporary, cleaned up after use)


## 💻 Development Guide

### Prerequisites

- **Go**: Version 1.24+ (as specified in go.mod)
- **Docker**: For building container images
- **kubectl**: Kubernetes command-line tool
- **Kind**: For local testing (optional but recommended)
- **Kustomize**: For manifest management
- **Kubebuilder**: v3.0+ (for code generation)

### Local Development Setup

1. **Clone the repository**:
```bash
git clone https://github.com/openkube-hub/KubeUser.git
cd KubeUser
```

2. **Install dependencies**:
```bash
go mod tidy
```

3. **Generate code and manifests**:
```bash
make generate
make manifests
```

4. **Run tests**:
```bash
make test
```

### Building and Running Locally

```bash
# Build the manager binary
make build

# Run against a Kubernetes cluster (requires kubeconfig)
make run

# Build and load Docker image (requires Docker)
make docker-build
```

### Testing

#### Unit Tests
```bash
# Run all unit tests
make test

# Run tests with coverage
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

#### End-to-End Tests
```bash
# Run e2e tests (creates Kind cluster)
make test-e2e

# Manual e2e testing
make setup-test-e2e  # Creates Kind cluster
# ... run manual tests ...
make cleanup-test-e2e  # Cleanup
```

### Linting and Code Quality

```bash
# Run linter
make lint

# Fix linting issues automatically
make lint-fix

# Verify linting configuration
make lint-config

# Format code
make fmt

# Vet code
make vet
```

### Development Workflow

1. **Make changes** to the code
2. **Generate code**: `make generate manifests`
3. **Run tests**: `make test`
4. **Test locally**: `make run`
5. **Build image**: `make docker-build`
6. **Run e2e tests**: `make test-e2e`


## 🤝 Contributing

We welcome contributions to KubeUser! Please follow these guidelines:


### Submitting Pull Requests

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/amazing-feature`
3. **Follow** the development setup above
4. **Make** your changes with tests
5. **Ensure** all tests pass: `make test lint`
6. **Commit** with conventional commit format:
   ```
   feat: add user group management
   
   - Implement UserGroup CRD
   - Add controller logic for group management
   - Include comprehensive tests
   
   Fixes #123
   ```
7. **Push** to your fork: `git push origin feature/amazing-feature`
8. **Create** a Pull Request

### Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Pass `golangci-lint` checks
- Write comprehensive tests for new features
- Update documentation for user-facing changes

### Commit Message Format

We use [Conventional Commits](https://conventionalcommits.org/):

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test-related changes
- `refactor:` Code refactoring
- `ci:` CI/CD changes
- `chore:` Maintenance tasks

---

If you find KubeUser useful, please consider giving it a ⭐ on GitHub!