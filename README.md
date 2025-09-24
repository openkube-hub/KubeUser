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
- [ ] Finalizers: Proper cleanup of user resources when User objects are deleted
- [ ] Certificate Management: Automatic generation of client certificates for users
- [ ] Kubeconfig Generation: Creates ready-to-use kubeconfig files stored as secrets
- [ ] RBAC Integration: Creates RoleBindings and ClusterRoleBindings based on User spec
- [ ] Role Validation: Validates that referenced Roles and ClusterRoles exist
- [ ] Status Reporting: Comprehensive status updates with conditions
- [ ] Expiry Support: Time-based access control with configurable expiration
- [ ] High availability: support for multi-replica deployments
- [ ] Metrics Endpoint: Prometheus-compatible metrics on port 8080
- [ ] Health Checks: Liveness and readiness probes for robust deployments
- [ ] Resource Cleanup: Automatic cleanup of associated resources on user deletion
- [ ] Webhook validation for User resources
- [ ] Certificate rotation and renewal
- [ ] User group management
- [ ] Audit logging for user access changes
- [ ] Grafana dashboard for user management metrics

## 📦 Installation Instructions

### Prerequisites

- Kubernetes cluster (v1.28+)
- kubectl configured to access your cluster
- Cluster admin permissions


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

## ⚙️ Configuration

### Environment Variables

The operator supports the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `KUBERNETES_API_SERVER` | `https://kubernetes.default.svc` | Kubernetes api address |


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