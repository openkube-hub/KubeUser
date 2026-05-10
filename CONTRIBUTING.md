# Contributing to KubeUser

Thank you for your interest in contributing! KubeUser is a Kubernetes operator that
manages users declaratively via a `User` CRD — handling x509 certificate generation,
kubeconfig provisioning, and RBAC binding reconciliation.

This guide covers everything you need to go from zero to a merged pull request.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Making Changes](#making-changes)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)
- [Testing](#testing)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Issues](#reporting-issues)
- [Security Issues](#security-issues)
- [Getting Help](#getting-help)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](./CODE_OF_CONDUCT.md).
By participating, you agree to uphold its terms.

---

## Prerequisites

Make sure the following tools are installed before you begin:

| Tool | Version | Purpose |
|------|---------|---------|
| [Go](https://go.dev/dl/) | 1.24+ | Build and test |
| [kubectl](https://kubernetes.io/docs/tasks/tools/) | Latest | Cluster interaction |
| [kind](https://kind.sigs.k8s.io/docs/user/quick-start/) | Latest | Local cluster for e2e tests |
| [Docker](https://docs.docker.com/get-docker/) | Latest | Building images |
| [make](https://www.gnu.org/software/make/) | Any | Build automation |
| [golangci-lint](https://golangci-lint.run/welcome/install/) | Latest | Linting |

---

## Getting Started

```bash
# 1. Fork the repo on GitHub, then clone your fork
git clone https://github.com/<your-username>/KubeUser.git
cd KubeUser

# 2. Add the upstream remote
git remote add upstream https://github.com/openkube-hub/KubeUser.git

# 3. Install CRDs into your current cluster context
make install

# 4. Run the operator locally (auto-generates webhook certs)
make run
```

> **Note**: `make run` uses your current `kubeconfig` context. Use `kind create cluster`
> if you need a clean local cluster.

---

## Project Structure

| Path | Purpose |
|------|---------|
| `api/v1alpha1/` | `User` CRD types — edit these to change the API |
| `internal/controller/` | Main `UserReconciler` orchestrator |
| `internal/controller/auth/` | x509 cert generation via Kubernetes CSR API |
| `internal/controller/renewal/` | Certificate rotation state machine |
| `internal/controller/rbac/` | RoleBinding / ClusterRoleBinding reconciliation |
| `internal/controller/certs/` | Kubeconfig generation and CA retrieval |
| `internal/controller/cleanup/` | Finalizer-based deletion logic |
| `internal/webhook/` | Mutating and validating webhooks |
| `helm/kubeuser/` | Helm chart |
| `config/` | Kustomize manifests (CRDs, RBAC, webhook configs) |
| `test/` | e2e test suite |

---

## Making Changes

### Modifying API Types

If you change anything in `api/v1alpha1/` or add/update `// +kubebuilder:...` markers,
regenerate the DeepCopy methods and manifests:

```bash
make generate   # Regenerates DeepCopy methods
make manifests  # Regenerates CRD, RBAC, and webhook manifests
```

Always commit the generated files alongside your type changes.

### Running Locally

```bash
make build       # Compile binary to bin/manager
make run         # Run operator locally against current cluster context
make install     # Install CRDs only (no operator process)
```

### Building the Docker Image

```bash
make docker-build   # Builds ghcr.io/openkube-hub/kubeuser-controller:latest
```

---

## Code Style

```bash
make fmt       # Run gofmt
make vet       # Run go vet
make lint      # Run golangci-lint
make lint-fix  # Run golangci-lint with auto-fix
```

All CI checks must pass before a PR can be merged. Run `make fmt vet lint` locally
before pushing.

---

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

**Common types:**

| Type | When to use |
|------|-------------|
| `feat` | New feature or behavior |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that is neither a fix nor a feature |
| `test` | Adding or updating tests |
| `chore` | Build, CI, dependency updates |
| `perf` | Performance improvement |

**Examples:**

```
feat(renewal): add configurable renewBefore floor via env var

fix(rbac): prevent duplicate ClusterRoleBinding creation on requeue

docs(contributing): add API type modification workflow

chore(deps): bump controller-runtime to v0.20.0
```

> Breaking changes must include `BREAKING CHANGE:` in the commit footer.

---

## Testing

### Unit and Integration Tests

Tests use [`envtest`](https://pkg.go.dev/sigs.k8s.io/controller-runtime/pkg/envtest)
— a local API server. No real cluster is required.

```bash
make test                                              # Run all tests
go test ./... -coverprofile=coverage.out              # With coverage
go test -run TestFunctionName ./internal/controller/... # Single test
```

### End-to-End Tests

e2e tests spin up a local `kind` cluster named `kubeuser-test-e2e`:

```bash
make test-e2e
```

> Requires Docker and `kind` to be installed and running.

### What to Test

- Add unit tests for any new reconciliation logic, renewal calculations, or webhook rules.
- Add or update integration tests when changing controller behavior.
- Ensure `make test` passes with no regressions before opening a PR.

---

## Submitting a Pull Request

1. **Create a branch** from the latest `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Make your changes**, following the [code style](#code-style) and
   [commit message](#commit-messages) guidelines.

3. **Run the full check suite**:
   ```bash
   make generate manifests fmt vet lint test
   ```

4. **Open a PR** against `main` with:
   - A clear title following the conventional commit format.
   - A description of *what* changed and *why*.
   - Reference to any related issues (e.g., `Closes #42`).
   - Notes on any manual testing performed.

5. **PR checklist** (reviewers will check these):
   - [ ] `make generate manifests` run if API types or markers changed
   - [ ] `make fmt vet lint` passes with no errors
   - [ ] `make test` passes with no regressions
   - [ ] New behavior is covered by tests
   - [ ] Documentation updated if the change affects user-facing behavior
   - [ ] Helm chart updated if operator flags or defaults changed

**Review SLA**: A maintainer will review your PR within **5 business days**. At least
**one maintainer approval** is required to merge.

---

## Reporting Issues

Use [GitHub Issues](../../issues) to report bugs, ask questions, or suggest features.

When reporting a bug, please include:

- A clear title and description.
- Kubernetes version and cloud provider (if applicable).
- KubeUser version or commit SHA.
- Steps to reproduce the problem.
- Relevant logs, events (`kubectl describe user <name>`), or screenshots.

Looking for a first contribution? Check issues labeled
[`good first issue`](../../issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).

---

## Security Issues

**Do not open public GitHub issues for security vulnerabilities.**

Please see [SECURITY.md](./SECURITY.md) for the responsible disclosure process.

---

## Getting Help

- **GitHub Discussions** — for questions, design proposals, and general conversation.
- **GitHub Issues** — for confirmed bugs and feature requests.
- **Email** — yahya.muhaned@gmail.com for anything that doesn't fit the above.
