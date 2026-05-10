# Security Policy

This document describes how security vulnerabilities are handled in the **KubeUser** project.

---

## Supported Versions

Only the **latest release** receives security fixes. We do not backport security patches
to older versions.

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Older releases | ❌ |

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues by emailing:

**yahya.muhaned@gmail.com**

Include as much of the following as possible:

- A description of the vulnerability and its potential impact.
- The component(s) affected (e.g., webhook, cert rotation, RBAC reconciliation).
- Steps to reproduce or a proof-of-concept (if available).
- Any suggested mitigations you are aware of.

All reports are treated as confidential. We will not disclose your identity without
your permission.

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | Within **48 hours** of receipt |
| Severity assessment | Within **5 business days** |
| Fix for Critical / High severity | Within **30 days** |
| Fix for Medium severity | Within **60 days** |
| Fix for Low severity | Best-effort, typically the next minor release |

If we are unable to meet a deadline, we will communicate the delay and revised timeline
directly with the reporter.

---

## Coordinated Disclosure

We follow a **coordinated disclosure** model:

1. Reporter submits the vulnerability privately.
2. We confirm the issue and agree on a fix timeline with the reporter.
3. A fix is developed in a private branch and tested.
4. A new release is cut and published.
5. A public security advisory is posted on GitHub **after** the fix is released.
6. The reporter is credited in the advisory (unless they prefer to remain anonymous).

We request that reporters **do not publicly disclose** the vulnerability until a fix
has been released or 90 days have elapsed since the initial report, whichever comes first.

---

## Scope

### In Scope

The following are considered in scope for security reports:

- Operator reconciliation logic that could lead to privilege escalation or data exposure.
- Mutating or validating webhook bypasses.
- Certificate rotation flaws (shadow secret pattern, CSR approval, atomic flip).
- RBAC binding reconciliation errors that could grant unintended permissions.
- Kubeconfig generation issues (e.g., CA bundle exposure, incorrect server URL).
- Insecure defaults in the Helm chart.
- Dependency vulnerabilities with a known exploit path in KubeUser's context.

### Out of Scope

The following are **not** in scope:

- Vulnerabilities in the Kubernetes API server, CSR API, or controller-runtime that are
  not specific to KubeUser.
- Issues arising from operator misconfiguration by the cluster administrator.
- Vulnerabilities in upstream dependencies that have no realistic exploit path within
  KubeUser.
- Denial-of-service attacks that require cluster-admin privileges to execute.

---

## Deployment Security Recommendations

When deploying KubeUser in production:

- **Restrict Secret access**: The operator's ServiceAccount should only have access to
  the namespaces and secrets it manages. Use namespace-scoped RBAC where possible.
- **Set appropriate TTLs**: Use the shortest TTL appropriate for your environment.
  The default is `2160h` (90 days); consider reducing this for sensitive workloads.
- **CSR signer**: For EKS or GKE, set `KUBEUSER_SIGNER_NAME` to the appropriate
  platform-specific signer rather than using `kubernetes.io/kube-apiserver-client`.
- **Webhook TLS**: Ensure the mutating and validating webhooks are served over TLS
  with a valid certificate. Do not expose the webhook server without TLS.
- **Image verification**: Verify the controller image signature with cosign before
  deploying to production. See the release notes for verification instructions.
- **Limit RBAC scope**: Grant users only the Roles/ClusterRoles they need.
  KubeUser does not validate whether a role is least-privilege; that is the
  responsibility of the cluster administrator.
