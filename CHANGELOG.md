# Changelog

All notable changes to this project will be documented in this file.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed
- **Generated RoleBinding/ClusterRoleBinding names.** The scheme moved from
  `<user>-<role>-rb` / `<user>-<role>-crb` to
  `<user>-<sanitized-role>-<digest>-rb` / `-crb`, where the digest covers
  (user, RoleRef kind, namespace, reference name). The old format omitted the
  RoleRef kind, so a `Role` and a `ClusterRole` of the same name in the same
  namespace collided on a single object name (see below). Secondarily, the old
  format interpolated the reference verbatim: the apiserver accepts that —
  binding names are validated with the laxer RBAC path-segment rules, so
  `alice-system:basic-user-rb` is legal — but the result was neither a valid
  DNS subdomain nor length-bounded. Generated names are now valid DNS
  subdomains for every valid reference and stay within the 253-char budget.
  **Migration is automatic:** on first reconcile after upgrade the controller
  creates the new-scheme binding and reaps the legacy one in the same pass, so
  the grant is never absent in between. Operators or tooling that hardcode
  generated binding names must switch to the `auth.openkube.io/user` label
  selector, which is unchanged. See #93.
- **`spec.roles` uniqueness now includes the RoleRef kind.** A namespaced
  `Role` and a `ClusterRole` of the same name in the same namespace are
  distinct grants and are admitted as two bindings. This relaxes the blanket
  rejection added in #91, which was a stopgap for the fact that both collapsed
  onto one generated object name. Genuine duplicates are still rejected at
  admission and by the controller backstop. See #93.
- **Pod termination behavior.** `terminationGracePeriodSeconds` increased from
  `10` to `45` to accommodate the new `GracefulShutdownTimeout: 30s` drain
  window. SREs running this operator with strict PodDisruptionBudgets or
  tight rolling-update budgets should be aware that node drains and rolling
  updates may now wait up to ~45s per pod (was ~10s). Configurable via
  `terminationGracePeriodSeconds` and `manager.gracefulShutdownTimeoutSeconds`
  in the Helm chart, or via `KUBEUSER_GRACEFUL_SHUTDOWN_TIMEOUT` env var on
  the binary. See #51.

### Added
- Manager voluntarily releases the leader-election lease on SIGTERM
  (`LeaderElectionReleaseOnCancel: true`). Leader handoff on graceful pod
  termination drops from ~15s to <1s in HA deployments. See #51.
- Helm chart enforces `terminationGracePeriodSeconds > GracefulShutdownTimeout`
  with a `fail` template at install/upgrade time. Misconfigurations now error
  at deploy time instead of producing a pod kubelet will SIGKILL mid-drain.
- `--graceful-shutdown-timeout` CLI flag and `KUBEUSER_GRACEFUL_SHUTDOWN_TIMEOUT`
  env var expose the drain window without rebuilding the binary.

### Removed
- Package-level `activeReconcileCount` counter. Replaced by controller-runtime's
  built-in `workqueue_depth{name="user"}` metric. Existing Prometheus alerts
  referencing `kubeuser_workqueue_depth` must be repointed to `workqueue_depth`.
