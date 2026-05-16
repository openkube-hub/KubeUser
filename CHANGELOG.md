# Changelog

All notable changes to this project will be documented in this file.
The format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Changed
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
