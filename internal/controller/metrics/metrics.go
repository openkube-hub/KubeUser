package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// Certificate Operations
	CertRotationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubeuser_cert_rotations_total",
			Help: "Total number of certificate rotations",
		},
		[]string{"namespace", "user", "status"},
	)

	CertRotationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kubeuser_cert_rotation_duration_seconds",
			Help:    "Duration of certificate rotation operations",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30},
		},
		[]string{"namespace"},
	)

	CertRotationErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubeuser_cert_rotation_errors_total",
			Help: "Total certificate rotation errors",
		},
		[]string{"namespace", "user", "error_type"},
	)

	// User Status
	UsersTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeuser_users_total",
			Help: "Total number of managed users",
		},
		[]string{"namespace", "status"},
	)

	UserSyncStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeuser_user_sync_status",
			Help: "User sync status (1=synced, 0=pending)",
		},
		[]string{"namespace", "user"},
	)

	// Performance Metrics
	ReconciliationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kubeuser_reconciliations_total",
			Help: "Total reconciliation attempts",
		},
		[]string{"controller", "result"},
	)

	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "kubeuser_reconcile_duration_seconds",
			Help:    "Duration of reconciliation loop",
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 15),
		},
		[]string{"controller"},
	)

	// Admission Safety (Thundering Herd)
	ConcurrentRotations = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "kubeuser_concurrent_rotations",
			Help: "Number of concurrent certificate rotations",
		},
	)

	RotationQueueLength = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "kubeuser_rotation_queue_length",
			Help: "Number of pending rotations in queue",
		},
	)

	ThrottledRotations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "kubeuser_throttled_rotations_total",
			Help: "Number of rotations throttled to prevent thundering herd",
		},
	)

	// Expiry Tracking
	CertExpiryTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeuser_cert_expiry_timestamp_seconds",
			Help: "Certificate expiry time as Unix timestamp",
		},
		[]string{"namespace", "user", "cert_type"},
	)

	CertsExpiringWithin24h = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeuser_certs_expiring_24h",
			Help: "Number of certificates expiring within 24 hours",
		},
		[]string{"namespace"},
	)

	CertsExpiringWithin7d = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kubeuser_certs_expiring_7d",
			Help: "Number of certificates expiring within 7 days",
		},
		[]string{"namespace"},
	)
)

func init() {
	// Register all metrics
	metrics.Registry.MustRegister(
		CertRotationsTotal,
		CertRotationDuration,
		CertRotationErrors,
		UsersTotal,
		UserSyncStatus,
		ReconciliationsTotal,
		ReconcileDuration,
		ConcurrentRotations,
		RotationQueueLength,
		ThrottledRotations,
		CertExpiryTimestamp,
		CertsExpiringWithin24h,
		CertsExpiringWithin7d,
	)
}
