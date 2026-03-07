package metrics

import (
	"time"
)

type Recorder struct{}

func NewRecorder() *Recorder {
	return &Recorder{}
}

// Certificate Operations
func (r *Recorder) RecordCertRotation(namespace, user, status string) {
	CertRotationsTotal.WithLabelValues(namespace, user, status).Inc()
}

func (r *Recorder) ObserveCertRotationDuration(namespace string, duration time.Duration) {
	CertRotationDuration.WithLabelValues(namespace).Observe(duration.Seconds())
}

func (r *Recorder) RecordRotationError(namespace, user, errorType string) {
	CertRotationErrors.WithLabelValues(namespace, user, errorType).Inc()
}

// User Tracking
func (r *Recorder) SetUserCount(namespace, status string, count float64) {
	UsersTotal.WithLabelValues(namespace, status).Set(count)
}

func (r *Recorder) SetUserSyncStatus(namespace, user string, synced bool) {
	val := float64(0)
	if synced {
		val = 1
	}
	UserSyncStatus.WithLabelValues(namespace, user).Set(val)
}

// Performance
func (r *Recorder) RecordReconciliation(controller, result string, duration time.Duration) {
	ReconciliationsTotal.WithLabelValues(controller, result).Inc()
	ReconcileDuration.WithLabelValues(controller).Observe(duration.Seconds())
}

func (r *Recorder) SetWorkQueueDepth(controller string, depth int) {
	WorkQueueDepth.WithLabelValues(controller).Set(float64(depth))
}

// Thundering Herd Protection
func (r *Recorder) SetConcurrentRotations(count int) {
	ConcurrentRotations.Set(float64(count))
}

func (r *Recorder) SetRotationQueueLength(length int) {
	RotationQueueLength.Set(float64(length))
}

func (r *Recorder) RecordThrottledRotation() {
	ThrottledRotations.Inc()
}

// Expiry Tracking
func (r *Recorder) SetCertExpiry(namespace, user, certType string, expiry time.Time) {
	CertExpiryTimestamp.WithLabelValues(namespace, user, certType).Set(float64(expiry.Unix()))
}

func (r *Recorder) UpdateExpiryAlerts(namespace string, within24h, within7d int) {
	CertsExpiringWithin24h.WithLabelValues(namespace).Set(float64(within24h))
	CertsExpiringWithin7d.WithLabelValues(namespace).Set(float64(within7d))
}
