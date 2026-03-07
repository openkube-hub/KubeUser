package metrics

import (
	"testing"
	"time"
)

func TestRecorder_RecordCertRotation(t *testing.T) {
	recorder := NewRecorder()

	// Should not panic
	recorder.RecordCertRotation("default", "test-user", "success")
	recorder.RecordCertRotation("default", "test-user", "failure")
}

func TestRecorder_ObserveCertRotationDuration(t *testing.T) {
	recorder := NewRecorder()

	// Should not panic
	recorder.ObserveCertRotationDuration("default", 5*time.Second)
	recorder.ObserveCertRotationDuration("default", 100*time.Millisecond)
}

func TestRecorder_RecordRotationError(t *testing.T) {
	recorder := NewRecorder()

	// Should not panic
	recorder.RecordRotationError("default", "test-user", "csr_approval")
	recorder.RecordRotationError("default", "test-user", "atomic_flip")
}

func TestRecorder_SetUserCount(t *testing.T) {
	recorder := NewRecorder()

	// Should not panic
	recorder.SetUserCount("default", "active", 10)
	recorder.SetUserCount("default", "pending", 2)
}

func TestRecorder_SetUserSyncStatus(t *testing.T) {
	recorder := NewRecorder()

	// Should not panic
	recorder.SetUserSyncStatus("default", "test-user", true)
	recorder.SetUserSyncStatus("default", "test-user", false)
}

func TestRecorder_RecordReconciliation(t *testing.T) {
	recorder := NewRecorder()

	// Should not panic
	recorder.RecordReconciliation("user", "success", 100*time.Millisecond)
	recorder.RecordReconciliation("user", "error", 50*time.Millisecond)
}

func TestRecorder_ThrottlingMetrics(t *testing.T) {
	recorder := NewRecorder()

	// Should not panic
	recorder.SetConcurrentRotations(5)
	recorder.SetRotationQueueLength(10)
	recorder.RecordThrottledRotation()
}

func TestRecorder_ExpiryTracking(t *testing.T) {
	recorder := NewRecorder()

	expiry := time.Now().Add(24 * time.Hour)

	// Should not panic
	recorder.SetCertExpiry("default", "test-user", "client", expiry)
	recorder.UpdateExpiryAlerts("default", 2, 5)
}
