package renewal

import (
	"testing"
	"time"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Helper function for tests
func boolPtr(b bool) *bool {
	return &b
}

func TestRenewalCalculator_Basic(t *testing.T) {
	rc := NewRenewalCalculator()
	now := time.Now()

	// Test basic 33% rule
	user := &authv1alpha1.User{
		Spec: authv1alpha1.UserSpec{
			Auth: &authv1alpha1.AuthSpec{
				AutoRenew: boolPtr(true),
			},
		},
	}

	certExpiry := now.Add(24 * time.Hour)
	certDuration := 24 * time.Hour

	renewalTime, err := rc.CalculateRenewalTime(user, certExpiry, certDuration)
	if err != nil {
		t.Fatalf("CalculateRenewalTime() error = %v", err)
	}

	// Should renew before expiry
	if !renewalTime.Before(certExpiry) {
		t.Errorf("Renewal time should be before expiry")
	}

	// Should renew after now
	if !renewalTime.After(now) {
		t.Errorf("Renewal time should be after now")
	}
}

func TestRenewalCalculator_CustomRenewBefore(t *testing.T) {
	rc := NewRenewalCalculator()
	now := time.Now()

	user := &authv1alpha1.User{
		Spec: authv1alpha1.UserSpec{
			Auth: &authv1alpha1.AuthSpec{
				AutoRenew:   boolPtr(true),
				RenewBefore: &metav1.Duration{Duration: 2 * time.Hour},
			},
		},
	}

	certExpiry := now.Add(6 * time.Hour)
	certDuration := 6 * time.Hour

	renewalTime, err := rc.CalculateRenewalTime(user, certExpiry, certDuration)
	if err != nil {
		t.Fatalf("CalculateRenewalTime() error = %v", err)
	}

	// Should renew approximately 2 hours before expiry
	timeBefore := certExpiry.Sub(renewalTime)
	if timeBefore < 1*time.Hour+50*time.Minute || timeBefore > 2*time.Hour+10*time.Minute {
		t.Errorf("Expected renewal ~2h before expiry, got %v", timeBefore)
	}
}

func TestRenewalCalculator_ShouldRenewNow_Basic(t *testing.T) {
	rc := NewRenewalCalculator()
	now := time.Now()

	// Certificate that should renew (past renewal time)
	user := &authv1alpha1.User{
		Spec: authv1alpha1.UserSpec{
			Auth: &authv1alpha1.AuthSpec{
				AutoRenew:   boolPtr(true),
				RenewBefore: &metav1.Duration{Duration: 2 * time.Hour},
			},
		},
	}

	certExpiry := now.Add(1 * time.Hour) // Expires in 1h, should renew 2h before
	certDuration := 6 * time.Hour

	shouldRenew, err := rc.ShouldRenewNow(user, certExpiry, certDuration)
	if err != nil {
		t.Fatalf("ShouldRenewNow() error = %v", err)
	}

	if !shouldRenew {
		t.Errorf("Should renew now, but got false")
	}
}

func TestRotationManager_CSRName(t *testing.T) {
	rm := NewRotationManager(nil, nil, "", nil)

	csrName := rm.generateUniqueCSRName("alice", "12345678-1234-1234-1234-123456789012")
	expected := "alice-renewal-12345678"

	if csrName != expected {
		t.Errorf("generateUniqueCSRName() = %v, want %v", csrName, expected)
	}
}

func TestRotationManager_RequeueDelay(t *testing.T) {
	rm := NewRotationManager(nil, nil, "", nil)

	tests := []struct {
		name         string
		certDuration time.Duration
		want         time.Duration
	}{
		{"short cert", 30 * time.Minute, 10 * time.Second},
		{"medium cert", 12 * time.Hour, 30 * time.Second},
		{"long cert", 7 * 24 * time.Hour, 2 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rm.GetRotationRequeueDelay(tt.certDuration)
			if got != tt.want {
				t.Errorf("GetRotationRequeueDelay() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateRenewalConfig_Basic(t *testing.T) {
	tests := []struct {
		name    string
		user    *authv1alpha1.User
		wantErr bool
	}{
		{
			name: "auto-renewal disabled",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						AutoRenew: boolPtr(false),
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid config",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						AutoRenew:   boolPtr(true),
						TTL:         "24h",
						RenewBefore: &metav1.Duration{Duration: 6 * time.Hour},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "negative renewBefore",
			user: &authv1alpha1.User{
				Spec: authv1alpha1.UserSpec{
					Auth: &authv1alpha1.AuthSpec{
						AutoRenew:   boolPtr(true),
						TTL:         "24h",
						RenewBefore: &metav1.Duration{Duration: -1 * time.Hour},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRenewalConfig(tt.user)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRenewalConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
