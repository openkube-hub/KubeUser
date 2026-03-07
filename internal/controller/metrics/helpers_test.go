package metrics

import (
	"errors"
	"testing"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: "none",
		},
		{
			name:     "CSR error",
			err:      errors.New("failed to create CSR"),
			expected: "csr_error",
		},
		{
			name:     "certificate error",
			err:      errors.New("certificate validation failed"),
			expected: "cert_error",
		},
		{
			name:     "approval error",
			err:      errors.New("CSR approval failed"),
			expected: "approval_error",
		},
		{
			name:     "secret error",
			err:      errors.New("failed to update secret"),
			expected: "secret_error",
		},
		{
			name:     "RBAC error",
			err:      errors.New("role binding creation failed"),
			expected: "rbac_error",
		},
		{
			name:     "not found error",
			err:      errors.New("resource not found"),
			expected: "not_found",
		},
		{
			name:     "already exists error",
			err:      errors.New("resource already exists"),
			expected: "already_exists",
		},
		{
			name:     "timeout error",
			err:      errors.New("operation timeout"),
			expected: "timeout",
		},
		{
			name:     "validation error",
			err:      errors.New("invalid configuration"),
			expected: "validation_error",
		},
		{
			name:     "unknown error",
			err:      errors.New("something went wrong"),
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ClassifyError(tt.err)
			if result != tt.expected {
				t.Errorf("ClassifyError() = %v, want %v", result, tt.expected)
			}
		})
	}
}
