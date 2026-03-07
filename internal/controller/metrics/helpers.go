package metrics

import (
	"strings"
)

// ClassifyError categorizes errors for metrics tracking
func ClassifyError(err error) string {
	if err == nil {
		return "none"
	}

	errStr := err.Error()

	// Check approval before CSR since "CSR approval failed" contains both
	if strings.Contains(errStr, "approval") {
		return "approval_error"
	}

	// Certificate-related errors
	if strings.Contains(errStr, "CSR") || strings.Contains(errStr, "csr") {
		return "csr_error"
	}
	if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "cert") {
		return "cert_error"
	}

	// Secret-related errors
	if strings.Contains(errStr, "secret") || strings.Contains(errStr, "Secret") {
		return "secret_error"
	}

	// RBAC-related errors
	if strings.Contains(errStr, "role") || strings.Contains(errStr, "binding") {
		return "rbac_error"
	}

	// API errors
	if strings.Contains(errStr, "not found") {
		return "not_found"
	}
	if strings.Contains(errStr, "already exists") {
		return "already_exists"
	}
	if strings.Contains(errStr, "timeout") {
		return "timeout"
	}

	// Validation errors
	if strings.Contains(errStr, "invalid") || strings.Contains(errStr, "validation") {
		return "validation_error"
	}

	return "unknown"
}
