package helpers

import (
	"strings"
	"testing"

	authv1alpha1 "github.com/openkube-hub/KubeUser/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

func TestGetKubeconfigClusterNameDefault(t *testing.T) {
	t.Setenv("KUBEUSER_CLUSTER_NAME", "")

	if got := GetKubeconfigClusterName(); got != DefaultKubeconfigClusterName {
		t.Fatalf("GetKubeconfigClusterName() = %q, want %q", got, DefaultKubeconfigClusterName)
	}
}

func TestGetKubeconfigClusterNameCustom(t *testing.T) {
	t.Setenv("KUBEUSER_CLUSTER_NAME", "production")

	if got := GetKubeconfigClusterName(); got != "production" {
		t.Fatalf("GetKubeconfigClusterName() = %q, want production", got)
	}
}

func TestValidateKubeconfigClusterName(t *testing.T) {
	tests := []struct {
		name        string
		clusterName string
		wantErr     bool
	}{
		// Accepted: DNS-1123 labels.
		{
			name:        "default",
			clusterName: DefaultKubeconfigClusterName,
			wantErr:     false,
		},
		{
			name:        "custom",
			clusterName: "production",
			wantErr:     false,
		},
		{
			name:        "hyphenated region",
			clusterName: "prod-eu-west-1",
			wantErr:     false,
		},
		{
			name:        "single character",
			clusterName: "a",
			wantErr:     false,
		},
		{
			name:        "max length 63",
			clusterName: strings.Repeat("a", 63),
			wantErr:     false,
		},
		// Rejected: violations of the DNS-1123 label rule.
		{
			name:        "empty",
			clusterName: "",
			wantErr:     true,
		},
		{
			name:        "uppercase",
			clusterName: "Production",
			wantErr:     true,
		},
		{
			name:        "all uppercase",
			clusterName: "PROD",
			wantErr:     true,
		},
		{
			name:        "underscore",
			clusterName: "prod_east",
			wantErr:     true,
		},
		{
			name:        "over 63 characters",
			clusterName: strings.Repeat("a", 64),
			wantErr:     true,
		},
		{
			name:        "leading hyphen",
			clusterName: "-prod",
			wantErr:     true,
		},
		{
			name:        "trailing hyphen",
			clusterName: "prod-",
			wantErr:     true,
		},
		{
			name:        "leading whitespace",
			clusterName: " production",
			wantErr:     true,
		},
		{
			name:        "embedded whitespace",
			clusterName: "prod east",
			wantErr:     true,
		},
		{
			name:        "context separator",
			clusterName: "prod@east",
			wantErr:     true,
		},
		{
			name:        "yaml separator",
			clusterName: "prod:east",
			wantErr:     true,
		},
		{
			name:        "dot separator",
			clusterName: "prod.east",
			wantErr:     true,
		},
		{
			name:        "newline",
			clusterName: "prod\neast",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateKubeconfigClusterName(tt.clusterName)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateKubeconfigClusterName(%q) error = %v, wantErr %v", tt.clusterName, err, tt.wantErr)
			}
		})
	}
}

// TestIsOwnedByUser pins the trust check used at the shadow-secret and key-secret
// read paths. A false positive here silently accepts externally planted key
// material as if the operator had produced it, which is the class of bug the
// helper exists to prevent.
func TestIsOwnedByUser(t *testing.T) {
	user := &authv1alpha1.User{
		ObjectMeta: metav1.ObjectMeta{
			Name: "alice",
			UID:  types.UID("legit-uid-1234"),
		},
	}

	tests := []struct {
		name string
		obj  metav1.Object
		user *authv1alpha1.User
		want bool
	}{
		{
			name: "matching kind and UID",
			obj: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{{Kind: "User", UID: "legit-uid-1234"}},
			}},
			user: user,
			want: true,
		},
		{
			name: "no owner references at all",
			obj:  &corev1.Secret{ObjectMeta: metav1.ObjectMeta{}},
			user: user,
			want: false,
		},
		{
			name: "wrong UID (impersonation attempt with correct Kind)",
			obj: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{{Kind: "User", UID: "attacker-uid"}},
			}},
			user: user,
			want: false,
		},
		{
			name: "wrong Kind (matching UID but different Kind)",
			obj: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{{Kind: "ConfigMap", UID: "legit-uid-1234"}},
			}},
			user: user,
			want: false,
		},
		{
			name: "match present alongside unrelated refs",
			obj: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "Deployment", UID: "somethin-else"},
					{Kind: "User", UID: "legit-uid-1234"},
				},
			}},
			user: user,
			want: true,
		},
		{
			name: "nil object",
			obj:  nil,
			user: user,
			want: false,
		},
		{
			name: "nil user",
			obj:  &corev1.Secret{},
			user: nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsOwnedByUser(tt.obj, tt.user); got != tt.want {
				t.Errorf("IsOwnedByUser() = %v, want %v", got, tt.want)
			}
		})
	}
}
