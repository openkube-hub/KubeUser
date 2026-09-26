/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package rbac

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

const (
	// maxObjectNameLen is the apiserver's DNS-subdomain budget for metadata.name.
	maxObjectNameLen = 253
	// nameDigestLen is the hex width of the identity digest. 32 bits is ample
	// for the per-user key space while keeping the readable prefix long.
	nameDigestLen = 8
)

// illegalNameChars matches everything a DNS-1123 subdomain forbids. Role and
// ClusterRole names are validated with the RBAC name rules, which are laxer:
// ":" (system:basic-user), "_" and uppercase are all legal there. The apiserver
// would accept them in a binding name too, but a name that is a plain DNS
// subdomain stays usable everywhere an object name is expected — a label value,
// for one, cannot contain a colon.
var illegalNameChars = regexp.MustCompile(`[^a-z0-9-]+`)

// roleBindingName returns the object name for the RoleBinding backing one
// spec.roles entry. roleKind is part of the identity because a namespaced Role
// and a ClusterRole of the same name in the same namespace are two distinct
// grants that must be representable as two separate RoleBindings.
func roleBindingName(username, namespace, roleKind, roleName string) string {
	return bindingName(username, roleName, "rb", username, namespace, roleKind, roleName)
}

// clusterRoleBindingName returns the object name for the ClusterRoleBinding
// backing one spec.clusterRoles entry.
func clusterRoleBindingName(username, clusterRoleName string) string {
	return bindingName(username, clusterRoleName, "crb", username, "ClusterRole", clusterRoleName)
}

// bindingName renders "<username>-<ref>-<digest>-<suffix>", a valid DNS
// subdomain for every valid Role/ClusterRole reference. The readable prefix is
// sanitized and truncated for humans; the digest over identity carries the
// uniqueness that sanitizing and truncation would otherwise collapse.
func bindingName(username, refName, suffix string, identity ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(identity, "\x00")))
	digest := hex.EncodeToString(sum[:])[:nameDigestLen]

	readable := sanitizeNameSegment(username) + "-" + sanitizeNameSegment(refName)
	// Two separators sit between the three trailing segments.
	if budget := maxObjectNameLen - len(digest) - len(suffix) - 2; len(readable) > budget {
		readable = readable[:budget]
	}

	return readable + "-" + digest + "-" + suffix
}

func sanitizeNameSegment(s string) string {
	return illegalNameChars.ReplaceAllString(strings.ToLower(s), "-")
}
