/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package v1alpha1

// GroupName is the API group for all KubeUser resources. Single source of
// truth — every label, annotation, and finalizer constant in this file
// derives from it, and groupversion_info.go uses the same value for the
// CRD GroupVersion. Changing this string is a breaking API change.
const GroupName = "auth.openkube.io"

// CSRNameAnnotation is the key used on a rotation Shadow Secret to record
// the name of the in-flight CSR. It lives on metadata.annotations (not in
// data) because the CSR object itself is cluster-visible — the name is
// not secret. The writer (createShadowSecretForRotation) and every reader
// must reference this constant; typing the literal at a call site is the
// drift pattern that produced the silent rotation desync bug.
const CSRNameAnnotation = GroupName + "/csr-name"
