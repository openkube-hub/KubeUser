{{/*
Expand the name of the chart.
*/}}
{{- define "kubeuser.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kubeuser.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kubeuser.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kubeuser.labels" -}}
helm.sh/chart: {{ include "kubeuser.chart" . }}
{{ include "kubeuser.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kubeuser.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubeuser.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kubeuser.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kubeuser.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create manager labels for controller-manager
*/}}
{{- define "kubeuser.managerLabels" -}}
control-plane: controller-manager
app.kubernetes.io/name: {{ include "kubeuser.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Create selector labels for controller-manager
*/}}
{{- define "kubeuser.managerSelectorLabels" -}}
control-plane: controller-manager
app.kubernetes.io/name: {{ include "kubeuser.name" . }}
{{- end }}

{{/*
Create image name
*/}}
{{- define "kubeuser.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Validate that terminationGracePeriodSeconds leaves at least 5 seconds of
headroom above manager.gracefulShutdownTimeoutSeconds. Headroom covers the
leader-lease release PATCH and any straggling API calls on the way out.

Called from templates/deployment.yaml — fails the install/upgrade with a
descriptive message instead of silently producing a Pod kubelet will
SIGKILL mid-drain.
*/}}
{{- define "kubeuser.validateGracePeriod" -}}
{{- $grace := int .Values.terminationGracePeriodSeconds -}}
{{- $drain := int .Values.manager.gracefulShutdownTimeoutSeconds -}}
{{- if le $grace $drain -}}
{{- fail (printf "terminationGracePeriodSeconds (%d) must be strictly greater than manager.gracefulShutdownTimeoutSeconds (%d). Recommended: %d." $grace $drain (add $drain 15)) -}}
{{- end -}}
{{- if lt (sub $grace $drain) 5 -}}
{{- fail (printf "terminationGracePeriodSeconds (%d) must exceed manager.gracefulShutdownTimeoutSeconds (%d) by at least 5s for the lease-release PATCH. Recommended: %d." $grace $drain (add $drain 15)) -}}
{{- end -}}
{{- end -}}
