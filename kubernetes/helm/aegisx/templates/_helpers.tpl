{{- define "aegisx.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "aegisx.fullname" -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "aegisx.labels" -}}
app.kubernetes.io/name: {{ include "aegisx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aegisx-platform
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end }}

{{- define "aegisx.selectorLabels" -}}
app.kubernetes.io/name: {{ include "aegisx.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "aegisx.image" -}}
{{- $registry := .imageRoot.registry | default .Values.global.imageRegistry -}}
{{- $repo := .imageRoot.repository -}}
{{- $tag := .imageRoot.tag | default .Chart.AppVersion -}}
{{- printf "%s/%s:%s" $registry $repo $tag -}}
{{- end }}

{{- define "aegisx.namespace" -}}
{{- .Release.Namespace | trunc 63 | trimSuffix "-" }}
{{- end }}
