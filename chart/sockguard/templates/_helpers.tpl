{{/*
Expand the name of the chart.
*/}}
{{- define "sockguard.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
Truncate at 63 chars because some Kubernetes name fields are limited to this.
*/}}
{{- define "sockguard.fullname" -}}
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
Create chart label (name + version).
*/}}
{{- define "sockguard.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "sockguard.labels" -}}
helm.sh/chart: {{ include "sockguard.chart" . }}
{{ include "sockguard.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "sockguard.selectorLabels" -}}
app.kubernetes.io/name: {{ include "sockguard.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Validate and normalize a signed policy bundle object reference.
*/}}
{{- define "sockguard.bundleRef" -}}
{{- $label := .label -}}
{{- $value := .value -}}
{{- if not (kindIs "map" $value) -}}
  {{- fail (printf "%s must be a map containing secretRef or configMapRef" $label) -}}
{{- end -}}
{{- $secretRef := get $value "secretRef" -}}
{{- $configMapRef := get $value "configMapRef" -}}
{{- if not (kindIs "map" $secretRef) -}}
  {{- fail (printf "%s.secretRef must be a map with name and key" $label) -}}
{{- end -}}
{{- if not (kindIs "map" $configMapRef) -}}
  {{- fail (printf "%s.configMapRef must be a map with name and key" $label) -}}
{{- end -}}
{{- $secretEnabled := gt (len $secretRef) 0 -}}
{{- $configMapEnabled := gt (len $configMapRef) 0 -}}
{{- if and $secretEnabled $configMapEnabled -}}
  {{- fail (printf "only one of secretRef or configMapRef may be configured under %s" $label) -}}
{{- end -}}
{{- $enabled := or $secretEnabled $configMapEnabled -}}
{{- $name := "" -}}
{{- $key := "" -}}
{{- $kind := "" -}}
{{- if $enabled -}}
  {{- $refLabel := printf "%s.configMapRef" $label -}}
  {{- $ref := $configMapRef -}}
  {{- $kind = "configMap" -}}
  {{- if $secretEnabled -}}
    {{- $refLabel = printf "%s.secretRef" $label -}}
    {{- $ref = $secretRef -}}
    {{- $kind = "secret" -}}
  {{- end -}}
  {{- if or (not (hasKey $ref "name")) (not (hasKey $ref "key")) -}}
    {{- fail (printf "%s requires non-empty name and key" $refLabel) -}}
  {{- end -}}
  {{- if or (not (kindIs "string" (get $ref "name"))) (not (kindIs "string" (get $ref "key"))) -}}
    {{- fail (printf "%s requires non-empty name and key" $refLabel) -}}
  {{- end -}}
  {{- $name = trim (get $ref "name") -}}
  {{- $key = trim (get $ref "key") -}}
  {{- if or (eq $name "") (eq $key "") -}}
    {{- fail (printf "%s requires non-empty name and key" $refLabel) -}}
  {{- end -}}
{{- end -}}
{{- dict "enabled" $enabled "kind" $kind "name" $name "key" $key | toJson -}}
{{- end }}
