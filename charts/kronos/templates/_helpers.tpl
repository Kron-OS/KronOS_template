{{/*
Expand the name of the chart.
*/}}
{{- define "kronos.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "kronos.fullname" -}}
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
Create chart label.
*/}}
{{- define "kronos.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "kronos.labels" -}}
helm.sh/chart: {{ include "kronos.chart" . }}
{{ include "kronos.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "kronos.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kronos.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Backend selector labels.
*/}}
{{- define "kronos.backend.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kronos.name" . }}-backend
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: backend
{{- end }}

{{/*
Nginx selector labels.
*/}}
{{- define "kronos.nginx.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kronos.name" . }}-nginx
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: nginx
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "kronos.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kronos.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Vault agent injection annotations.
*/}}
{{- define "kronos.vaultAnnotations" -}}
{{- if .Values.vault.agentInject }}
vault.hashicorp.com/agent-inject: "true"
vault.hashicorp.com/role: {{ .Values.vault.role | quote }}
vault.hashicorp.com/agent-inject-secret-database: "secret/kronos/database"
vault.hashicorp.com/agent-inject-secret-minio: "secret/kronos/minio"
vault.hashicorp.com/agent-inject-secret-keycloak: "secret/kronos/keycloak"
vault.hashicorp.com/agent-inject-template-database: |
  {{`{{- with secret "secret/kronos/database" -}}`}}
  DATABASE_URL={{ `{{ .Data.data.url }}` }}
  {{`{{- end }}`}}
{{- end }}
{{- end }}

{{/*
Common environment variables for backend containers.
*/}}
{{- define "kronos.commonEnv" -}}
- name: OPENSEARCH_URL
  valueFrom:
    configMapKeyRef:
      name: {{ include "kronos.fullname" . }}-config
      key: opensearch-url
- name: KEYCLOAK_URL
  valueFrom:
    configMapKeyRef:
      name: {{ include "kronos.fullname" . }}-config
      key: keycloak-url
- name: KEYCLOAK_REALM
  valueFrom:
    configMapKeyRef:
      name: {{ include "kronos.fullname" . }}-config
      key: keycloak-realm
- name: KEYCLOAK_CLIENT_ID
  value: {{ .Values.keycloak.clientId | quote }}
- name: MINIO_ENDPOINT
  valueFrom:
    configMapKeyRef:
      name: {{ include "kronos.fullname" . }}-config
      key: minio-endpoint
- name: MINIO_USE_TLS
  value: {{ .Values.minio.useTls | quote }}
{{- end }}
