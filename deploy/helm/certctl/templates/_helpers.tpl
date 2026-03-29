{{/*
Expand the name of the chart.
*/}}
{{- define "certctl.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "certctl.fullname" -}}
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
{{- define "certctl.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "certctl.labels" -}}
helm.sh/chart: {{ include "certctl.chart" . }}
{{ include "certctl.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels for the main service (server, agent, postgres)
*/}}
{{- define "certctl.selectorLabels" -}}
app.kubernetes.io/name: {{ include "certctl.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Server selector labels
*/}}
{{- define "certctl.serverSelectorLabels" -}}
{{ include "certctl.selectorLabels" . }}
app.kubernetes.io/component: server
{{- end }}

{{/*
Agent selector labels
*/}}
{{- define "certctl.agentSelectorLabels" -}}
{{ include "certctl.selectorLabels" . }}
app.kubernetes.io/component: agent
{{- end }}

{{/*
PostgreSQL selector labels
*/}}
{{- define "certctl.postgresSelectorLabels" -}}
{{ include "certctl.selectorLabels" . }}
app.kubernetes.io/component: postgres
{{- end }}

{{/*
Service account name
*/}}
{{- define "certctl.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "certctl.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Server image
*/}}
{{- define "certctl.serverImage" -}}
{{- $image := .Values.server.image }}
{{- printf "%s:%s" $image.repository (coalesce $image.tag .Chart.AppVersion) }}
{{- end }}

{{/*
Agent image
*/}}
{{- define "certctl.agentImage" -}}
{{- $image := .Values.agent.image }}
{{- printf "%s:%s" $image.repository (coalesce $image.tag .Chart.AppVersion) }}
{{- end }}

{{/*
PostgreSQL image
*/}}
{{- define "certctl.postgresImage" -}}
{{- $image := .Values.postgresql.image }}
{{- printf "%s:%s" $image.repository $image.tag }}
{{- end }}

{{/*
Database connection string
*/}}
{{- define "certctl.databaseURL" -}}
postgres://{{ .Values.postgresql.auth.username }}:$(POSTGRES_PASSWORD)@{{ include "certctl.fullname" . }}-postgres:5432/{{ .Values.postgresql.auth.database }}?sslmode=disable
{{- end }}

{{/*
Server URL (for agents)
*/}}
{{- define "certctl.serverURL" -}}
http://{{ include "certctl.fullname" . }}-server:{{ .Values.server.service.port }}
{{- end }}
