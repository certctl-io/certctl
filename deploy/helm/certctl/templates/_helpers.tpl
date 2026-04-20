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
Server URL (for agents). HTTPS-only as of v2.2 — see docs/tls.md.
*/}}
{{- define "certctl.serverURL" -}}
https://{{ include "certctl.fullname" . }}-server:{{ .Values.server.service.port }}
{{- end }}

{{/*
TLS Secret name resolver.

Operator-facing precedence:
  1. server.tls.existingSecret        — operator points at a pre-existing kubernetes.io/tls Secret
  2. server.tls.certManager.secretName — explicit secret name for the cert-manager Certificate CR
  3. "<fullname>-tls"                  — default when cert-manager is enabled but secretName is blank

Never emits an empty string — that case is already excluded by certctl.tls.required below,
which must be invoked by any template that depends on the resolved secret name.
*/}}
{{- define "certctl.tls.secretName" -}}
{{- if .Values.server.tls.existingSecret -}}
{{- .Values.server.tls.existingSecret -}}
{{- else if .Values.server.tls.certManager.secretName -}}
{{- .Values.server.tls.certManager.secretName -}}
{{- else -}}
{{- printf "%s-tls" (include "certctl.fullname" .) -}}
{{- end -}}
{{- end }}

{{/*
TLS configuration gate.

HTTPS is the only supported listener mode (v2.2+). The server refuses to start
without a cert/key pair mounted at server.tls.mountPath, so `helm template` /
`helm install` must fail loudly at render-time rather than shipping a broken
Deployment that crash-loops with "tls config required".

Operators MUST configure EXACTLY ONE of:
  (a) server.tls.existingSecret: <name-of-kubernetes.io/tls-secret>
  (b) server.tls.certManager.enabled: true  (+ issuerRef.name populated)

Any template that mounts the TLS Secret must call
`{{ include "certctl.tls.required" . }}` at the top so this guard runs once
per affected resource. No-op when configured correctly.
*/}}
{{- define "certctl.tls.required" -}}
{{- if and (not .Values.server.tls.existingSecret) (not .Values.server.tls.certManager.enabled) -}}
{{- fail "\n\ncertctl refuses to start without TLS.\n\nSet EXACTLY ONE of:\n  --set server.tls.existingSecret=<your-kubernetes.io/tls-secret-name>\nOR\n  --set server.tls.certManager.enabled=true \\\n  --set server.tls.certManager.issuerRef.name=<your-issuer-or-clusterissuer>\n\nSee docs/tls.md for the full setup walkthrough, including bootstrap\nguidance for air-gapped clusters without cert-manager.\n" -}}
{{- end -}}
{{- if and .Values.server.tls.certManager.enabled (not .Values.server.tls.certManager.issuerRef.name) -}}
{{- fail "\n\nserver.tls.certManager.enabled=true but server.tls.certManager.issuerRef.name is empty.\n\nSet:\n  --set server.tls.certManager.issuerRef.name=<your-issuer-or-clusterissuer>\n\nSee docs/tls.md.\n" -}}
{{- end -}}
{{- end }}
