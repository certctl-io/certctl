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

Bundle B / Audit M-018 (PCI-DSS Req 4 / CWE-319):
  - postgresql.tls.mode is the operator-facing knob.
    Default: "disable" (preserves the in-cluster Helm-bundled-Postgres
    behavior; pod-to-pod traffic stays on the K8s pod network and is
    encrypted by the CNI when the cluster is configured with a TLS-aware
    CNI such as Cilium WireGuard).
  - Operators on PCI-DSS-scoped clusters or operators using an external
    managed Postgres (RDS, Cloud SQL, Azure DB) MUST set
    postgresql.tls.mode to "require", "verify-ca", or "verify-full" and
    point postgresql.tls.caSecretRef at a Secret containing the
    server-ca.crt under key "ca.crt".
  - The connection string sslmode parameter is wired from
    postgresql.tls.mode without further translation.
*/}}
{{- define "certctl.databaseURL" -}}
{{- $sslMode := default "disable" .Values.postgresql.tls.mode -}}
postgres://{{ .Values.postgresql.auth.username }}:$(POSTGRES_PASSWORD)@{{ include "certctl.fullname" . }}-postgres:5432/{{ .Values.postgresql.auth.database }}?sslmode={{ $sslMode }}
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

{{/*
Auth-type validation gate.

G-1 (P1): pre-G-1 the chart accepted server.auth.type=jwt and the
certctl-server container silently routed every request through the
api-key bearer middleware (no JWT impl ships with certctl). Post-G-1
the chart fails at template-time with a pointer at the authenticating-
gateway pattern. The valid set must stay in sync with
internal/config.ValidAuthTypes() in the Go binary; if you add a value
there you must add it here too (and update the property test in
internal/config/config_test.go that pins both surfaces).

Any template that consumes .Values.server.auth.type should call
`{{ include "certctl.validateAuthType" . }}` at the top so this guard
runs once per affected resource. No-op when configured correctly.
*/}}
{{- define "certctl.validateAuthType" -}}
{{- $valid := list "api-key" "none" -}}
{{- if not (has .Values.server.auth.type $valid) -}}
{{- fail (printf "\n\nserver.auth.type=%q is not supported (valid: %v).\n\nFor JWT/OIDC, run an authenticating gateway in front of certctl\n(oauth2-proxy / Envoy ext_authz / Traefik ForwardAuth / Pomerium) and\nset server.auth.type=none here so the gateway terminates federated\nidentity. See docs/architecture.md \"Authenticating-gateway pattern\"\nand docs/upgrade-to-v2-jwt-removal.md for the migration walkthrough.\n\nG-1 audit closure: pre-G-1 the chart accepted type=jwt and the binary\nsilently downgraded to api-key middleware. The chart now fails at\ntemplate time so misconfigured deployments cannot ship.\n" .Values.server.auth.type $valid) -}}
{{- end -}}
{{- end }}
