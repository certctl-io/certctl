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
{{- if .Values.postgresql.enabled -}}
{{- $sslMode := default "disable" .Values.postgresql.tls.mode -}}
postgres://{{ .Values.postgresql.auth.username }}:$(POSTGRES_PASSWORD)@{{ include "certctl.fullname" . }}-postgres:5432/{{ .Values.postgresql.auth.database }}?sslmode={{ $sslMode }}
{{- else -}}
{{- /*
  Bundle 3 closure (D2 + OPS-L2): external-Postgres first-class path.
  When postgresql.enabled=false, the chart NEVER renders the
  bundled StatefulSet, postgres-secret, or postgres-service —
  templates/postgres-*.yaml gate themselves on .Values.postgresql.enabled.
  The connection string comes from externalDatabase.url (the canonical
  form) or, for backward-compat with pre-Bundle-3 deploys, from
  server.env.CERTCTL_DATABASE_URL (which overrides this helper at the
  pod-spec level — see server-deployment.yaml).

  externalDatabase.url is consumed VERBATIM by the server's
  CERTCTL_DATABASE_URL env var. Operators are responsible for choosing
  the right sslmode (`verify-full` recommended for managed Postgres
  per PCI-DSS Req 4 §2.2.5; see docs/database-tls.md).
*/ -}}
{{- required "externalDatabase.url is required when postgresql.enabled=false" .Values.externalDatabase.url -}}
{{- end -}}
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
{{- if and .Values.server.tls.existingSecret .Values.server.tls.certManager.enabled -}}
{{- /*
  Bundle 3 closure (D7): pre-Bundle-3 the helper only rejected the
  NEITHER-set case. Setting BOTH (`existingSecret` AND `certManager.enabled=true`)
  produced two TLS sources of truth — the existing Secret got mounted but
  cert-manager simultaneously provisioned a Certificate CR pointing at a
  conflicting Secret. Operators ended up with a dangling cert-manager
  Certificate or a wrong-source TLS bundle. The chart now refuses at
  render-time so the misconfiguration cannot ship.
*/ -}}
{{- fail "\n\nserver.tls.existingSecret AND server.tls.certManager.enabled are BOTH set.\n\nThe chart requires EXACTLY ONE TLS ownership path (Bundle 3 closure / audit D7):\n  - existingSecret: operator owns the TLS Secret; cert-manager must NOT provision one.\n  - certManager.enabled: cert-manager owns the TLS Secret; existingSecret must be empty.\n\nUnset one of:\n  --set server.tls.existingSecret=\"\"          (let cert-manager own it)\nOR\n  --set server.tls.certManager.enabled=false   (let the existing Secret stand)\n\nSee docs/tls.md.\n" -}}
{{- end -}}
{{- if and .Values.server.tls.certManager.enabled (not .Values.server.tls.certManager.issuerRef.name) -}}
{{- fail "\n\nserver.tls.certManager.enabled=true but server.tls.certManager.issuerRef.name is empty.\n\nSet:\n  --set server.tls.certManager.issuerRef.name=<your-issuer-or-clusterissuer>\n\nSee docs/tls.md.\n" -}}
{{- end -}}
{{- end }}

{{/*
Pod- vs container-scope security context split (Bundle 3 closure / audit D3).

The Kubernetes API splits SecurityContext into two non-overlapping
field sets, and silently DROPS fields that land at the wrong scope —
which is exactly the audit D3 finding pre-Bundle-3.

Pod-scope fields (applied via spec.securityContext):
  runAsNonRoot, runAsUser, runAsGroup, fsGroup, fsGroupChangePolicy,
  supplementalGroups, seLinuxOptions, seccompProfile, sysctls.

Container-scope fields (applied via spec.containers[].securityContext):
  readOnlyRootFilesystem, allowPrivilegeEscalation, capabilities,
  privileged, procMount, runAsNonRoot/runAsUser/runAsGroup (override),
  seLinuxOptions/seccompProfile (override).

These helpers split a single operator-facing `securityContext` map
into the two sub-maps so the chart renders each field at the scope
where Kubernetes actually honors it. The split is conservative — a
field that COULD live at either scope is rendered at pod scope only
(no override at container scope) so behavior matches the pre-Bundle-3
operator intent: pod-level setting is the source of truth.

Operators don't need to change values.yaml; the existing
`server.securityContext` and `agent.securityContext` blocks keep
working byte-for-byte. The Helm template just routes each field to
the correct YAML node now.
*/}}
{{- define "certctl.podSecurityContext" -}}
{{- $sc := . -}}
{{- $podKeys := list "runAsNonRoot" "runAsUser" "runAsGroup" "fsGroup" "fsGroupChangePolicy" "supplementalGroups" "seLinuxOptions" "seccompProfile" "sysctls" -}}
{{- $out := dict -}}
{{- range $k := $podKeys -}}
{{- if hasKey $sc $k -}}
{{- $_ := set $out $k (index $sc $k) -}}
{{- end -}}
{{- end -}}
{{- toYaml $out -}}
{{- end }}

{{- define "certctl.containerSecurityContext" -}}
{{- $sc := . -}}
{{- $containerKeys := list "readOnlyRootFilesystem" "allowPrivilegeEscalation" "capabilities" "privileged" "procMount" -}}
{{- $out := dict -}}
{{- range $k := $containerKeys -}}
{{- if hasKey $sc $k -}}
{{- $_ := set $out $k (index $sc $k) -}}
{{- end -}}
{{- end -}}
{{- toYaml $out -}}
{{- end }}

{{/*
Required-secret gate (Bundle 3 closure / audit D1).

Pre-Bundle-3 the chart accepted empty `server.auth.apiKey` and empty
`postgresql.auth.password` and rendered Secrets with empty values; the
certctl-server container then crash-looped at startup with the auth
configuration error or with `pq: password authentication failed for
user "certctl"`. Worse, an operator who forgot to set the api-key
ended up with auth.type=api-key + empty CERTCTL_AUTH_SECRET in the
Secret, which Validate() rejects at startup — but the diagnostic
surfaces inside a CrashLoopBackOff, not at `helm install` time where
it would be caught immediately.

Post-Bundle-3 the chart fails at template time with operator-actionable
guidance. The bundled-Postgres path (`postgresql.enabled=true`)
requires `postgresql.auth.password`; the external-Postgres path
(`postgresql.enabled=false`) skips that check because credentials are
embedded in `externalDatabase.url` instead.

Any template that depends on either secret value should call
`{{ include "certctl.requiredSecrets" . }}` at the top so this guard
runs once per affected resource. No-op when configured correctly.
*/}}
{{- define "certctl.requiredSecrets" -}}
{{- if and (eq .Values.server.auth.type "api-key") (not .Values.server.auth.apiKey) -}}
{{- fail "\n\nserver.auth.type=\"api-key\" but server.auth.apiKey is empty.\n\nSet:\n  --set server.auth.apiKey=$(openssl rand -base64 32)\n\nor put the value in a values override. The certctl-server container\nrefuses to start without an API key when auth.type=api-key.\n\nFor demo deploys without authentication, use:\n  --set server.auth.type=none\n(only safe behind an authenticating gateway — see docs/operator/security.md).\n" -}}
{{- end -}}
{{- if and .Values.postgresql.enabled (not .Values.postgresql.auth.password) -}}
{{- fail "\n\npostgresql.enabled=true but postgresql.auth.password is empty.\n\nSet:\n  --set postgresql.auth.password=$(openssl rand -base64 32)\n\nor put the value in a values override. The bundled Postgres\nStatefulSet refuses to bootstrap initdb without POSTGRES_PASSWORD.\n\nFor external Postgres deployments, set:\n  --set postgresql.enabled=false\n  --set externalDatabase.url=postgres://user:pass@host:5432/db?sslmode=require\nSee deploy/helm/examples/values-external-db.yaml.\n" -}}
{{- end -}}
{{- if and (not .Values.postgresql.enabled) (not .Values.externalDatabase.url) (not .Values.server.env.CERTCTL_DATABASE_URL) -}}
{{- fail "\n\npostgresql.enabled=false but no external database URL is configured.\n\nSet ONE of:\n  --set externalDatabase.url=postgres://user:pass@host:5432/db?sslmode=require\nOR (legacy)\n  --set server.env.CERTCTL_DATABASE_URL=postgres://user:pass@host:5432/db?sslmode=require\n\nSee deploy/helm/examples/values-external-db.yaml.\n" -}}
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
{{- $valid := list "api-key" "none" "oidc" -}}
{{- if not (has .Values.server.auth.type $valid) -}}
{{- fail (printf "\n\nserver.auth.type=%q is not supported (valid: %v).\n\nFor JWT/SAML/LDAP, run an authenticating gateway in front of certctl\n(oauth2-proxy / Envoy ext_authz / Traefik ForwardAuth / Pomerium) and\nset server.auth.type=none here so the gateway terminates federated\nidentity. See docs/architecture.md \"Authenticating-gateway pattern\"\nand docs/upgrade-to-v2-jwt-removal.md for the migration walkthrough.\n\nG-1 audit closure: pre-G-1 the chart accepted type=jwt and the binary\nsilently downgraded to api-key middleware. The chart now fails at\ntemplate time so misconfigured deployments cannot ship.\n\nAuth Bundle 2 Phase 0: server.auth.type=oidc is in the valid set but\nthe OIDC handler chain ships in later Bundle 2 phases. Pre-Bundle-2\noperators who set type=oidc see the certctl-server container exit at\nstartup with an actionable error — chart-time validation no longer\nblocks deploy because the binary's runtime guard takes over. Once\nBundle 2 lands, the runtime guard relaxes and OIDC works end-to-end.\n" .Values.server.auth.type $valid) -}}
{{- end -}}
{{- end }}
