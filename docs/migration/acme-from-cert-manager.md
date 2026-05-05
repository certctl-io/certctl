# cert-manager Integration Walkthrough

> Last reviewed: 2026-05-05

> **Use this walkthrough when** you're already running cert-manager
> 1.15+ in Kubernetes and want it to issue certs from certctl (your
> internal CA, your private PKI, or a local sub-CA chained under an
> enterprise root) via the standard ACME `ClusterIssuer` model. If
> you want certctl to coexist with cert-manager rather than replace
> its issuer backend, see
> [`docs/migration/cert-manager-coexistence.md`](cert-manager-coexistence.md)
> instead.

End-to-end recipe for issuing certs from a certctl-server deployment
through cert-manager 1.15+. Target audience: Kubernetes operator who
has never deployed certctl before and wants a working
`Certificate` → `Secret` flow on their cluster in under 30 minutes.

The Phase 5 integration test (`make acme-cert-manager-test`) automates
exactly the recipe below. The YAML snippets in this doc are byte-equal
to the files under `deploy/test/acme-integration/` — re-running the
test from a fresh clone produces the same results documented here.

## Prereqs

- A Kubernetes cluster (kind / k3d / EKS / GKE / AKS / on-prem). For
  local trial, `kind v0.20+` works exactly the way the Phase 5 test
  uses it. The kind config lives at
  [`deploy/test/acme-integration/kind-config.yaml`](../deploy/test/acme-integration/kind-config.yaml).
- `kubectl` v1.27+, `helm` v3.13+.
- `cert-manager` v1.15.0 installed in the `cert-manager` namespace.
  If absent, run:

  ```
  bash deploy/test/acme-integration/cert-manager-install.sh
  ```

  which is the same idempotent installer the integration test uses.
- A certctl Helm chart published to a registry your cluster can pull
  from. The Phase 5 test uses an `image.tag=test` placeholder; production
  deployments use the actual image tag for your release line.

## Step 1 — Deploy certctl-server

```
helm install certctl-test deploy/helm/certctl/ \
  --set acmeServer.enabled=true \
  --set acmeServer.defaultProfileId=prof-test \
  --set image.tag=test
kubectl wait --for=condition=Available --timeout=3m deployment/certctl-test
```

`acmeServer.enabled=true` flips the `CERTCTL_ACME_SERVER_ENABLED`
env var which gates the ACME route registration.
`acmeServer.defaultProfileId` sets `CERTCTL_ACME_SERVER_DEFAULT_PROFILE_ID`
so the `/acme/*` shorthand path mirrors the per-profile path family.

## Step 2 — Create the certctl profile

The ACME server requires a `certificate_profiles` row to bind issuance
to. Create one via the certctl API or GUI; for the simplest case set
`acme_auth_mode='trust_authenticated'`:

```
curl -X POST https://certctl-test.default.svc.cluster.local:8443/api/profiles \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $CERTCTL_API_KEY" \
  -d '{
    "id": "prof-test",
    "name": "ACME test profile",
    "issuer_id": "iss-internal-ca",
    "max_ttl_seconds": 7776000,
    "acme_auth_mode": "trust_authenticated"
  }'
```

Auth-mode tradeoffs are covered in
[`docs/acme-server.md` § Auth-mode decision tree](../reference/protocols/acme-server.md#auth-mode-decision-tree).
For first-time deployments, `trust_authenticated` is the right default.

## Step 3 — Capture the certctl bootstrap CA

cert-manager validates the certctl-server's TLS chain before sending
any account / order / finalize JWS. With certctl's self-signed
bootstrap cert (the demo default at `deploy/test/certs/server.crt`),
cert-manager rejects the directory URL with
`x509: certificate signed by unknown authority` unless you feed the
bootstrap CA in.

```
cat deploy/test/certs/ca.crt | base64 -w0
```

Capture the output for Step 4. This is **the** single biggest first-
time-deploy footgun on the cert-manager integration path. The reference
recipe lives in
[`docs/acme-server.md` § TLS trust bootstrap](../reference/protocols/acme-server.md#tls-trust-bootstrap-read-this-before-configuring-cert-manager).

## Step 4 — Apply the ClusterIssuer

```yaml
# Phase 5 — sample ClusterIssuer for the certctl trust_authenticated
# auth mode (RFC 8555 §6 + certctl auth_mode=trust_authenticated, where
# the JWS-authenticated ACME account is trusted to issue any identifier
# the profile policy permits — no per-identifier ownership challenges).
#
# Use this as the starting template for any internal-PKI rollout.
# Replace the caBundle placeholder with the base64-encoded PEM of the
# certctl-server's self-signed bootstrap root, then `kubectl apply`.
#
# Generate the caBundle via:
#   cat deploy/test/certs/ca.crt | base64 -w0
# (See certctl/docs/acme-server.md "TLS trust bootstrap" section for the
# end-to-end walkthrough — this is the single biggest first-time-deploy
# footgun on cert-manager, captured as audit fix #9.)
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: certctl-test-trust
spec:
  acme:
    email: test@example.com
    # Replace 'certctl-test' with your release name + adjust the
    # profile path segment. Default profile path:
    #   https://<service>.<namespace>.svc.cluster.local:8443/acme/profile/<profile-id>/directory
    server: https://certctl-test.default.svc.cluster.local:8443/acme/profile/prof-test/directory
    # caBundle: Audit fix #9. cert-manager validates the ACME server's
    # TLS chain before submitting any account/order/finalize. With a
    # self-signed bootstrap root, the ClusterIssuer MUST carry the root
    # explicitly via this field.
    caBundle: |
      LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCi4uLgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
    privateKeySecretRef:
      name: certctl-test-trust-account-key
    solvers:
      # In trust_authenticated mode the solver is unused at the
      # validation step but cert-manager still requires at least one
      # solver in the spec. http01-via-ingress-nginx is the cheapest
      # placeholder shape that round-trips correctly through cert-
      # manager's validation webhooks.
      - http01:
          ingress:
            class: nginx
```

This block is byte-equal to
[`deploy/test/acme-integration/clusterissuer-trust-authenticated.yaml`](../deploy/test/acme-integration/clusterissuer-trust-authenticated.yaml).
Replace the `caBundle` placeholder with the base64 string from Step 3.
The full reference YAML lives at
[`deploy/test/acme-integration/clusterissuer-trust-authenticated.yaml`](../deploy/test/acme-integration/clusterissuer-trust-authenticated.yaml).

```
kubectl apply -f deploy/test/acme-integration/clusterissuer-trust-authenticated.yaml
kubectl wait --for=condition=Ready --timeout=2m clusterissuer/certctl-test-trust
```

The solver block is a placeholder under `trust_authenticated` mode —
cert-manager 1.15 still requires at least one solver in the spec, but
certctl auto-resolves authzs without a solver round-trip. The
http01-ingress-nginx shape validates against cert-manager's webhook
without needing an actual ingress controller deployed.

For `challenge` mode profiles, swap to
[`deploy/test/acme-integration/clusterissuer-challenge.yaml`](../deploy/test/acme-integration/clusterissuer-challenge.yaml)
— same shape, but the solver is now load-bearing and you need
ingress-nginx (or your chosen ingress class) actually deployed for
HTTP-01 to work.

## Step 5 — Apply the Certificate

```yaml
# Phase 5 — Certificate resource the integration test applies and
# waits for. The certctl-test-trust ClusterIssuer (trust_authenticated
# mode) issues the cert without any solver round-trip; the resulting
# Secret 'test-com-tls' is asserted to carry tls.crt + tls.key.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: test-com
  namespace: default
spec:
  secretName: test-com-tls
  commonName: test.example.com
  dnsNames:
    - test.example.com
    - www.test.example.com
  issuerRef:
    name: certctl-test-trust
    kind: ClusterIssuer
  duration: 720h     # 30d
  renewBefore: 240h  # 10d
```

This block is byte-equal to
[`deploy/test/acme-integration/certificate-test.yaml`](../deploy/test/acme-integration/certificate-test.yaml).

```
kubectl apply -f deploy/test/acme-integration/certificate-test.yaml
kubectl wait --for=condition=Ready --timeout=3m certificate/test-com
```

cert-manager creates an `Order`, the ACME flow runs against certctl,
and the resulting Secret is populated.

## Step 6 — Verify

```
kubectl get certificate test-com -o wide
# NAME       READY   SECRET         ISSUER               STATUS                                          AGE
# test-com   True    test-com-tls   certctl-test-trust   Certificate is up to date and has not expired   42s

kubectl get secret test-com-tls -o yaml | yq '.data."tls.crt"' | base64 -d | openssl x509 -noout -subject -issuer -dates
# subject= CN=test.example.com
# issuer= CN=certctl test internal CA
# notBefore=...  notAfter=...
```

Both the cert-manager `Certificate` resource and the underlying Secret
are populated. The actor on the certctl side is `acme:<account-id>`,
which you can correlate via the `audit_events` table:

```
psql -c "SELECT created_at, action, resource_type, resource_id
         FROM audit_events
         WHERE actor LIKE 'acme:%'
         ORDER BY created_at DESC LIMIT 10;"
```

## Common failure modes

These are operator-side; full troubleshooting reference is in
[`docs/acme-server.md` § Troubleshooting](../reference/protocols/acme-server.md#troubleshooting).

- `400 Bad Request: badNonce` → clock skew between certctl-server and
  cert-manager, or a multi-replica certctl fleet without sticky
  sessions.
- `x509: certificate signed by unknown authority` → missing or stale
  `caBundle`. Re-run Step 3, paste the fresh value.
- `connection refused` from the HTTP-01 validator → ingress controller
  not deployed, OR your network blocks port 80 inbound to the solver
  Ingress.
- `Ready=False` with `rejectedIdentifier` → CSR has a SAN your profile
  policy doesn't permit. Decode the `subproblems` array of the RFC
  7807 problem doc.

## Cleanup

```
kubectl delete -f deploy/test/acme-integration/certificate-test.yaml
kubectl delete -f deploy/test/acme-integration/clusterissuer-trust-authenticated.yaml
helm uninstall certctl-test
# Optional: delete the certctl profile via API.
```

## See also

- [`docs/acme-server.md`](../reference/protocols/acme-server.md) — canonical reference.
- [`docs/acme-server-threat-model.md`](../reference/protocols/acme-server-threat-model.md) —
  security posture.
- [`docs/acme-caddy-walkthrough.md`](./acme-from-caddy.md) —
  Caddy-side recipe.
- [`docs/acme-traefik-walkthrough.md`](./acme-from-traefik.md) —
  Traefik-side recipe.
- [`deploy/test/acme-integration/`](../deploy/test/acme-integration/) —
  Phase 5 integration test (the same recipe, automated).
