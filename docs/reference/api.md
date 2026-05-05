# OpenAPI Specification Guide

certctl ships with a complete OpenAPI 3.1 specification at `api/openapi.yaml`. This spec documents all 78 API operations currently specified, every request/response schema, pagination conventions, authentication requirements, and error formats. It's the single source of truth for the documented REST API. (Note: The spec will be updated to include 7 additional certificate discovery endpoints from M18b.)

This guide covers how to use the spec for API exploration, client SDK generation, and integration testing.

## Where to Find It

The spec lives at `api/openapi.yaml` in the repository root. It's versioned alongside the code and updated with every API change.

```bash
# View the spec
cat api/openapi.yaml

# Count operations
grep "operationId:" api/openapi.yaml | wc -l
# 78 (includes health + ready, 7 discovery endpoints pending spec update)
```

## Viewing with Swagger UI

The fastest way to explore the API interactively is Swagger UI. Run it as a Docker container pointing at the spec:

```bash
# From the certctl repo root
docker run -p 8080:8080 \
  -e SWAGGER_JSON=/spec/openapi.yaml \
  -v $(pwd)/api:/spec \
  swaggerapi/swagger-ui
```

Open http://localhost:8080 to see the full API reference with "Try it out" buttons for every endpoint.

Alternatively, use Redoc for a cleaner read-only view:

```bash
docker run -p 8080:80 \
  -e SPEC_URL=/spec/openapi.yaml \
  -v $(pwd)/api:/usr/share/nginx/html/spec \
  redocly/redoc
```

## API Structure

The spec organizes endpoints into 16 tags:

| Tag | Endpoints | Description |
|-----|-----------|-------------|
| Certificates | 12 | CRUD, versions, renewal, deployment, revocation, deployments |
| CRL & OCSP | 3 | JSON CRL, DER CRL per issuer, OCSP responder |
| Issuers | 5 | CA connector management |
| Targets | 5 | Deployment target management |
| Agents | 7 | Registration, heartbeat, CSR submission, work polling |
| Jobs | 5 | Job queue with approve/reject |
| Policies | 5 | Policy rules and violations |
| Profiles | 5 | Certificate enrollment profiles |
| Teams | 5 | Team management |
| Owners | 5 | Certificate owners |
| Agent Groups | 5 | Dynamic agent grouping |
| Audit | 2 | Immutable audit trail |
| Notifications | 3 | Notification events |
| Stats | 5 | Dashboard statistics |
| Metrics | 1 | System metrics |
| Health | 3 | Health, readiness, auth info |

## Authentication

The spec declares a `bearerAuth` security scheme applied globally. All endpoints under `/api/v1/` require a Bearer token by default:

```bash
# The default compose stack uses a self-signed cert; pin with --cacert
curl --cacert ./deploy/test/certs/ca.crt \
  -H "Authorization: Bearer your-api-key" \
  https://localhost:8443/api/v1/certificates
```

Three endpoints are exempt from auth (declared with `security: []` in the spec): `/health`, `/ready`, and `/api/v1/auth/info`. The auth info endpoint tells clients whether authentication is enabled and what type is required — useful for GUIs that need to show/hide a login screen.

## Pagination Convention

All list endpoints follow the same pagination pattern:

**Request parameters:**
- `page` (integer, default 1) — page number
- `per_page` (integer, default 50, max 500) — results per page

**Response envelope:**
```json
{
  "data": [...],
  "total": 150,
  "page": 1,
  "per_page": 50
}
```

Certificates also support cursor-based pagination for large datasets:
- `cursor` (string) — opaque cursor token from previous response
- `page_size` (integer) — results per page when using cursor mode

## Generating Client SDKs

The OpenAPI spec can generate typed client libraries for any language. Here are examples using common generators:

### TypeScript (openapi-typescript-codegen)

```bash
npx openapi-typescript-codegen \
  --input api/openapi.yaml \
  --output src/generated/certctl \
  --client axios
```

### Python (openapi-python-client)

```bash
pip install openapi-python-client
openapi-python-client generate --path api/openapi.yaml
```

### Go (oapi-codegen)

```bash
go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@latest
oapi-codegen -generate types,client -package certctl api/openapi.yaml > certctl_client.go
```

### Java (OpenAPI Generator)

```bash
npx @openapitools/openapi-generator-cli generate \
  -i api/openapi.yaml \
  -g java \
  -o generated/java-client
```

## Validating the Spec

Verify the spec is valid OpenAPI 3.1:

```bash
# Using spectral (recommended)
npx @stoplight/spectral-cli lint api/openapi.yaml

# Using swagger-cli
npx @apidevtools/swagger-cli validate api/openapi.yaml
```

## Using with Postman

Import the spec directly into Postman:

1. Open Postman → Import → File → select `api/openapi.yaml`
2. Postman creates a collection with all 78 documented operations organized by tag
3. Set the `baseUrl` variable to `https://localhost:8443` (HTTPS-only as of v2.2)
4. Add an `Authorization: Bearer your-api-key` header to the collection
5. Import the demo stack CA bundle (`deploy/test/certs/ca.crt`) into Postman's Settings → Certificates → CA Certificates, or disable certificate verification for the `localhost` host (Settings → General → SSL certificate verification)

## Key Schemas

The spec defines typed schemas for all domain objects. Key schemas to know:

| Schema | Description |
|--------|-------------|
| `ManagedCertificate` | Core certificate record with status, expiry, owner, tags, profile |
| `CertificateVersion` | Individual cert version with PEM, serial, fingerprint, validity |
| `Agent` | Agent with heartbeat, metadata (OS, arch, IP, version), capabilities |
| `Job` | Job record with type, status (7 states), certificate/target references |
| `PolicyRule` | Policy with type (5 types), config, severity, enabled state |
| `CertificateProfile` | Enrollment profile with allowed key types, max TTL, constraints |
| `AuditEvent` | Immutable audit record with actor, action, resource, timestamp |
| `RevocationReason` | RFC 5280 reason code enum (8 values) |
| `DashboardSummary` | Aggregate stats (total certs, expiring, agents, jobs) |

## Integration Testing

Use the spec to generate contract tests that verify the API matches the spec:

```bash
# Using schemathesis for fuzz testing against the spec
pip install schemathesis
# The default compose stack uses a self-signed cert — export a CA bundle or set REQUESTS_CA_BUNDLE
export REQUESTS_CA_BUNDLE=$(pwd)/deploy/test/certs/ca.crt
schemathesis run api/openapi.yaml \
  --base-url https://localhost:8443 \
  --header "Authorization: Bearer your-api-key"
```

This sends randomized valid requests to every endpoint and verifies the responses match the declared schemas.

## What's Next

- [MCP Server Guide](mcp.md) — AI-native access to the certctl API
- [Quick Start](quickstart.md) — Get certctl running locally
- [Connector Guide](connectors.md) — Build custom issuer and target connectors
- [Architecture](architecture.md) — System design deep dive
