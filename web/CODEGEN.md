# Generated API Client

> Last reviewed: 2026-05-13

Phase 5 of the certctl architecture diligence remediation introduced
orval-based code generation for the frontend API client. The
hand-rolled `web/src/api/client.ts` (1,396 lines, 161 exported
functions) is staged to be retired in favor of the generated
TanStack-Query-shaped surface emitted by orval from
`api/openapi.yaml`.

## Where things live

| Path | What |
|---|---|
| `api/openapi.yaml` | Source of truth — 158 operations |
| `api/openapi-handler-exceptions.yaml` | 64 routes intentionally NOT in OpenAPI (35 wire-protocol carve-outs + 29 REST-deferred) |
| `web/orval.config.ts` | Codegen config — emits `react-query` hooks |
| `web/src/api/generated/` | Output tree (regenerated, git-tracked) |
| `web/src/api/client.ts` | Legacy hand-rolled client (TO BE DELETED in follow-up PR) |
| `web/src/api/mutator.ts` | Fetch wrapper used by the generated client (CSRF, auth) |
| `scripts/ci-guards/openapi-handler-parity.sh` | Verifies every router route is in OpenAPI OR exceptions |
| `scripts/ci-guards/openapi-codegen-drift.sh` | Blocks the build when openapi.yaml changes but generated/ wasn't regenerated |

## First-time setup

Run from the repo root:

```bash
cd web
npm install                                    # installs orval as a devDep
npm run generate                               # regenerates web/src/api/generated/
git add web/src/api/generated/ web/src/api/mutator.ts
git commit -m "feat(web): initial generated API client"
```

The mutator at `web/src/api/mutator.ts` is operator-authored (orval
references it from `orval.config.ts`); it must export a
`certctlFetch<T>(config: AxiosRequestConfig): Promise<T>` function
that the generated code calls for every HTTP request. The mutator is
where CSRF + bearer-token + retry policy + 401-redirect logic lives
in one place.

## Migration pattern (per consumer)

The generated client emits one hook per OpenAPI operation. Migrate
consumers one page at a time; the hand-rolled client and generated
client coexist until the last consumer migrates.

```tsx
// Legacy (web/src/api/client.ts → web/src/pages/CertificatesPage.tsx):
import { useQuery } from '@tanstack/react-query';
import { getCertificates } from '../api/client';

const certs = useQuery({
  queryKey: ['certificates'],
  queryFn: getCertificates,
});

// Generated (web/src/api/generated/certificates/certificates.ts):
import { useGetCertificates } from '../api/generated/certificates/certificates';

const certs = useGetCertificates();   // wires queryKey + queryFn automatically
```

The generated `useGetCertificates()` honors the QueryClient defaults
set in `main.tsx` (frontend-design-audit Phase 2 TQ-H2 / TQ-M1 tier
model). Per-call overrides (`staleTime`, `refetchInterval`, etc.) pass
through as the second argument:

```tsx
const certs = useGetCertificates({
  query: { staleTime: STALE_TIME.REAL_TIME },
});
```

## When the OpenAPI burn-down completes

Today 29 router routes are deferred from `openapi.yaml` (see the
"REST-shaped" group in `api/openapi-handler-exceptions.yaml`). The
generated client only covers what's in `openapi.yaml` — those 29
routes still go through `web/src/api/client.ts` until their OpenAPI
ops land. The burn-down plan:

```
Sprint A — Cluster 1 (auth/sessions + auth/oidc): 12 ops
Sprint B — Cluster 2 (auth/breakglass + auth/users + runtime-config): 8 ops
Sprint C — Cluster 3 (auth/logout + audit/export + misc): 9 ops
```

After Sprint C, every router route is either an OpenAPI operation or
a wire-protocol carve-out. The last consumer migrates off
`web/src/api/client.ts` and the file gets deleted in a follow-up PR.

## CI guards

- `openapi-handler-parity.sh` blocks any new router route that isn't
  in `openapi.yaml` AND isn't in the exceptions YAML.
- `openapi-codegen-drift.sh` blocks any `openapi.yaml` change that
  doesn't regenerate `web/src/api/generated/` alongside.

Both run automatically as part of the per-PR CI guard sweep at
`.github/workflows/ci.yml`.
