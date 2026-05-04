# Intermediate CA hierarchy — operator runbook

Rank 8 of the 2026-05-03 deep-research deliverable. This page is the
canonical reference for operators running certctl as a multi-level
internal PKI.

The default `single`-mode flow (one operator-supplied sub-CA loaded
from disk at boot) is unchanged and will keep working byte-for-byte
forever. This page is for operators who need a real CA tree:

- FedRAMP boundary-CA deployments where the regulator requires
  separation of policy and issuing authorities.
- Financial-services policy-CA deployments (one root, one policy CA
  per business unit, one issuing CA per environment).
- OT / industrial control networks where the air-gapped root signs
  online sub-CAs that go in and out of service on a rotation.

## Concepts

`Issuer.HierarchyMode` is a per-issuer column on the `issuers` table.
Two values are valid (the database default is `"single"` — back-compat
byte-identical for unmigrated rows):

- `single` — pre-Rank-8 historical flow. The local connector loads a
  pre-signed CA cert+key from disk via `local.Config.CACertPath` /
  `local.Config.CAKeyPath`. Existing operators upgrade with no
  behavior change.
- `tree` — the issuer's CAs are managed via the `intermediate_cas`
  table. Chain assembly walks the `parent_ca_id` foreign key from the
  issuing leaf CA up to the root and attaches the assembled chain to
  every `IssuanceResult`.

Each row in `intermediate_cas` is one CA cert (root, policy, issuing).
The lifecycle is `created` → `active` → `retiring` → `retired`. The
state column is a closed enum and validates at the service layer; the
postgres CHECK constraint enforces it at the database layer too.

A CA's private key bytes are NEVER persisted on the row. The
`key_driver_id` column is a reference (filesystem path / KMS key ID /
HSM slot) that the `signer.Driver` resolves at sign time. A SQL
injection or a row-leak surface MUST NEVER expose key bytes; only the
reference can leak.

## Lifecycle states

```
created (CreateRoot or CreateChild)
   │
   ▼
active (issuing certs)
   │
   ▼
retiring  (drain — children still active; this CA stops issuing
           NEW children but existing children continue)
   │
   ▼
retired   (terminal — no issuance, OCSP responder keeps responding
           for already-issued leaves until expiry)
```

Drain-first semantics: a CA in `retiring` state cannot terminalize to
`retired` while it still has active children. The service layer
returns `ErrCAStillHasActiveChildren`; the API surfaces HTTP 409. Drain
the children first.

## Common deployment patterns

### Pattern A — 4-level FedRAMP boundary CA

```
Acme Root CA          (path_len=3, offline air-gapped)
  └── Acme Policy CA  (path_len=2, FedRAMP-Moderate boundary)
        └── Acme Issuing A   (path_len=0, prod workload leaves)
              └── Acme Issuing B (path_len=0, ephemeral pod identity)
```

Operator workflow:

1. Mint the root cert+key on the offline workstation. Move the cert
   PEM (no key) to the online operator workstation.
2. `POST /api/v1/issuers/{id}/intermediates` with the empty
   `parent_ca_id` and `root_cert_pem` + `key_driver_id` populated
   (the operator pre-positions the root key file at the path the
   `key_driver_id` points to). The service validates RFC 5280 §3.2
   self-signed semantics + cross-checks the operator-supplied key
   matches the cert (rejects mismatched bundles at registration time
   with `ErrCAKeyMismatch`).
3. `POST /api/v1/issuers/{id}/intermediates` with `parent_ca_id`
   pointing at the root for the Policy CA. The service generates the
   child key via `signer.Driver.Generate`, signs the child cert via
   the parent's signer (loaded from the parent's `key_driver_id`),
   and persists the new row with the next `path_len` value (parent's
   - 1 if unset). Repeat for each lower level.
4. Set `Issuer.HierarchyMode = "tree"` on the issuer row + set the
   `treeIssuingCAID` connector field to point at the deepest CA
   (Acme Issuing B in the example above) — issued leaves chain via
   `AssembleChain` from B up to the root.

### Pattern B — 3-level financial-services policy CA

```
FinCo Root CA       (path_len=2)
  └── FinCo Trading Policy CA   (path_len=1; permitted DNS = trading.finco.example)
        └── FinCo Trading Issuing CA (path_len=0)
```

Per business-unit name constraints: each policy CA carries a
`PermittedDNSDomains` list scoped to the business unit (RFC 5280
§4.2.1.10). The service enforces subset semantics — a child policy CA
cannot widen the parent's permitted set, and cannot remove an
excluded subtree. Operators submit `name_constraints` on the
`POST /api/v1/issuers/{id}/intermediates` body.

### Pattern C — 2-level internal PKI

```
Internal Root CA  (path_len=0)
  └── Internal Issuing CA (path_len=0; issues leaves directly)
```

The simplest tree-mode deployment. Roughly equivalent to single mode
in terms of operator overhead, but provides one extra layer of
indirection so the root key can stay offline while only the issuing
CA's key sits on the certctl host.

## RFC 5280 enforcement

All enforcement happens at the service layer. The local connector
trusts the service's contract; the API layer translates errors to
HTTP codes.

- §3.2 self-signed root validation: `cert.CheckSignatureFrom(cert)` +
  subject == issuer DN. Rejected with `ErrCANotSelfSigned` →
  HTTP 400.
- §4.2.1.9 path-length tightening: child's `PathLenConstraint` must
  be strictly less than parent's. Default to `parent - 1` when unset.
  Rejected with `ErrPathLenExceeded` → HTTP 400.
- §4.2.1.10 NameConstraints subset: child's `Permitted` set must be a
  subset of parent's; child's `Excluded` set must be a superset of
  parent's. Rejected with `ErrNameConstraintExceeded` → HTTP 400.
- §4.1.2.5 validity capping: child's `notAfter` capped to parent's
  `notAfter` automatically (chain breaks at parent's expiry
  regardless).

## Migrating a single-mode issuer to tree mode

Pre-flight: the load-bearing pin
`TestLocal_HierarchyMode_SingleVsTree_ByteIdentical` guarantees that
a 1-level tree wired around the same on-disk root cert+key produces
byte-identical issuance bundles to single mode. Migration is therefore
a no-downtime operation if done carefully:

1. Register the existing single-mode CA cert as an `intermediate_cas`
   row via `CreateRoot` (with the existing on-disk key referenced as
   `key_driver_id`).
2. Update the issuer row's `hierarchy_mode` to `"tree"` and set the
   connector's `SetTreeIssuingCAID` to the new row's ID. Restart the
   server (no new code path activates until the connector reads the
   updated mode at boot).
3. Issue a test cert. The byte-equivalence pin guarantees the wire
   bytes match the pre-migration output for a 1-level tree.
4. Build out the child CAs via `CreateChild` calls. Update
   `treeIssuingCAID` to the new leaf CA. Test, then ramp.

If the pin breaks during migration, abort: roll back the
`hierarchy_mode` flip and investigate. The byte-equivalence pin is
the canary — if it goes red, deeper bugs lurk.

## API reference

All endpoints under `/api/v1/issuers/{id}/intermediates` and
`/api/v1/intermediates/{id}` are admin-gated. Non-admin Bearer callers
get HTTP 403.

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/issuers/{id}/intermediates` | Register root OR sign child (body discriminator) |
| GET  | `/api/v1/issuers/{id}/intermediates` | List flat hierarchy for issuer |
| GET  | `/api/v1/intermediates/{id}` | Single-row detail |
| POST | `/api/v1/intermediates/{id}/retire` | Two-phase retirement |

See `api/openapi.yaml` for full request/response schemas.

## Observability

`IntermediateCAMetrics` ships counters dimensioned by `(issuer_id,
kind)`:

- `create_root` — successful CreateRoot calls.
- `create_child` — successful CreateChild calls.
- `retire_retiring` — `active → retiring` transitions.
- `retire_retired` — `retiring → retired` transitions.

The Prometheus exposer reads the snapshot via
`SnapshotIntermediateCA()` from a single instance constructed in
`cmd/server/main.go` (the snapshotter is the single source of truth
between the service-side recording path and the metrics-side exposing
path).

The audit table receives one row per CreateRoot / CreateChild /
Retire transition, scoped to the actor extracted from the API
request's auth context.

## Known limitations

The following are tracked in `WORKSPACE-ROADMAP.md` as Rank-8 follow-on
work — none are required for the v2.1.0 acquisition gate:

- HSM-backed roots beyond `signer.FileDriver` (PKCS#11 / cloud KMS
  drivers).
- Automated rotation: scheduled re-issuance of sub-CAs ahead of
  expiry with parallel-validity windows.
- Intra-hierarchy CRL chaining: each non-leaf CA publishes a CRL
  covering its direct children's revocations.
- NameConstraints policy templates: declarative templates an operator
  can pick from instead of hand-rolling the JSON.
- D3 dendrogram visualization on the GUI page (today's render is a
  recursive `<ul>` nested list).
