# GUI QA Checklist

> Last reviewed: 2026-05-05

Manual GUI verification pass for release sign-off. Vitest covers component-level behavior; this checklist covers end-to-end flows that only land correctly when the React SPA, the REST API, and the database are all wired together.

## Prereqs

The full stack must be running and healthy per [`qa-prerequisites.md`](qa-prerequisites.md). Open `https://localhost:8443` in a fresh browser session (Incognito / Private mode is fine — avoids cached state from previous QA passes).

## Pages to verify

For each page, the verification is "open it, confirm it renders without console errors, exercise the documented action, confirm the action lands as expected."

| Page | Action to verify | Expected result |
|---|---|---|
| `/dashboard` | Page loads, all 4 stat cards populate | Total / Active / Expiring / Expired counts match `GET /api/v1/stats/summary` |
| `/certificates` | Inventory list paginates | "Next page" button works; URL updates with cursor; row count consistent |
| `/certificates/<id>` | Detail page opens for any cert | Cert chain renders, deployment status shows, audit timeline visible |
| `/issuers` | Catalog renders all configured issuers | Each issuer card shows last-used / status; clicking opens detail |
| `/issuers/<id>` | Issuer config form | Edit + Save round-trips through `PATCH /api/v1/issuers/<id>` |
| `/issuers/hierarchy` | CA tree view | Multi-level hierarchy renders; admin-gated CRUD buttons present for admins only |
| `/agents` | Fleet view | Online/offline status accurate; OS/arch grouping correct |
| `/agents/<id>` | Agent detail | Last heartbeat, registered date, deployment job history |
| `/agents/groups` | Agent groups CRUD | Create + edit + delete a test group; verify dynamic membership matching |
| `/jobs` | Job queue | Filter by status / type works; click into a job opens detail |
| `/jobs/<id>` | Job detail | Status, retries, logs, owner attribution |
| `/policies` | Renewal policies CRUD | Edit AlertChannels matrix, save, verify backend reflects change |
| `/profiles` | Certificate profiles | EKU constraints + max TTL editable; profile binding works |
| `/notifications` | Notifier config | Test connection button against each configured notifier |
| `/discovery` | Discovery triage | Claim / Dismiss buttons round-trip to backend |
| `/network-scans` | Scan target CRUD | Create scan target, trigger immediate scan, results appear |
| `/audit` | Audit trail | Filter by actor / action / time range; CSV export works |
| `/short-lived` | Short-lived credential dashboard | Live TTL countdown updates; auto-refresh every 10s |
| `/observability` | Observability dashboard | Charts render: expiration heatmap, renewal trends, issuance rate |
| `/health` | Health monitor | TLS endpoint health: healthy / degraded / down states accurate |
| `/digest` | Digest preview | Email preview renders; "Send digest" button dispatches |
| `/owners` | Owners CRUD | Create owner with team, edit, delete (after reassigning certs) |
| `/teams` | Teams CRUD | Create + delete; verify cascade removes orphan owners |
| `/scep` | SCEP admin tabs | Profiles / Intune Monitoring / Recent Activity all populate |
| `/est` | EST admin tabs | Profiles / Recent Activity / Trust Bundle all populate |
| `/login` | Login flow | API key entry persists for the session; bad key rejected |

## Console hygiene

Open browser DevTools and confirm:

- No uncaught exceptions on any page
- No 404 / 500 responses in the Network tab from API calls
- No CORS errors
- No CSP violations

## Mobile / narrow-viewport

The dashboard is desktop-first but should not break catastrophically on narrow viewports. Resize the browser to 380px width; confirm:

- Sidebar collapses to a hamburger menu
- Tables either scroll horizontally or stack on mobile
- Forms remain usable

## Accessibility spot-check

- Tab through any single page using only the keyboard. Every interactive element must be reachable, and the focus indicator must be visible.
- Lighthouse accessibility audit on `/dashboard`: target ≥ 90.

## Sign-off

Document any deviations in the release sign-off matrix at [`release-sign-off.md`](release-sign-off.md).
