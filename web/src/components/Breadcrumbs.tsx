// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Breadcrumbs — Phase 3 closure for UX-M5 (zero breadcrumb component,
// zero navigate(-1), 3-deep routes like issuers/:id/hierarchy have no
// wayfinding).
//
// Implementation note: the audit prompt suggested useMatches() + per-
// route handle.crumb. That requires React Router v6's data-router
// (createBrowserRouter), but the certctl app currently uses the JSX
// <BrowserRouter> form. Migrating the router config is its own
// phase-sized effort with non-trivial blast radius (every Route
// element, every test's MemoryRouter wrapper). Instead, this version
// uses useLocation() to read the current pathname + walks the
// segments, mapping each one to a label via the static
// pathSegmentLabels lookup below. Limitations: only the top-level +
// detail-route segments get a label (anything matching /:id/.../ at a
// depth > 2 falls back to the literal segment). Sufficient for the
// 3-deep routes the audit flagged (e.g. /issuers/:id/hierarchy);
// upgrading to data-router-driven crumbs is a future task once the
// router migration ships.

import { Link, useLocation, useInRouterContext } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';

// pathSegmentLabels — map first-segment URL keys to human labels.
// Add entries here as new top-level routes land. Lookup is exact-
// match on the first path segment; subsequent segments are heuristics
// (see crumbsFor below).
const pathSegmentLabels: Record<string, string> = {
  certificates:    'Certificates',
  issuers:         'Issuers',
  agents:          'Agents',
  targets:         'Targets',
  jobs:            'Jobs',
  notifications:   'Notifications',
  policies:        'Policies',
  'renewal-policies': 'Renewal Policies',
  profiles:        'Profiles',
  owners:          'Owners',
  teams:           'Teams',
  'agent-groups':  'Agent Groups',
  audit:           'Audit Trail',
  'short-lived':   'Short-Lived',
  fleet:           'Fleet Overview',
  discovery:       'Discovery',
  'network-scans': 'Network Scans',
  'health-monitor': 'Health Monitor',
  digest:          'Digest',
  observability:   'Observability',
  scep:            'SCEP Admin',
  est:             'EST Admin',
  auth:            'Access',
};

// Auth-subtree subsegments (e.g. /auth/oidc/providers).
const authSubsegmentLabels: Record<string, string> = {
  oidc:       'OIDC',
  providers:  'Providers',
  sessions:   'Sessions',
  users:      'Users',
  roles:      'Roles',
  keys:       'API Keys',
  approvals:  'Approvals',
  breakglass: 'Break-glass',
  settings:   'Auth Settings',
};

interface Crumb {
  pathname: string;
  label: string;
  isLast: boolean;
}

function crumbsFor(pathname: string): Crumb[] {
  // Dashboard root produces no breadcrumb trail — the title alone
  // suffices.
  if (pathname === '/' || pathname === '') return [];

  const segments = pathname.split('/').filter(Boolean);
  if (segments.length === 0) return [];

  // The Dashboard ("Home") crumb is always the first hop.
  const out: Crumb[] = [{ pathname: '/', label: 'Home', isLast: false }];

  // First segment — top-level route.
  const first = segments[0]!;
  const firstLabel = pathSegmentLabels[first] ?? first;
  out.push({
    pathname: '/' + first,
    label: firstLabel,
    isLast: segments.length === 1,
  });

  // Subsequent segments — heuristics:
  //   - /auth/<sub>[/...] uses authSubsegmentLabels for each piece
  //   - any other segment that looks like an :id (starts with a
  //     known prefix or is hex/random) becomes "Detail"
  //   - terminal /hierarchy on /issuers/:id/hierarchy → "Hierarchy"
  let acc = '/' + first;
  for (let i = 1; i < segments.length; i++) {
    const seg = segments[i]!;
    acc += '/' + seg;
    let label: string;
    if (first === 'auth') {
      label = authSubsegmentLabels[seg] ?? seg;
    } else if (seg === 'hierarchy') {
      label = 'Hierarchy';
    } else if (looksLikeID(seg)) {
      label = 'Detail';
    } else {
      label = seg;
    }
    out.push({ pathname: acc, label, isLast: i === segments.length - 1 });
  }

  return out;
}

/** ID-shape heuristic — certctl IDs look like cert-001, iss-vault, t-iis-prod. */
function looksLikeID(s: string): boolean {
  // Anything with a hyphen is treated as an ID for breadcrumb purposes.
  // Hyphenated segments that aren't IDs (renewal-policies, agent-groups,
  // network-scans, health-monitor, short-lived) are top-level routes
  // resolved by pathSegmentLabels BEFORE this heuristic fires.
  return s.includes('-') || /^[a-f0-9]{8,}$/i.test(s);
}

// Breadcrumbs is the public entry. Defensive against missing Router
// context (a test that mounts a PageHeader without a <MemoryRouter>
// wrapper used to crash here). useLocation() throws an invariant
// error if there's no Router; gate it behind useInRouterContext()
// + render the actual logic in a sibling so useLocation() is only
// called when we know the context is present.
export default function Breadcrumbs() {
  const inRouter = useInRouterContext();
  if (!inRouter) return null;
  return <BreadcrumbsInner />;
}

function BreadcrumbsInner() {
  const { pathname } = useLocation();
  const crumbs = crumbsFor(pathname);

  if (crumbs.length === 0) return null;

  return (
    <nav aria-label="Breadcrumb" className="mb-1">
      <ol className="flex items-center gap-1 text-xs text-ink-muted">
        {crumbs.map((c, i) => (
          <li key={c.pathname} className="flex items-center gap-1">
            {i > 0 && (
              <ChevronRight
                className="w-3 h-3 text-ink-faint shrink-0"
                strokeWidth={1.5}
                aria-hidden="true"
              />
            )}
            {c.isLast ? (
              <span aria-current="page" className="text-ink font-medium">
                {c.label}
              </span>
            ) : (
              <Link
                to={c.pathname}
                className="hover:text-brand-500 hover:underline transition-colors"
              >
                {c.label}
              </Link>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
