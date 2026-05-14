// Phase 0 hygiene (FE-H4 / PERF-H3): self-hosted fonts. Replaces the
// Google Fonts @import that used to live at the top of src/index.css —
// Vite hashes + bundles these CSS files into web/dist on build, so cold
// loads no longer touch fonts.googleapis.com / fonts.gstatic.com.
import '@fontsource-variable/inter';
import '@fontsource/jetbrains-mono/400.css';
import '@fontsource/jetbrains-mono/500.css';
import '@fontsource/jetbrains-mono/600.css';

import { StrictMode, Suspense, lazy } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ErrorBoundary from './components/ErrorBoundary';
import AuthProvider from './components/AuthProvider';
import AuthGate from './components/AuthGate';
import Layout from './components/Layout';
// Phase 4 closure (FE-M5 + SCALE-H1): per-route code splitting.
// Pre-Phase-4 every page import above was eager — every page's React
// tree + its api/client + its query-key constants + its chart panels
// landed in the same first-load index-*.js (~1.07 MB raw / ~281 KB gz).
//
// Post-Phase-4 the dashboard stays eager (it's the landing route for
// every cold load) and every other page becomes a React.lazy() boundary
// so its chunk only ships when an operator navigates to that route.
// Each route is wrapped in a <Suspense fallback={<Skeleton variant=
// "page" />}> so the route transition shows a page-shaped skeleton
// instead of a blank white frame during the chunk fetch.
//
// Vite's manualChunks config (see vite.config.ts) splits react /
// react-router-dom / @tanstack/react-query / recharts / lucide-react
// into their own vendor chunks so vendor caches survive feature
// deploys (the index-*.js hash flips on every feature change; vendor
// chunks only re-hash when their package versions change in
// package-lock.json).
//
// Net cold-load budget post-Phase-4: vendor-react + vendor-router +
// vendor-query + (per-route chunk) + index-*.js (now only the routing
// + provider plumbing, not the page bodies). Dashboard adds
// vendor-recharts on demand.
import DashboardPage from './pages/DashboardPage';
import Skeleton from './components/Skeleton';

// Inventory.
const CertificatesPage      = lazy(() => import('./pages/CertificatesPage'));
const CertificateDetailPage = lazy(() => import('./pages/CertificateDetailPage'));
const IssuersPage           = lazy(() => import('./pages/IssuersPage'));
const IssuerDetailPage      = lazy(() => import('./pages/IssuerDetailPage'));
const IssuerHierarchyPage   = lazy(() => import('./pages/IssuerHierarchyPage'));
const TargetsPage           = lazy(() => import('./pages/TargetsPage'));
const TargetDetailPage      = lazy(() => import('./pages/TargetDetailPage'));
const ProfilesPage          = lazy(() => import('./pages/ProfilesPage'));
// Delivery & jobs.
const JobsPage              = lazy(() => import('./pages/JobsPage'));
const JobDetailPage         = lazy(() => import('./pages/JobDetailPage'));
const AgentsPage            = lazy(() => import('./pages/AgentsPage'));
const AgentDetailPage       = lazy(() => import('./pages/AgentDetailPage'));
const AgentFleetPage        = lazy(() => import('./pages/AgentFleetPage'));
const AgentGroupsPage       = lazy(() => import('./pages/AgentGroupsPage'));
// Policy & notify.
const PoliciesPage          = lazy(() => import('./pages/PoliciesPage'));
const RenewalPoliciesPage   = lazy(() => import('./pages/RenewalPoliciesPage'));
const NotificationsPage     = lazy(() => import('./pages/NotificationsPage'));
const DigestPage            = lazy(() => import('./pages/DigestPage'));
// People.
const OwnersPage            = lazy(() => import('./pages/OwnersPage'));
const TeamsPage             = lazy(() => import('./pages/TeamsPage'));
// Audit & ops.
const AuditPage             = lazy(() => import('./pages/AuditPage'));
const ShortLivedPage        = lazy(() => import('./pages/ShortLivedPage'));
const DiscoveryPage         = lazy(() => import('./pages/DiscoveryPage'));
const NetworkScanPage       = lazy(() => import('./pages/NetworkScanPage'));
const HealthMonitorPage     = lazy(() => import('./pages/HealthMonitorPage'));
const ObservabilityPage     = lazy(() => import('./pages/ObservabilityPage'));
// Protocol admin.
const SCEPAdminPage         = lazy(() => import('./pages/SCEPAdminPage'));
const ESTAdminPage          = lazy(() => import('./pages/ESTAdminPage'));
// Access (Bundle 1 Phase 10 — RBAC management).
const RolesPage             = lazy(() => import('./pages/auth/RolesPage'));
const RoleDetailPage        = lazy(() => import('./pages/auth/RoleDetailPage'));
const KeysPage              = lazy(() => import('./pages/auth/KeysPage'));
const AuthSettingsPage      = lazy(() => import('./pages/auth/AuthSettingsPage'));
const ApprovalsPage         = lazy(() => import('./pages/auth/ApprovalsPage'));
// Access (Bundle 2 Phase 8 — OIDC + session management).
const OIDCProvidersPage     = lazy(() => import('./pages/auth/OIDCProvidersPage'));
const OIDCProviderDetailPage = lazy(() => import('./pages/auth/OIDCProviderDetailPage'));
const GroupMappingsPage     = lazy(() => import('./pages/auth/GroupMappingsPage'));
const SessionsPage          = lazy(() => import('./pages/auth/SessionsPage'));
const BreakglassPage        = lazy(() => import('./pages/auth/BreakglassPage'));
// Audit 2026-05-10 MED-11 closure — federated-user admin.
const UsersPage             = lazy(() => import('./pages/auth/UsersPage'));

// Phase 1 closure (UX-H3): toast / snackbar system. Mounted once near
// the root so any component can `import { toast } from "sonner"` and
// call toast.success / toast.error without provider plumbing.
import Toaster from './components/Toaster';
// Phase 3 closure (UX-H6 + FE-L4): cmd+k command palette mounted at
// the root. The hook + listener live in CommandPaletteHost so the
// keydown binding stays scoped to the React tree (auto-cleanup on
// HMR + StrictMode).
import CommandPaletteHost from './components/CommandPaletteHost';
import { STALE_TIME, GC_TIME } from './api/queryConstants';
import './index.css';

// Phase 2 closure (TQ-H2 + TQ-M1): QueryClient defaults rewritten.
// Pre-Phase-2: staleTime 10s + refetchOnWindowFocus true caused a
// refetch storm on every tab refocus across 242 query sites and a
// 10s "freshness" window meaning every cross-page navigation
// triggered backend hits.
//
// Post-Phase-2: 5min REFERENCE staleTime is the dominant-case sane
// default; queries that legitimately need live data (jobs, in-flight
// scans, agent heartbeats — the live-tile cohort) opt in PER-QUERY to
// staleTime: STALE_TIME.REAL_TIME + refetchOnWindowFocus: true. gcTime
// is now explicit at STANDARD (5min) so the contract is documented at
// the root rather than implicit-defaulted by TanStack.
//
// retry: 1 stays — lowering to 0 surfaces network blips; raising to
// the TanStack default of 3 hammers the backend on transient 503s.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: STALE_TIME.REFERENCE,    // 5 min — see api/queryConstants.ts
      gcTime:    GC_TIME.STANDARD,        // 5 min — explicit; was TanStack-default
      retry:     1,
      refetchOnWindowFocus: false,        // per-query opt-in for live-tile queries
    },
  },
});

// Phase 4 helper: wrap a lazy route in a page-shaped Suspense fallback.
// The same Skeleton variant lands on every route so the transition is
// visually consistent — operators learn "skeleton bars = chunk loading"
// once and never see a different placeholder elsewhere.
function lazyRoute(element: React.ReactNode) {
  return <Suspense fallback={<Skeleton variant="page" />}>{element}</Suspense>;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <Toaster />
        <AuthProvider>
          <AuthGate>
            <BrowserRouter>
              <CommandPaletteHost />
              <Routes>
                <Route element={<Layout />}>
                  {/* Dashboard stays eager — landing route for every cold load. */}
                  <Route index element={<DashboardPage />} />
                  <Route path="certificates"            element={lazyRoute(<CertificatesPage />)} />
                  <Route path="certificates/:id"        element={lazyRoute(<CertificateDetailPage />)} />
                  <Route path="agents"                  element={lazyRoute(<AgentsPage />)} />
                  <Route path="agents/:id"              element={lazyRoute(<AgentDetailPage />)} />
                  <Route path="fleet"                   element={lazyRoute(<AgentFleetPage />)} />
                  <Route path="jobs"                    element={lazyRoute(<JobsPage />)} />
                  <Route path="jobs/:id"                element={lazyRoute(<JobDetailPage />)} />
                  <Route path="notifications"           element={lazyRoute(<NotificationsPage />)} />
                  <Route path="policies"                element={lazyRoute(<PoliciesPage />)} />
                  <Route path="renewal-policies"        element={lazyRoute(<RenewalPoliciesPage />)} />
                  <Route path="profiles"                element={lazyRoute(<ProfilesPage />)} />
                  <Route path="issuers"                 element={lazyRoute(<IssuersPage />)} />
                  <Route path="issuers/:id"             element={lazyRoute(<IssuerDetailPage />)} />
                  {/* Rank 8 — operator-managed multi-level CA hierarchy.
                      Admin-gated at the API; the page renders the
                      backend's 403 as ErrorState for non-admin
                      callers. See docs/intermediate-ca-hierarchy.md. */}
                  <Route path="issuers/:id/hierarchy"   element={lazyRoute(<IssuerHierarchyPage />)} />
                  <Route path="targets"                 element={lazyRoute(<TargetsPage />)} />
                  <Route path="targets/:id"             element={lazyRoute(<TargetDetailPage />)} />
                  <Route path="owners"                  element={lazyRoute(<OwnersPage />)} />
                  <Route path="teams"                   element={lazyRoute(<TeamsPage />)} />
                  <Route path="agent-groups"            element={lazyRoute(<AgentGroupsPage />)} />
                  <Route path="audit"                   element={lazyRoute(<AuditPage />)} />
                  <Route path="short-lived"             element={lazyRoute(<ShortLivedPage />)} />
                  <Route path="discovery"               element={lazyRoute(<DiscoveryPage />)} />
                  <Route path="network-scans"           element={lazyRoute(<NetworkScanPage />)} />
                  <Route path="health-monitor"          element={lazyRoute(<HealthMonitorPage />)} />
                  <Route path="digest"                  element={lazyRoute(<DigestPage />)} />
                  <Route path="observability"           element={lazyRoute(<ObservabilityPage />)} />
                  {/* SCEP RFC 8894 + Intune master bundle Phase 9.4 (initial)
                      + Phase 9 follow-up (rebrand): per-profile SCEP
                      Administration page with Profiles / Intune Monitoring /
                      Recent Activity tabs. Route is unconditional; the page
                      itself renders an "Admin access required" banner for
                      non-admin callers and skips the underlying API calls so
                      the server never sees a 403-prone request. */}
                  <Route path="scep"                    element={lazyRoute(<SCEPAdminPage />)} />
                  {/* Backward-compat alias for external bookmarks the Phase 9
                      release advertised. Lands on the Intune Monitoring tab. */}
                  <Route path="scep/intune"             element={lazyRoute(<SCEPAdminPage />)} />
                  {/* EST RFC 7030 hardening master bundle Phase 8: per-profile
                      EST Administration page with Profiles / Recent Activity /
                      Trust Bundle tabs. Same admin-gate pattern as SCEP — the
                      route is unconditional; the page renders an "Admin access
                      required" banner for non-admin callers and skips the
                      underlying API calls so the server never sees a 403. */}
                  <Route path="est"                     element={lazyRoute(<ESTAdminPage />)} />
                  {/* Bundle 1 Phase 10 — RBAC management surface.
                      Every page reads /api/v1/auth/me on mount via the
                      useAuthMe hook and gates affordances against the
                      cached effective_permissions slice. Server-side
                      enforcement is the load-bearing layer; client-side
                      hide/disable is UX. */}
                  {/* Bundle 2 Phase 8 — OIDC + session management surface. */}
                  <Route path="auth/oidc/providers"               element={lazyRoute(<OIDCProvidersPage />)} />
                  <Route path="auth/oidc/providers/:id"           element={lazyRoute(<OIDCProviderDetailPage />)} />
                  <Route path="auth/oidc/providers/:id/mappings"  element={lazyRoute(<GroupMappingsPage />)} />
                  <Route path="auth/sessions"                     element={lazyRoute(<SessionsPage />)} />
                  <Route path="auth/roles"                        element={lazyRoute(<RolesPage />)} />
                  <Route path="auth/roles/:id"                    element={lazyRoute(<RoleDetailPage />)} />
                  <Route path="auth/keys"                         element={lazyRoute(<KeysPage />)} />
                  <Route path="auth/settings"                     element={lazyRoute(<AuthSettingsPage />)} />
                  <Route path="auth/approvals"                    element={lazyRoute(<ApprovalsPage />)} />
                  {/* Audit 2026-05-10 CRIT-4 closure — break-glass admin surface. */}
                  <Route path="auth/breakglass"                   element={lazyRoute(<BreakglassPage />)} />
                  {/* Audit 2026-05-10 MED-11 closure — federated-user admin. */}
                  <Route path="auth/users"                        element={lazyRoute(<UsersPage />)} />
                </Route>
              </Routes>
            </BrowserRouter>
          </AuthGate>
        </AuthProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  </StrictMode>
);
