// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// Phase 3 joint closure (UX-H1 + FE-H2 + FE-L4, 2026-05-14):
//
//   UX-H1 — sidebar regrouped from a flat 31-item list into 7 semantic
//   groups: Inventory, Trust, Delivery, People, Notify, Access, Audit.
//   Audit-accuracy callout: the original UX-H1 finding's wording
//   ("/auth/* completely absent from primary nav") was factually wrong
//   — all 8 /auth/* entries + /audit were already in the array; the
//   issue was UNGROUPED, not absent. The correct framing is "31 flat
//   items, no hierarchy, scroll-list to find Audit Trail."
//
//   FE-H2 — every nav item now carries a lucide-react icon component
//   reference instead of a literal SVG path string. 31 path strings
//   removed; 27 named lucide imports added.
//
//   FE-L4 — collapsible groups (click the group header to fold/unfold)
//   give the keyboard-first power-user a way to compact the sidebar
//   to just the surfaces they care about. State persists per-group in
//   localStorage so the choice survives reloads.
//
// FE-M6 (CSP unsafe-inline tightening) is NOT closed here — pre-Phase-3
// re-verification confirmed the CSP comment on style-src 'unsafe-inline'
// cites "Tailwind (via Vite) injects per-component <style> blocks at
// build time," not inline SVG attributes. There are also 17 production
// tsx files with React style={...} attributes (Tooltip, AgentFleetPage,
// UsersPage, etc.) that emit inline styles. Tightening the CSP needs
// all those paths migrated to utility classes/CSS variables — out of
// scope for this phase.

import { useState, useEffect } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  // Inventory
  LayoutDashboard, ShieldCheck, Search, Server, Network, Radar, Timer,
  // Trust
  KeyRound, FileText, ScrollText, RefreshCw, Wrench,
  // Delivery
  Target, ListTodo, HeartPulse,
  // People
  User, Users, Group,
  // Notify
  Bell, Inbox, Activity,
  // Access
  Clock, UserCog, CheckCircle2, AlertTriangle, Cog,
  // Logout + setup
  LogOut, HelpCircle,
  // Group header chevron
  ChevronDown, ChevronRight,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useAuth } from './AuthProvider';
import logo from '../assets/certctl-logo.png';

// -----------------------------------------------------------------------------
// Nav model — 7 semantic groups across 31 items.
// -----------------------------------------------------------------------------
interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** Optional data-testid; today only `nav-auth-users` (Audit 2026-05-11 Fix 11). */
  testID?: string;
}
interface NavGroup {
  /** localStorage key suffix for collapsed-state persistence. */
  id: string;
  /** Sidebar header label. */
  label: string;
  items: NavItem[];
}

const navGroups: NavGroup[] = [
  {
    id: 'inventory',
    label: 'Inventory',
    items: [
      { to: '/',               label: 'Dashboard',      icon: LayoutDashboard },
      { to: '/certificates',   label: 'Certificates',   icon: ShieldCheck },
      { to: '/discovery',      label: 'Discovery',      icon: Search },
      { to: '/agents',         label: 'Agents',         icon: Server },
      { to: '/fleet',          label: 'Fleet Overview', icon: Network },
      { to: '/network-scans',  label: 'Network Scans',  icon: Radar },
      { to: '/short-lived',    label: 'Short-Lived',    icon: Timer },
    ],
  },
  {
    id: 'trust',
    label: 'Trust',
    items: [
      { to: '/issuers',          label: 'Issuers',          icon: KeyRound },
      { to: '/profiles',         label: 'Profiles',         icon: FileText },
      { to: '/policies',         label: 'Policies',         icon: ScrollText },
      { to: '/renewal-policies', label: 'Renewal Policies', icon: RefreshCw },
      { to: '/scep',             label: 'SCEP Admin',       icon: Wrench },
      { to: '/est',              label: 'EST Admin',        icon: Wrench },
    ],
  },
  {
    id: 'delivery',
    label: 'Delivery',
    items: [
      { to: '/targets',         label: 'Targets',        icon: Target },
      { to: '/jobs',            label: 'Jobs',           icon: ListTodo },
      { to: '/health-monitor',  label: 'Health Monitor', icon: HeartPulse },
    ],
  },
  {
    id: 'people',
    label: 'People',
    items: [
      { to: '/owners',       label: 'Owners',       icon: User },
      { to: '/teams',        label: 'Teams',        icon: Users },
      { to: '/agent-groups', label: 'Agent Groups', icon: Group },
    ],
  },
  {
    id: 'notify',
    label: 'Notify',
    items: [
      { to: '/notifications', label: 'Notifications', icon: Bell },
      { to: '/digest',        label: 'Digest',        icon: Inbox },
      { to: '/observability', label: 'Observability', icon: Activity },
    ],
  },
  {
    id: 'access',
    label: 'Access',
    items: [
      // Bundle 2 Phase 8 — OIDC + Sessions.
      { to: '/auth/oidc/providers', label: 'OIDC Providers', icon: ShieldCheck },
      { to: '/auth/sessions',       label: 'Sessions',       icon: Clock },
      // Audit 2026-05-11 Fix 11 — `nav-auth-users` testid pins this entry's
      // selectability; sit Users immediately after Sessions to preserve the
      // federated-identity DOM order asserted in Layout.test.tsx.
      { to: '/auth/users',          label: 'Users',          icon: Users,    testID: 'nav-auth-users' },
      { to: '/auth/roles',          label: 'Roles',          icon: UserCog },
      { to: '/auth/keys',           label: 'API Keys',       icon: KeyRound },
      { to: '/auth/approvals',      label: 'Approvals',      icon: CheckCircle2 },
      // Audit 2026-05-10 CRIT-4 closure — break-glass admin.
      { to: '/auth/breakglass',     label: 'Break-glass',    icon: AlertTriangle },
      { to: '/auth/settings',       label: 'Auth Settings',  icon: Cog },
    ],
  },
  {
    id: 'audit',
    label: 'Audit',
    items: [
      { to: '/audit', label: 'Audit Trail', icon: ScrollText },
    ],
  },
];

// -----------------------------------------------------------------------------
// useCollapsedGroups — persist per-group collapsed state in localStorage.
// -----------------------------------------------------------------------------
const STORAGE_KEY = 'certctl:nav:collapsed-groups';

function useCollapsedGroups(): [Set<string>, (id: string) => void] {
  const [collapsed, setCollapsed] = useState<Set<string>>(() => {
    if (typeof window === 'undefined') return new Set();
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      return new Set(raw ? (JSON.parse(raw) as string[]) : []);
    } catch {
      return new Set();
    }
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify([...collapsed]));
    } catch {
      /* noop — storage quota / privacy mode */
    }
  }, [collapsed]);

  const toggle = (id: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return [collapsed, toggle];
}

// -----------------------------------------------------------------------------
// Layout
// -----------------------------------------------------------------------------
export default function Layout() {
  const { authRequired, logout } = useAuth();
  const navigate = useNavigate();
  const [collapsed, toggleGroup] = useCollapsedGroups();

  const openSetupGuide = () => {
    try { localStorage.removeItem('certctl:onboarding-dismissed'); } catch { /* noop */ }
    navigate('/?onboarding=1');
  };

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar — deep teal from logo */}
      <aside className="w-60 bg-sidebar flex flex-col shadow-xl">
        {/* Logo — large and prominent */}
        <div className="px-4 pt-5 pb-4 flex flex-col items-center gap-2">
          <div className="bg-white rounded-xl p-2 shadow-lg">
            <img src={logo} alt="certctl" className="h-16 w-16" width={64} height={64} loading="eager" decoding="async" />
          </div>
          <div className="text-center">
            <h1 className="text-lg font-bold text-white tracking-tight">certctl</h1>
            <p className="text-2xs text-brand-300 uppercase tracking-[0.2em]">Control Plane</p>
          </div>
        </div>

        <nav className="flex-1 py-2 px-3 space-y-3 overflow-y-auto" aria-label="Primary navigation">
          {navGroups.map((group) => {
            const isCollapsed = collapsed.has(group.id);
            return (
              <div key={group.id} className="space-y-0.5">
                {/* Group header — clickable to toggle collapse. */}
                <button
                  type="button"
                  onClick={() => toggleGroup(group.id)}
                  aria-expanded={!isCollapsed}
                  aria-controls={`nav-group-${group.id}`}
                  className="w-full flex items-center justify-between px-3 py-1.5 text-2xs uppercase tracking-wider text-brand-300/60 hover:text-brand-300 transition-colors border-t border-white/10 pt-2 mt-1 first:border-t-0 first:pt-1 first:mt-0"
                >
                  <span>{group.label}</span>
                  {isCollapsed
                    ? <ChevronRight className="w-3 h-3 shrink-0" aria-hidden="true" />
                    : <ChevronDown  className="w-3 h-3 shrink-0" aria-hidden="true" />}
                </button>
                {/* Group items — fold via inline display:none when collapsed
                    (vs unmount) so the NavLinks retain focus state and the
                    operator's next click doesn't re-render the entire group.
                    aria-hidden mirrors the visual state for screen readers. */}
                <div
                  id={`nav-group-${group.id}`}
                  className={`space-y-0.5 ${isCollapsed ? 'hidden' : ''}`}
                  aria-hidden={isCollapsed}
                >
                  {group.items.map((item) => {
                    const ItemIcon = item.icon;
                    return (
                      <NavLink
                        key={item.to}
                        to={item.to}
                        end={item.to === '/'}
                        data-testid={item.testID}
                        className={({ isActive }) =>
                          `flex items-center gap-3 px-3 py-2 text-sm rounded transition-all duration-150 ${
                            isActive
                              ? 'bg-white/15 text-white font-semibold shadow-sm'
                              : 'text-sidebar-text hover:text-white hover:bg-white/10'
                          }`
                        }
                      >
                        <ItemIcon className="w-[18px] h-[18px] shrink-0" strokeWidth={1.75} aria-hidden="true" />
                        {item.label}
                      </NavLink>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </nav>

        <div className="px-3 pb-2 pt-2 border-t border-white/10">
          <button
            type="button"
            onClick={openSetupGuide}
            title="Reopen the onboarding wizard"
            className="w-full flex items-center gap-3 px-3 py-2 text-sm rounded text-sidebar-text hover:text-white hover:bg-white/10 transition-all duration-150"
          >
            <HelpCircle className="w-[18px] h-[18px] shrink-0" strokeWidth={1.75} aria-hidden="true" />
            Setup guide
          </button>
        </div>

        {/* Maintainer attribution row — mirrors the landing-page footer
            (certctl.io: "Built and maintained by Shankar · certctl.io").
            Same font-mono / muted-text typography; only "Shankar" carries
            the LinkedIn link (the same href + rel="me noopener" pattern
            the landing page uses). Single-maintainer OSS standard
            (Cal.com, Plausible, Beekeeper Studio do the same). */}
        <div className="px-5 pt-3 pb-1 border-t border-white/10">
          <span className="text-2xs text-sidebar-text/70 font-mono">
            Built and maintained by{' '}
            <a
              href="https://www.linkedin.com/in/shankar-k-a1b6853ba"
              target="_blank"
              rel="me noopener noreferrer"
              className="text-sidebar-text/90 hover:text-white transition-colors underline-offset-2 hover:underline"
              title="Shankar on LinkedIn — opens in a new tab"
            >
              Shankar
            </a>
          </span>
        </div>

        <div className="px-5 pt-1 pb-3 flex items-center justify-between">
          <span className="text-2xs text-brand-300/60 font-mono">certctl</span>
          {authRequired && (
            <button
              onClick={logout}
              className="text-xs text-sidebar-text hover:text-white transition-colors"
              title="Sign out"
              aria-label="Sign out"
            >
              <LogOut className="w-4 h-4" strokeWidth={1.75} aria-hidden="true" />
            </button>
          )}
        </div>
      </aside>

      {/* Main content — light background */}
      <main className="flex-1 flex flex-col overflow-hidden bg-page">
        <Outlet />
      </main>
    </div>
  );
}
