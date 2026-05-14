// Copyright 2026 certctl LLC. All rights reserved.
// SPDX-License-Identifier: BUSL-1.1
//
// CommandPalette — Phase 3 closure for UX-H6 (no cmd+k palette, no
// <input type="search">, no global keyboard-shortcut surface) and
// FE-L4 (rolls under UX-H6 per the audit's framing).
//
// Built on `cmdk`. Three sections:
//
//   1. Navigation — every route surfaced in Layout.tsx's navGroups.
//      Operator types "audit", picks the matching row, navigates to
//      /audit. Reproduces a sidebar without the scroll.
//   2. Actions — quick-fire operations that aren't routes: "Issue
//      new certificate" (navigates to / + ?onboarding=1), "Create
//      issuer", "Trigger discovery scan". Each action is a callback
//      that closes the palette.
//   3. Server-search — debounced fetch against /api/v1/certificates?q=
//      + /api/v1/issuers?q= for typeahead across cert names + issuer
//      names. Results stream into the same cmdk list under a "Search
//      results" heading; clicking jumps to that record's detail page.
//
// Global keydown listener (meta+k on macOS, ctrl+k everywhere else)
// is wired in web/src/main.tsx — the palette itself is render-only
// and reads `open` from a prop.

import { Command } from 'cmdk';
import { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, ShieldCheck, Search, Server, Network, Radar, Timer,
  KeyRound, FileText, ScrollText, RefreshCw, Wrench,
  Target, ListTodo, HeartPulse,
  User, Users, Group,
  Bell, Inbox, Activity,
  Clock, UserCog, CheckCircle2, AlertTriangle, Cog,
  Plus, Zap,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { getCertificates, getIssuers } from '../api/client';
import type { Certificate, Issuer } from '../api/types';

export interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface NavCommand {
  to: string;
  label: string;
  group: string;
  icon: LucideIcon;
}

// NAV_COMMANDS — flattened view of Layout.tsx's navGroups, kept in
// sync by hand. (DRY-ing this against the Layout would require an
// extra module just to share the table; the audit notes future work
// could collapse them.)
const NAV_COMMANDS: NavCommand[] = [
  // Inventory
  { to: '/',               label: 'Dashboard',       group: 'Inventory', icon: LayoutDashboard },
  { to: '/certificates',   label: 'Certificates',    group: 'Inventory', icon: ShieldCheck },
  { to: '/discovery',      label: 'Discovery',       group: 'Inventory', icon: Search },
  { to: '/agents',         label: 'Agents',          group: 'Inventory', icon: Server },
  { to: '/fleet',          label: 'Fleet Overview',  group: 'Inventory', icon: Network },
  { to: '/network-scans',  label: 'Network Scans',   group: 'Inventory', icon: Radar },
  { to: '/short-lived',    label: 'Short-Lived',     group: 'Inventory', icon: Timer },
  // Trust
  { to: '/issuers',          label: 'Issuers',          group: 'Trust', icon: KeyRound },
  { to: '/profiles',         label: 'Profiles',         group: 'Trust', icon: FileText },
  { to: '/policies',         label: 'Policies',         group: 'Trust', icon: ScrollText },
  { to: '/renewal-policies', label: 'Renewal Policies', group: 'Trust', icon: RefreshCw },
  { to: '/scep',             label: 'SCEP Admin',       group: 'Trust', icon: Wrench },
  { to: '/est',              label: 'EST Admin',        group: 'Trust', icon: Wrench },
  // Delivery
  { to: '/targets',         label: 'Targets',        group: 'Delivery', icon: Target },
  { to: '/jobs',            label: 'Jobs',           group: 'Delivery', icon: ListTodo },
  { to: '/health-monitor',  label: 'Health Monitor', group: 'Delivery', icon: HeartPulse },
  // People
  { to: '/owners',       label: 'Owners',       group: 'People', icon: User },
  { to: '/teams',        label: 'Teams',        group: 'People', icon: Users },
  { to: '/agent-groups', label: 'Agent Groups', group: 'People', icon: Group },
  // Notify
  { to: '/notifications', label: 'Notifications', group: 'Notify', icon: Bell },
  { to: '/digest',        label: 'Digest',        group: 'Notify', icon: Inbox },
  { to: '/observability', label: 'Observability', group: 'Notify', icon: Activity },
  // Access
  { to: '/auth/oidc/providers', label: 'OIDC Providers', group: 'Access', icon: ShieldCheck },
  { to: '/auth/sessions',       label: 'Sessions',       group: 'Access', icon: Clock },
  { to: '/auth/users',          label: 'Users',          group: 'Access', icon: Users },
  { to: '/auth/roles',          label: 'Roles',          group: 'Access', icon: UserCog },
  { to: '/auth/keys',           label: 'API Keys',       group: 'Access', icon: KeyRound },
  { to: '/auth/approvals',      label: 'Approvals',      group: 'Access', icon: CheckCircle2 },
  { to: '/auth/breakglass',     label: 'Break-glass',    group: 'Access', icon: AlertTriangle },
  { to: '/auth/settings',       label: 'Auth Settings',  group: 'Access', icon: Cog },
  // Audit
  { to: '/audit', label: 'Audit Trail', group: 'Audit', icon: ScrollText },
];

interface SearchResult {
  type: 'certificate' | 'issuer';
  id: string;
  label: string;
  to: string;
}

/**
 * useDebouncedValue — small hook to throttle the server-search query
 * so we don't fire a fetch on every keystroke.
 */
function useDebouncedValue<T>(value: T, ms: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return debounced;
}

export default function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const debouncedQuery = useDebouncedValue(query, 250);
  const [serverResults, setServerResults] = useState<SearchResult[]>([]);

  // Server-search on debounced input. Empty / <2-char queries skip
  // the fetch (too many results to be useful + load on the API).
  useEffect(() => {
    if (!open || debouncedQuery.length < 2) {
      setServerResults([]);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const [certsResp, issuersResp] = await Promise.all([
          getCertificates({ q: debouncedQuery, per_page: '8' }),
          getIssuers({ q: debouncedQuery, per_page: '8' }),
        ]);
        if (cancelled) return;
        const certs: SearchResult[] = (certsResp?.data ?? []).map((c: Certificate) => ({
          type: 'certificate',
          id: c.id,
          label: c.common_name || c.id,
          to: `/certificates/${c.id}`,
        }));
        const issuers: SearchResult[] = (issuersResp?.data ?? []).map((i: Issuer) => ({
          type: 'issuer',
          id: i.id,
          label: i.name || i.id,
          to: `/issuers/${i.id}`,
        }));
        setServerResults([...certs, ...issuers]);
      } catch {
        // Silent — keep whatever's already in the list.
        if (!cancelled) setServerResults([]);
      }
    })();
    return () => { cancelled = true; };
  }, [debouncedQuery, open]);

  // Reset query each time the palette opens — fresh state per session.
  useEffect(() => {
    if (open) setQuery('');
  }, [open]);

  const navByGroup = useMemo(() => {
    const m = new Map<string, NavCommand[]>();
    for (const n of NAV_COMMANDS) {
      if (!m.has(n.group)) m.set(n.group, []);
      m.get(n.group)!.push(n);
    }
    return m;
  }, []);

  const go = (to: string) => {
    onOpenChange(false);
    navigate(to);
  };

  if (!open) return null;

  return (
    <Command.Dialog
      open={open}
      onOpenChange={onOpenChange}
      label="Global command palette"
      className="fixed inset-0 z-50 flex items-start justify-center pt-24"
    >
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40"
        aria-hidden="true"
        onClick={() => onOpenChange(false)}
      />

      {/* Panel */}
      <div className="relative w-full max-w-xl bg-surface border border-surface-border rounded-lg shadow-2xl overflow-hidden">
        <Command.Input
          autoFocus
          value={query}
          onValueChange={setQuery}
          placeholder="Type a page name, action, or search certs / issuers…"
          className="w-full px-4 py-3 text-sm text-ink bg-transparent border-b border-surface-border focus:outline-none placeholder:text-ink-faint"
        />
        <Command.List className="max-h-96 overflow-y-auto py-1">
          <Command.Empty className="px-4 py-6 text-center text-sm text-ink-faint">
            No matches — try a different term.
          </Command.Empty>

          {/* Navigation — every sidebar item, grouped */}
          {Array.from(navByGroup.entries()).map(([groupName, items]) => (
            <Command.Group key={groupName} heading={groupName}>
              {items.map((item) => {
                const I = item.icon;
                return (
                  <Command.Item
                    key={item.to}
                    value={`${groupName} ${item.label}`}
                    onSelect={() => go(item.to)}
                    className="px-4 py-2 text-sm text-ink cursor-pointer flex items-center gap-3 data-[selected=true]:bg-brand-50 data-[selected=true]:text-brand-700"
                  >
                    <I className="w-4 h-4 shrink-0 text-ink-muted" strokeWidth={1.75} aria-hidden="true" />
                    <span>{item.label}</span>
                  </Command.Item>
                );
              })}
            </Command.Group>
          ))}

          {/* Actions — quick-fire operations that aren't routes */}
          <Command.Group heading="Actions">
            <Command.Item
              value="action issue new certificate"
              onSelect={() => go('/?onboarding=1')}
              className="px-4 py-2 text-sm text-ink cursor-pointer flex items-center gap-3 data-[selected=true]:bg-brand-50 data-[selected=true]:text-brand-700"
            >
              <Plus className="w-4 h-4 shrink-0 text-ink-muted" strokeWidth={1.75} aria-hidden="true" />
              <span>Issue new certificate (Setup guide)</span>
            </Command.Item>
            <Command.Item
              value="action create issuer"
              onSelect={() => go('/issuers')}
              className="px-4 py-2 text-sm text-ink cursor-pointer flex items-center gap-3 data-[selected=true]:bg-brand-50 data-[selected=true]:text-brand-700"
            >
              <KeyRound className="w-4 h-4 shrink-0 text-ink-muted" strokeWidth={1.75} aria-hidden="true" />
              <span>Create issuer…</span>
            </Command.Item>
            <Command.Item
              value="action trigger discovery scan"
              onSelect={() => go('/network-scans')}
              className="px-4 py-2 text-sm text-ink cursor-pointer flex items-center gap-3 data-[selected=true]:bg-brand-50 data-[selected=true]:text-brand-700"
            >
              <Zap className="w-4 h-4 shrink-0 text-ink-muted" strokeWidth={1.75} aria-hidden="true" />
              <span>Trigger discovery scan…</span>
            </Command.Item>
          </Command.Group>

          {/* Server search — only render the heading if we have hits */}
          {serverResults.length > 0 && (
            <Command.Group heading="Search results">
              {serverResults.map((r) => (
                <Command.Item
                  key={`${r.type}-${r.id}`}
                  value={`search ${r.label} ${r.id}`}
                  onSelect={() => go(r.to)}
                  className="px-4 py-2 text-sm text-ink cursor-pointer flex items-center gap-3 data-[selected=true]:bg-brand-50 data-[selected=true]:text-brand-700"
                >
                  {r.type === 'certificate'
                    ? <ShieldCheck className="w-4 h-4 shrink-0 text-ink-muted" strokeWidth={1.75} aria-hidden="true" />
                    : <KeyRound    className="w-4 h-4 shrink-0 text-ink-muted" strokeWidth={1.75} aria-hidden="true" />}
                  <span className="flex-1">{r.label}</span>
                  <span className="text-xs text-ink-faint capitalize">{r.type}</span>
                </Command.Item>
              ))}
            </Command.Group>
          )}
        </Command.List>

        {/* Footer hint */}
        <div className="px-4 py-2 border-t border-surface-border text-xs text-ink-faint flex items-center justify-between">
          <span>↑↓ navigate · ↵ select · esc close</span>
          <span><kbd className="px-1 py-0.5 text-2xs bg-surface-muted border border-surface-border rounded">⌘K</kbd></span>
        </div>
      </div>
    </Command.Dialog>
  );
}
