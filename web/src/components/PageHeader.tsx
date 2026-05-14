import Breadcrumbs from './Breadcrumbs';

interface PageHeaderProps {
  title: string;
  subtitle?: string;
  action?: React.ReactNode;
}

export default function PageHeader({ title, subtitle, action }: PageHeaderProps) {
  return (
    <div className="flex items-center justify-between px-6 py-4 border-b border-surface-border bg-surface">
      <div>
        {/* Phase 3 UX-M5 closure: breadcrumb trail derived from
            useLocation() + the static pathSegmentLabels map in
            Breadcrumbs.tsx (see that file's header comment for why
            we pivoted away from the useMatches() + handle.crumb
            pattern the audit prompt suggested). Renders nothing on
            the dashboard root — backward-compatible with every
            existing PageHeader consumer. */}
        <Breadcrumbs />
        <h2 className="text-lg font-semibold text-ink">{title}</h2>
        {subtitle && <p className="text-sm text-ink-muted mt-0.5">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}
