// Phase 4 closure (PERF-M1 + P-H3): memoized dashboard chart panels.
//
// Pre-Phase-4 the four chart panels lived as inline JSX inside
// DashboardPage's return statement. DashboardPage has 9 useQuery hooks
// (health / summary / issuers / statusCounts / expirationTimeline /
// jobTrends / issuanceRate / certs / jobs) and each refetch — including
// the per-tab refocus refetches the Phase 2 work narrowed but didn't
// eliminate for the live-tile cohort — forced React to re-evaluate every
// chart's JSX subtree, including the Recharts ResponsiveContainer
// reconciliation that the library uses under the hood (~10-50 ms each
// for charts with non-trivial data).
//
// Post-Phase-4 each chart is its own React.memo-wrapped component. When
// only `summary` updates, the four chart panels skip re-render entirely
// because their `data` prop didn't change. When `jobTrends` updates,
// only `JobTrendsLineChart` re-renders; the other three panels skip.
//
// React.memo's default equality is referential (Object.is). The parent
// DashboardPage passes the query result's `.data` arrays directly — TanStack
// Query returns a stable reference until the underlying data actually
// changes (it caches via queryKey), so referential equality is the
// correct check for this layer. No custom areEqual function needed.

import { memo } from 'react';
import {
  BarChart, Bar, LineChart, Line, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

// ─── Shared helpers ──────────────────────────────────────

/** PascalCase → space-separated for display ("RenewalInProgress" → "Renewal In Progress"). */
const formatStatus = (s: string) => s.replace(/([a-z])([A-Z])/g, '$1 $2');

/** "2026-05-10" → "5/10" for compact x-axis labels. */
const formatShortDate = (dateStr: string) => {
  const d = new Date(dateStr + 'T00:00:00');
  return `${d.getMonth() + 1}/${d.getDate()}`;
};

interface TooltipPayloadEntry {
  color?: string;
  name?: string;
  value?: number | string;
}

interface CustomTooltipProps {
  active?: boolean;
  payload?: TooltipPayloadEntry[];
  label?: string;
}

const CustomTooltip = ({ active, payload, label }: CustomTooltipProps) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-surface border border-surface-border rounded px-3 py-2 text-xs shadow-lg">
      <p className="text-ink mb-1">{label}</p>
      {payload.map((entry, i) => (
        <p key={i} style={{ color: entry.color }}>
          {entry.name}: {typeof entry.value === 'number' && entry.name?.includes('rate') ? `${entry.value.toFixed(1)}%` : entry.value}
        </p>
      ))}
    </div>
  );
};

interface ChartCardProps {
  title: string;
  children: React.ReactNode;
}

export function ChartCard({ title, children }: ChartCardProps) {
  return (
    <div className="bg-surface border border-surface-border rounded p-5 shadow-sm">
      <h3 className="text-sm font-semibold text-ink-muted mb-4">{title}</h3>
      <div className="h-64">
        {children}
      </div>
    </div>
  );
}

// ─── Memoized chart panels ───────────────────────────────

export interface PieDatum {
  name: string;
  value: number;
  fill: string;
}

/** Certificates-by-Status pie chart. Re-renders only when `data` ref changes. */
export const CertsByStatusPieChart = memo(function CertsByStatusPieChart({ data }: { data: PieDatum[] }) {
  return (
    <ChartCard title="Certificates by Status">
      {data.length > 0 ? (
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={2}
              dataKey="value"
              label={({ name, value }) => `${formatStatus(name || '')}: ${value}`}
              labelLine={false}
            >
              {data.map((entry, index) => (
                <Cell key={index} fill={entry.fill} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
            <Legend
              verticalAlign="bottom"
              height={36}
              formatter={(value: string) => <span className="text-xs text-ink-muted">{formatStatus(value)}</span>}
            />
          </PieChart>
        </ResponsiveContainer>
      ) : (
        <div className="h-full flex items-center justify-center text-sm text-ink-faint">No certificate data</div>
      )}
    </ChartCard>
  );
});

export interface WeeklyExpirationDatum {
  week: string;
  count: number;
}

/** Expiration Heatmap bar chart. Re-renders only when `data` ref changes. */
export const ExpirationTimelineBarChart = memo(function ExpirationTimelineBarChart({ data }: { data: WeeklyExpirationDatum[] }) {
  return (
    <ChartCard title="Expiration Timeline (Next 90 Days)">
      {data.length > 0 ? (
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis dataKey="week" tick={{ fill: '#64748b', fontSize: 11 }} tickFormatter={formatShortDate} />
            <YAxis tick={{ fill: '#64748b', fontSize: 11 }} allowDecimals={false} />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="count" name="Expiring certs" fill="#f59e0b" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <div className="h-full flex items-center justify-center text-sm text-ink-faint">No expiration data</div>
      )}
    </ChartCard>
  );
});

export interface JobTrendDatum {
  date: string;
  completed_count: number;
  failed_count: number;
}

/** Job Success/Failure trend line chart. Re-renders only when `data` ref changes. */
export const JobTrendsLineChart = memo(function JobTrendsLineChart({ data }: { data: JobTrendDatum[] }) {
  return (
    <ChartCard title="Job Success/Failure Trends (30 Days)">
      {data.length > 0 ? (
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 11 }} tickFormatter={formatShortDate} />
            <YAxis tick={{ fill: '#64748b', fontSize: 11 }} allowDecimals={false} />
            <Tooltip content={<CustomTooltip />} />
            <Legend formatter={(value: string) => <span className="text-xs text-ink-muted">{value}</span>} />
            <Line type="monotone" dataKey="completed_count" name="Completed" stroke="#10b981" strokeWidth={2} dot={false} />
            <Line type="monotone" dataKey="failed_count" name="Failed" stroke="#ef4444" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      ) : (
        <div className="h-full flex items-center justify-center text-sm text-ink-faint">No job trend data</div>
      )}
    </ChartCard>
  );
});

export interface IssuanceRateDatum {
  date: string;
  issued_count: number;
}

/** Certificate Issuance Rate bar chart. Re-renders only when `data` ref changes. */
export const IssuanceRateBarChart = memo(function IssuanceRateBarChart({ data }: { data: IssuanceRateDatum[] }) {
  return (
    <ChartCard title="Certificate Issuance Rate (30 Days)">
      {data.length > 0 ? (
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis dataKey="date" tick={{ fill: '#64748b', fontSize: 11 }} tickFormatter={formatShortDate} />
            <YAxis tick={{ fill: '#64748b', fontSize: 11 }} allowDecimals={false} />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="issued_count" name="Issued" fill="#2ea88f" radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      ) : (
        <div className="h-full flex items-center justify-center text-sm text-ink-faint">No issuance data</div>
      )}
    </ChartCard>
  );
});
