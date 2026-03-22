import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';
import { getAgents } from '../api/client';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import type { Agent } from '../api/types';

const OS_COLORS: Record<string, string> = {
  linux: '#f97316',
  darwin: '#3b82f6',
  windows: '#8b5cf6',
  unknown: '#64748b',
};

const STATUS_COLORS: Record<string, string> = {
  Online: '#10b981',
  Offline: '#ef4444',
  Unknown: '#64748b',
};

interface GroupedAgents {
  os: string;
  arch: string;
  agents: Agent[];
  online: number;
  offline: number;
}

function groupAgents(agents: Agent[]): GroupedAgents[] {
  const groups = new Map<string, GroupedAgents>();

  for (const agent of agents) {
    const os = agent.os || 'unknown';
    const arch = agent.architecture || 'unknown';
    const key = `${os}/${arch}`;

    if (!groups.has(key)) {
      groups.set(key, { os, arch, agents: [], online: 0, offline: 0 });
    }
    const group = groups.get(key)!;
    group.agents.push(agent);
    if (agent.status === 'Online') {
      group.online++;
    } else {
      group.offline++;
    }
  }

  return Array.from(groups.values()).sort((a, b) => b.agents.length - a.agents.length);
}

const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-xs shadow-lg">
      {payload.map((entry: any, i: number) => (
        <p key={i} style={{ color: entry.payload?.fill || entry.color }}>
          {entry.name}: {entry.value}
        </p>
      ))}
    </div>
  );
};

export default function AgentFleetPage() {
  const navigate = useNavigate();
  const { data: agentsResponse, isLoading } = useQuery({
    queryKey: ['agents'],
    queryFn: () => getAgents(),
    refetchInterval: 15000,
  });

  const agents = agentsResponse?.data || [];
  const groups = groupAgents(agents);

  // Summary stats
  const totalAgents = agents.length;
  const onlineAgents = agents.filter(a => a.status === 'Online').length;
  const offlineAgents = totalAgents - onlineAgents;

  // OS distribution for pie chart
  const osDistribution = agents.reduce<Record<string, number>>((acc, a) => {
    const os = a.os || 'unknown';
    acc[os] = (acc[os] || 0) + 1;
    return acc;
  }, {});
  const osPieData = Object.entries(osDistribution).map(([name, value]) => ({
    name,
    value,
    fill: OS_COLORS[name.toLowerCase()] || '#64748b',
  }));

  // Status for pie chart
  const statusPieData = [
    { name: 'Online', value: onlineAgents, fill: STATUS_COLORS.Online },
    { name: 'Offline', value: offlineAgents, fill: STATUS_COLORS.Offline },
  ].filter(s => s.value > 0);

  // Version distribution
  const versionCounts = agents.reduce<Record<string, number>>((acc, a) => {
    const v = a.version || 'unknown';
    acc[v] = (acc[v] || 0) + 1;
    return acc;
  }, {});

  return (
    <>
      <PageHeader
        title="Agent Fleet Overview"
        subtitle={`${totalAgents} agents — ${onlineAgents} online, ${offlineAgents} offline`}
      />
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="card p-5 text-center">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Total Agents</p>
            <p className="text-3xl font-bold mt-2 text-blue-400">{totalAgents}</p>
          </div>
          <div className="card p-5 text-center">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Online</p>
            <p className="text-3xl font-bold mt-2 text-emerald-400">{onlineAgents}</p>
          </div>
          <div className="card p-5 text-center">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Offline</p>
            <p className="text-3xl font-bold mt-2 text-red-400">{offlineAgents}</p>
          </div>
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* OS Distribution */}
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">OS Distribution</h3>
            <div className="h-48">
              {osPieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={osPieData} cx="50%" cy="50%" outerRadius={70} dataKey="value" label={({ name, value }) => `${name}: ${value}`} labelLine={false}>
                      {osPieData.map((entry, index) => (
                        <Cell key={index} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-sm text-slate-500">No data</div>
              )}
            </div>
          </div>

          {/* Status Distribution */}
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Status Distribution</h3>
            <div className="h-48">
              {statusPieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={statusPieData} cx="50%" cy="50%" innerRadius={40} outerRadius={70} dataKey="value" label={({ name, value }) => `${name}: ${value}`} labelLine={false}>
                      {statusPieData.map((entry, index) => (
                        <Cell key={index} fill={entry.fill} />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="h-full flex items-center justify-center text-sm text-slate-500">No data</div>
              )}
            </div>
          </div>

          {/* Version Breakdown */}
          <div className="card p-5">
            <h3 className="text-sm font-semibold text-slate-300 mb-4">Agent Versions</h3>
            <div className="space-y-3">
              {Object.entries(versionCounts)
                .sort(([, a], [, b]) => b - a)
                .map(([version, count]) => (
                  <div key={version} className="flex items-center justify-between">
                    <span className="text-sm text-slate-300 font-mono">{version}</span>
                    <div className="flex items-center gap-2">
                      <div className="w-24 bg-slate-700 rounded-full h-2">
                        <div
                          className="bg-blue-500 h-2 rounded-full"
                          style={{ width: `${(count / totalAgents) * 100}%` }}
                        />
                      </div>
                      <span className="text-xs text-slate-400 w-8 text-right">{count}</span>
                    </div>
                  </div>
                ))}
              {Object.keys(versionCounts).length === 0 && (
                <p className="text-sm text-slate-500">No version data</p>
              )}
            </div>
          </div>
        </div>

        {/* Environment Groups */}
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Fleet by Platform</h3>
          {isLoading ? (
            <p className="text-sm text-slate-500">Loading fleet data...</p>
          ) : groups.length === 0 ? (
            <p className="text-sm text-slate-500">No agents registered</p>
          ) : (
            <div className="space-y-4">
              {groups.map(group => (
                <div key={`${group.os}/${group.arch}`} className="card">
                  <div className="px-5 py-4 border-b border-slate-700 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: OS_COLORS[group.os.toLowerCase()] || '#64748b' }}
                      />
                      <h4 className="text-sm font-medium text-slate-200">
                        {group.os} / {group.arch}
                      </h4>
                      <span className="text-xs text-slate-500">
                        {group.agents.length} agent{group.agents.length !== 1 ? 's' : ''}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      <span className="text-emerald-400">{group.online} online</span>
                      {group.offline > 0 && <span className="text-red-400">{group.offline} offline</span>}
                    </div>
                  </div>
                  <div className="divide-y divide-slate-700/50">
                    {group.agents.map(agent => (
                      <div
                        key={agent.id}
                        onClick={() => navigate(`/agents/${agent.id}`)}
                        className="px-5 py-3 flex items-center justify-between hover:bg-slate-700/30 cursor-pointer transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <div className={`w-2 h-2 rounded-full ${agent.status === 'Online' ? 'bg-emerald-400' : 'bg-red-400'}`} />
                          <div>
                            <div className="text-sm text-slate-200">{agent.name || agent.hostname}</div>
                            <div className="text-xs text-slate-500">{agent.ip_address || agent.id}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-4">
                          {agent.version && (
                            <span className="text-xs text-slate-500 font-mono">{agent.version}</span>
                          )}
                          <StatusBadge status={agent.status} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </>
  );
}
