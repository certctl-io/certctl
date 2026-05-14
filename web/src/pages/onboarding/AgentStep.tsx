// Phase 4 closure (FE-M3): OnboardingWizard mega-page split — Step 2.
// Deploy a certctl Agent. Behavior preserved byte-equivalent from the
// pre-split src/pages/OnboardingWizard.tsx lines 282-408.
//
// Note: this step keeps Phase 2's TQ-H1 closure intact — the agents
// poll runs every 5s ONLY until the first agent registers, then the
// v5-functional refetchInterval flips to false and the poll stops.

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { STALE_TIME } from '../../api/queryConstants';
import { getAgents, getApiKey } from '../../api/client';
import { CodeBlock, WizardFooter } from './StepShell';

export default function AgentStep({ onNext, onSkip }: { onNext: () => void; onSkip: () => void }) {
  const [activeTab, setActiveTab] = useState<'linux' | 'macos' | 'docker'>('linux');

  const apiKey = getApiKey() || '<your-api-key>';
  const serverUrl = typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.hostname}:8443` : 'http://localhost:8443';

  // Phase 2 TQ-H1 closure: poll every 5s ONLY until the first agent
  // registers, then stop. v5 functional refetchInterval returns false
  // (or 0) to disable. Pre-fix this polled forever; once the wizard
  // succeeded the next user landed in a state with a 5-second cadence
  // hitting /api/v1/agents indefinitely until they reloaded the tab.
  // Now: as soon as agents.length > 0, the interval flips to false
  // and the poll stops.
  const { data: agents } = useQuery({
    queryKey: ['agents'],
    queryFn: () => getAgents(),
    refetchInterval: (query) =>
      (query.state.data?.data?.length ?? 0) > 0 ? false : 5_000,
    refetchOnWindowFocus: true,
    staleTime: STALE_TIME.REAL_TIME,
  });

  const agentList = agents?.data || [];
  const hasAgents = agentList.length > 0;

  const tabs = [
    { key: 'linux' as const, label: 'Linux' },
    { key: 'macos' as const, label: 'macOS' },
    { key: 'docker' as const, label: 'Docker' },
  ];

  const commands: Record<string, { code: string; label: string }> = {
    linux: {
      label: 'Install via shell script (systemd service)',
      code: `# Non-interactive install (recommended for curl | bash):
curl -sSL https://raw.githubusercontent.com/certctl-io/certctl/master/install-agent.sh \\
  | sudo bash -s -- \\
      --server-url ${serverUrl} \\
      --api-key ${apiKey}

# The script downloads the agent binary, writes /etc/certctl/agent.env,
# installs /etc/systemd/system/certctl-agent.service, and starts it.
# Check status with: sudo systemctl status certctl-agent`,
    },
    macos: {
      label: 'Install via shell script (launchd service)',
      code: `# Non-interactive install (recommended for curl | bash):
curl -sSL https://raw.githubusercontent.com/certctl-io/certctl/master/install-agent.sh \\
  | bash -s -- \\
      --server-url ${serverUrl} \\
      --api-key ${apiKey}

# The script writes ~/.certctl/agent.env and loads
# ~/Library/LaunchAgents/com.certctl.agent.plist.
# Check status with: launchctl list | grep certctl`,
    },
    docker: {
      label: 'Run as Docker container',
      code: `docker run -d --name certctl-agent \\
  -e CERTCTL_SERVER_URL=${serverUrl} \\
  -e CERTCTL_API_KEY=${apiKey} \\
  ghcr.io/certctl-io/certctl-agent:latest`,
    },
  };

  return (
    <div>
      <h2 className="text-lg font-semibold text-ink mb-1">Deploy a certctl Agent</h2>
      <p className="text-sm text-ink-muted mb-6">
        Agents run on your infrastructure to manage certificates, generate keys, and deploy to targets.
        Install one now or skip to do it later.
      </p>

      {/* OS Tabs */}
      <div className="flex gap-1 mb-4 bg-surface-border/30 rounded-lg p-1 w-fit">
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setActiveTab(t.key)}
            className={`px-4 py-1.5 text-sm rounded-md transition-colors ${
              activeTab === t.key
                ? 'bg-surface text-ink font-medium shadow-sm'
                : 'text-ink-muted hover:text-ink'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <CodeBlock code={commands[activeTab].code} label={commands[activeTab].label} />

      {/* Agent detection */}
      <div className="mt-6 p-4 border border-surface-border rounded-lg">
        <div className="flex items-center gap-3">
          {hasAgents ? (
            <>
              <div className="w-3 h-3 rounded-full bg-emerald-500" />
              <div>
                <div className="text-sm font-medium text-emerald-700">
                  {agentList.length} agent{agentList.length !== 1 ? 's' : ''} detected
                </div>
                <div className="text-xs text-ink-muted mt-0.5">
                  {agentList.slice(0, 3).map(a => a.name || a.id).join(', ')}
                  {agentList.length > 3 && ` and ${agentList.length - 3} more`}
                </div>
              </div>
            </>
          ) : (
            <>
              <div className="w-3 h-3 rounded-full bg-amber-400 animate-pulse" />
              <div className="text-sm text-ink-muted">
                Waiting for an agent to connect... <span className="text-xs">(polling every 5s)</span>
              </div>
            </>
          )}
        </div>
      </div>

      <WizardFooter
        onSkip={onSkip}
        onNext={onNext}
        nextLabel={hasAgents ? 'Next: Add Certificate' : 'Next: Add Certificate'}
      />
    </div>
  );
}
