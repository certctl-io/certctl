import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import ErrorBoundary from './components/ErrorBoundary';
import AuthProvider from './components/AuthProvider';
import AuthGate from './components/AuthGate';
import Layout from './components/Layout';
import DashboardPage from './pages/DashboardPage';
import CertificatesPage from './pages/CertificatesPage';
import CertificateDetailPage from './pages/CertificateDetailPage';
import AgentsPage from './pages/AgentsPage';
import AgentDetailPage from './pages/AgentDetailPage';
import JobsPage from './pages/JobsPage';
import NotificationsPage from './pages/NotificationsPage';
import PoliciesPage from './pages/PoliciesPage';
import IssuersPage from './pages/IssuersPage';
import TargetsPage from './pages/TargetsPage';
import ProfilesPage from './pages/ProfilesPage';
import OwnersPage from './pages/OwnersPage';
import TeamsPage from './pages/TeamsPage';
import AgentGroupsPage from './pages/AgentGroupsPage';
import AuditPage from './pages/AuditPage';
import ShortLivedPage from './pages/ShortLivedPage';
import AgentFleetPage from './pages/AgentFleetPage';
import DiscoveryPage from './pages/DiscoveryPage';
import NetworkScanPage from './pages/NetworkScanPage';
import DigestPage from './pages/DigestPage';
import ObservabilityPage from './pages/ObservabilityPage';
import JobDetailPage from './pages/JobDetailPage';
import IssuerDetailPage from './pages/IssuerDetailPage';
import TargetDetailPage from './pages/TargetDetailPage';
import './index.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10_000,
      retry: 1,
      refetchOnWindowFocus: true,
    },
  },
});

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <AuthGate>
            <BrowserRouter>
              <Routes>
                <Route element={<Layout />}>
                  <Route index element={<DashboardPage />} />
                  <Route path="certificates" element={<CertificatesPage />} />
                  <Route path="certificates/:id" element={<CertificateDetailPage />} />
                  <Route path="agents" element={<AgentsPage />} />
                  <Route path="agents/:id" element={<AgentDetailPage />} />
                  <Route path="fleet" element={<AgentFleetPage />} />
                  <Route path="jobs" element={<JobsPage />} />
                  <Route path="jobs/:id" element={<JobDetailPage />} />
                  <Route path="notifications" element={<NotificationsPage />} />
                  <Route path="policies" element={<PoliciesPage />} />
                  <Route path="profiles" element={<ProfilesPage />} />
                  <Route path="issuers" element={<IssuersPage />} />
                  <Route path="issuers/:id" element={<IssuerDetailPage />} />
                  <Route path="targets" element={<TargetsPage />} />
                  <Route path="targets/:id" element={<TargetDetailPage />} />
                  <Route path="owners" element={<OwnersPage />} />
                  <Route path="teams" element={<TeamsPage />} />
                  <Route path="agent-groups" element={<AgentGroupsPage />} />
                  <Route path="audit" element={<AuditPage />} />
                  <Route path="short-lived" element={<ShortLivedPage />} />
                  <Route path="discovery" element={<DiscoveryPage />} />
                  <Route path="network-scans" element={<NetworkScanPage />} />
                  <Route path="digest" element={<DigestPage />} />
                  <Route path="observability" element={<ObservabilityPage />} />
                </Route>
              </Routes>
            </BrowserRouter>
          </AuthGate>
        </AuthProvider>
      </QueryClientProvider>
    </ErrorBoundary>
  </StrictMode>
);
