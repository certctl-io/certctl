import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import Layout from './components/Layout';
import DashboardPage from './pages/DashboardPage';
import CertificatesPage from './pages/CertificatesPage';
import CertificateDetailPage from './pages/CertificateDetailPage';
import AgentsPage from './pages/AgentsPage';
import JobsPage from './pages/JobsPage';
import NotificationsPage from './pages/NotificationsPage';
import PoliciesPage from './pages/PoliciesPage';
import AuditPage from './pages/AuditPage';
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
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<DashboardPage />} />
            <Route path="certificates" element={<CertificatesPage />} />
            <Route path="certificates/:id" element={<CertificateDetailPage />} />
            <Route path="agents" element={<AgentsPage />} />
            <Route path="jobs" element={<JobsPage />} />
            <Route path="notifications" element={<NotificationsPage />} />
            <Route path="policies" element={<PoliciesPage />} />
            <Route path="audit" element={<AuditPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>
);
