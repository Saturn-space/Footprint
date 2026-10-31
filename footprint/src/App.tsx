import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { InvestigationProvider } from './context/InvestigationContext';
import { AppLayout } from './components/layout/AppLayout';

import { DashboardPage } from './pages/DashboardPage';
import { InvestigationsPage } from './pages/InvestigationsPage';
import { NewInvestigationPage } from './pages/NewInvestigationPage';
import { PassiveReconPage } from './pages/PassiveReconPage';
import { ActiveScanningPage } from './pages/ActiveScanningPage';
import { EntityGraphPage } from './pages/EntityGraphPage';
import { FindingsPage } from './pages/FindingsPage';
import { ExposureScorePage } from './pages/ExposureScorePage';
import { ReportsPage } from './pages/ReportsPage';
import { AuditLogPage } from './pages/AuditLogPage';
import { SettingsPage } from './pages/SettingsPage';
import { HelpEthicsPage } from './pages/HelpEthicsPage';

export default function App() {
  return (
    <AuthProvider>
      <InvestigationProvider>
        <BrowserRouter>
          <Routes>
            <Route element={<AppLayout />}>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/investigations" element={<InvestigationsPage />} />
              <Route path="/new-investigation" element={<NewInvestigationPage />} />
              <Route path="/passive-recon" element={<PassiveReconPage />} />
              <Route path="/active-scanning" element={<ActiveScanningPage />} />
              <Route path="/entity-graph" element={<EntityGraphPage />} />
              <Route path="/findings" element={<FindingsPage />} />
              <Route path="/exposure-score" element={<ExposureScorePage />} />
              <Route path="/reports" element={<ReportsPage />} />
              <Route path="/audit-log" element={<AuditLogPage />} />
              <Route path="/settings" element={<SettingsPage />} />
              <Route path="/help-ethics" element={<HelpEthicsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Route>
          </Routes>
        </BrowserRouter>
      </InvestigationProvider>
    </AuthProvider>
  );
}
