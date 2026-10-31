import React from 'react';
import { ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';

interface AuthorizationBannerProps {
  mode?: 'passive' | 'active' | 'global';
  showDetails?: boolean;
}

export const AuthorizationBanner: React.FC<AuthorizationBannerProps> = ({
  mode = 'global',
  showDetails = false
}) => {
  const { activeInvestigation } = useInvestigation();
  const authorization = activeInvestigation?.authorization;

  if (mode === 'active') {
    return (
      <div className="border border-amber-800/80 bg-amber-950/30 rounded-lg p-3.5 mb-6 text-slate-200">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="flex-1 text-xs space-y-1">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-amber-300 uppercase tracking-wider text-xs">
                Active Reconnaissance Safety Gate
              </span>
              <span className="text-slate-400">·</span>
              <span className="text-amber-200 font-mono text-[11px]">
                {authorization?.activeScanningEnabled ? 'ENABLED (STRICT ALLOWLIST ONLY)' : 'DISABLED BY POLICY'}
              </span>
            </div>
            <p className="text-slate-300">
              Active operations (Nmap/OpenVAS) send live network packets and are permitted <span className="text-amber-300 font-medium">strictly for verified IP targets in the authorization allowlist</span>. Unrestricted scanning or probing unauthorized infrastructure is strictly prohibited.
            </p>
            {activeInvestigation && (
              <div className="pt-1 flex flex-wrap items-center gap-3 text-[11px] text-slate-400">
                <span>Ref: <strong className="text-slate-200 font-mono">{authorization?.authorizationReference}</strong></span>
                <span>·</span>
                <span>Approved By: <strong className="text-slate-200">{authorization?.approvedBy}</strong></span>
                <span>·</span>
                <span>Permitted Host: <strong className="text-amber-300 font-mono">192.168.56.102</strong></span>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="border border-cyan-900/60 bg-slate-900/80 rounded-lg px-4 py-2.5 mb-6 flex flex-wrap items-center justify-between gap-3 text-xs">
      <div className="flex items-center gap-2.5 text-slate-200">
        <ShieldAlert className="w-4 h-4 text-cyan-400 shrink-0" />
        <span className="font-semibold text-slate-100">Authorized Educational Use Only:</span>
        <span className="text-slate-300 hidden sm:inline">
          Reconnaissance activities are restricted to lab assets and approved team scopes.
        </span>
      </div>
      <div className="flex items-center gap-3 text-[11px] text-slate-400">
        {authorization?.rulesOfEngagementConfirmed && (
          <span className="flex items-center gap-1 text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5" /> RoE Confirmed
          </span>
        )}
        <span>·</span>
        <span className="font-mono text-slate-300">Lab Team: Ali & Prasad</span>
      </div>
    </div>
  );
};
