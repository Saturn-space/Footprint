import React, { useState } from 'react';
import {
  Radio,
  FileCode,
  ShieldAlert,
  AlertTriangle,
  Upload,
  Lock,
  CheckCircle2,
  XCircle,
  FileCheck,
  Server,
  RefreshCw,
  Cpu,
  Layers
} from 'lucide-react';
import { useInvestigation } from '../context/InvestigationContext';
import { useAuth } from '../context/AuthContext';
import { SAMPLE_NMAP_XML, SAMPLE_OPENVAS_XML } from '../data/sampleScanFiles';
import { AuthorizationBanner } from '../components/layout/AuthorizationBanner';
import { AccessDeniedBanner } from '../components/auth/AccessDeniedBanner';
import { AuthSwitchModal } from '../components/auth/AuthSwitchModal';
import { WorkflowRunCard } from '../components/workflow/WorkflowRunCard';
import { WorkerManagerPanel } from '../components/workflow/WorkerManagerPanel';

export const ActiveScanningPage: React.FC = () => {
  const {
    activeInvestigation,
    importNmapXml,
    importOpenVASXml,
    isServerConnected,
    workflowRun,
    startWorkflow,
    runSafeDemo
  } = useInvestigation();

  const { canImportActiveScans } = useAuth();
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'workflow' | 'workers' | 'manual'>('workflow');

  const [nmapInput, setNmapInput] = useState<string>('');
  const [openvasInput, setOpenvasInput] = useState<string>('');
  const [isNmapLoading, setIsNmapLoading] = useState(false);
  const [isOpenvasLoading, setIsOpenvasLoading] = useState(false);

  const [importStatus, setImportStatus] = useState<{
    type: 'idle' | 'success' | 'blocked' | 'error';
    message: string;
  }>({ type: 'idle', message: '' });

  const activeAllowlist = activeInvestigation?.scope.activeTargets || [];

  // Parse and validate Nmap XML via server API
  const handleImportNmap = async () => {
    if (!nmapInput.trim()) {
      setImportStatus({ type: 'error', message: 'Please provide Nmap XML content or load sample.' });
      return;
    }

    setIsNmapLoading(true);
    try {
      const res = await importNmapXml(nmapInput, 'nmap_scan_import.xml');
      setImportStatus({
        type: 'success',
        message: `SERVER VALIDATED & INGESTED: All host targets confirmed in active allowlist. Successfully parsed ${res.servicesIngested} services across ${res.hosts.length} hosts.`
      });
    } catch (err: any) {
      if (err.message.includes('BLOCKED') || err.message.includes('allowlist')) {
        setImportStatus({
          type: 'blocked',
          message: err.message
        });
      } else {
        setImportStatus({
          type: 'error',
          message: err.message || 'Nmap XML processing failed'
        });
      }
    } finally {
      setIsNmapLoading(false);
    }
  };

  // Parse and validate OpenVAS XML via server API
  const handleImportOpenVAS = async () => {
    if (!openvasInput.trim()) {
      setImportStatus({ type: 'error', message: 'Please provide OpenVAS XML content or load sample.' });
      return;
    }

    setIsOpenvasLoading(true);
    try {
      const res = await importOpenVASXml(openvasInput, 'openvas_report_import.xml');
      setImportStatus({
        type: 'success',
        message: `SERVER VALIDATED & INGESTED: OpenVAS report targets confirmed in allowlist. Ingested ${res.findingsIngested} vulnerability findings for ${res.hosts.join(', ')}.`
      });
    } catch (err: any) {
      if (err.message.includes('BLOCKED') || err.message.includes('allowlist')) {
        setImportStatus({
          type: 'blocked',
          message: err.message
        });
      } else {
        setImportStatus({
          type: 'error',
          message: err.message || 'OpenVAS XML processing failed'
        });
      }
    } finally {
      setIsOpenvasLoading(false);
    }
  };

  // Helper to load an out-of-scope XML fixture for testing allowlist blocking
  const handleLoadOutOfScopeNmap = () => {
    const outOfScopeXml = SAMPLE_NMAP_XML.replace('192.168.56.102', '10.99.99.1');
    setNmapInput(outOfScopeXml);
  };

  return (
    <div className="space-y-6">
      {/* Prominent Amber Safety Banner */}
      <AuthorizationBanner mode="active" />

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-bold text-slate-100">Active Scanning Operations & Workflow Hub</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Orchestrate semi-autonomous reconnaissance runs, manage authorized worker daemons, and ingest validated scan outputs.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-400">
            Allowlist Gatekeeper: <strong className="text-emerald-400">{isServerConnected ? 'Server Verified' : 'Local Sandbox'}</strong>
          </span>
        </div>
      </div>

      {/* Access Denied Warning for Reviewers/Viewers */}
      {!canImportActiveScans && (
        <AccessDeniedBanner
          requiredRoles={['admin', 'investigator']}
          actionDescription="Executing active scans, approving workflow stages, or ingesting scan outputs"
          onOpenSwitcher={() => setIsAuthModalOpen(true)}
        />
      )}

      {/* Allowlist Scope Badge Bar */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <span className="text-xs font-semibold text-slate-200 block">
            Current Active Target Allowlist
          </span>
          <div className="flex flex-wrap items-center gap-2 mt-1.5">
            {activeAllowlist.map(ip => (
              <span
                key={ip}
                className="px-2 py-0.5 bg-emerald-950/60 border border-emerald-800/80 text-emerald-400 text-xs font-mono font-medium rounded flex items-center gap-1.5"
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                {ip}
              </span>
            ))}
            {activeAllowlist.length === 0 && (
              <span className="text-xs text-slate-400 italic">No targets currently on active allowlist.</span>
            )}
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <ShieldAlert className="w-4 h-4 text-amber-400" />
          <span>Non-allowlisted IP addresses are rejected by server policy</span>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 text-xs">
        <button
          onClick={() => setActiveTab('workflow')}
          className={`pb-3 px-3 font-semibold transition-colors border-b-2 -mb-px flex items-center gap-2 cursor-pointer ${
            activeTab === 'workflow'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>Semi-Autonomous Recon Workflow</span>
          {workflowRun && (
            <span className="text-[10px] font-mono px-1.5 py-0.2 bg-cyan-950 text-cyan-400 rounded border border-cyan-800">
              {workflowRun.currentState}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('workers')}
          className={`pb-3 px-3 font-semibold transition-colors border-b-2 -mb-px flex items-center gap-2 cursor-pointer ${
            activeTab === 'workers'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Server className="w-4 h-4" />
          <span>Authorized Worker Control Plane</span>
        </button>

        <button
          onClick={() => setActiveTab('manual')}
          className={`pb-3 px-3 font-semibold transition-colors border-b-2 -mb-px flex items-center gap-2 cursor-pointer ${
            activeTab === 'manual'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCode className="w-4 h-4" />
          <span>Manual / Offline XML Ingestion</span>
        </button>
      </div>

      {/* TAB 1: Semi-Autonomous Recon Workflow */}
      {activeTab === 'workflow' && (
        <WorkflowRunCard
          run={workflowRun}
          onStartWorkflow={() => startWorkflow()}
          onRunSafeDemo={() => runSafeDemo()}
        />
      )}

      {/* TAB 2: Authorized Worker Control Plane */}
      {activeTab === 'workers' && (
        <WorkerManagerPanel />
      )}

      {/* TAB 3: Offline XML Ingestion */}
      {activeTab === 'manual' && (
        <div className="space-y-6">
          {/* Status Message Alert */}
          {importStatus.type !== 'idle' && (
            <div
              className={`p-4 rounded-lg border text-xs flex items-start gap-3 ${
                importStatus.type === 'success'
                  ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                  : importStatus.type === 'blocked'
                  ? 'bg-amber-950/40 border-amber-800 text-amber-300'
                  : 'bg-rose-950/40 border-rose-800 text-rose-300'
              }`}
            >
              {importStatus.type === 'success' && <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-400 mt-0.5" />}
              {importStatus.type === 'blocked' && <ShieldAlert className="w-5 h-5 shrink-0 text-amber-400 mt-0.5" />}
              {importStatus.type === 'error' && <XCircle className="w-5 h-5 shrink-0 text-rose-400 mt-0.5" />}
              <div>
                <div className="font-semibold uppercase tracking-wider text-[11px] mb-0.5">
                  {importStatus.type === 'success' && 'Scan Ingestion Verified'}
                  {importStatus.type === 'blocked' && 'Scope Enforcement Intercept'}
                  {importStatus.type === 'error' && 'Ingestion Error'}
                </div>
                <div className="leading-relaxed">{importStatus.message}</div>
              </div>
            </div>
          )}

          {/* Import Columns Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Column 1: Nmap XML Parser */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between shadow-sm space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-cyan-400" />
                    <h2 className="text-sm font-semibold text-slate-200">
                      Nmap XML Parser & Ingestion
                    </h2>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400">
                    Safe Service Detection
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">
                  Imports port states, discovered listening services, product versions, and service banners. All reported target IP addresses are validated against the active allowlist prior to storage.
                </p>

                {/* Fixture Load Shortcuts */}
                <div className="flex flex-wrap gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => setNmapInput(SAMPLE_NMAP_XML)}
                    className="px-2.5 py-1 text-[11px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition-colors"
                  >
                    Load Safe Sample (192.168.56.102)
                  </button>
                  <button
                    type="button"
                    onClick={handleLoadOutOfScopeNmap}
                    className="px-2.5 py-1 text-[11px] font-mono bg-rose-950/40 hover:bg-rose-900/60 text-rose-300 rounded border border-rose-800/80 transition-colors"
                    title="Loads an IP not on the allowlist to demonstrate enforcement"
                  >
                    Load Out-of-Scope Sample (Test Block)
                  </button>
                </div>

                <textarea
                  value={nmapInput}
                  onChange={e => setNmapInput(e.target.value)}
                  placeholder="Paste raw Nmap XML output (-oX scan.xml)..."
                  rows={8}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400 resize-none"
                />
              </div>

              <button
                onClick={handleImportNmap}
                disabled={isNmapLoading || !canImportActiveScans}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded transition-colors cursor-pointer"
              >
                {isNmapLoading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Enforcing Allowlist & Ingesting...</span>
                  </>
                ) : (
                  <>
                    <Upload className="w-3.5 h-3.5" />
                    <span>Validate & Ingest Nmap XML</span>
                  </>
                )}
              </button>
            </div>

            {/* Column 2: OpenVAS XML Parser */}
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between shadow-sm space-y-4">
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Radio className="w-4 h-4 text-emerald-400" />
                    <h2 className="text-sm font-semibold text-slate-200">
                      OpenVAS / Greenbone XML Report
                    </h2>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-emerald-400">
                    CVE / Vulnerability Audit
                  </span>
                </div>

                <p className="text-xs text-slate-400 leading-relaxed">
                  Imports security findings, CVSS scores, vulnerability descriptions, and remediation guidance from Greenbone/OpenVAS XML exports.
                </p>

                {/* Fixture Load Shortcut */}
                <div className="flex flex-wrap gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() => setOpenvasInput(SAMPLE_OPENVAS_XML)}
                    className="px-2.5 py-1 text-[11px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded border border-slate-700 transition-colors"
                  >
                    Load Safe Sample (OpenVAS Audit)
                  </button>
                </div>

                <textarea
                  value={openvasInput}
                  onChange={e => setOpenvasInput(e.target.value)}
                  placeholder="Paste raw OpenVAS report XML content..."
                  rows={8}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-400 resize-none"
                />
              </div>

              <button
                onClick={handleImportOpenVAS}
                disabled={isOpenvasLoading || !canImportActiveScans}
                className="w-full flex items-center justify-center gap-2 px-4 py-2 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 disabled:opacity-50 rounded transition-colors cursor-pointer"
              >
                {isOpenvasLoading ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Enforcing Allowlist & Ingesting...</span>
                  </>
                ) : (
                  <>
                    <Upload className="w-3.5 h-3.5" />
                    <span>Validate & Ingest OpenVAS XML</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Role Switcher Modal */}
      <AuthSwitchModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
      />
    </div>
  );
};
