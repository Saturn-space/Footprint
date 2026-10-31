import React, { useState } from 'react';
import {
  Settings,
  Users,
  Shield,
  Database,
  Trash2,
  Save,
  CheckCircle2,
  AlertTriangle
} from 'lucide-react';
import { useInvestigation } from '../context/InvestigationContext';
import { TEAM_MEMBERS } from '../data/seedData';

export const SettingsPage: React.FC = () => {
  const { activeInvestigation, addNotification } = useInvestigation();

  const [strictAllowlist, setStrictAllowlist] = useState(true);
  const [logRetentionDays, setLogRetentionDays] = useState(90);
  const [anonymizeExports, setAnonymizeExports] = useState(false);
  const [isSaved, setIsSaved] = useState(false);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaved(true);
    addNotification('success', 'Preferences Committed', 'System configuration updated successfully.');
    setTimeout(() => setIsSaved(false), 2000);
  };

  const handleResetData = () => {
    if (window.confirm('Reset local storage to original NorthStar Analytics Lab seed data?')) {
      localStorage.clear();
      window.location.reload();
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-lg font-bold text-slate-100">Toolkit Configuration & Lab Governance</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Configure safety controls, team access credentials, and local repository storage.
        </p>
      </div>

      {/* Team Credentials Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
          <Users className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold text-slate-100">Authorized Research Team Credentials</h2>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
          {TEAM_MEMBERS.map(member => (
            <div key={member.id} className="p-3.5 bg-slate-950/60 border border-slate-800 rounded-lg space-y-1">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-slate-200">{member.name}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/50 border border-cyan-800/60 text-cyan-300">
                  {member.role.replace('_', ' ').toUpperCase()}
                </span>
              </div>
              <div className="text-cyan-400 font-mono text-[11px]">Student ID: {member.studentId}</div>
              <div className="text-slate-400 text-[11px]">{member.email}</div>
              <div className="text-[10px] text-slate-500 pt-1">{member.organization}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Safety & Retention Form */}
      <form onSubmit={handleSave} className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-5 text-xs">
        <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
          <Shield className="w-4 h-4 text-amber-400" />
          <h2 className="text-sm font-semibold text-slate-100">Reconnaissance Guardrails & Policies</h2>
        </div>

        <div className="space-y-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <span className="font-medium text-slate-200 block">Strict Active Allowlist Enforcement</span>
              <p className="text-slate-400 text-[11px] mt-0.5">
                Automatically rejects and audit-flags any imported XML containing IP addresses outside the authorized scope.
              </p>
            </div>
            <input
              type="checkbox"
              checked={strictAllowlist}
              onChange={e => setStrictAllowlist(e.target.checked)}
              className="mt-1 rounded border-slate-700 bg-slate-950 text-cyan-500"
            />
          </div>

          <div className="flex items-start justify-between gap-4">
            <div>
              <span className="font-medium text-slate-200 block">Anonymize Redacted Target Identifiers</span>
              <p className="text-slate-400 text-[11px] mt-0.5">
                Masks external emails and employee names with hash digests during PDF/CSV exports.
              </p>
            </div>
            <input
              type="checkbox"
              checked={anonymizeExports}
              onChange={e => setAnonymizeExports(e.target.checked)}
              className="mt-1 rounded border-slate-700 bg-slate-950 text-cyan-500"
            />
          </div>

          <div>
            <label className="font-medium text-slate-200 block mb-1">
              Audit Event Retention Window (Days)
            </label>
            <input
              type="number"
              min={30}
              max={365}
              value={logRetentionDays}
              onChange={e => setLogRetentionDays(parseInt(e.target.value) || 90)}
              className="w-32 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 text-xs font-mono"
            />
          </div>
        </div>

        <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
          <button
            type="submit"
            className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
          >
            <Save className="w-3.5 h-3.5" />
            <span>{isSaved ? 'Preferences Saved' : 'Save System Settings'}</span>
          </button>
        </div>
      </form>

      {/* Local Storage & Data Reset */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3 text-xs">
        <div className="flex items-center gap-2 pb-2 border-b border-slate-800">
          <Database className="w-4 h-4 text-rose-400" />
          <h2 className="text-sm font-semibold text-slate-100">Local Repository Storage Management</h2>
        </div>

        <p className="text-slate-400 text-xs leading-relaxed">
          In Phase 1, investigations and evidence are securely indexed in your browser's local sandbox storage using repository interfaces. You can reset the state back to the pristine NorthStar Analytics Lab baseline at any time.
        </p>

        <div className="pt-2">
          <button
            type="button"
            onClick={handleResetData}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-rose-300 hover:text-white bg-rose-950/40 border border-rose-800/80 rounded hover:bg-rose-900 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Reset Demo Local Storage</span>
          </button>
        </div>
      </div>
    </div>
  );
};
