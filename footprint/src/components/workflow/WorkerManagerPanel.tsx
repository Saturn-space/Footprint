import React, { useState } from 'react';
import {
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  Activity,
  Plus,
  Copy,
  Check,
  RotateCw,
  Key,
  Lock,
  Radio,
  FileCode,
  Trash2,
  ExternalLink,
  Play
} from 'lucide-react';
import { WorkerRegistration, ApprovedScanProfile } from '../../types/workflow';
import { useInvestigation } from '../../context/InvestigationContext';
import { useAuth } from '../../context/AuthContext';
import { formatDate } from '../../utils/formatters';
import { Modal } from '../common/Modal';

export const WorkerManagerPanel: React.FC = () => {
  const {
    workers,
    refreshWorkers,
    registerWorker,
    revokeWorker,
    simulateWorkerJob
  } = useInvestigation();
  const { canManageSettings } = useAuth();

  const [isRegisterOpen, setIsRegisterOpen] = useState(false);
  const [newWorkerName, setNewWorkerName] = useState('Lab Worker Daemon #02');
  const [newWorkerEnv, setNewWorkerEnv] = useState<'local_lab' | 'simulated_preview'>('local_lab');
  const [newWorkerIp, setNewWorkerIp] = useState('192.168.56.205');
  const [selectedProfiles, setSelectedProfiles] = useState<ApprovedScanProfile[]>([
    'safe-service-detection',
    'openvas-basic'
  ]);

  const [copiedTokenId, setCopiedTokenId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'workers' | 'script' | 'architecture'>('workers');

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedTokenId(id);
    setTimeout(() => setCopiedTokenId(null), 2000);
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWorkerName.trim()) return;
    await registerWorker(newWorkerName, newWorkerEnv, selectedProfiles, newWorkerIp);
    setIsRegisterOpen(false);
  };

  const toggleProfile = (p: ApprovedScanProfile) => {
    setSelectedProfiles(prev =>
      prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p]
    );
  };

  const sampleWorkerScript = `#!/usr/bin/env bash
# FootprintIQ Authorized Lab Worker Daemon
# Run on local hypervisor machine (e.g. 192.168.56.200)
CONTROL_PLANE="http://localhost:3000/api/v1"
WORKER_ID="${workers[0]?.workerId || 'worker-sim-lab01'}"
SECRET_TOKEN="${workers[0]?.secretToken || 'sec-sample-token-12345'}"

echo "[*] FootprintIQ Worker Daemon started for \${WORKER_ID}"

while true; do
  # 1. Send heartbeat
  curl -s -X POST "\${CONTROL_PLANE}/workers/heartbeat" \\
    -H "Content-Type: application/json" \\
    -d "{\\"workerId\\":\\"\${WORKER_ID}\\",\\"token\\":\\"\${SECRET_TOKEN}\\"}" > /dev/null

  # 2. Poll for authorized jobs
  JOBS=$(curl -s -X POST "\${CONTROL_PLANE}/workers/jobs/poll" \\
    -H "Content-Type: application/json" \\
    -d "{\\"workerId\\":\\"\${WORKER_ID}\\",\\"secretToken\\":\\"\${SECRET_TOKEN}\\"}")

  # Check if pending job returned
  JOB_ID=$(echo "\${JOBS}" | grep -o '"id":"[^"]*' | head -1 | cut -d'"' -f4)

  if [ -n "\${JOB_ID}" ]; then
    echo "[+] Accepted authorized job: \${JOB_ID}"
    # 3. Accept job
    # 4. Execute approved profile (Nmap/OpenVAS strictly against target 192.168.56.102)
    # 5. Compute SHA-256 hash
    # 6. Upload signed result payload
  fi

  sleep 5
done`;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-sm space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              Authorized Worker Control Plane
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-emerald-400 font-semibold">
              {workers.filter(w => w.status === 'active').length} Daemon(s) Online
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Separation of Concerns: Hosted web application manages control plane and state; active scanners execute in an authorized lab machine.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {canManageSettings && (
            <button
              onClick={() => setIsRegisterOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>Register Worker Daemon</span>
            </button>
          )}

          <button
            onClick={refreshWorkers}
            className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors"
            title="Refresh Worker Status"
          >
            <RotateCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 text-xs">
        <button
          onClick={() => setActiveTab('workers')}
          className={`pb-2.5 px-2 font-semibold transition-colors border-b-2 -mb-px ${
            activeTab === 'workers'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Registered Workers ({workers.length})
        </button>
        <button
          onClick={() => setActiveTab('script')}
          className={`pb-2.5 px-2 font-semibold transition-colors border-b-2 -mb-px ${
            activeTab === 'script'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Worker Daemon Script & CLI
        </button>
        <button
          onClick={() => setActiveTab('architecture')}
          className={`pb-2.5 px-2 font-semibold transition-colors border-b-2 -mb-px ${
            activeTab === 'architecture'
              ? 'border-cyan-400 text-cyan-400'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Security Architecture
        </button>
      </div>

      {/* TAB 1: Registered Workers Table */}
      {activeTab === 'workers' && (
        <div className="space-y-4">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px] uppercase bg-slate-950/60">
                  <th className="py-2.5 px-3">Daemon Name</th>
                  <th className="py-2.5 px-3">Environment</th>
                  <th className="py-2.5 px-3">Target IP / Bound Range</th>
                  <th className="py-2.5 px-3">Supported Profiles</th>
                  <th className="py-2.5 px-3">Heartbeat / Status</th>
                  <th className="py-2.5 px-3">Secret Token</th>
                  <th className="py-2.5 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {workers.map(w => (
                  <tr key={w.workerId} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-3">
                      <div className="font-semibold text-slate-200">{w.name}</div>
                      <div className="text-[10px] font-mono text-slate-400">{w.workerId}</div>
                    </td>
                    <td className="py-3 px-3">
                      <span className={`text-[10px] font-mono uppercase px-2 py-0.5 rounded border ${
                        w.environment === 'simulated_preview'
                          ? 'bg-purple-950/60 text-purple-300 border-purple-800'
                          : 'bg-blue-950/60 text-blue-300 border-blue-800'
                      }`}>
                        {w.environment.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="py-3 px-3 font-mono text-slate-300">
                      {w.ipAddress || '192.168.56.0/24'}
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex flex-wrap gap-1 max-w-xs">
                        {w.supportedProfiles.map(p => (
                          <span key={p} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                            {p}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full ${
                          w.status === 'active' ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'
                        }`} />
                        <span className="capitalize font-semibold text-slate-200">{w.status}</span>
                      </div>
                      <div className="text-[10px] font-mono text-slate-500">
                        {formatDate(w.lastHeartbeat)}
                      </div>
                    </td>
                    <td className="py-3 px-3 font-mono text-[11px]">
                      <div className="flex items-center gap-1">
                        <span className="text-slate-400">•••••••••••</span>
                        <button
                          onClick={() => handleCopy(w.secretToken, w.workerId)}
                          className="p-1 text-slate-400 hover:text-cyan-400 transition-colors"
                          title="Copy Secret Token"
                        >
                          {copiedTokenId === w.workerId ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="py-3 px-3 text-right">
                      {canManageSettings && w.status === 'active' && (
                        <button
                          onClick={() => revokeWorker(w.workerId)}
                          className="px-2 py-1 text-[11px] text-rose-400 hover:bg-rose-950/60 border border-rose-900/60 rounded transition-colors"
                          title="Revoke worker token"
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: Worker Daemon Script & Instructions */}
      {activeTab === 'script' && (
        <div className="space-y-4">
          <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold text-slate-200">
                  Local Worker Daemon Implementation (Bash / cURL)
                </span>
              </div>
              <button
                onClick={() => handleCopy(sampleWorkerScript, 'script')}
                className="flex items-center gap-1 px-2.5 py-1 text-xs font-mono text-cyan-300 hover:bg-cyan-950/60 border border-cyan-800/80 rounded transition-colors"
              >
                {copiedTokenId === 'script' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                <span>Copy Daemon Code</span>
              </button>
            </div>

            <pre className="p-3 bg-slate-900 border border-slate-800 rounded font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
              {sampleWorkerScript}
            </pre>
          </div>

          <div className="p-3 bg-slate-950/60 border border-slate-800 rounded text-xs text-slate-300 space-y-1.5">
            <div className="font-semibold text-slate-200">API Contract for Authorized Scanning Worker:</div>
            <ul className="list-disc pl-5 space-y-1 text-slate-400 font-mono text-[11px]">
              <li><strong className="text-cyan-400">POST /api/v1/workers/heartbeat</strong> — Send periodic ping with secretToken.</li>
              <li><strong className="text-cyan-400">POST /api/v1/workers/jobs/poll</strong> — Fetch pending queued scan jobs assigned to this worker.</li>
              <li><strong className="text-cyan-400">POST /api/v1/workers/jobs/:jobId/accept</strong> — Claim job with short-lived TTL job token.</li>
              <li><strong className="text-cyan-400">POST /api/v1/workers/jobs/:jobId/progress</strong> — Report 0-100% execution progress.</li>
              <li><strong className="text-cyan-400">POST /api/v1/workers/jobs/:jobId/result</strong> — Submit target-bound XML result with SHA-256 digest signature.</li>
            </ul>
          </div>
        </div>
      )}

      {/* TAB 3: Security Architecture */}
      {activeTab === 'architecture' && (
        <div className="space-y-4 text-xs text-slate-300 leading-relaxed">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
              <div className="flex items-center gap-1.5 text-cyan-400 font-bold">
                <Lock className="w-4 h-4" />
                <span>1. Token-Based Authentication</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Workers authenticate via high-entropy secret tokens generated upon registration. All job claims use single-use cryptographic tokens with 15-minute expiration windows.
              </p>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
              <div className="flex items-center gap-1.5 text-amber-400 font-bold">
                <ShieldAlert className="w-4 h-4" />
                <span>2. Target Binding Enforcement</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                The server explicitly verifies that reported scan targets match the allowlisted IP assigned to that job. Any deviation results in immediate rejection and audit alerting.
              </p>
            </div>

            <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-2">
              <div className="flex items-center gap-1.5 text-emerald-400 font-bold">
                <ShieldCheck className="w-4 h-4" />
                <span>3. SHA-256 Digest Verification</span>
              </div>
              <p className="text-slate-400 text-[11px]">
                Every uploaded XML output is hashed and verified server-side. Tampered or corrupted scan outputs are discarded to maintain chain-of-custody integrity.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Register Worker Modal */}
      <Modal
        isOpen={isRegisterOpen}
        onClose={() => setIsRegisterOpen(false)}
        title="Register Authorized Scanning Worker"
        subtitle="Provision worker credentials for an isolated lab scanner daemon"
      >
        <form onSubmit={handleRegister} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Daemon Identifier Name
            </label>
            <input
              type="text"
              value={newWorkerName}
              onChange={e => setNewWorkerName(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-xs text-slate-100 focus:outline-none focus:border-cyan-400"
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Environment
              </label>
              <select
                value={newWorkerEnv}
                onChange={e => setNewWorkerEnv(e.target.value as any)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-xs text-slate-100"
              >
                <option value="local_lab">Local Lab Daemon</option>
                <option value="simulated_preview">Simulated Preview Sandbox</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1">
                Worker IP / Bound Subnet
              </label>
              <input
                type="text"
                value={newWorkerIp}
                onChange={e => setNewWorkerIp(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-xs text-slate-100 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Permitted Scan Profiles
            </label>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              {(['safe-service-detection', 'openvas-basic', 'host-discovery', 'safe-os-detection'] as ApprovedScanProfile[]).map(p => (
                <label key={p} className="flex items-center gap-2 p-2 bg-slate-950 border border-slate-800 rounded cursor-pointer hover:border-slate-700">
                  <input
                    type="checkbox"
                    checked={selectedProfiles.includes(p)}
                    onChange={() => toggleProfile(p)}
                    className="rounded text-cyan-500 focus:ring-0"
                  />
                  <span className="font-mono text-[11px] text-slate-300">{p}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsRegisterOpen(false)}
              className="px-3.5 py-1.5 text-xs text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded"
            >
              Issue Secret Credentials
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
