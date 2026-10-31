import React from 'react';
import {
  Play,
  CheckCircle2,
  AlertTriangle,
  Clock,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  RotateCcw,
  XCircle,
  Cpu,
  Lock,
  Layers,
  Sparkles,
  RefreshCw
} from 'lucide-react';
import { WorkflowRun, WorkflowState } from '../../types/workflow';
import { useInvestigation } from '../../context/InvestigationContext';
import { useAuth } from '../../context/AuthContext';
import { formatDate } from '../../utils/formatters';

interface WorkflowRunCardProps {
  run: WorkflowRun | null;
  onStartWorkflow: () => void;
  onRunSafeDemo: () => void;
}

const STAGES: {
  key: string;
  name: string;
  states: WorkflowState[];
  description: string;
}[] = [
  {
    key: 'scope',
    name: '1. Scope & Auth',
    states: ['CREATED', 'SCOPE_VALIDATED'],
    description: 'Verify written permission, active allowlist, and date bounds'
  },
  {
    key: 'passive',
    name: '2. Passive OSINT',
    states: ['PASSIVE_RUNNING', 'PASSIVE_COMPLETE'],
    description: 'Query RDAP, authoritative DNS, and search disclosures'
  },
  {
    key: 'gatekeeper',
    name: '3. Approval Gate',
    states: ['WAITING_FOR_APPROVAL'],
    description: 'Mandatory investigator confirmation prior to packet dispatch'
  },
  {
    key: 'active',
    name: '4. Worker Audit',
    states: ['NMAP_QUEUED', 'NMAP_RUNNING', 'NMAP_COMPLETE', 'OPENVAS_QUEUED', 'OPENVAS_RUNNING', 'OPENVAS_COMPLETE'],
    description: 'Isolated lab worker executes safe Nmap & OpenVAS checks'
  },
  {
    key: 'scoring',
    name: '5. Correlation & Score',
    states: ['CORRELATING', 'SCORING'],
    description: 'Map knowledge graph and calculate 5-factor Exposure Score'
  },
  {
    key: 'reporting',
    name: '6. Final Dossier',
    states: ['REPORTING', 'COMPLETED'],
    description: 'Compile 20-section audit report with cryptographic hashes'
  }
];

export const WorkflowRunCard: React.FC<WorkflowRunCardProps> = ({
  run,
  onStartWorkflow,
  onRunSafeDemo
}) => {
  const {
    activeInvestigation,
    approveActiveWorkflowStage,
    resumeWorkflow,
    cancelWorkflow
  } = useInvestigation();
  const { canImportActiveScans } = useAuth();

  const isTerminal = run ? ['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED', 'BLOCKED_OUT_OF_SCOPE'].includes(run.currentState) : false;
  const isWaitingApproval = run?.currentState === 'WAITING_FOR_APPROVAL';

  // Determine stage status
  const getStageStatus = (stageStates: WorkflowState[]) => {
    if (!run) return 'pending';
    const currentStateIndex = STAGES.findIndex(s => s.states.includes(run.currentState));
    const thisStageIndex = STAGES.findIndex(s => s.states === stageStates);

    if (run.currentState === 'BLOCKED_OUT_OF_SCOPE' || run.currentState === 'FAILED') {
      if (stageStates.includes(run.currentState)) return 'failed';
    }

    if (stageStates.includes(run.currentState)) {
      if (run.currentState === 'WAITING_FOR_APPROVAL') return 'waiting';
      if (run.currentState === 'COMPLETED') return 'completed';
      return 'running';
    }

    if (currentStateIndex > thisStageIndex) return 'completed';
    return 'pending';
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-sm space-y-5">
      {/* Top Banner & Control Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold uppercase tracking-wider text-cyan-400 font-mono flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              Semi-Autonomous Recon Controller
            </span>
            {run && (
              <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold uppercase ${
                run.currentState === 'COMPLETED'
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : run.currentState === 'WAITING_FOR_APPROVAL'
                  ? 'bg-amber-950 text-amber-300 border border-amber-800 animate-pulse'
                  : run.currentState === 'BLOCKED_OUT_OF_SCOPE' || run.currentState === 'FAILED'
                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                  : 'bg-blue-950 text-blue-300 border border-blue-800'
              }`}>
                {run.currentState.replace(/_/g, ' ')}
              </span>
            )}
          </div>
          <p className="text-xs text-slate-300 mt-1">
            End-to-end reconnaissance lifecycle: scope enforcement, passive OSINT aggregation, approval gating, worker dispatch, graph correlation, and exposure scoring.
          </p>
        </div>

        {/* Global Action Buttons */}
        <div className="flex items-center gap-2 flex-wrap shrink-0">
          <button
            onClick={onRunSafeDemo}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-900 bg-gradient-to-r from-emerald-400 to-cyan-400 hover:from-emerald-300 hover:to-cyan-300 rounded shadow transition-all cursor-pointer"
            title="Runs complete NorthStar Analytics Lab demonstration with safe mock data"
          >
            <Sparkles className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>One-Click Safe Demo</span>
          </button>

          {(!run || isTerminal) && (
            <button
              onClick={onStartWorkflow}
              disabled={!canImportActiveScans}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-100 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 border border-slate-700 rounded transition-colors cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current text-cyan-400" />
              <span>Start Autonomous Run</span>
            </button>
          )}

          {run && !isTerminal && (
            <button
              onClick={() => cancelWorkflow(run.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-rose-300 bg-rose-950/40 hover:bg-rose-900/60 border border-rose-800/80 rounded transition-colors cursor-pointer"
            >
              <XCircle className="w-3.5 h-3.5" />
              <span>Cancel Run</span>
            </button>
          )}

          {run && (run.currentState === 'FAILED' || run.currentState === 'CANCELLED') && (
            <button
              onClick={() => resumeWorkflow(run.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-yellow-300 bg-yellow-950/40 hover:bg-yellow-900/60 border border-yellow-800/80 rounded transition-colors cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Resume Safe Checkpoint</span>
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar */}
      {run && (
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Run: <strong className="text-slate-200">{run.id}</strong></span>
            <span>Progress: <strong className="text-cyan-400">{run.stageProgressPercent}%</strong></span>
          </div>
          <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className={`h-full transition-all duration-500 rounded-full ${
                run.currentState === 'COMPLETED'
                  ? 'bg-emerald-500'
                  : run.currentState === 'WAITING_FOR_APPROVAL'
                  ? 'bg-amber-400 animate-pulse'
                  : run.currentState === 'FAILED' || run.currentState === 'BLOCKED_OUT_OF_SCOPE'
                  ? 'bg-rose-500'
                  : 'bg-cyan-500'
              }`}
              style={{ width: `${run.stageProgressPercent}%` }}
            />
          </div>
        </div>
      )}

      {/* Mandatory Human Gatekeeper Attention Banner */}
      {isWaitingApproval && (
        <div className="p-4 bg-gradient-to-r from-amber-950/70 to-slate-900 border-2 border-amber-500/80 rounded-lg shadow-lg space-y-3">
          <div className="flex items-start gap-3">
            <div className="p-2 bg-amber-500/20 text-amber-300 rounded-lg border border-amber-500/30 shrink-0">
              <ShieldAlert className="w-5 h-5 animate-pulse" />
            </div>
            <div className="space-y-1">
              <h3 className="text-sm font-bold text-amber-200 flex items-center gap-2">
                <span>STAGE GATEKEEPER PAUSE: Authorization Required</span>
                <span className="text-[10px] font-mono px-2 py-0.2 bg-amber-900/60 text-amber-300 rounded border border-amber-700">
                  Human-in-the-Loop Policy
                </span>
              </h3>
              <p className="text-xs text-slate-300 leading-relaxed">
                Passive data collection has completed successfully. Before any active port discovery or vulnerability probing packets can be transmitted, an authorized investigator must explicitly certify rules of engagement for target: <code className="text-amber-300 font-bold bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">[{activeInvestigation?.scope.activeTargets.join(', ') || '192.168.56.102'}]</code>.
              </p>
            </div>
          </div>

          <div className="flex items-center justify-between pt-2 border-t border-amber-800/40">
            <div className="text-[11px] text-slate-400 font-mono">
              Role Required: <span className="text-amber-300">Investigator</span> or <span className="text-amber-300">Admin</span>
            </div>
            <button
              onClick={() => run && approveActiveWorkflowStage(run.id)}
              disabled={!canImportActiveScans}
              className="flex items-center gap-2 px-4 py-2 text-xs font-bold text-slate-950 bg-amber-400 hover:bg-amber-300 disabled:opacity-50 rounded shadow transition-all cursor-pointer"
            >
              <CheckCircle2 className="w-4 h-4 stroke-[2.5]" />
              <span>Authorize & Dispatch Lab Worker</span>
            </button>
          </div>
        </div>
      )}

      {/* Stepper Stages Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {STAGES.map((stage, idx) => {
          const status = getStageStatus(stage.states);
          return (
            <div
              key={stage.key}
              className={`p-3.5 rounded-lg border transition-all ${
                status === 'completed'
                  ? 'bg-emerald-950/20 border-emerald-900/60 text-slate-200'
                  : status === 'running'
                  ? 'bg-cyan-950/30 border-cyan-700/80 shadow-cyan-950/50 shadow-sm'
                  : status === 'waiting'
                  ? 'bg-amber-950/30 border-amber-700/80 shadow-amber-950/50 shadow-sm'
                  : status === 'failed'
                  ? 'bg-rose-950/30 border-rose-900/80'
                  : 'bg-slate-950/40 border-slate-800/60 opacity-70'
              }`}
            >
              <div className="flex items-center justify-between gap-2 mb-1.5">
                <span className="text-xs font-bold text-slate-200">{stage.name}</span>
                {status === 'completed' && (
                  <span className="flex items-center gap-1 text-[10px] font-mono font-semibold text-emerald-400">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Done</span>
                  </span>
                )}
                {status === 'running' && (
                  <span className="flex items-center gap-1 text-[10px] font-mono font-semibold text-cyan-400 animate-pulse">
                    <RefreshCw className="w-3 h-3 animate-spin" />
                    <span>Active</span>
                  </span>
                )}
                {status === 'waiting' && (
                  <span className="flex items-center gap-1 text-[10px] font-mono font-semibold text-amber-400">
                    <Lock className="w-3 h-3" />
                    <span>Awaiting Approval</span>
                  </span>
                )}
                {status === 'failed' && (
                  <span className="flex items-center gap-1 text-[10px] font-mono font-semibold text-rose-400">
                    <XCircle className="w-3.5 h-3.5" />
                    <span>Blocked</span>
                  </span>
                )}
                {status === 'pending' && (
                  <span className="text-[10px] font-mono text-slate-500">Queued</span>
                )}
              </div>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                {stage.description}
              </p>
            </div>
          );
        })}
      </div>

      {/* State Transition History Logs */}
      {run && run.stateHistory && run.stateHistory.length > 0 && (
        <div className="pt-3 border-t border-slate-800/80 space-y-2">
          <span className="text-xs font-semibold text-slate-300 block">
            State Transition Audit Trail
          </span>
          <div className="max-h-44 overflow-y-auto space-y-1.5 p-2.5 bg-slate-950 border border-slate-800 rounded font-mono text-[11px]">
            {run.stateHistory.slice().reverse().map((entry, i) => (
              <div key={i} className="flex items-start gap-2 text-slate-300 leading-tight">
                <span className="text-slate-500 shrink-0">{formatDate(entry.timestamp)}</span>
                <span className="text-cyan-400 font-bold shrink-0">[{entry.state}]</span>
                <span className="text-slate-300">{entry.message || 'State transition recorded'}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
