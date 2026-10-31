import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Gauge,
  ShieldAlert,
  ShieldCheck,
  TrendingDown,
  ArrowRight,
  Server,
  AlertTriangle,
  Mail,
  Sliders,
  CheckCircle2,
  RotateCcw,
  Sparkles,
  Layers,
  Activity,
  FileCheck,
  Info
} from 'lucide-react';
import { useInvestigation } from '../context/InvestigationContext';
import { useAuth } from '../context/AuthContext';
import { formatDate } from '../utils/formatters';

export const ExposureScorePage: React.FC = () => {
  const navigate = useNavigate();
  const {
    exposureScore,
    findings,
    services,
    entities,
    evidence,
    recalculateScore
  } = useInvestigation();
  const { canReviewFindings } = useAuth();

  const [isRecalculating, setIsRecalculating] = useState(false);
  const [reviewerNotes, setReviewerNotes] = useState(exposureScore?.reviewerNotes || '');

  // Actual values from 5-factor breakdown (or defaults)
  const P = exposureScore?.P ?? 45;
  const D = exposureScore?.D ?? 40;
  const S = exposureScore?.S ?? 68;
  const V = exposureScore?.V ?? 75;
  const C = exposureScore?.C ?? 85;

  const actualScore = exposureScore?.totalScore ?? 62;
  const tier = exposureScore?.tier ?? 'High';

  // What-If Simulation State
  const [simP, setSimP] = useState<number>(P);
  const [simD, setSimD] = useState<number>(D);
  const [simS, setSimS] = useState<number>(S);
  const [simV, setSimV] = useState<number>(V);
  const [simC, setSimC] = useState<number>(C);
  const [isSimulating, setIsSimulating] = useState(false);

  // Compute simulated composite
  const simulatedScore = Math.min(
    100,
    Math.max(
      0,
      Math.round(
        (0.20 * simP) +
        (0.15 * simD) +
        (0.25 * simS) +
        (0.35 * simV) +
        (0.05 * simC)
      )
    )
  );

  const getTierForScore = (s: number): 'Minimal' | 'Low' | 'Moderate' | 'High' | 'Critical' => {
    if (s >= 80) return 'Critical';
    if (s >= 60) return 'High';
    if (s >= 40) return 'Moderate';
    if (s >= 20) return 'Low';
    return 'Minimal';
  };

  const simTier = getTierForScore(simulatedScore);

  // Tier color styling
  const tierColors: Record<string, { text: string; bg: string; border: string }> = {
    Minimal: { text: 'text-emerald-400', bg: 'bg-emerald-950/40', border: 'border-emerald-800' },
    Low: { text: 'text-cyan-400', bg: 'bg-cyan-950/40', border: 'border-cyan-800' },
    Moderate: { text: 'text-yellow-400', bg: 'bg-yellow-950/40', border: 'border-yellow-800' },
    High: { text: 'text-amber-400', bg: 'bg-amber-950/40', border: 'border-amber-800' },
    Critical: { text: 'text-rose-400', bg: 'bg-rose-950/40', border: 'border-rose-800' }
  };

  const currentTierStyle = tierColors[tier] || tierColors['Moderate'];
  const simTierStyle = tierColors[simTier] || tierColors['Moderate'];

  const handleRecalculate = async () => {
    setIsRecalculating(true);
    try {
      await recalculateScore(reviewerNotes);
    } finally {
      setIsRecalculating(false);
    }
  };

  const handleResetSimulation = () => {
    setSimP(P);
    setSimD(D);
    setSimS(S);
    setSimV(V);
    setSimC(C);
    setIsSimulating(false);
  };

  const componentsList = [
    {
      factor: 'P',
      name: 'Public Footprint Exposure',
      weight: '20% (w=0.20)',
      value: P,
      simValue: simP,
      setter: setSimP,
      color: '#a855f7',
      icon: Mail,
      rationale: `Derived from ${entities.filter(e => e.type === 'Email').length} exposed email addresses, leaked technical documentation, and search disclosures.`
    },
    {
      factor: 'D',
      name: 'Domain Hygiene & Misconfigurations',
      weight: '15% (w=0.15)',
      value: D,
      simValue: simD,
      setter: setSimD,
      color: '#06b6d4',
      icon: Sliders,
      rationale: `Evaluates ${entities.filter(e => e.type === 'Subdomain').length} enumerated subdomains, missing DMARC quarantine policies, and SPF record syntax.`
    },
    {
      factor: 'S',
      name: 'Service Exposure & Listening Ports',
      weight: '25% (w=0.25)',
      value: S,
      simValue: simS,
      setter: setSimS,
      color: '#38bdf8',
      icon: Server,
      rationale: `Calculated from ${services.length} listening network ports with extra penalties for exposed database (5432) or admin endpoints.`
    },
    {
      factor: 'V',
      name: 'Vulnerability Severity (CVSS Weighted)',
      weight: '35% (w=0.35)',
      value: V,
      simValue: simV,
      setter: setSimV,
      color: '#f43f5e',
      icon: AlertTriangle,
      rationale: `Aggregates active OpenVAS findings and unmitigated CVEs (e.g. Jenkins metrics CVE-2023-38606, weak TLS).`
    },
    {
      factor: 'C',
      name: 'Correlation Confidence Boost',
      weight: '5% (w=0.05)',
      value: C,
      simValue: simC,
      setter: setSimC,
      color: '#10b981',
      icon: Activity,
      rationale: `Quantifies corroboration across ${evidence.length} evidence items and independent collectors to avoid false-alarm skew.`
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100">
            5-Factor Digital Exposure Score
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Algorithmic quantification of organizational exposure based on empirically collected OSINT and active audit findings.
          </p>
        </div>

        {canReviewFindings && (
          <button
            onClick={handleRecalculate}
            disabled={isRecalculating}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded transition-colors shrink-0 cursor-pointer"
          >
            <RotateCcw className={`w-3.5 h-3.5 ${isRecalculating ? 'animate-spin' : ''}`} />
            <span>Recalculate Score</span>
          </button>
        )}
      </div>

      {/* Hero Score Card */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 flex flex-col md:flex-row items-center justify-between gap-6 shadow-sm">
        <div className="space-y-3 max-w-xl">
          <div className="flex items-center gap-2">
            <span className={`px-2.5 py-1 text-xs font-bold uppercase rounded border ${currentTierStyle.bg} ${currentTierStyle.text} ${currentTierStyle.border}`}>
              {tier} Risk Tier
            </span>
            <span className="text-xs text-slate-400 font-mono">
              Formula: v3.0-5factor
            </span>
          </div>

          <h2 className="text-base font-semibold text-slate-100">
            Overall Attack Surface Exposure Index
          </h2>
          <p className="text-xs text-slate-300 leading-relaxed">
            FootprintIQ calculates an exposure score from 0 (minimal attack surface) to 100 (critical perimeter exposure). The formula balances passive public disclosures against verified listening services and scanner findings.
          </p>

          {/* Mathematical Formula Display */}
          <div className="p-3 bg-slate-950 border border-slate-800 rounded font-mono text-xs text-slate-300 overflow-x-auto">
            <span className="text-cyan-400 font-bold">Exposure</span> = (0.20 × <strong className="text-purple-400">{P}</strong>) + (0.15 × <strong className="text-cyan-400">{D}</strong>) + (0.25 × <strong className="text-sky-400">{S}</strong>) + (0.35 × <strong className="text-rose-400">{V}</strong>) + (0.05 × <strong className="text-emerald-400">{C}</strong>) = <strong className="text-slate-100">{actualScore}/100</strong>
          </div>
        </div>

        {/* Big circular score gauge */}
        <div className="flex flex-col items-center justify-center shrink-0">
          <div className="relative w-36 h-36 flex items-center justify-center">
            <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle
                cx="50"
                cy="50"
                r="40"
                stroke="currentColor"
                strokeWidth="8"
                fill="transparent"
                className="text-slate-800"
              />
              <circle
                cx="50"
                cy="50"
                r="40"
                stroke="currentColor"
                strokeWidth="8"
                fill="transparent"
                strokeDasharray={`${2 * Math.PI * 40}`}
                strokeDashoffset={`${2 * Math.PI * 40 * (1 - actualScore / 100)}`}
                strokeLinecap="round"
                className={`${currentTierStyle.text} transition-all duration-700`}
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-3xl font-bold font-mono text-slate-100 tabular-nums">
                {actualScore}
              </span>
              <span className="text-[10px] text-slate-400 uppercase tracking-widest font-mono">
                / 100
              </span>
            </div>
          </div>
          <div className="mt-2 text-xs font-mono text-slate-400">
            Calculated: {formatDate(exposureScore?.calculationDate || new Date().toISOString())}
          </div>
        </div>
      </div>

      {/* 5-Factor Component Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {componentsList.map(item => (
          <div
            key={item.factor}
            className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between shadow-sm space-y-3"
          >
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div
                    className="p-1.5 rounded"
                    style={{ backgroundColor: `${item.color}20`, color: item.color }}
                  >
                    <item.icon className="w-4 h-4" />
                  </div>
                  <div>
                    <span className="text-xs font-bold text-slate-200">
                      Factor {item.factor} · {item.name}
                    </span>
                    <span className="block text-[10px] font-mono text-slate-400">
                      Weight: {item.weight}
                    </span>
                  </div>
                </div>
                <span
                  className="text-lg font-mono font-bold"
                  style={{ color: item.color }}
                >
                  {item.value}
                </span>
              </div>

              <p className="text-xs text-slate-300 mt-3 leading-relaxed">
                {item.rationale}
              </p>
            </div>

            <div className="pt-2 border-t border-slate-800/80">
              <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-500"
                  style={{ width: `${item.value}%`, backgroundColor: item.color }}
                />
              </div>
            </div>
          </div>
        ))}

        {/* Tier Classification Reference Card */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between shadow-sm space-y-3">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-slate-200">
                Risk Tier Classification Scale
              </span>
            </div>
            <div className="space-y-1.5 text-xs font-mono">
              <div className="flex justify-between items-center px-2 py-1 rounded bg-slate-950 border border-slate-800">
                <span className="text-emerald-400 font-bold">Minimal</span>
                <span className="text-slate-400">0 – 19</span>
              </div>
              <div className="flex justify-between items-center px-2 py-1 rounded bg-slate-950 border border-slate-800">
                <span className="text-cyan-400 font-bold">Low</span>
                <span className="text-slate-400">20 – 39</span>
              </div>
              <div className="flex justify-between items-center px-2 py-1 rounded bg-slate-950 border border-slate-800">
                <span className="text-yellow-400 font-bold">Moderate</span>
                <span className="text-slate-400">40 – 59</span>
              </div>
              <div className="flex justify-between items-center px-2 py-1 rounded bg-slate-950 border border-slate-800">
                <span className="text-amber-400 font-bold">High</span>
                <span className="text-slate-400">60 – 79</span>
              </div>
              <div className="flex justify-between items-center px-2 py-1 rounded bg-slate-950 border border-slate-800">
                <span className="text-rose-400 font-bold">Critical</span>
                <span className="text-slate-400">80 – 100</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Interactive What-If Simulation Sandbox */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-100">
                Remediation What-If Simulator
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                Interactive Model
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Adjust hypothetical metric factors below to model the security ROI of remediating findings or shrinking exposed services.
            </p>
          </div>

          <button
            onClick={handleResetSimulation}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-300 hover:text-slate-100 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors shrink-0 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Sliders</span>
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-center">
          {/* Sliders Column */}
          <div className="lg:col-span-2 space-y-4">
            {componentsList.map(item => (
              <div key={item.factor} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-300">
                    Factor {item.factor}: {item.name}
                  </span>
                  <span className="font-mono font-bold text-slate-100">
                    {item.simValue} / 100
                  </span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="100"
                  value={item.simValue}
                  onChange={e => {
                    item.setter(parseInt(e.target.value, 10));
                    setIsSimulating(true);
                  }}
                  className="w-full accent-cyan-400 cursor-pointer"
                />
              </div>
            ))}
          </div>

          {/* Simulated Result Gauge */}
          <div className="p-5 bg-slate-950 border border-slate-800 rounded-lg flex flex-col items-center justify-center text-center space-y-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              Simulated Exposure Score
            </span>
            <div className="text-4xl font-bold font-mono text-slate-100">
              {simulatedScore}
              <span className="text-xs text-slate-500 font-normal"> / 100</span>
            </div>
            <span className={`px-2 py-0.5 text-xs font-bold uppercase rounded border ${simTierStyle.bg} ${simTierStyle.text} ${simTierStyle.border}`}>
              {simTier} Risk Tier
            </span>

            {simulatedScore !== actualScore && (
              <div className="text-xs font-mono text-cyan-400 pt-2 border-t border-slate-800 w-full">
                Delta: {simulatedScore > actualScore ? `+${simulatedScore - actualScore}` : `${simulatedScore - actualScore}`} points
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Reviewer Assessment & Governance Notes */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 shadow-sm space-y-3">
        <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
          <FileCheck className="w-4 h-4 text-cyan-400" />
          <span>Investigator & Reviewer Governance Notes</span>
        </h3>
        <textarea
          value={reviewerNotes}
          onChange={e => setReviewerNotes(e.target.value)}
          placeholder="Document institutional context, accepted lab risks, or rationale for algorithm override..."
          rows={3}
          className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 focus:outline-none focus:border-cyan-400 resize-none"
        />
        <div className="flex justify-end">
          <button
            onClick={handleRecalculate}
            disabled={isRecalculating || !canReviewFindings}
            className="px-3.5 py-1.5 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 rounded transition-colors cursor-pointer"
          >
            Save Notes & Update Baseline
          </button>
        </div>
      </div>
    </div>
  );
};
