import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderKanban,
  Target,
  Globe,
  Radio,
  Mail,
  Server,
  AlertTriangle,
  Gauge,
  Plus,
  ArrowRight,
  ShieldCheck,
  CheckCircle2,
  Clock,
  ExternalLink,
  Activity,
  Sparkles,
  Cpu,
  Lock,
  RefreshCw,
  Sliders
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip as RechartsTooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid
} from 'recharts';
import { useInvestigation } from '../context/InvestigationContext';
import { StatCard } from '../components/common/StatCard';
import { SeverityBadge, InteractionBadge } from '../components/common/Badge';
import { formatDate } from '../utils/formatters';
import { COLLECTOR_STATUSES } from '../data/seedData';

const SEVERITY_COLORS = {
  critical: '#f43f5e',
  high: '#f97316',
  medium: '#eab308',
  low: '#38bdf8',
  info: '#64748b'
};

export const DashboardPage: React.FC = () => {
  const navigate = useNavigate();
  const {
    investigations,
    activeInvestigation,
    targets,
    entities,
    services,
    findings,
    auditLogs,
    exposureScore,
    workflowRun,
    runSafeDemo,
    approveActiveWorkflowStage
  } = useInvestigation();

  // Metrics computation
  const totalInvestigations = investigations.length;
  const authorizedTargets = targets.length;
  const discoveredDomains = entities.filter(e => e.type === 'Domain').length;
  const discoveredSubdomains = entities.filter(e => e.type === 'Subdomain').length;
  const discoveredIPs = entities.filter(e => e.type === 'IP address').length;
  const discoveredEmails = entities.filter(e => e.type === 'Email').length;
  const openPorts = services.filter(s => s.state === 'open').length;
  const totalFindings = findings.length;

  // Donut chart data
  const severityDistribution = [
    { name: 'Critical', count: findings.filter(f => f.severity === 'critical').length, color: SEVERITY_COLORS.critical },
    { name: 'High', count: findings.filter(f => f.severity === 'high').length, color: SEVERITY_COLORS.high },
    { name: 'Medium', count: findings.filter(f => f.severity === 'medium').length, color: SEVERITY_COLORS.medium },
    { name: 'Low', count: findings.filter(f => f.severity === 'low').length, color: SEVERITY_COLORS.low },
    { name: 'Info', count: findings.filter(f => f.severity === 'info').length, color: SEVERITY_COLORS.info }
  ].filter(d => d.count > 0);

  // Mock trend data for Exposure Score timeline
  const scoreTrendData = [
    { date: 'Sep 15', score: 28 },
    { date: 'Sep 16', score: 38 },
    { date: 'Sep 17', score: 42 },
    { date: 'Sep 18', score: 58 },
    { date: 'Sep 19', score: exposureScore?.totalScore || 62 },
    { date: 'Today', score: exposureScore?.totalScore || 62 }
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner / Welcome Action */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 bg-slate-900 border border-slate-800 rounded-lg shadow-sm">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono uppercase tracking-wider text-cyan-400">
              Active Investigation
            </span>
            <span className="text-slate-500">·</span>
            <span className="text-xs text-slate-300 font-medium">
              {activeInvestigation?.status.toUpperCase() || 'ACTIVE'}
            </span>
          </div>
          <h1 className="text-lg font-bold text-slate-100 mt-1">
            {activeInvestigation?.name || 'NorthStar Analytics Lab Assessment'}
          </h1>
          <p className="text-xs text-slate-400 mt-0.5 max-w-2xl">
            {activeInvestigation?.description || 'Authorized educational footprint reconnaissance.'}
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
          <button
            onClick={() => {
              runSafeDemo();
              navigate('/active-scanning');
            }}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-bold text-slate-950 bg-gradient-to-r from-emerald-400 to-cyan-400 hover:from-emerald-300 hover:to-cyan-300 rounded-md transition-all shadow-xs cursor-pointer"
            title="Sets up NorthStar Analytics Lab testbed and executes full recon workflow"
          >
            <Sparkles className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>One-Click Safe Demo</span>
          </button>
          <button
            onClick={() => navigate('/passive-recon')}
            className="px-3 py-2 text-xs font-medium text-slate-200 bg-slate-800 hover:bg-slate-750 border border-slate-700 rounded-md transition-colors"
          >
            Launch Passive Query
          </button>
          <button
            onClick={() => navigate('/new-investigation')}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors shadow-xs"
          >
            <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>New Investigation</span>
          </button>
        </div>
      </div>

      {/* Autonomous Workflow Live Status Banner (if active) */}
      {workflowRun && (
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-col md:flex-row items-center justify-between gap-4 shadow-sm">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-cyan-950 text-cyan-400 border border-cyan-800 rounded-lg shrink-0">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold text-slate-200">
                  Semi-Autonomous Workflow Run: <code className="text-cyan-400 font-mono">{workflowRun.id}</code>
                </span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold uppercase ${
                  workflowRun.currentState === 'COMPLETED'
                    ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                    : workflowRun.currentState === 'WAITING_FOR_APPROVAL'
                    ? 'bg-amber-950 text-amber-300 border border-amber-800 animate-pulse'
                    : 'bg-blue-950 text-blue-300 border border-blue-800'
                }`}>
                  {workflowRun.currentState.replace(/_/g, ' ')}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Current progress: {workflowRun.stageProgressPercent}% · Checkpoint: {workflowRun.lastSafeState}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            {workflowRun.currentState === 'WAITING_FOR_APPROVAL' && (
              <button
                onClick={() => approveActiveWorkflowStage(workflowRun.id)}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-slate-950 bg-amber-400 hover:bg-amber-300 rounded transition-colors shadow cursor-pointer"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Approve Active Scan</span>
              </button>
            )}

            <button
              onClick={() => navigate('/active-scanning')}
              className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors cursor-pointer"
            >
              <span>Workflow Hub</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* KPI Tiles Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
        <StatCard
          label="Total Investigations"
          value={totalInvestigations}
          subtext="Active & archived"
          icon={FolderKanban}
          onClick={() => navigate('/investigations')}
        />
        <StatCard
          label="Authorized Targets"
          value={authorizedTargets}
          subtext="Allowlist verified"
          icon={Target}
          variant="cyan"
        />
        <StatCard
          label="Discovered Domains"
          value={`${discoveredDomains} / ${discoveredSubdomains}`}
          subtext="Apex & subdomains"
          icon={Globe}
          onClick={() => navigate('/entity-graph')}
        />
        <StatCard
          label="Active Target IP"
          value={discoveredIPs}
          subtext="Lab hypervisor host"
          icon={Server}
          onClick={() => navigate('/active-scanning')}
        />
        <StatCard
          label="Public Emails"
          value={discoveredEmails}
          subtext="theHarvester OSINT"
          icon={Mail}
          onClick={() => navigate('/passive-recon')}
        />
        <StatCard
          label="Open Port Listeners"
          value={openPorts}
          subtext="SSH, HTTP, PG, Jenkins"
          icon={Radio}
          variant="amber"
          onClick={() => navigate('/active-scanning')}
        />
        <StatCard
          label="Vulnerability Findings"
          value={totalFindings}
          subtext="CVEs & disclosures"
          icon={AlertTriangle}
          variant="rose"
          onClick={() => navigate('/findings')}
        />
        <StatCard
          label="Exposure Score"
          value={`${exposureScore?.totalScore || 0}/100`}
          subtext={exposureScore?.tier || 'Calculating'}
          icon={Gauge}
          variant={exposureScore && exposureScore.totalScore > 50 ? 'amber' : 'emerald'}
          onClick={() => navigate('/exposure-score')}
        />
        <StatCard
          label="Knowledge Nodes"
          value={entities.length}
          subtext="Correlated graph"
          icon={Activity}
          variant="cyan"
          onClick={() => navigate('/entity-graph')}
        />
        <StatCard
          label="Audit Events"
          value={auditLogs.length}
          subtext="Tamper-evident logs"
          icon={ShieldCheck}
          variant="emerald"
          onClick={() => navigate('/audit-log')}
        />
      </div>

      {/* Analytical Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Severity Donut */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Findings by Severity</h2>
              <p className="text-xs text-slate-400 mt-0.5">Triage distribution across all targets</p>
            </div>
            <button
              onClick={() => navigate('/findings')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
            >
              View All
            </button>
          </div>

          <div className="h-56 relative my-2">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={80}
                  paddingAngle={4}
                  dataKey="count"
                >
                  {severityDistribution.map(entry => (
                    <Cell key={entry.name} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
                  ))}
                </Pie>
                <RechartsTooltip
                  content={({ payload }) => {
                    if (!payload || !payload[0]) return null;
                    const data = payload[0];
                    return (
                      <div className="bg-slate-950 border border-slate-800 px-2.5 py-1.5 rounded shadow-lg text-xs">
                        <span className="font-semibold text-slate-200">{data.name}: </span>
                        <span className="font-mono text-cyan-400">{data.value} findings</span>
                      </div>
                    );
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
                {totalFindings}
              </span>
              <span className="text-[10px] text-slate-400 uppercase tracking-wider">Findings</span>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-3 pt-2 text-xs">
            {severityDistribution.map(item => (
              <div key={item.name} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-slate-300">{item.name}</span>
                <span className="font-mono text-slate-400 tabular-nums">({item.count})</span>
              </div>
            ))}
          </div>
        </div>

        {/* Exposure Trend Chart */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Exposure Score Trajectory</h2>
              <p className="text-xs text-slate-400 mt-0.5">Aggregated risk trajectory over reconnaissance phases</p>
            </div>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-cyan-300">
              Current: {exposureScore?.totalScore || 0}/100 ({exposureScore?.tier || 'Calculating'})
            </span>
          </div>

          <div className="h-56 my-2">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={scoreTrendData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="date" stroke="#64748b" fontSize={11} />
                <YAxis domain={[0, 100]} stroke="#64748b" fontSize={11} />
                <RechartsTooltip
                  content={({ payload, label }) => {
                    if (!payload || !payload[0]) return null;
                    return (
                      <div className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded shadow-lg text-xs">
                        <span className="text-slate-400">{label}: </span>
                        <strong className="text-cyan-400 font-mono">{payload[0].value} / 100</strong>
                      </div>
                    );
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="score"
                  stroke="#22d3ee"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#scoreGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800/60">
            <span className="font-mono text-[11px]">Formula: 0.20×P (Public) + 0.15×D (Domain) + 0.25×S (Services) + 0.35×V (Vulns) + 0.05×C (Confidence)</span>
            <button
              onClick={() => navigate('/exposure-score')}
              className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 shrink-0"
            >
              <span>Explore Breakdown</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Two-Column Lower View: Recent Investigations + Data Source Health */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Investigations Table */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-3">
            <h2 className="text-sm font-semibold text-slate-100">Lab Investigations</h2>
            <button
              onClick={() => navigate('/investigations')}
              className="text-xs text-cyan-400 hover:text-cyan-300"
            >
              View Directory
            </button>
          </div>

          <div className="divide-y divide-slate-800/60">
            {investigations.map(inv => (
              <div key={inv.id} className="py-3 flex items-center justify-between gap-3 text-xs">
                <div>
                  <div className="font-medium text-slate-200 hover:text-cyan-300 cursor-pointer"
                       onClick={() => navigate('/investigations')}>
                    {inv.name}
                  </div>
                  <div className="text-[11px] text-slate-400 flex items-center gap-2 mt-0.5">
                    <span>{inv.organizationName}</span>
                    <span>·</span>
                    <span className="font-mono text-cyan-400">{inv.scope.ownedDomains.join(', ')}</span>
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono uppercase bg-slate-950 border border-slate-800 text-slate-300">
                    {inv.status}
                  </span>
                  <div className="text-[10px] text-slate-400 mt-1">
                    {formatDate(inv.createdAt)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Data Source & Collector Readiness */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-3">
            <h2 className="text-sm font-semibold text-slate-100">Data-Source Health & Modules</h2>
            <span className="text-[11px] text-emerald-400 flex items-center gap-1 font-mono">
              <CheckCircle2 className="w-3.5 h-3.5" /> 6 Ready
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {COLLECTOR_STATUSES.map(col => (
              <div
                key={col.id}
                className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-md text-xs space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-slate-200">{col.name}</span>
                  <InteractionBadge type={col.type} />
                </div>
                <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                  {col.description}
                </p>
                <div className="pt-1 text-[10px] text-slate-500 font-mono">
                  Supported: {col.supportedFormats.join(', ')}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Audit Activity Stream */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-3">
          <div>
            <h2 className="text-sm font-semibold text-slate-100">Recent Audit Activities</h2>
            <p className="text-xs text-slate-400 mt-0.5">Tamper-evident sequence of investigator operations</p>
          </div>
          <button
            onClick={() => navigate('/audit-log')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
          >
            Full Audit Ledger
          </button>
        </div>

        <div className="divide-y divide-slate-800/60">
          {auditLogs.slice(0, 4).map(log => (
            <div key={log.id} className="py-2.5 flex items-start justify-between gap-4 text-xs">
              <div className="space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-cyan-400 text-[11px]">{log.action}</span>
                  <span className="text-slate-400">·</span>
                  <span className="text-slate-300 font-medium">{log.actor}</span>
                </div>
                <p className="text-slate-400 text-[11px] leading-relaxed">{log.details}</p>
              </div>
              <div className="text-right shrink-0">
                <span className="text-[10px] font-mono text-slate-400 block">{formatDate(log.timestamp)}</span>
                <span className="text-[10px] font-mono text-slate-400 truncate max-w-28 block">
                  {log.auditHash.slice(0, 16)}...
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
