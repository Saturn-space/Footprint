import React, { useState } from 'react';
import {
  AlertTriangle,
  Search,
  Filter,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  ShieldAlert,
  SlidersHorizontal,
  Plus
} from 'lucide-react';
import { useInvestigation } from '../context/InvestigationContext';
import { useAuth } from '../context/AuthContext';
import { Finding, FindingSeverity, FindingStatus } from '../types/models';
import { SeverityBadge, InteractionBadge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';
import { formatDate } from '../utils/formatters';

export const FindingsPage: React.FC = () => {
  const {
    findings,
    updateFindingStatus,
    activeInvestigation
  } = useInvestigation();

  const { canReviewFindings } = useAuth();

  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const filtered = findings.filter(f => {
    const matchesSearch =
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.target.toLowerCase().includes(search.toLowerCase()) ||
      f.description.toLowerCase().includes(search.toLowerCase());

    const matchesSeverity = severityFilter === 'all' || f.severity === severityFilter;
    const matchesStatus = statusFilter === 'all' || f.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100">Reconnaissance Findings & Exposures</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Triaged security weaknesses, misconfigurations, and external information disclosures.
          </p>
        </div>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs">
        <div className="relative flex-1 min-w-56">
          <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by title, target, CVE..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-hidden"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Severity Dropdown */}
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-200 py-1.5 px-2.5 rounded-md text-xs focus:outline-hidden focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          {/* Status Dropdown */}
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-200 py-1.5 px-2.5 rounded-md text-xs focus:outline-hidden focus:border-cyan-500"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="under_review">Under Review</option>
            <option value="mitigated">Mitigated</option>
            <option value="false_positive">False Positive</option>
          </select>
        </div>
      </div>

      {/* Findings Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/80 text-[11px] text-slate-400 uppercase tracking-wider font-mono border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Severity</th>
                <th className="py-2.5 px-4">Title & Description</th>
                <th className="py-2.5 px-4">Target</th>
                <th className="py-2.5 px-4">Source Tool</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filtered.map(fnd => (
                <tr
                  key={fnd.id}
                  className="hover:bg-slate-850/50 transition-colors cursor-pointer group"
                  onClick={() => setSelectedFinding(fnd)}
                >
                  <td className="py-3 px-4 shrink-0">
                    <SeverityBadge severity={fnd.severity} />
                  </td>
                  <td className="py-3 px-4 max-w-sm">
                    <div className="font-medium text-slate-100 group-hover:text-cyan-300 transition-colors">
                      {fnd.title}
                    </div>
                    <div className="text-[11px] text-slate-400 truncate mt-0.5">
                      {fnd.cve && <span className="font-mono text-cyan-400 mr-1.5">{fnd.cve}</span>}
                      <span>{fnd.category.replace('_', ' ')}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-300 text-[11px] truncate max-w-40">
                    {fnd.target}
                  </td>
                  <td className="py-3 px-4">
                    <span className="font-mono text-slate-400 text-[11px]">{fnd.sourceTool}</span>
                  </td>
                  <td className="py-3 px-4" onClick={e => e.stopPropagation()}>
                    <select
                      value={fnd.status}
                      onChange={e => updateFindingStatus(fnd.id, e.target.value as FindingStatus)}
                      className={`text-xs py-1 px-2 rounded border bg-slate-950 focus:outline-hidden font-medium ${
                        fnd.status === 'open'
                          ? 'border-rose-900/60 text-rose-300'
                          : fnd.status === 'under_review'
                          ? 'border-amber-900/60 text-amber-300'
                          : fnd.status === 'mitigated'
                          ? 'border-emerald-900/60 text-emerald-300'
                          : 'border-slate-800 text-slate-400'
                      }`}
                    >
                      <option value="open">Open</option>
                      <option value="under_review">Under Review</option>
                      <option value="mitigated">Mitigated</option>
                      <option value="false_positive">False Positive</option>
                    </select>
                  </td>
                  <td className="py-3 px-4 text-right">
                    <button
                      onClick={() => setSelectedFinding(fnd)}
                      className="text-xs text-cyan-400 hover:text-cyan-300"
                    >
                      Details →
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filtered.length === 0 && (
          <div className="p-12 text-center text-xs text-slate-500">
            No findings match your search or filter settings.
          </div>
        )}
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <Modal
          isOpen={!!selectedFinding}
          onClose={() => setSelectedFinding(null)}
          title={selectedFinding.title}
          subtitle={`Category: ${selectedFinding.category.replace('_', ' ')} · Detected: ${formatDate(selectedFinding.detectedAt)}`}
          maxWidth="2xl"
        >
          <div className="space-y-4 text-xs">
            <div className="flex flex-wrap items-center gap-3 pb-2 border-b border-slate-800">
              <SeverityBadge severity={selectedFinding.severity} />
              <InteractionBadge type={selectedFinding.interactionType} />
              {selectedFinding.cvss && (
                <span className="font-mono text-xs text-slate-200">
                  CVSS Score: <strong className="text-cyan-400 font-semibold">{selectedFinding.cvss}</strong>
                </span>
              )}
              {selectedFinding.cve && (
                <span className="font-mono text-xs text-cyan-400 px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                  {selectedFinding.cve}
                </span>
              )}
            </div>

            <div>
              <span className="text-slate-400 block mb-1">Target Endpoint / Interface</span>
              <div className="p-2 bg-slate-950 border border-slate-800 rounded font-mono text-slate-200">
                {selectedFinding.target}
              </div>
            </div>

            <div>
              <span className="text-slate-400 block mb-1">Detailed Description</span>
              <p className="text-slate-300 leading-relaxed bg-slate-950/60 p-3 rounded border border-slate-800">
                {selectedFinding.description}
              </p>
            </div>

            <div>
              <span className="text-emerald-400 font-semibold block mb-1">Remediation Guidance</span>
              <p className="text-slate-200 leading-relaxed bg-emerald-950/20 border border-emerald-900/60 p-3 rounded">
                {selectedFinding.remediationAdvice}
              </p>
            </div>

            <div className="pt-2 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="text-slate-400">Change Status:</span>
                <select
                  value={selectedFinding.status}
                  onChange={e => {
                    const newStatus = e.target.value as FindingStatus;
                    updateFindingStatus(selectedFinding.id, newStatus);
                    setSelectedFinding({ ...selectedFinding, status: newStatus });
                  }}
                  className="bg-slate-950 border border-slate-700 text-slate-200 py-1 px-2 rounded text-xs"
                >
                  <option value="open">Open</option>
                  <option value="under_review">Under Review</option>
                  <option value="mitigated">Mitigated</option>
                  <option value="false_positive">False Positive</option>
                </select>
              </div>

              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs"
              >
                Close
              </button>
            </div>
          </div>
        </Modal>
      )}
    </div>
  );
};
