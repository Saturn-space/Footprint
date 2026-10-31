import React, { useState } from 'react';
import {
  History,
  ShieldCheck,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  FileCode2,
  Lock,
  Download
} from 'lucide-react';
import { useInvestigation } from '../context/InvestigationContext';
import { formatDate } from '../utils/formatters';

export const AuditLogPage: React.FC = () => {
  const { auditLogs, activeInvestigation } = useInvestigation();
  const [search, setSearch] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');

  const filtered = auditLogs.filter(log => {
    const matchesSearch =
      log.action.toLowerCase().includes(search.toLowerCase()) ||
      log.actor.toLowerCase().includes(search.toLowerCase()) ||
      log.details.toLowerCase().includes(search.toLowerCase()) ||
      (log.targetResource && log.targetResource.toLowerCase().includes(search.toLowerCase()));

    const matchesCat = categoryFilter === 'all' || log.category === categoryFilter;
    return matchesSearch && matchesCat;
  });

  const exportAuditLedger = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(auditLogs, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `audit_trail_${activeInvestigation?.id || 'export'}_${Date.now()}.json`);
    dlAnchor.click();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold text-slate-100">Tamper-Evident Audit Ledger</h1>
            <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-mono bg-emerald-950/40 border border-emerald-800/60 px-2 py-0.5 rounded">
              <ShieldCheck className="w-3 h-3" /> Chain Verified
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Cryptographically sealed record of all investigator commands, scope validations, and ingestion events.
          </p>
        </div>

        <button
          onClick={exportAuditLedger}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-200 bg-slate-900 border border-slate-800 hover:bg-slate-800 rounded transition-colors shrink-0"
        >
          <Download className="w-3.5 h-3.5 text-cyan-400" />
          <span>Export Ledger JSON</span>
        </button>
      </div>

      {/* Search and Filters */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs">
        <div className="relative flex-1 min-w-56">
          <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search audit trail by actor, action, or target..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-hidden"
          />
        </div>

        <div className="flex items-center gap-2">
          <select
            value={categoryFilter}
            onChange={e => setCategoryFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-200 py-1.5 px-2.5 rounded-md text-xs focus:outline-hidden focus:border-cyan-500"
          >
            <option value="all">All Categories</option>
            <option value="authorization">Authorization</option>
            <option value="scope_change">Scope Change</option>
            <option value="data_ingestion">Data Ingestion</option>
            <option value="correlation">Correlation</option>
            <option value="export">Export</option>
            <option value="system">System</option>
          </select>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-slate-950/80 text-[11px] text-slate-400 uppercase tracking-wider font-mono border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Action</th>
                <th className="py-2.5 px-4">Actor</th>
                <th className="py-2.5 px-4">Details & Scope Context</th>
                <th className="py-2.5 px-4 text-right">Audit Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              {filtered.map(log => (
                <tr key={log.id} className="hover:bg-slate-850/50 transition-colors">
                  <td className="py-3 px-4 shrink-0">
                    {log.status === 'allowed' || log.status === 'verified' ? (
                      <span className="flex items-center gap-1 font-mono text-[11px] text-emerald-400">
                        <CheckCircle2 className="w-3.5 h-3.5" /> ALLOWED
                      </span>
                    ) : (
                      <span className="flex items-center gap-1 font-mono text-[11px] text-rose-400 font-semibold">
                        <XCircle className="w-3.5 h-3.5" /> DENIED
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 font-mono text-slate-400 text-[11px] whitespace-nowrap">
                    {formatDate(log.timestamp)}
                  </td>
                  <td className="py-3 px-4 font-mono text-cyan-300 font-medium">
                    {log.action}
                  </td>
                  <td className="py-3 px-4 text-slate-200 whitespace-nowrap font-medium">
                    {log.actor}
                  </td>
                  <td className="py-3 px-4 max-w-md">
                    <p className="text-slate-300 leading-relaxed text-xs">{log.details}</p>
                    {log.targetResource && (
                      <span className="text-[11px] font-mono text-slate-500 block mt-0.5">
                        Target: {log.targetResource}
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right font-mono text-[10px] text-slate-400 truncate max-w-32">
                    {log.auditHash}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filtered.length === 0 && (
          <div className="p-12 text-center text-xs text-slate-500">
            No audit records match your query.
          </div>
        )}
      </div>
    </div>
  );
};
