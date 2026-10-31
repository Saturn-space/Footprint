import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  FolderKanban,
  Plus,
  Search,
  CheckCircle2,
  Trash2,
  Calendar,
  Shield,
  FileText,
  Eye,
  Target
} from 'lucide-react';
import { useInvestigation } from '../context/InvestigationContext';
import { formatDate } from '../utils/formatters';
import { Modal } from '../components/common/Modal';
import { Investigation } from '../types/models';

export const InvestigationsPage: React.FC = () => {
  const navigate = useNavigate();
  const {
    investigations,
    activeInvestigation,
    selectInvestigation,
    deleteInvestigation
  } = useInvestigation();

  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'completed' | 'draft' | 'archived'>('all');
  const [selectedInvForModal, setSelectedInvForModal] = useState<Investigation | null>(null);

  const filtered = investigations.filter(inv => {
    const matchesSearch =
      inv.name.toLowerCase().includes(search.toLowerCase()) ||
      inv.organizationName.toLowerCase().includes(search.toLowerCase()) ||
      inv.scope.ownedDomains.some(d => d.toLowerCase().includes(search.toLowerCase()));

    const matchesStatus = statusFilter === 'all' || inv.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100">Reconnaissance Investigations</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Manage authorized OSINT cases, target scopes, and authorization lifecycles.
          </p>
        </div>

        <button
          onClick={() => navigate('/new-investigation')}
          className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors shrink-0"
        >
          <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
          <span>New Investigation</span>
        </button>
      </div>

      {/* Search and Filters Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 bg-slate-900 border border-slate-800 rounded-lg">
        <div className="relative flex-1 min-w-56">
          <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-400" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by case title, target domain, or organization..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-md text-slate-100 placeholder:text-slate-500 focus:border-cyan-500 focus:outline-hidden"
          />
        </div>

        {/* Filter Tabs */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-md border border-slate-800">
          {(['all', 'active', 'completed', 'archived'] as const).map(tab => (
            <button
              key={tab}
              onClick={() => setStatusFilter(tab)}
              className={`px-3 py-1 text-xs font-medium rounded transition-colors uppercase ${
                statusFilter === tab
                  ? 'bg-slate-800 text-cyan-300 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>
      </div>

      {/* Investigation Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered.map(inv => {
          const isActive = inv.id === activeInvestigation?.id;
          return (
            <div
              key={inv.id}
              className={`bg-slate-900 border rounded-lg p-5 flex flex-col justify-between transition-all ${
                isActive
                  ? 'border-cyan-500/80 shadow-lg shadow-cyan-950/20'
                  : 'border-slate-800 hover:border-slate-700'
              }`}
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400">
                    {inv.status}
                  </span>
                  {isActive && (
                    <span className="flex items-center gap-1 text-[11px] text-cyan-300 font-medium">
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" /> Active Context
                    </span>
                  )}
                </div>

                <h2 className="text-sm font-semibold text-slate-100 truncate">{inv.name}</h2>
                <div className="text-xs text-slate-400 mt-0.5">{inv.organizationName}</div>
                <p className="text-xs text-slate-300 mt-2 line-clamp-2 leading-relaxed">
                  {inv.description}
                </p>

                <div className="mt-4 pt-3 border-t border-slate-800/60 space-y-1.5 text-xs text-slate-400">
                  <div className="flex justify-between">
                    <span>Apex Domain:</span>
                    <span className="font-mono text-cyan-300">{inv.scope.ownedDomains.join(', ')}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Auth Ref:</span>
                    <span className="font-mono text-slate-300">{inv.authorization.authorizationReference}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Lead Investigator:</span>
                    <span className="text-slate-300 truncate max-w-40">{inv.leadInvestigator}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Created:</span>
                    <span className="font-mono text-[11px]">{formatDate(inv.createdAt)}</span>
                  </div>
                </div>
              </div>

              {/* Action buttons */}
              <div className="mt-5 pt-3 border-t border-slate-800/60 flex items-center justify-between gap-2">
                <button
                  onClick={() => setSelectedInvForModal(inv)}
                  className="px-2.5 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-950 border border-slate-800 rounded hover:bg-slate-800 transition-colors"
                >
                  View Scope
                </button>

                <div className="flex items-center gap-2">
                  {!isActive && (
                    <button
                      onClick={() => selectInvestigation(inv.id)}
                      className="px-2.5 py-1.5 text-xs font-medium text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
                    >
                      Set Active
                    </button>
                  )}
                  {investigations.length > 1 && (
                    <button
                      onClick={() => deleteInvestigation(inv.id)}
                      className="p-1.5 text-slate-500 hover:text-rose-400 transition-colors"
                      title="Delete Investigation"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div className="p-12 text-center bg-slate-900 border border-slate-800 rounded-lg text-slate-400">
          <FolderKanban className="w-8 h-8 mx-auto text-slate-600 mb-2" />
          <p className="text-xs">No investigations matching your criteria.</p>
        </div>
      )}

      {/* Scope Details Modal */}
      {selectedInvForModal && (
        <Modal
          isOpen={!!selectedInvForModal}
          onClose={() => setSelectedInvForModal(null)}
          title={`Investigation Dossier: ${selectedInvForModal.name}`}
          subtitle={selectedInvForModal.organizationName}
          maxWidth="2xl"
        >
          <div className="space-y-4 text-xs">
            <div>
              <span className="text-slate-400 block mb-1">Reconnaissance Scope & Targets</span>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-2">
                <div>
                  <strong className="text-slate-200">Owned Domains: </strong>
                  <span className="font-mono text-cyan-300">
                    {selectedInvForModal.scope.ownedDomains.join(', ')}
                  </span>
                </div>
                <div>
                  <strong className="text-slate-200">Approved Subnets: </strong>
                  <span className="font-mono text-slate-300">
                    {selectedInvForModal.scope.approvedCIDRs.join(', ') || 'None specified'}
                  </span>
                </div>
                <div>
                  <strong className="text-slate-200">Active Scanning Allowlist: </strong>
                  <span className="font-mono text-amber-300">
                    {selectedInvForModal.scope.activeTargets.join(', ') || 'No active targets allowed'}
                  </span>
                </div>
                <div>
                  <strong className="text-slate-200">Excluded Targets: </strong>
                  <span className="font-mono text-rose-300">
                    {selectedInvForModal.scope.excludedTargets.join(', ') || 'None'}
                  </span>
                </div>
              </div>
            </div>

            <div>
              <span className="text-slate-400 block mb-1">Authorization Attestation</span>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-1.5">
                <div>
                  <strong className="text-slate-200">Approved By: </strong>
                  <span>{selectedInvForModal.authorization.approvedBy}</span>
                </div>
                <div>
                  <strong className="text-slate-200">Reference: </strong>
                  <span className="font-mono text-cyan-400">
                    {selectedInvForModal.authorization.authorizationReference}
                  </span>
                </div>
                <div>
                  <strong className="text-slate-200">Active Reconnaissance Enabled: </strong>
                  <span
                    className={
                      selectedInvForModal.authorization.activeScanningEnabled
                        ? 'text-amber-400 font-semibold'
                        : 'text-slate-400'
                    }
                  >
                    {selectedInvForModal.authorization.activeScanningEnabled ? 'YES' : 'NO'}
                  </span>
                </div>
                <div>
                  <strong className="text-slate-200">Rules of Engagement: </strong>
                  <span className="text-emerald-400">Confirmed & Signed</span>
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedInvForModal(null)}
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
