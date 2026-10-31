import React from 'react';
import { X, ExternalLink, ShieldCheck, Link2, FileText, Activity } from 'lucide-react';
import { Entity, Relationship, Evidence } from '../../types/models';
import { formatDate } from '../../utils/formatters';

interface NodeDetailDrawerProps {
  entity: Entity | null;
  relationships: Relationship[];
  allEntities: Entity[];
  evidenceList: Evidence[];
  onClose: () => void;
  onSelectEntity: (entityId: string) => void;
}

export const NodeDetailDrawer: React.FC<NodeDetailDrawerProps> = ({
  entity,
  relationships,
  allEntities,
  evidenceList,
  onClose,
  onSelectEntity
}) => {
  if (!entity) return null;

  // Filter incoming and outgoing relationships
  const outgoing = relationships.filter(r => r.sourceEntityId === entity.id);
  const incoming = relationships.filter(r => r.targetEntityId === entity.id);

  // Filter linked evidence
  const linkedEvidence = evidenceList.filter(ev =>
    entity.sourceEvidenceIds.includes(ev.id)
  );

  const getEntityName = (id: string): string => {
    const found = allEntities.find(e => e.id === id);
    return found ? `${found.name} (${found.type})` : id;
  };

  return (
    <div className="w-80 sm:w-96 bg-slate-900 border-l border-slate-800 h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
      {/* Drawer Header */}
      <div className="p-4 border-b border-slate-800 bg-slate-950/60 flex items-start justify-between gap-3">
        <div>
          <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400">
            {entity.type} Entity
          </span>
          <h2 className="text-sm font-semibold text-slate-100 mt-0.5 break-all">
            {entity.name}
          </h2>
          <div className="text-xs font-mono text-slate-400 break-all">{entity.primaryValue}</div>
        </div>
        <button
          onClick={onClose}
          className="p-1 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors"
          aria-label="Close entity detail drawer"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Drawer Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-5 text-xs text-slate-300">
        {/* Confidence & Verification Status */}
        <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg flex items-center justify-between">
          <div>
            <span className="text-slate-400 block text-[11px]">Recon Confidence</span>
            <span className="text-sm font-semibold font-mono text-emerald-400 tabular-nums">
              {(entity.confidence * 100).toFixed(0)}%
            </span>
          </div>
          <div className="text-right">
            <span className="text-slate-400 block text-[11px]">Discovered</span>
            <span className="text-[11px] font-mono text-slate-300">
              {formatDate(entity.firstDiscoveredAt)}
            </span>
          </div>
        </div>

        {/* Metadata Attributes */}
        <div>
          <h3 className="text-xs font-semibold text-slate-200 mb-2 flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>Attributes & Metadata</span>
          </h3>
          <div className="bg-slate-950/40 border border-slate-800/80 rounded-md p-2.5 divide-y divide-slate-800/40 font-mono text-[11px]">
            {Object.entries(entity.metadata).map(([key, val]) => (
              <div key={key} className="py-1.5 flex justify-between gap-2">
                <span className="text-slate-400 capitalize">{key}:</span>
                <span className="text-slate-200 truncate max-w-48 text-right font-medium">
                  {String(val)}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Outgoing & Incoming Graph Relationships */}
        <div>
          <h3 className="text-xs font-semibold text-slate-200 mb-2 flex items-center gap-1.5">
            <Link2 className="w-3.5 h-3.5 text-cyan-400" />
            <span>Correlated Relationships ({outgoing.length + incoming.length})</span>
          </h3>
          <div className="space-y-2">
            {outgoing.map(rel => (
              <button
                key={rel.id}
                onClick={() => onSelectEntity(rel.targetEntityId)}
                className="w-full text-left p-2 rounded bg-slate-950/60 border border-slate-800 hover:border-cyan-800 hover:bg-slate-850 transition-colors"
              >
                <div className="flex items-center justify-between text-[11px] text-cyan-400 font-mono">
                  <span>→ {rel.type}</span>
                  <span className="text-slate-400">{(rel.confidence * 100).toFixed(0)}%</span>
                </div>
                <div className="text-xs text-slate-200 truncate mt-0.5">
                  {getEntityName(rel.targetEntityId)}
                </div>
              </button>
            ))}

            {incoming.map(rel => (
              <button
                key={rel.id}
                onClick={() => onSelectEntity(rel.sourceEntityId)}
                className="w-full text-left p-2 rounded bg-slate-950/60 border border-slate-800 hover:border-cyan-800 hover:bg-slate-850 transition-colors"
              >
                <div className="flex items-center justify-between text-[11px] text-emerald-400 font-mono">
                  <span>← {rel.type}</span>
                  <span className="text-slate-400">{(rel.confidence * 100).toFixed(0)}%</span>
                </div>
                <div className="text-xs text-slate-200 truncate mt-0.5">
                  {getEntityName(rel.sourceEntityId)}
                </div>
              </button>
            ))}

            {outgoing.length === 0 && incoming.length === 0 && (
              <p className="text-[11px] text-slate-400 italic">No direct links discovered yet.</p>
            )}
          </div>
        </div>

        {/* Source Evidence */}
        <div>
          <h3 className="text-xs font-semibold text-slate-200 mb-2 flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>Supporting Evidence Records ({linkedEvidence.length})</span>
          </h3>
          <div className="space-y-2">
            {linkedEvidence.map(ev => (
              <div key={ev.id} className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
                <div className="flex items-center justify-between gap-1 text-[11px]">
                  <span className="font-mono text-cyan-300">{ev.sourceTool}</span>
                  <span className="font-mono text-[10px] text-slate-400 uppercase">{ev.interactionType}</span>
                </div>
                <p className="text-xs text-slate-300 mt-1 leading-snug">{ev.value}</p>
                <div className="mt-1.5 text-[10px] text-slate-400 font-mono truncate">
                  Hash: {ev.evidenceHash}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
