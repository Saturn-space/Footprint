import React, { useState } from 'react';
import { EntityGraph } from '../components/graph/EntityGraph';
import { useInvestigation } from '../context/InvestigationContext';
import { useAuth } from '../context/AuthContext';
import {
  Sparkles,
  Network,
  RotateCw,
  Download,
  Share2,
  FileSpreadsheet,
  Layers,
  CheckCircle2
} from 'lucide-react';

export const EntityGraphPage: React.FC = () => {
  const {
    entities,
    relationships,
    evidence,
    runCorrelation,
    exportGraphml
  } = useInvestigation();
  const { canReviewFindings } = useAuth();

  const [isCorrelating, setIsCorrelating] = useState(false);

  const handleCorrelation = async () => {
    setIsCorrelating(true);
    try {
      await runCorrelation();
    } finally {
      setIsCorrelating(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header and Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold text-slate-100">
              Entity Knowledge Graph & Correlation
            </h1>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 font-semibold">
              {entities.length} Nodes · {relationships.length} Links
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Multi-factor graph topology linking organizations, domains, subdomains, IP addresses, listening ports, services, and CVEs.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {canReviewFindings && (
            <button
              onClick={handleCorrelation}
              disabled={isCorrelating}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold text-slate-950 bg-gradient-to-r from-emerald-400 to-cyan-400 hover:from-emerald-300 hover:to-cyan-300 disabled:opacity-50 rounded shadow transition-all cursor-pointer"
            >
              <RotateCw className={`w-3.5 h-3.5 ${isCorrelating ? 'animate-spin' : ''}`} />
              <span>{isCorrelating ? 'Correlating Assets...' : 'Run Correlation Engine'}</span>
            </button>
          )}

          <button
            onClick={exportGraphml}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-slate-100 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors cursor-pointer"
            title="Export as GraphML XML for Gephi / Cytoscape"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export GraphML</span>
          </button>
        </div>
      </div>

      {/* Main Interactive Graph Component */}
      <EntityGraph
        entities={entities}
        relationships={relationships}
        evidenceList={evidence}
      />
    </div>
  );
};
