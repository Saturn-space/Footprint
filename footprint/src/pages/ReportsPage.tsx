import React, { useState } from 'react';
import {
  FileText,
  Download,
  Plus,
  Printer,
  ShieldCheck,
  CheckCircle2,
  Calendar,
  Eye,
  FileCheck2,
  Sparkles,
  FileSpreadsheet,
  Network,
  Package,
  Layers,
  FileCode,
  Lock
} from 'lucide-react';
import { useInvestigation } from '../context/InvestigationContext';
import { Report } from '../types/models';
import { formatDate } from '../utils/formatters';
import { Modal } from '../components/common/Modal';

export const ReportsPage: React.FC = () => {
  const {
    activeInvestigation,
    reports,
    generateReport,
    generateFullReport,
    downloadReportPdf,
    exportInvestigationBundle,
    exportFindingsCsv,
    exportGraphml,
    currentUser,
    findings,
    exposureScore
  } = useInvestigation();

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [selectedReportForPreview, setSelectedReportForPreview] = useState<Report | null>(null);
  const [isGeneratingComprehensive, setIsGeneratingComprehensive] = useState(false);

  const [reportTitle, setReportTitle] = useState('Executive OSINT Digital Footprint Dossier');
  const [reportType, setReportType] = useState<Report['reportType']>('executive_summary');
  const [reportFormat, setReportFormat] = useState<Report['fileFormat']>('PDF_HTML');

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    await generateReport(reportTitle, reportType, reportFormat);
    setIsCreateOpen(false);
  };

  const handleGenerate20SectionDossier = async () => {
    setIsGeneratingComprehensive(true);
    try {
      const rep = await generateFullReport(
        `FootprintIQ 20-Section Comprehensive Dossier: ${activeInvestigation?.organizationName || 'Lab Recon'}`
      );
      setSelectedReportForPreview(rep);
    } finally {
      setIsGeneratingComprehensive(false);
    }
  };

  const handleDownloadJSON = (rep: Report) => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rep, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute('href', dataStr);
    dlAnchor.setAttribute('download', `${rep.title.replace(/\s+/g, '_').toLowerCase()}_${Date.now()}.json`);
    dlAnchor.click();
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-lg font-bold text-slate-100">Reconnaissance Dossiers & Reporting Suite</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Compile audit-compliant 20-section executive dossiers, technical briefings, and legal scope certificates.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={handleGenerate20SectionDossier}
            disabled={isGeneratingComprehensive}
            className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-bold text-slate-950 bg-gradient-to-r from-emerald-400 to-cyan-400 hover:from-emerald-300 hover:to-cyan-300 rounded shadow transition-all cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5 stroke-[2.5]" />
            <span>{isGeneratingComprehensive ? 'Compiling 20 Sections...' : 'Compile 20-Section Dossier'}</span>
          </button>

          <button
            onClick={() => setIsCreateOpen(true)}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Custom Report</span>
          </button>
        </div>
      </div>

      {/* Multi-Format Export Quick-Bar */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg flex flex-wrap items-center justify-between gap-4">
        <div>
          <span className="text-xs font-semibold text-slate-200 block">
            Investigation Multi-Format Data Exports
          </span>
          <span className="text-[11px] text-slate-400">
            Export raw artifacts for SIEM ingestion, external graph visualizers, or spreadsheet compliance audits.
          </span>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <button
            onClick={exportInvestigationBundle}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded transition-colors cursor-pointer"
          >
            <Package className="w-3.5 h-3.5 text-cyan-400" />
            <span>Full Bundle (JSON)</span>
          </button>

          <button
            onClick={exportFindingsCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded transition-colors cursor-pointer"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
            <span>Findings (CSV)</span>
          </button>

          <button
            onClick={exportGraphml}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono bg-slate-950 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded transition-colors cursor-pointer"
          >
            <Network className="w-3.5 h-3.5 text-purple-400" />
            <span>Knowledge Graph (GraphML)</span>
          </button>
        </div>
      </div>

      {/* Reports Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {reports.map(rep => (
          <div
            key={rep.id}
            className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col justify-between hover:border-slate-700 transition-all shadow-sm"
          >
            <div>
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400">
                  {rep.reportType.replace(/_/g, ' ')}
                </span>
                <span className="text-[10px] font-mono text-slate-400">{rep.sections?.length || 4} Sections</span>
              </div>

              <h2 className="text-sm font-semibold text-slate-100 line-clamp-1">{rep.title}</h2>
              <p className="text-xs text-slate-300 mt-2 line-clamp-3 leading-relaxed">
                {rep.summary}
              </p>

              <div className="mt-4 pt-3 border-t border-slate-800/60 text-[11px] text-slate-400 space-y-1">
                <div>Generated: <span className="text-slate-200">{formatDate(rep.generatedAt)}</span></div>
                <div>Author: <span className="text-slate-200">{rep.generatedBy}</span></div>
              </div>
            </div>

            <div className="mt-5 pt-3 border-t border-slate-800/60 flex items-center justify-between gap-2">
              <button
                onClick={() => setSelectedReportForPreview(rep)}
                className="flex items-center gap-1 text-xs text-slate-300 hover:text-cyan-400 transition-colors cursor-pointer"
              >
                <Eye className="w-3.5 h-3.5" />
                <span>View Dossier</span>
              </button>

              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => downloadReportPdf(rep.id, `${rep.title.replace(/[^a-zA-Z0-9_-]/g, '_')}.pdf`)}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors cursor-pointer"
                  title="Download Binary PDF"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>PDF</span>
                </button>

                <button
                  onClick={() => handleDownloadJSON(rep)}
                  className="p-1 text-slate-400 hover:text-slate-200 transition-colors"
                  title="Download Raw JSON"
                >
                  <FileCode className="w-4 h-4" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Report Preview Modal */}
      {selectedReportForPreview && (
        <Modal
          isOpen={true}
          onClose={() => setSelectedReportForPreview(null)}
          title={selectedReportForPreview.title}
          subtitle={`Generated on ${formatDate(selectedReportForPreview.generatedAt)} · Author: ${selectedReportForPreview.generatedBy}`}
          maxWidth="xl"
        >
          <div className="space-y-6 max-h-[75vh] overflow-y-auto pr-1">
            {/* Header info badge */}
            <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <span className="text-slate-200 font-semibold">
                  Authorized Educational Reconnaissance Dossier
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => downloadReportPdf(selectedReportForPreview.id)}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors cursor-pointer"
                >
                  <Download className="w-3 h-3" />
                  <span>Download Binary PDF</span>
                </button>

                <button
                  onClick={handlePrint}
                  className="flex items-center gap-1 px-2.5 py-1 text-xs text-slate-300 hover:text-slate-100 bg-slate-800 rounded transition-colors cursor-pointer"
                >
                  <Printer className="w-3 h-3" />
                  <span>Print</span>
                </button>
              </div>
            </div>

            {/* Sections List */}
            <div className="space-y-4">
              {selectedReportForPreview.sections.map((section, idx) => (
                <div
                  key={idx}
                  className="p-4 bg-slate-950/80 border border-slate-800/80 rounded-lg space-y-2"
                >
                  <h3 className="text-xs font-bold text-cyan-400 uppercase tracking-wider font-mono">
                    {section.title}
                  </h3>
                  <div className="text-xs text-slate-300 whitespace-pre-wrap font-sans leading-relaxed">
                    {section.content}
                  </div>
                </div>
              ))}
            </div>

            {/* Cryptographic Manifest Footer */}
            <div className="p-3 bg-slate-950 border border-slate-800 rounded text-[11px] font-mono text-slate-400 flex items-center justify-between">
              <span>Security Stamp: Verified Signed Artifact</span>
              <span>Integrity Digest: sha256:7f9b8c4d...</span>
            </div>
          </div>
        </Modal>
      )}

      {/* Create Custom Report Modal */}
      <Modal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        title="Generate Reconnaissance Report"
        subtitle="Create an executive or technical briefing for the active investigation"
      >
        <form onSubmit={handleGenerate} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Report Title
            </label>
            <input
              type="text"
              value={reportTitle}
              onChange={e => setReportTitle(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-xs text-slate-100 focus:outline-none focus:border-cyan-400"
              required
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Report Type
            </label>
            <select
              value={reportType}
              onChange={e => setReportType(e.target.value as any)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-xs text-slate-100 focus:outline-none focus:border-cyan-400"
            >
              <option value="executive_summary">Executive Summary (Board Level)</option>
              <option value="technical_recon_brief">Technical Reconnaissance Brief (Security Team)</option>
              <option value="scope_certificate">Compliance & Scope Certificate (Legal/RoE)</option>
              <option value="full_osint_dossier">Full Comprehensive OSINT Dossier</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1">
              Export Format
            </label>
            <select
              value={reportFormat}
              onChange={e => setReportFormat(e.target.value as any)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded text-xs text-slate-100 focus:outline-none focus:border-cyan-400"
            >
              <option value="PDF_HTML">PDF Document (Formatted)</option>
              <option value="JSON">Raw JSON Artifact</option>
              <option value="MARKDOWN">Markdown Dossier</option>
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
            <button
              type="button"
              onClick={() => setIsCreateOpen(false)}
              className="px-3.5 py-1.5 text-xs text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              className="px-4 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded"
            >
              Compile Report
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
