import React, { useState } from 'react';
import {
  Globe,
  Radio,
  FileSearch,
  Mail,
  Plus,
  CheckCircle2,
  AlertCircle,
  Hash,
  Search,
  Filter,
  ArrowUpRight,
  Upload,
  Lock,
  Clock
} from 'lucide-react';
import { useInvestigation } from '../context/InvestigationContext';
import { useAuth } from '../context/AuthContext';
import { Evidence } from '../types/models';
import { InteractionBadge, ValidationBadge } from '../components/common/Badge';
import { formatDate } from '../utils/formatters';
import { AccessDeniedBanner } from '../components/auth/AccessDeniedBanner';
import { AuthSwitchModal } from '../components/auth/AuthSwitchModal';

export const PassiveReconPage: React.FC = () => {
  const {
    activeInvestigation,
    evidence,
    triggerRDAPCollection,
    triggerDNSCollection,
    importHarvesterDump,
    addManualEvidenceRecord,
    addNotification,
    isServerConnected
  } = useInvestigation();

  const { canCollectPassiveData } = useAuth();
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<'rdap' | 'dns' | 'harvester' | 'search' | 'evidence_list'>('rdap');

  // Interactive collector states
  const [whoisQueryDomain, setWhoisQueryDomain] = useState(
    activeInvestigation?.scope.ownedDomains[0] || 'lab.example'
  );
  const [whoisResult, setWhoisResult] = useState<any | null>(null);
  const [isQueryingWhois, setIsQueryingWhois] = useState(false);
  const [whoisError, setWhoisError] = useState<string | null>(null);

  const [dnsQueryDomain, setDnsQueryDomain] = useState(
    activeInvestigation?.scope.ownedDomains[0] || 'lab.example'
  );
  const [dnsResult, setDnsResult] = useState<any | null>(null);
  const [isQueryingDns, setIsQueryingDns] = useState(false);
  const [dnsError, setDnsError] = useState<string | null>(null);

  // theHarvester state
  const [harvesterInput, setHarvesterInput] = useState('');
  const [isImportingHarvester, setIsImportingHarvester] = useState(false);
  const [harvesterSummary, setHarvesterSummary] = useState<any | null>(null);

  // Search evidence logger
  const [searchDocTitle, setSearchDocTitle] = useState('');
  const [searchDocUrl, setSearchDocUrl] = useState('');
  const [searchDocSnippet, setSearchDocSnippet] = useState('');
  const [searchConfidence, setSearchConfidence] = useState(0.85);
  const [isLoggingSearch, setIsLoggingSearch] = useState(false);

  // Passive evidence filter
  const passiveEvidenceList = evidence.filter(e => e.interactionType === 'passive');

  // Handle server RDAP collection
  const handleQueryWhois = async () => {
    setIsQueryingWhois(true);
    setWhoisError(null);
    try {
      const data = await triggerRDAPCollection(whoisQueryDomain);
      setWhoisResult(data.rdap);
    } catch (err: any) {
      setWhoisError(err.message || 'RDAP query failed');
    } finally {
      setIsQueryingWhois(false);
    }
  };

  // Handle server DNS collection
  const handleQueryDns = async () => {
    setIsQueryingDns(true);
    setDnsError(null);
    try {
      const data = await triggerDNSCollection(dnsQueryDomain);
      setDnsResult(data.dns);
    } catch (err: any) {
      setDnsError(err.message || 'DNS resolution failed');
    } finally {
      setIsQueryingDns(false);
    }
  };

  // Handle theHarvester import
  const handleImportHarvester = async () => {
    if (!harvesterInput.trim()) return;
    setIsImportingHarvester(true);
    try {
      const res = await importHarvesterDump(harvesterInput, 'harvester_export.json');
      setHarvesterSummary(res.summary);
    } catch (err: any) {
      addNotification('error', 'Import Failed', err.message);
    } finally {
      setIsImportingHarvester(false);
    }
  };

  const handleLoadSampleHarvester = () => {
    const sample = {
      target: activeInvestigation?.scope.ownedDomains[0] || 'lab.example',
      emails: ['elena.rostova@lab.example', 'm.vance@lab.example', 'devops@lab.example'],
      hosts: ['research.lab.example', 'auth.lab.example', 'vpn.lab.example'],
      ips: ['192.168.56.102'],
      sources: ['google', 'bing', 'crtsh']
    };
    setHarvesterInput(JSON.stringify(sample, null, 2));
  };

  // Handle manual search evidence add
  const handleAddSearchEvidence = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchDocTitle || !searchDocUrl) return;

    setIsLoggingSearch(true);
    try {
      await addManualEvidenceRecord({
        searchQuery: 'Internal Documentation',
        resultTitle: searchDocTitle,
        resultUrl: searchDocUrl,
        observation: searchDocSnippet,
        collectionTime: new Date().toISOString(),
        confidence: searchConfidence,
        reviewerStatus: 'unreviewed'
      });

      setSearchDocTitle('');
      setSearchDocUrl('');
      setSearchDocSnippet('');
    } catch (err: any) {
      addNotification('error', 'Logging Failed', err.message);
    } finally {
      setIsLoggingSearch(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-bold text-slate-100">Passive OSINT Reconnaissance</h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Non-intrusive footprint discovery via RDAP, WHOIS, authoritative DNS, search indices, and imported OSINT dossiers.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-[11px] font-mono text-slate-400">
            Collector Engine: <strong className="text-emerald-400">{isServerConnected ? 'Server Node.js' : 'Local Fallback'}</strong>
          </span>
        </div>
      </div>

      {/* Access Denied Warning for Viewers */}
      {!canCollectPassiveData && (
        <AccessDeniedBanner
          requiredRoles={['admin', 'investigator']}
          actionDescription="Triggering passive recon collectors or importing new OSINT dumps"
          onOpenSwitcher={() => setIsAuthModalOpen(true)}
        />
      )}

      {/* Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-2">
        {[
          { key: 'rdap', label: 'RDAP / WHOIS', icon: Globe },
          { key: 'dns', label: 'DNS Telemetry', icon: Radio },
          { key: 'harvester', label: 'theHarvester Import', icon: Mail },
          { key: 'search', label: 'Search Evidence Logger', icon: FileSearch },
          { key: 'evidence_list', label: `Passive Evidence (${passiveEvidenceList.length})`, icon: Hash }
        ].map(tab => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key as any)}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                activeTab === tab.key
                  ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 shadow-xs'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* TAB 1: RDAP / WHOIS */}
      {activeTab === 'rdap' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">RDAP Domain Lookup</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Queries registry authorities without sending probe packets to the target server.
              </p>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Target Apex Domain</label>
              <input
                type="text"
                value={whoisQueryDomain}
                onChange={e => setWhoisQueryDomain(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded font-mono text-cyan-300 focus:border-cyan-500 focus:outline-hidden"
              />
            </div>

            <button
              onClick={handleQueryWhois}
              disabled={isQueryingWhois || !canCollectPassiveData}
              className="w-full py-2 px-3 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors disabled:opacity-50"
            >
              {isQueryingWhois ? 'Executing Server RDAP Query...' : 'Execute Passive RDAP Query'}
            </button>

            {whoisError && (
              <div className="p-3 rounded bg-rose-950/40 border border-rose-800/80 text-xs text-rose-300">
                {whoisError}
              </div>
            )}

            <div className="text-[11px] text-slate-400 space-y-1 pt-2 border-t border-slate-800">
              <div>• Protocol: Registration Data Access Protocol (RFC 7480)</div>
              <div>• Rate Limit: 10 queries/minute (Server-enforced token bucket)</div>
              <div>• Cache TTL: 60 minutes</div>
            </div>
          </div>

          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h2 className="text-sm font-semibold text-slate-100 mb-3">RDAP Query Output</h2>
            {whoisResult ? (
              <div className="space-y-4 text-xs font-mono">
                <div className="p-3 bg-slate-950 border border-slate-800 rounded grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <span className="text-slate-400 block text-[11px]">Domain:</span>
                    <span className="text-cyan-300">{whoisResult.domain}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Registrar:</span>
                    <span className="text-slate-200">{whoisResult.registrar} (IANA ID: {whoisResult.ianaId || 'N/A'})</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Registrant Org:</span>
                    <span className="text-slate-200">{whoisResult.registrantOrg || 'REDACTED FOR PRIVACY'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Registration Date:</span>
                    <span className="text-slate-300">{formatDate(whoisResult.registrationDate || '')}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">Nameservers:</span>
                    <span className="text-slate-300">{whoisResult.nameservers?.join(', ') || 'None published'}</span>
                  </div>
                  <div>
                    <span className="text-slate-400 block text-[11px]">DNSSEC:</span>
                    <span className="text-amber-400">{whoisResult.dnssec || 'unsigned'}</span>
                  </div>
                </div>

                <div className="p-3 bg-slate-950/80 border border-slate-800 rounded text-slate-400 text-[11px]">
                  <span className="text-emerald-400 font-semibold">✓ Ingested into Evidence: </span>
                  Record committed to the investigation audit trail with verifiable cryptographic hash.
                </div>
              </div>
            ) : (
              <div className="p-12 text-center text-xs text-slate-500">
                Execute a passive RDAP query to inspect registration and authoritative delegation details.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: DNS Telemetry */}
      {activeTab === 'dns' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">DNS Zone Reconnaissance</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Resolves public authoritative records (A, AAAA, MX, NS, TXT/SPF, DMARC) using Node.js DNS promises API.
              </p>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Target Domain</label>
              <input
                type="text"
                value={dnsQueryDomain}
                onChange={e => setDnsQueryDomain(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded font-mono text-cyan-300 focus:border-cyan-500 focus:outline-hidden"
              />
            </div>

            <button
              onClick={handleQueryDns}
              disabled={isQueryingDns || !canCollectPassiveData}
              className="w-full py-2 px-3 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors disabled:opacity-50"
            >
              {isQueryingDns ? 'Querying Resolvers...' : 'Resolve Authoritative Records'}
            </button>

            {dnsError && (
              <div className="p-3 rounded bg-rose-950/40 border border-rose-800/80 text-xs text-rose-300">
                {dnsError}
              </div>
            )}
          </div>

          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h2 className="text-sm font-semibold text-slate-100 mb-3">Discovered DNS Records</h2>
            {dnsResult ? (
              <div className="space-y-4 text-xs">
                <div className="p-3 bg-slate-950 border border-slate-800 rounded space-y-3 font-mono">
                  <div>
                    <span className="text-slate-400 block text-[11px] mb-1">Resolved Resource Records ({dnsResult.records.length}):</span>
                    {dnsResult.records.map((r: any, idx: number) => (
                      <div key={idx} className="flex justify-between py-1 border-b border-slate-900">
                        <span className="text-cyan-400 font-semibold">{r.type}</span>
                        <span className="text-slate-200 truncate max-w-sm">{r.value}</span>
                        <span className="text-slate-500 text-[10px]">{r.ttl ? `${r.ttl}s` : ''}</span>
                      </div>
                    ))}
                  </div>

                  {dnsResult.dmarcAudit && (
                    <div className="pt-2 border-t border-slate-800">
                      <span className="text-amber-400 font-semibold block text-[11px]">DMARC Policy Check:</span>
                      <span className="text-slate-300">{dnsResult.dmarcAudit.recommendation}</span>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="p-12 text-center text-xs text-slate-500">
                Click "Resolve Authoritative Records" to query DNS records for the lab target.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: theHarvester Import */}
      {activeTab === 'harvester' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">theHarvester OSINT Ingestion Engine</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Ingest reconnaissance data exports containing harvested public emails, subdomains, and employee names.
              </p>
            </div>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-950/40 border border-cyan-800/60 text-cyan-300">
              Format: JSON / XML
            </span>
          </div>

          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <label className="text-xs text-slate-400">Export Payload (JSON or XML)</label>
              <button
                type="button"
                onClick={handleLoadSampleHarvester}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium"
              >
                Load Sample OSINT Payload
              </button>
            </div>

            <textarea
              rows={6}
              value={harvesterInput}
              onChange={e => setHarvesterInput(e.target.value)}
              placeholder="Paste JSON or XML from theHarvester export..."
              className="w-full p-2.5 text-xs font-mono bg-slate-950 border border-slate-800 rounded text-slate-200 focus:border-cyan-500 focus:outline-hidden"
            />

            <button
              onClick={handleImportHarvester}
              disabled={isImportingHarvester || !harvesterInput.trim() || !canCollectPassiveData}
              className="px-4 py-2 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors disabled:opacity-50 flex items-center gap-1.5"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>{isImportingHarvester ? 'Validating & Normalizing...' : 'Import & Correlate OSINT Dump'}</span>
            </button>
          </div>

          {harvesterSummary && (
            <div className="p-4 bg-emerald-950/20 border border-emerald-800/80 rounded-lg text-xs space-y-2">
              <div className="font-semibold text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4" /> Ingestion Completed
              </div>
              <div className="grid grid-cols-3 gap-2 font-mono text-slate-300 text-[11px]">
                <div>Emails: {harvesterSummary.emailsExtracted}</div>
                <div>Hosts: {harvesterSummary.hostsExtracted}</div>
                <div>Graph Entities: {harvesterSummary.entitiesAdded}</div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: Search Evidence Logger */}
      {activeTab === 'search' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <form onSubmit={handleAddSearchEvidence} className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Log Search Engine Evidence</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Record public search engine disclosures (Google Dorks, leaked documents, cached pastes).
              </p>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Document / Finding Title</label>
              <input
                type="text"
                required
                value={searchDocTitle}
                onChange={e => setSearchDocTitle(e.target.value)}
                placeholder="e.g. Lab Architecture Whitepaper PDF"
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-100 focus:border-cyan-500 focus:outline-hidden"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Target URL / Source</label>
              <input
                type="url"
                required
                value={searchDocUrl}
                onChange={e => setSearchDocUrl(e.target.value)}
                placeholder="https://lab.example/docs/paper.pdf"
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded font-mono text-slate-200 focus:border-cyan-500 focus:outline-hidden"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Snippet / Disclosed Content</label>
              <textarea
                rows={3}
                value={searchDocSnippet}
                onChange={e => setSearchDocSnippet(e.target.value)}
                placeholder="Disclosed employee names, internal subnets, credentials..."
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-100 focus:border-cyan-500 focus:outline-hidden"
              />
            </div>

            <div>
              <div className="flex justify-between text-xs text-slate-300 mb-1">
                <span>Confidence Rating:</span>
                <span className="font-mono text-cyan-400">{(searchConfidence * 100).toFixed(0)}%</span>
              </div>
              <input
                type="range"
                min="0.1"
                max="1.0"
                step="0.05"
                value={searchConfidence}
                onChange={e => setSearchConfidence(parseFloat(e.target.value))}
                className="w-full accent-cyan-400 cursor-pointer"
              />
            </div>

            <button
              type="submit"
              disabled={isLoggingSearch || !canCollectPassiveData}
              className="w-full py-2 px-3 text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors disabled:opacity-50"
            >
              {isLoggingSearch ? 'Cataloging on Server...' : 'Catalog Search Evidence'}
            </button>
          </form>

          <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-5">
            <h2 className="text-sm font-semibold text-slate-100 mb-3">Logged Search Evidence</h2>
            <div className="space-y-3">
              {evidence
                .filter(e => e.sourceTool.toLowerCase().includes('search'))
                .map(ev => (
                  <div key={ev.id} className="p-3 bg-slate-950 border border-slate-800 rounded text-xs">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-medium text-cyan-300">{ev.value}</span>
                      <span className="font-mono text-slate-400 text-[11px]">
                        Confidence: {(ev.confidence * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="text-[11px] font-mono text-slate-400 truncate">{ev.target}</div>
                    <div className="mt-1 text-[10px] text-slate-500 font-mono">Hash: {ev.evidenceHash}</div>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: Passive Evidence Table */}
      {activeTab === 'evidence_list' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Passive Evidence Repository</h2>
              <p className="text-xs text-slate-400 mt-0.5">
                All records collected without transmitting probes to target network endpoints.
              </p>
            </div>
            <span className="text-xs font-mono text-cyan-400">
              {passiveEvidenceList.length} verified items
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-950/80 text-[11px] text-slate-400 uppercase tracking-wider font-mono border-b border-slate-800">
                <tr>
                  <th className="py-2.5 px-4">Tool</th>
                  <th className="py-2.5 px-4">Target</th>
                  <th className="py-2.5 px-4">Evidence Payload</th>
                  <th className="py-2.5 px-4">Confidence</th>
                  <th className="py-2.5 px-4">Hash</th>
                  <th className="py-2.5 px-4">Collected</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-sans">
                {passiveEvidenceList.map(ev => (
                  <tr key={ev.id} className="hover:bg-slate-850/50 transition-colors">
                    <td className="py-3 px-4 font-mono text-cyan-400 text-[11px]">{ev.sourceTool}</td>
                    <td className="py-3 px-4 font-mono text-slate-200">{ev.target}</td>
                    <td className="py-3 px-4 max-w-xs truncate" title={ev.value}>{ev.value}</td>
                    <td className="py-3 px-4 font-mono tabular-nums text-emerald-400">
                      {(ev.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="py-3 px-4 font-mono text-[10px] text-slate-400 truncate max-w-28">
                      {ev.evidenceHash.slice(0, 16)}...
                    </td>
                    <td className="py-3 px-4 text-[11px] text-slate-400">{formatDate(ev.collectedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Auth Switcher Modal */}
      <AuthSwitchModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
      />
    </div>
  );
};
