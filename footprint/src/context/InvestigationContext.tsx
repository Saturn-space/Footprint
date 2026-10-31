import React, { createContext, useContext, useState, useEffect, useCallback, useMemo } from 'react';
import {
  Investigation,
  Target,
  Evidence,
  Entity,
  Relationship,
  Service,
  Finding,
  AuditEvent,
  Report,
  ExposureScoreBreakdown,
  User,
  ScopeValidationResult,
  ManualEvidenceInput
} from '../types/models';
import {
  WorkflowRun,
  WorkerRegistration,
  WorkerJob,
  ApprovedScanProfile
} from '../types/workflow';
import {
  MockInvestigationRepository,
  MockTargetRepository,
  MockEvidenceRepository,
  MockEntityRepository,
  MockFindingRepository,
  MockAuditRepository,
  MockExposureRepository,
  MockReportRepository,
  initializeStorage
} from '../repositories/mockRepository';
import { useAuth } from './AuthContext';

interface NotificationItem {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message: string;
  timestamp: string;
}

interface InvestigationContextType {
  currentUser: User;
  investigations: Investigation[];
  activeInvestigation: Investigation | null;
  targets: Target[];
  evidence: Evidence[];
  entities: Entity[];
  relationships: Relationship[];
  services: Service[];
  findings: Finding[];
  auditLogs: AuditEvent[];
  reports: Report[];
  exposureScore: ExposureScoreBreakdown | null;
  workflowRun: WorkflowRun | null;
  workflowRuns: WorkflowRun[];
  workers: WorkerRegistration[];
  isLoading: boolean;
  isServerConnected: boolean;
  notifications: NotificationItem[];
  dismissNotification: (id: string) => void;
  addNotification: (type: NotificationItem['type'], title: string, message: string) => void;
  selectInvestigation: (id: string) => void;
  createInvestigation: (investigation: Investigation) => Promise<Investigation>;
  deleteInvestigation: (id: string) => Promise<boolean>;
  validateTargetScope: (target: string, isActiveCheck?: boolean) => Promise<ScopeValidationResult>;
  triggerRDAPCollection: (domain?: string) => Promise<{ rdap: any; evidenceId: string }>;
  triggerDNSCollection: (domain?: string) => Promise<{ dns: any; evidenceId: string }>;
  importNmapXml: (xmlContent: string, filename?: string) => Promise<{ hosts: any[]; servicesIngested: number }>;
  importOpenVASXml: (xmlContent: string, filename?: string) => Promise<{ findingsIngested: number; hosts: string[] }>;
  importHarvesterDump: (content: string, filename?: string) => Promise<{ summary: any }>;
  addManualEvidenceRecord: (input: ManualEvidenceInput) => Promise<Evidence>;
  updateFindingStatus: (id: string, status: Finding['status']) => Promise<void>;
  generateReport: (title: string, reportType: Report['reportType'], format: Report['fileFormat']) => Promise<Report>;
  startWorkflow: (invId?: string) => Promise<WorkflowRun>;
  approveActiveWorkflowStage: (runId: string) => Promise<void>;
  resumeWorkflow: (runId: string) => Promise<void>;
  cancelWorkflow: (runId: string) => Promise<void>;
  runSafeDemo: () => Promise<void>;
  refreshWorkers: () => Promise<void>;
  registerWorker: (name: string, environment: 'local_lab' | 'simulated_preview', profiles: ApprovedScanProfile[], ipAddress?: string) => Promise<WorkerRegistration>;
  revokeWorker: (workerId: string) => Promise<void>;
  simulateWorkerJob: (jobId: string) => Promise<void>;
  runCorrelation: (invId?: string) => Promise<any>;
  recalculateScore: (reviewerNotes?: string) => Promise<ExposureScoreBreakdown>;
  generateFullReport: (title?: string) => Promise<Report>;
  downloadReportPdf: (reportId: string, filename?: string) => Promise<void>;
  exportInvestigationBundle: () => Promise<void>;
  exportFindingsCsv: () => Promise<void>;
  exportGraphml: () => Promise<void>;
  refreshAllData: () => Promise<void>;
}

const InvestigationContext = createContext<InvestigationContextType | null>(null);

export const InvestigationProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { currentUser, token } = useAuth();

  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [activeInvestigationId, setActiveInvestigationId] = useState<string>('');
  const [targets, setTargets] = useState<Target[]>([]);
  const [evidence, setEvidence] = useState<Evidence[]>([]);
  const [entities, setEntities] = useState<Entity[]>([]);
  const [relationships, setRelationships] = useState<Relationship[]>([]);
  const [services, setServices] = useState<Service[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditEvent[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [exposureScore, setExposureScore] = useState<ExposureScoreBreakdown | null>(null);
  const [workflowRun, setWorkflowRun] = useState<WorkflowRun | null>(null);
  const [workflowRuns, setWorkflowRuns] = useState<WorkflowRun[]>([]);
  const [workers, setWorkers] = useState<WorkerRegistration[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isServerConnected, setIsServerConnected] = useState<boolean>(false);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);

  // Fallback local repos - memoized
  const localRepos = useMemo(() => ({
    investigation: new MockInvestigationRepository(),
    target: new MockTargetRepository(),
    evidence: new MockEvidenceRepository(),
    entity: new MockEntityRepository(),
    finding: new MockFindingRepository(),
    audit: new MockAuditRepository(),
    exposure: new MockExposureRepository(),
    report: new MockReportRepository()
  }), []);

  const addNotification = useCallback((type: NotificationItem['type'], title: string, message: string) => {
    const id = `notif-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    setNotifications(prev => [{ id, type, title, message, timestamp: new Date().toISOString() }, ...prev]);
  }, []);

  const dismissNotification = useCallback((id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  // Server API helper
  const apiFetch = useCallback(async (endpoint: string, options: RequestInit = {}) => {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token || currentUser.id}`,
      ...(options.headers as Record<string, string> || {})
    };

    const res = await fetch(`/api/v1${endpoint}`, {
      ...options,
      headers
    });

    const json = await res.json();
    return { ok: res.ok, status: res.status, json };
  }, [token, currentUser]);

  const loadInvestigationData = useCallback(async (invId: string) => {
    if (!invId) return;

    try {
      // Attempt server load
      const [
        entRes,
        relRes,
        fndRes,
        srvRes,
        evRes,
        scrRes,
        audRes,
        wfRes,
        repRes,
        wkrRes
      ] = await Promise.all([
        apiFetch(`/investigations/${invId}/entities`),
        apiFetch(`/investigations/${invId}/relationships`),
        apiFetch(`/investigations/${invId}/findings`),
        apiFetch(`/investigations/${invId}/services`),
        apiFetch(`/investigations/${invId}/evidence`),
        apiFetch(`/investigations/${invId}/score`),
        apiFetch(`/investigations/${invId}/audit`),
        apiFetch(`/investigations/${invId}/workflow`),
        apiFetch(`/investigations/${invId}/reports`),
        apiFetch('/workers')
      ]);

      if (entRes.ok && entRes.json.success) {
        setIsServerConnected(true);
        setEntities(entRes.json.data || []);
        setRelationships(relRes.json.data || []);
        setFindings(fndRes.json.data || []);
        setServices(srvRes.json.data || []);
        setEvidence(evRes.json.data || []);
        setExposureScore(scrRes.json.data || null);
        setAuditLogs(audRes.json.data || []);
        if (wfRes.ok && wfRes.json.success) {
          const runs = wfRes.json.data || [];
          setWorkflowRuns(runs);
          if (runs.length > 0) {
            setWorkflowRun(runs[runs.length - 1]);
          }
        }
        if (repRes.ok && repRes.json.success) {
          setReports(repRes.json.data || []);
        }
        if (wkrRes.ok && wkrRes.json.success) {
          setWorkers(wkrRes.json.data || []);
        }
        return;
      }
    } catch {
      // Server unreachable, use local repos
      setIsServerConnected(false);
    }

    // Local repo fallback
    try {
      const [
        fetchedTargets,
        fetchedEvidence,
        fetchedEntities,
        fetchedRelationships,
        fetchedServices,
        fetchedFindings,
        fetchedAudit,
        fetchedReports,
        fetchedScore
      ] = await Promise.all([
        localRepos.target.getByInvestigationId(invId),
        localRepos.evidence.getByInvestigationId(invId),
        localRepos.entity.getEntities(invId),
        localRepos.entity.getRelationships(invId),
        localRepos.finding.getServices(invId),
        localRepos.finding.getByInvestigationId(invId),
        localRepos.audit.getByInvestigationId(invId),
        localRepos.report.getByInvestigationId(invId),
        localRepos.exposure.getScore(invId)
      ]);

      setTargets(fetchedTargets);
      setEvidence(fetchedEvidence);
      setEntities(fetchedEntities);
      setRelationships(fetchedRelationships);
      setServices(fetchedServices);
      setFindings(fetchedFindings);
      setAuditLogs(fetchedAudit);
      setReports(fetchedReports);
      setExposureScore(fetchedScore);
    } catch (e) {
      console.error('Error loading fallback items:', e);
    }
  }, [apiFetch, localRepos]);

  const refreshAllData = useCallback(async () => {
    try {
      const res = await apiFetch('/investigations');
      if (res.ok && res.json.success) {
        setIsServerConnected(true);
        const list = res.json.data || [];
        setInvestigations(list);
        const currentActive = activeInvestigationId || (list.length > 0 ? list[0].id : '');
        if (currentActive && currentActive !== activeInvestigationId) {
          setActiveInvestigationId(currentActive);
        }
        if (currentActive) {
          await loadInvestigationData(currentActive);
        }
        return;
      }
    } catch {
      setIsServerConnected(false);
    }

    // Fallback
    const list = await localRepos.investigation.getAll();
    setInvestigations(list);
    const activeId = activeInvestigationId || (list.length > 0 ? list[0].id : '');
    if (activeId && activeId !== activeInvestigationId) {
      setActiveInvestigationId(activeId);
    }
    if (activeId) {
      await loadInvestigationData(activeId);
    }
  }, [apiFetch, localRepos, activeInvestigationId, loadInvestigationData]);

  // Initial mount
  useEffect(() => {
    initializeStorage();
    const init = async () => {
      setIsLoading(true);
      await refreshAllData();
      setIsLoading(false);
    };
    init();
  }, [refreshAllData]);

  const selectInvestigation = useCallback((id: string) => {
    setActiveInvestigationId(id);
    loadInvestigationData(id);
    const selected = investigations.find(i => i.id === id);
    if (selected) {
      addNotification('info', 'Active Context Switched', `Active investigation set to "${selected.name}".`);
    }
  }, [investigations, loadInvestigationData, addNotification]);

  const activeInvestigation = useMemo(() => {
    return investigations.find(i => i.id === activeInvestigationId) || null;
  }, [investigations, activeInvestigationId]);

  // Server API Actions
  const createInvestigation = useCallback(async (inv: Investigation): Promise<Investigation> => {
    try {
      const res = await apiFetch('/investigations', {
        method: 'POST',
        body: JSON.stringify(inv)
      });

      if (res.ok && res.json.success) {
        const created = res.json.data;
        setInvestigations(prev => [created, ...prev]);
        setActiveInvestigationId(created.id);
        await loadInvestigationData(created.id);
        addNotification('success', 'Investigation Created', `"${created.name}" persisted to server database.`);
        return created;
      } else {
        throw new Error(res.json.error || 'Server rejected creation');
      }
    } catch (err: any) {
      // Local fallback
      const created = await localRepos.investigation.create(inv);
      setInvestigations(prev => [created, ...prev]);
      setActiveInvestigationId(created.id);
      await loadInvestigationData(created.id);
      addNotification('warning', 'Saved in Local Store', `Server offline: saved in browser database.`);
      return created;
    }
  }, [apiFetch, localRepos, loadInvestigationData, addNotification]);

  const deleteInvestigation = useCallback(async (id: string): Promise<boolean> => {
    try {
      const res = await apiFetch(`/investigations/${id}`, { method: 'DELETE' });
      if (res.ok && res.json.success) {
        const remaining = investigations.filter(i => i.id !== id);
        setInvestigations(remaining);
        if (activeInvestigationId === id && remaining.length > 0) {
          selectInvestigation(remaining[0].id);
        }
        addNotification('info', 'Investigation Purged', 'Investigation and isolated artifacts removed.');
        return true;
      }
    } catch {}

    const success = await localRepos.investigation.delete(id);
    if (success) {
      const remaining = investigations.filter(i => i.id !== id);
      setInvestigations(remaining);
      if (activeInvestigationId === id && remaining.length > 0) {
        selectInvestigation(remaining[0].id);
      }
    }
    return success;
  }, [apiFetch, localRepos, investigations, activeInvestigationId, selectInvestigation]);

  const validateTargetScope = useCallback(async (target: string, isActiveCheck = false): Promise<ScopeValidationResult> => {
    if (!activeInvestigationId) throw new Error('No active investigation selected');

    const res = await apiFetch(`/investigations/${activeInvestigationId}/validate-scope`, {
      method: 'POST',
      body: JSON.stringify({ target, isActiveCheck })
    });

    if (res.ok && res.json.success) {
      return res.json.data;
    }
    throw new Error(res.json.error || 'Scope validation request failed');
  }, [apiFetch, activeInvestigationId]);

  const triggerRDAPCollection = useCallback(async (domain?: string) => {
    if (!activeInvestigationId) throw new Error('No active investigation');
    const res = await apiFetch(`/investigations/${activeInvestigationId}/collect/rdap`, {
      method: 'POST',
      body: JSON.stringify({ domain })
    });

    if (res.ok && res.json.success) {
      await loadInvestigationData(activeInvestigationId);
      addNotification('success', 'RDAP Ingested', `Server RDAP collection completed for ${domain || 'owned domain'}.`);
      return res.json.data;
    }
    throw new Error(res.json.error || 'RDAP collection failed');
  }, [apiFetch, activeInvestigationId, loadInvestigationData, addNotification]);

  const triggerDNSCollection = useCallback(async (domain?: string) => {
    if (!activeInvestigationId) throw new Error('No active investigation');
    const res = await apiFetch(`/investigations/${activeInvestigationId}/collect/dns`, {
      method: 'POST',
      body: JSON.stringify({ domain })
    });

    if (res.ok && res.json.success) {
      await loadInvestigationData(activeInvestigationId);
      addNotification('success', 'DNS Telemetry Ingested', `Authoritative DNS records retrieved and correlated.`);
      return res.json.data;
    }
    throw new Error(res.json.error || 'DNS collection failed');
  }, [apiFetch, activeInvestigationId, loadInvestigationData, addNotification]);

  const importNmapXml = useCallback(async (xmlContent: string, filename?: string) => {
    if (!activeInvestigationId) throw new Error('No active investigation');
    const res = await apiFetch(`/investigations/${activeInvestigationId}/import/nmap`, {
      method: 'POST',
      body: JSON.stringify({ xmlContent, filename })
    });

    if (res.ok && res.json.success) {
      await loadInvestigationData(activeInvestigationId);
      addNotification('success', 'Nmap XML Ingested', `Validated allowlist and ingested ${res.json.data.servicesIngested} services.`);
      return res.json.data;
    }
    throw new Error(res.json.error || 'Nmap XML import failed');
  }, [apiFetch, activeInvestigationId, loadInvestigationData, addNotification]);

  const importOpenVASXml = useCallback(async (xmlContent: string, filename?: string) => {
    if (!activeInvestigationId) throw new Error('No active investigation');
    const res = await apiFetch(`/investigations/${activeInvestigationId}/import/openvas`, {
      method: 'POST',
      body: JSON.stringify({ xmlContent, filename })
    });

    if (res.ok && res.json.success) {
      await loadInvestigationData(activeInvestigationId);
      addNotification('success', 'OpenVAS Report Ingested', `Imported ${res.json.data.findingsIngested} vulnerability findings.`);
      return res.json.data;
    }
    throw new Error(res.json.error || 'OpenVAS XML import failed');
  }, [apiFetch, activeInvestigationId, loadInvestigationData, addNotification]);

  const importHarvesterDump = useCallback(async (content: string, filename?: string) => {
    if (!activeInvestigationId) throw new Error('No active investigation');
    const res = await apiFetch(`/investigations/${activeInvestigationId}/import/harvester`, {
      method: 'POST',
      body: JSON.stringify({ content, filename })
    });

    if (res.ok && res.json.success) {
      await loadInvestigationData(activeInvestigationId);
      addNotification('success', 'theHarvester Data Ingested', `Ingested OSINT harvest with ${res.json.data.summary.emailsExtracted} emails.`);
      return res.json.data;
    }
    throw new Error(res.json.error || 'theHarvester import failed');
  }, [apiFetch, activeInvestigationId, loadInvestigationData, addNotification]);

  const addManualEvidenceRecord = useCallback(async (input: ManualEvidenceInput): Promise<Evidence> => {
    if (!activeInvestigationId) throw new Error('No active investigation');
    const res = await apiFetch(`/investigations/${activeInvestigationId}/evidence/manual`, {
      method: 'POST',
      body: JSON.stringify(input)
    });

    if (res.ok && res.json.success) {
      await loadInvestigationData(activeInvestigationId);
      addNotification('success', 'Evidence Logged', `Recorded search evidence: "${input.resultTitle}".`);
      return res.json.data;
    }
    throw new Error(res.json.error || 'Failed to catalog manual search evidence');
  }, [apiFetch, activeInvestigationId, loadInvestigationData, addNotification]);

  const updateFindingStatus = useCallback(async (id: string, status: Finding['status']): Promise<void> => {
    if (!activeInvestigationId) return;
    try {
      await apiFetch(`/investigations/${activeInvestigationId}/findings/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ status })
      });
    } catch {}

    // Update in local state
    setFindings(prev => prev.map(f => f.id === id ? { ...f, status } : f));
    await loadInvestigationData(activeInvestigationId);
    addNotification('info', 'Finding Status Updated', `Status changed to ${status.replace('_', ' ')}.`);
  }, [apiFetch, activeInvestigationId, loadInvestigationData, addNotification]);

  const generateReport = useCallback(async (
    title: string,
    reportType: Report['reportType'],
    format: Report['fileFormat']
  ): Promise<Report> => {
    if (!activeInvestigationId || !activeInvestigation) throw new Error('No active investigation');

    const sections = [
      {
        title: '1. Executive Authorization & Scope Boundary',
        content: `This report details the authorized footprint assessment conducted for ${activeInvestigation.organizationName}. ` +
          `Authorization reference: ${activeInvestigation.authorization.authorizationReference}. ` +
          `Active scanning permitted: ${activeInvestigation.authorization.activeScanningEnabled ? 'YES (Allowlist Enforced)' : 'NO (Passive Reconnaissance Only)'}. ` +
          `Target scope covers apex domain [${activeInvestigation.scope.ownedDomains.join(', ')}] and lab CIDR [${activeInvestigation.scope.approvedCIDRs.join(', ')}].`
      },
      {
        title: '2. Attack Surface Telemetry',
        content: `Discovered entities: ${entities.length} correlated nodes across ${services.length} active service ports. ` +
          `Identified ${findings.length} findings requiring governance triage. Current calculated Exposure Score: ${exposureScore?.totalScore || 0}/100 (${exposureScore?.tier || 'Calculating'}).`
      },
      {
        title: '3. Findings & Triage Matrix',
        content: findings.map(f => `• [${f.severity.toUpperCase()}] ${f.title} (${f.target}) - Status: ${f.status}`).join('\n')
      },
      {
        title: '4. Legal & Educational Attestation',
        content: `Generated by ${currentUser.name} (ID: ${currentUser.studentId || currentUser.role}). Investigation maintained under strict institutional rules of engagement. All operations performed in compliance with lab security policies.`
      }
    ];

    const newReport: Report = {
      id: `rep-${Date.now()}`,
      investigationId: activeInvestigationId,
      title,
      reportType,
      generatedAt: new Date().toISOString(),
      generatedBy: `${currentUser.name} (${currentUser.role})`,
      summary: `Automated assessment summary for ${activeInvestigation.organizationName} with ${findings.length} findings and Exposure Tier ${exposureScore?.tier || 'Moderate'}.`,
      sections,
      fileFormat: format
    };

    const saved = await localRepos.report.create(newReport);
    setReports(prev => [saved, ...prev]);

    addNotification('success', 'Report Compiled', `Report "${title}" generated successfully.`);
    return saved;
  }, [activeInvestigationId, activeInvestigation, entities.length, services.length, findings.length, exposureScore, currentUser, localRepos, addNotification]);

  // Real-time workflow polling
  useEffect(() => {
    if (!workflowRun) return;
    const terminalStates: string[] = ['COMPLETED', 'PARTIALLY_COMPLETED', 'FAILED', 'CANCELLED', 'BLOCKED_OUT_OF_SCOPE'];
    if (terminalStates.includes(workflowRun.currentState)) return;

    const interval = setInterval(async () => {
      try {
        const res = await apiFetch(`/workflow/${workflowRun.id}`);
        if (res.ok && res.json.success) {
          const updated = res.json.data as WorkflowRun;
          setWorkflowRun(updated);
          setWorkflowRuns(prev => prev.map(r => r.id === updated.id ? updated : r));

          if (terminalStates.includes(updated.currentState)) {
            if (activeInvestigationId) {
              await loadInvestigationData(activeInvestigationId);
            }
            if (updated.currentState === 'COMPLETED') {
              addNotification('success', 'Workflow Run Complete', 'Semi-autonomous reconnaissance workflow completed with verified SHA-256 artifacts.');
            } else if (updated.currentState === 'WAITING_FOR_APPROVAL') {
              addNotification('warning', 'Approval Required', 'Passive collection complete. Active scanning requires explicit authorization.');
            } else if (updated.currentState === 'BLOCKED_OUT_OF_SCOPE') {
              addNotification('error', 'Scope Violation', 'Workflow blocked: target outside authorized allowlist.');
            }
          }
        }
      } catch (err) {
        console.warn('Workflow polling error:', err);
      }
    }, 1200);

    return () => clearInterval(interval);
  }, [workflowRun, activeInvestigationId, apiFetch, loadInvestigationData, addNotification]);

  const startWorkflow = useCallback(async (invId?: string): Promise<WorkflowRun> => {
    const id = invId || activeInvestigationId;
    if (!id) throw new Error('No investigation selected');
    const res = await apiFetch(`/investigations/${id}/workflow/start`, { method: 'POST' });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Failed to start workflow run');
    }
    const run: WorkflowRun = res.json.data;
    setWorkflowRun(run);
    setWorkflowRuns(prev => [run, ...prev]);
    addNotification('info', 'Workflow Started', `Autonomous workflow run ${run.id} initiated.`);
    return run;
  }, [apiFetch, activeInvestigationId, addNotification]);

  const approveActiveWorkflowStage = useCallback(async (runId: string): Promise<void> => {
    const res = await apiFetch(`/workflow/${runId}/approve`, { method: 'POST' });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Failed to approve active stage');
    }
    const updated: WorkflowRun = res.json.data;
    setWorkflowRun(updated);
    setWorkflowRuns(prev => prev.map(r => r.id === updated.id ? updated : r));
    addNotification('success', 'Active Stage Approved', 'Worker dispatched for allowlisted target scanning.');
  }, [apiFetch, addNotification]);

  const resumeWorkflow = useCallback(async (runId: string): Promise<void> => {
    const res = await apiFetch(`/workflow/${runId}/resume`, { method: 'POST' });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Failed to resume workflow');
    }
    const updated: WorkflowRun = res.json.data;
    setWorkflowRun(updated);
    setWorkflowRuns(prev => prev.map(r => r.id === updated.id ? updated : r));
    addNotification('info', 'Workflow Resumed', `Resumed execution from checkpoint: ${updated.lastSafeState}`);
  }, [apiFetch, addNotification]);

  const cancelWorkflow = useCallback(async (runId: string): Promise<void> => {
    const res = await apiFetch(`/workflow/${runId}/cancel`, { method: 'POST' });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Failed to cancel workflow');
    }
    const updated: WorkflowRun = res.json.data;
    setWorkflowRun(updated);
    setWorkflowRuns(prev => prev.map(r => r.id === updated.id ? updated : r));
    addNotification('warning', 'Workflow Cancelled', 'Execution stopped by investigator.');
  }, [apiFetch, addNotification]);

  const runSafeDemo = useCallback(async (): Promise<void> => {
    addNotification('info', 'Safe Demo Initiated', 'Setting up NorthStar Analytics Lab testbed and starting workflow...');
    const res = await apiFetch('/demo/run-safe', { method: 'POST' });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Failed to run safe demo');
    }
    const { run, investigationId } = res.json.data;
    setActiveInvestigationId(investigationId);
    setWorkflowRun(run);
    setWorkflowRuns(prev => [run, ...prev]);

    const invRes = await apiFetch('/investigations');
    if (invRes.ok && invRes.json.success) {
      setInvestigations(invRes.json.data);
    }
  }, [apiFetch, addNotification]);

  const refreshWorkers = useCallback(async (): Promise<void> => {
    const res = await apiFetch('/workers');
    if (res.ok && res.json.success) {
      setWorkers(res.json.data);
    }
  }, [apiFetch]);

  const registerWorker = useCallback(async (
    name: string,
    environment: 'local_lab' | 'simulated_preview',
    profiles: ApprovedScanProfile[],
    ipAddress?: string
  ): Promise<WorkerRegistration> => {
    const res = await apiFetch('/workers/register', {
      method: 'POST',
      body: JSON.stringify({ name, environment, supportedProfiles: profiles, ipAddress })
    });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Failed to register worker');
    }
    const w: WorkerRegistration = res.json.data;
    setWorkers(prev => [...prev, w]);
    addNotification('success', 'Worker Registered', `Worker "${w.name}" registered. Worker ID: ${w.workerId}`);
    return w;
  }, [apiFetch, addNotification]);

  const revokeWorker = useCallback(async (workerId: string): Promise<void> => {
    const res = await apiFetch(`/workers/${workerId}/revoke`, { method: 'POST' });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Failed to revoke worker');
    }
    setWorkers(prev => prev.map(w => w.workerId === workerId ? { ...w, status: 'revoked' } : w));
    addNotification('warning', 'Worker Revoked', `Worker ${workerId} credentials revoked immediately.`);
  }, [apiFetch, addNotification]);

  const simulateWorkerJob = useCallback(async (jobId: string): Promise<void> => {
    const res = await apiFetch(`/workers/simulate-job/${jobId}`, { method: 'POST' });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Simulation failed');
    }
    addNotification('success', 'Simulation Finished', `Job ${jobId} executed in preview sandbox.`);
  }, [apiFetch, addNotification]);

  const runCorrelation = useCallback(async (invId?: string): Promise<any> => {
    const id = invId || activeInvestigationId;
    if (!id) throw new Error('No active investigation');
    const res = await apiFetch(`/investigations/${id}/correlate`, { method: 'POST' });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Correlation failed');
    }
    await loadInvestigationData(id);
    addNotification('success', 'Correlation Engine Complete', res.json.message || 'Entities and relationships mapped.');
    return res.json.data;
  }, [apiFetch, activeInvestigationId, loadInvestigationData, addNotification]);

  const recalculateScore = useCallback(async (reviewerNotes?: string): Promise<ExposureScoreBreakdown> => {
    if (!activeInvestigationId) throw new Error('No active investigation');
    const res = await apiFetch(`/investigations/${activeInvestigationId}/score`, {
      method: 'POST',
      body: JSON.stringify({ reviewerNotes })
    });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Failed to calculate score');
    }
    const score: ExposureScoreBreakdown = res.json.data;
    setExposureScore(score);
    addNotification('success', 'Exposure Score Recalculated', `Score: ${score.totalScore}/100 (${score.tier}).`);
    return score;
  }, [apiFetch, activeInvestigationId, addNotification]);

  const generateFullReport = useCallback(async (title?: string): Promise<Report> => {
    if (!activeInvestigationId) throw new Error('No active investigation');
    const res = await apiFetch(`/investigations/${activeInvestigationId}/reports`, {
      method: 'POST',
      body: JSON.stringify({ title })
    });
    if (!res.ok || !res.json.success) {
      throw new Error(res.json.error || 'Report generation failed');
    }
    const rep: Report = res.json.data;
    setReports(prev => [rep, ...prev]);
    addNotification('success', '20-Section Dossier Compiled', `Report "${rep.title}" created with verified signatures.`);
    return rep;
  }, [apiFetch, activeInvestigationId, addNotification]);

  const downloadReportPdf = useCallback(async (reportId: string, filename?: string): Promise<void> => {
    const tokenHeader = `Bearer ${token || currentUser.id}`;
    const res = await fetch(`/api/v1/reports/${reportId}/pdf`, {
      headers: { 'Authorization': tokenHeader }
    });
    if (!res.ok) throw new Error('PDF download failed');
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || `footprintiq_dossier_${reportId}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }, [token, currentUser]);

  const exportInvestigationBundle = useCallback(async (): Promise<void> => {
    if (!activeInvestigationId) return;
    const res = await fetch(`/api/v1/investigations/${activeInvestigationId}/export/bundle`, {
      headers: { 'Authorization': `Bearer ${token || currentUser.id}` }
    });
    if (!res.ok) throw new Error('Export bundle failed');
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `footprintiq_bundle_${activeInvestigationId}.json`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }, [activeInvestigationId, token, currentUser]);

  const exportFindingsCsv = useCallback(async (): Promise<void> => {
    if (!activeInvestigationId) return;
    const res = await fetch(`/api/v1/investigations/${activeInvestigationId}/export/findings-csv`, {
      headers: { 'Authorization': `Bearer ${token || currentUser.id}` }
    });
    if (!res.ok) throw new Error('CSV export failed');
    const text = await res.text();
    const blob = new Blob([text], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `findings_${activeInvestigationId}.csv`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }, [activeInvestigationId, token, currentUser]);

  const exportGraphml = useCallback(async (): Promise<void> => {
    if (!activeInvestigationId) return;
    const res = await fetch(`/api/v1/investigations/${activeInvestigationId}/export/graphml`, {
      headers: { 'Authorization': `Bearer ${token || currentUser.id}` }
    });
    if (!res.ok) throw new Error('GraphML export failed');
    const text = await res.text();
    const blob = new Blob([text], { type: 'application/xml' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `knowledge_graph_${activeInvestigationId}.graphml`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }, [activeInvestigationId, token, currentUser]);

  const value = useMemo(() => ({
    currentUser,
    investigations,
    activeInvestigation,
    targets,
    evidence,
    entities,
    relationships,
    services,
    findings,
    auditLogs,
    reports,
    exposureScore,
    workflowRun,
    workflowRuns,
    workers,
    isLoading,
    isServerConnected,
    notifications,
    dismissNotification,
    addNotification,
    selectInvestigation,
    createInvestigation,
    deleteInvestigation,
    validateTargetScope,
    triggerRDAPCollection,
    triggerDNSCollection,
    importNmapXml,
    importOpenVASXml,
    importHarvesterDump,
    addManualEvidenceRecord,
    updateFindingStatus,
    generateReport,
    startWorkflow,
    approveActiveWorkflowStage,
    resumeWorkflow,
    cancelWorkflow,
    runSafeDemo,
    refreshWorkers,
    registerWorker,
    revokeWorker,
    simulateWorkerJob,
    runCorrelation,
    recalculateScore,
    generateFullReport,
    downloadReportPdf,
    exportInvestigationBundle,
    exportFindingsCsv,
    exportGraphml,
    refreshAllData
  }), [
    currentUser,
    investigations,
    activeInvestigation,
    targets,
    evidence,
    entities,
    relationships,
    services,
    findings,
    auditLogs,
    reports,
    exposureScore,
    workflowRun,
    workflowRuns,
    workers,
    isLoading,
    isServerConnected,
    notifications,
    dismissNotification,
    addNotification,
    selectInvestigation,
    createInvestigation,
    deleteInvestigation,
    validateTargetScope,
    triggerRDAPCollection,
    triggerDNSCollection,
    importNmapXml,
    importOpenVASXml,
    importHarvesterDump,
    addManualEvidenceRecord,
    updateFindingStatus,
    generateReport,
    startWorkflow,
    approveActiveWorkflowStage,
    resumeWorkflow,
    cancelWorkflow,
    runSafeDemo,
    refreshWorkers,
    registerWorker,
    revokeWorker,
    simulateWorkerJob,
    runCorrelation,
    recalculateScore,
    generateFullReport,
    downloadReportPdf,
    exportInvestigationBundle,
    exportFindingsCsv,
    exportGraphml,
    refreshAllData
  ]);

  return (
    <InvestigationContext.Provider value={value}>
      {children}
    </InvestigationContext.Provider>
  );
};

export function useInvestigation() {
  const context = useContext(InvestigationContext);
  if (!context) {
    throw new Error('useInvestigation must be used within an InvestigationProvider');
  }
  return context;
}
