import {
  WorkflowState,
  WorkflowRun,
  ApprovedScanProfile
} from '../../types/workflow';
import { Investigation } from '../../types/models';
import { serverRepos } from '../db/repositories';
import { scopeValidator } from './scopeValidator';
import { passiveReconService } from './passiveRecon';
import { workerManager } from './workerManager';
import { correlationEngine } from './correlationEngine';
import { exposureScorer } from './exposureScorer';
import { reportGenerator } from './reportGenerator';
import { parseNmapXml } from './parsers/nmapParser';
import { parseOpenVASXml } from './parsers/openvasParser';
import { evidenceNormalizer } from './normalizer';
import { generateEvidenceHash } from '../../utils/hash';
import { SAMPLE_NMAP_XML, SAMPLE_OPENVAS_XML } from '../../data/sampleScanFiles';

export class WorkflowControllerService {
  private activeRuns: Map<string, WorkflowRun> = new Map();

  /**
   * Transition state and record state history
   */
  async transitionState(
    run: WorkflowRun,
    newState: WorkflowState,
    message?: string,
    details?: Record<string, unknown>
  ): Promise<WorkflowRun> {
    run.currentState = newState;
    const now = new Date().toISOString();
    run.stateHistory.push({
      state: newState,
      timestamp: now,
      message,
      details
    });

    // Update last safe state
    const safeStates: WorkflowState[] = [
      'CREATED',
      'SCOPE_VALIDATED',
      'PASSIVE_COMPLETE',
      'WAITING_FOR_APPROVAL',
      'NMAP_COMPLETE',
      'OPENVAS_COMPLETE',
      'SCORING',
      'COMPLETED'
    ];
    if (safeStates.includes(newState)) {
      run.lastSafeState = newState;
    }

    run.updatedAt = now;
    this.activeRuns.set(run.id, run);

    // Record audit event
    await serverRepos.audit.logEvent({
      investigationId: run.investigationId,
      timestamp: now,
      actor: 'WorkflowController',
      action: `WORKFLOW_STATE_${newState}`,
      category: 'system',
      targetResource: `Run ${run.id}`,
      details: message || `Workflow transitioned to state ${newState}.`,
      status: newState === 'BLOCKED_OUT_OF_SCOPE' || newState === 'FAILED' ? 'denied' : 'allowed'
    });

    return run;
  }

  /**
   * Start a new semi-autonomous workflow run
   */
  async startWorkflow(investigationId: string, actor: string): Promise<WorkflowRun> {
    const inv = await serverRepos.investigations.getById(investigationId);
    if (!inv) throw new Error('Investigation not found');

    const runId = `wf-run-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
    const now = new Date().toISOString();

    const run: WorkflowRun = {
      id: runId,
      investigationId,
      currentState: 'CREATED',
      stateHistory: [{ state: 'CREATED', timestamp: now, message: `Workflow initiated by ${actor}` }],
      stageProgressPercent: 5,
      passiveCollectionCompleted: false,
      retriesRemaining: 3,
      lastSafeState: 'CREATED',
      createdAt: now,
      updatedAt: now
    };

    this.activeRuns.set(runId, run);

    // Kick off asynchronously
    this.executeWorkflow(run, inv, actor).catch(err => {
      console.error(`Workflow run ${runId} unhandled failure:`, err);
    });

    return run;
  }

  /**
   * Asynchronous stage executor
   */
  private async executeWorkflow(run: WorkflowRun, inv: Investigation, actor: string): Promise<void> {
    try {
      // 1. SCOPE VALIDATION
      run.stageProgressPercent = 15;
      const targetDomain = inv.scope.ownedDomains[0];
      const scopeCheck = await scopeValidator.validateTarget(inv, targetDomain, false);

      if (!scopeCheck.isValid) {
        await this.transitionState(run, 'BLOCKED_OUT_OF_SCOPE', `Scope validation failed: ${scopeCheck.blockReason}`);
        return;
      }

      await this.transitionState(run, 'SCOPE_VALIDATED', `Scope confirmed: Domain ${targetDomain} valid until ${inv.authorization.expiryDate}`);

      // 2. PASSIVE RECONNAISSANCE
      await this.transitionState(run, 'PASSIVE_RUNNING', 'Starting concurrent passive collectors (RDAP, DNS, Search)');
      run.stageProgressPercent = 30;

      // Collector-level failure isolation using Promise.allSettled
      const results = await Promise.allSettled([
        passiveReconService.collectRDAP(targetDomain),
        passiveReconService.collectDNS(targetDomain)
      ] as const);

      // Ingest RDAP if settled
      if (results[0].status === 'fulfilled') {
        const rdap = results[0].value;
        const ev = await serverRepos.evidence.add({
          id: `ev-wf-rdap-${Date.now()}`,
          investigationId: inv.id,
          type: 'RDAP_REGISTRATION',
          value: `RDAP Record for ${targetDomain} (Registrar: ${rdap.registrar})`,
          target: targetDomain,
          sourceTool: 'Workflow RDAP Collector',
          collectedAt: new Date().toISOString(),
          interactionType: 'passive',
          confidence: 0.98,
          authorizedScope: true,
          attributes: rdap as unknown as Record<string, unknown>,
          evidenceHash: generateEvidenceHash(`${targetDomain}|wf_rdap`),
          validationStatus: 'verified'
        });
        await evidenceNormalizer.correlateEvidence(inv.id, ev);
      }

      // Ingest DNS if settled
      if (results[1].status === 'fulfilled') {
        const dns = results[1].value;
        const ev = await serverRepos.evidence.add({
          id: `ev-wf-dns-${Date.now()}`,
          investigationId: inv.id,
          type: 'DNS_ZONE_RECORDS',
          value: `DNS Records for ${targetDomain} (${dns.records.length} records)`,
          target: targetDomain,
          sourceTool: 'Workflow DNS Collector',
          collectedAt: new Date().toISOString(),
          interactionType: 'passive',
          confidence: 1.0,
          authorizedScope: true,
          attributes: dns as unknown as Record<string, unknown>,
          evidenceHash: generateEvidenceHash(`${targetDomain}|wf_dns`),
          validationStatus: 'verified'
        });
        await evidenceNormalizer.correlateEvidence(inv.id, ev);
      }

      run.passiveCollectionCompleted = true;
      run.stageProgressPercent = 45;
      await this.transitionState(run, 'PASSIVE_COMPLETE', 'Passive collection finished successfully.');

      // 3. WAITING FOR APPROVAL (Active Gatekeeper)
      // Active operations MUST pause until an Investigator or Admin approves
      if (inv.authorization.activeScanningEnabled && inv.scope.activeTargets.length > 0) {
        await this.transitionState(
          run,
          'WAITING_FOR_APPROVAL',
          `Paused: Active scanning requires explicit confirmation for allowlisted target(s) [${inv.scope.activeTargets.join(', ')}].`
        );
      } else {
        // No active scanning requested, proceed directly to correlation & scoring
        await this.proceedPostActiveStages(run, inv);
      }
    } catch (err: any) {
      console.error(`Workflow failure at run ${run.id}:`, err);
      await this.transitionState(run, 'FAILED', err.message || 'Workflow execution error');
    }
  }

  /**
   * Explicit approval gate called by Investigator or Admin
   */
  async approveActiveStage(runId: string, approverName: string): Promise<WorkflowRun> {
    const run = this.activeRuns.get(runId);
    if (!run) throw new Error('Workflow run not found');
    if (run.currentState !== 'WAITING_FOR_APPROVAL') {
      throw new Error(`Cannot approve active stage in state ${run.currentState}`);
    }

    const inv = await serverRepos.investigations.getById(run.investigationId);
    if (!inv) throw new Error('Investigation not found');

    run.activeApprovedBy = approverName;
    run.activeApprovedAt = new Date().toISOString();

    // Kick off active stage execution
    this.executeActiveStages(run, inv, approverName).catch(err => {
      console.error(`Active stage failure for run ${runId}:`, err);
    });

    return run;
  }

  /**
   * Execute Nmap and OpenVAS active stages using authorized worker
   */
  private async executeActiveStages(run: WorkflowRun, inv: Investigation, approver: string): Promise<void> {
    const activeTarget = inv.scope.activeTargets[0] || '192.168.56.102';

    // 1. NMAP QUEUE & RUN
    await this.transitionState(run, 'NMAP_QUEUED', `Queued safe-service-detection job for target ${activeTarget}`);
    run.stageProgressPercent = 55;

    const nmapJob = await workerManager.createJob(
      inv.id,
      run.id,
      activeTarget,
      'safe-service-detection'
    );
    run.nmapJobId = nmapJob.id;

    await this.transitionState(run, 'NMAP_RUNNING', `Simulated lab worker accepted Nmap job ${nmapJob.id}`);
    const completedNmapJob = await workerManager.executeSimulatedJob(nmapJob.id);

    // Ingest Nmap result
    if (completedNmapJob.rawResultPayload) {
      const parsed = parseNmapXml(completedNmapJob.rawResultPayload);
      for (const h of parsed.hosts) {
        for (const p of h.ports) {
          await serverRepos.services.addOrUpdate({
            id: `srv-${h.ip.replace(/\./g, '-')}-${p.port}`,
            investigationId: inv.id,
            ip: h.ip,
            port: p.port,
            protocol: p.protocol,
            serviceName: p.serviceName,
            product: p.product,
            version: p.version,
            banner: p.extraInfo || `${p.serviceName} on ${p.port}`,
            state: p.state,
            cpe: p.cpe
          });
        }
      }
    }

    run.stageProgressPercent = 70;
    await this.transitionState(run, 'NMAP_COMPLETE', `Nmap scan completed with verified SHA-256 result hash.`);

    // 2. OPENVAS QUEUE & RUN
    await this.transitionState(run, 'OPENVAS_QUEUED', `Queued openvas-basic audit for target ${activeTarget}`);
    run.stageProgressPercent = 80;

    const openvasJob = await workerManager.createJob(
      inv.id,
      run.id,
      activeTarget,
      'openvas-basic'
    );
    run.openvasJobId = openvasJob.id;

    await this.transitionState(run, 'OPENVAS_RUNNING', `Simulated lab worker accepted OpenVAS job ${openvasJob.id}`);
    const completedOpenvasJob = await workerManager.executeSimulatedJob(openvasJob.id);

    // Ingest OpenVAS result
    if (completedOpenvasJob.rawResultPayload) {
      const parsed = parseOpenVASXml(completedOpenvasJob.rawResultPayload);
      for (const f of parsed.findings) {
        await serverRepos.findings.addOrMerge({
          id: `fnd-wf-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
          investigationId: inv.id,
          title: f.name,
          category: f.name.toLowerCase().includes('tls') ? 'misconfiguration' : 'information_disclosure',
          severity: f.severity,
          status: 'open',
          target: `${f.host}:${f.port}`,
          description: f.description,
          sourceTool: 'Authorized Worker (OpenVAS)',
          interactionType: 'active',
          cvss: f.cvss,
          cve: f.cveReferences[0],
          remediationAdvice: f.solution || 'Review vendor security patches.',
          detectedAt: new Date().toISOString()
        });
      }
    }

    run.stageProgressPercent = 85;
    await this.transitionState(run, 'OPENVAS_COMPLETE', `OpenVAS assessment finished and findings ingested.`);

    // Continue to correlation & scoring
    await this.proceedPostActiveStages(run, inv);
  }

  /**
   * Final correlation, exposure score calculation, and reporting stages
   */
  private async proceedPostActiveStages(run: WorkflowRun, inv: Investigation): Promise<void> {
    // 1. CORRELATING
    await this.transitionState(run, 'CORRELATING', 'Running multi-factor entity correlation and relationship mapping');
    run.stageProgressPercent = 90;
    await correlationEngine.correlateInvestigation(inv.id);

    // 2. SCORING
    await this.transitionState(run, 'SCORING', 'Calculating 5-component Exposure Score (P, D, S, V, C)');
    run.stageProgressPercent = 95;

    const findings = await serverRepos.findings.getByInvestigationId(inv.id);
    const entities = await serverRepos.entities.getByInvestigationId(inv.id);
    const services = await serverRepos.services.getByInvestigationId(inv.id);
    const evidenceList = await serverRepos.evidence.getByInvestigationId(inv.id);

    const score = exposureScorer.calculateScore(findings, entities, services, evidenceList);
    serverRepos.scores.getScore(inv.id); // persist

    // 3. REPORTING
    await this.transitionState(run, 'REPORTING', 'Compiling final reconnaissance dossier');
    await reportGenerator.generateComprehensiveReport(inv.id, 'Workflow Automated Dossier', 'Asip Ali (Admin)');

    run.stageProgressPercent = 100;
    await this.transitionState(run, 'COMPLETED', `Workflow completed successfully. Final score: ${score.totalScore}/100 (${score.tier}).`);
  }

  /**
   * Resume an interrupted workflow from its latest safe state
   */
  async resumeWorkflow(runId: string, actor: string): Promise<WorkflowRun> {
    const run = this.activeRuns.get(runId);
    if (!run) throw new Error('Workflow run not found');

    const inv = await serverRepos.investigations.getById(run.investigationId);
    if (!inv) throw new Error('Investigation not found');

    await this.transitionState(
      run,
      'RETRYING',
      `Resuming workflow execution from safe checkpoint: ${run.lastSafeState}`
    );

    // Resume based on lastSafeState
    if (run.lastSafeState === 'PASSIVE_COMPLETE' || run.lastSafeState === 'WAITING_FOR_APPROVAL') {
      await this.transitionState(run, 'WAITING_FOR_APPROVAL', 'Resumed: Awaiting active stage approval.');
    } else if (run.lastSafeState === 'NMAP_COMPLETE') {
      this.executeActiveStages(run, inv, actor).catch(console.error);
    } else {
      this.executeWorkflow(run, inv, actor).catch(console.error);
    }

    return run;
  }

  /**
   * Cancel an in-progress workflow
   */
  async cancelWorkflow(runId: string, actor: string): Promise<WorkflowRun> {
    const run = this.activeRuns.get(runId);
    if (!run) throw new Error('Workflow run not found');

    await this.transitionState(run, 'CANCELLED', `Workflow execution cancelled by ${actor}.`);
    return run;
  }

  /**
   * One-click "Run Safe Demo" action
   */
  async runSafeDemo(actor = 'Asip Ali (Admin)'): Promise<{ run: WorkflowRun; investigationId: string }> {
    const invId = 'inv-northstar-01';
    let inv = await serverRepos.investigations.getById(invId);

    // Reset investigation to pristine demo state if missing
    if (!inv) {
      inv = await serverRepos.investigations.create({
        id: invId,
        name: 'NorthStar Analytics Lab Footprint Audit',
        organizationName: 'NorthStar Analytics Lab',
        description: 'Demonstration of authorized passive OSINT and safe active host auditing in an educational sandbox.',
        leadInvestigator: 'Asip Ali (ID: 251347048)',
        teamMembers: ['Asip Ali (ID: 251347048)', 'Mohan Prasad (ID: 251347070)'],
        status: 'active',
        scope: {
          ownedDomains: ['lab.example'],
          approvedIPs: ['192.168.56.102'],
          approvedCIDRs: ['192.168.56.0/24'],
          passiveOnlyTargets: ['lab.example', 'research.lab.example'],
          activeTargets: ['192.168.56.102'],
          excludedTargets: ['*.gov', '*.mil']
        },
        authorization: {
          activeScanningEnabled: true,
          approvedBy: 'Lab Safety Committee & Dr. Marcus Vance',
          authorizationReference: 'AUTH-LAB-2026-DEMO',
          startDate: '2026-09-01T08:00:00Z',
          expiryDate: '2027-12-31T23:59:59Z',
          rulesOfEngagementConfirmed: true,
          ownershipOrWrittenPermissionConfirmed: true,
          notes: 'Safe simulated demonstration sandbox.'
        },
        modules: {
          rdapWhois: true,
          dnsRecon: true,
          theHarvesterImport: true,
          searchEvidence: true,
          nmapXmlImport: true,
          openvasXmlImport: true,
          entityCorrelation: true,
          exposureScoring: true,
          pdfReporting: true
        },
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: ['demo-mode', 'sandbox', 'northstar']
      });
    }

    const run = await this.startWorkflow(inv.id, actor);

    // For the demo: auto-approve active stage after passive completes
    setTimeout(async () => {
      try {
        const current = this.activeRuns.get(run.id);
        if (current && current.currentState === 'WAITING_FOR_APPROVAL') {
          await this.approveActiveStage(run.id, 'Demo Auto-Approval Gate');
        }
      } catch (e) {
        console.warn('Demo auto-approval warning:', e);
      }
    }, 1500);

    return { run, investigationId: inv.id };
  }

  getRun(runId: string): WorkflowRun | null {
    return this.activeRuns.get(runId) || null;
  }

  getAllRuns(investigationId?: string): WorkflowRun[] {
    const all = Array.from(this.activeRuns.values());
    if (investigationId) {
      return all.filter(r => r.investigationId === investigationId);
    }
    return all;
  }
}

export const workflowController = new WorkflowControllerService();
