import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { serverRepos } from '../db/repositories.js';
import { scopeValidator } from '../services/scopeValidator.js';
import { passiveReconService } from '../services/passiveRecon.js';
import { parseNmapXml } from '../services/parsers/nmapParser.js';
import { parseOpenVASXml } from '../services/parsers/openvasParser.js';
import { parseHarvesterExport } from '../services/parsers/harvesterParser.js';
import { evidenceNormalizer } from '../services/normalizer.js';
import { generateEvidenceHash } from '../../utils/hash.js';
import { User, UserRole, ApiResponse, Evidence, Finding } from '../../types/models.js';
import { InvestigationFormSchema } from '../../types/schemas.js';
import { workflowController } from '../services/workflowController.js';
import { workerManager } from '../services/workerManager.js';
import { correlationEngine } from '../services/correlationEngine.js';
import { exposureScorer } from '../services/exposureScorer.js';
import { reportGenerator } from '../services/reportGenerator.js';

export const apiRouter = Router();

// Middleware: attach request ID and timestamp helper
apiRouter.use((req: Request, res: Response, next: NextFunction) => {
  const reqId = `req-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  (req as any).requestId = reqId;

  // Helper method on res
  (res as any).sendApiResponse = <T>(
    statusCode: number,
    success: boolean,
    data: T | null,
    error: string | null = null,
    message: string = ''
  ) => {
    const payload: ApiResponse<T> = {
      success,
      data,
      error,
      message,
      requestId: reqId,
      timestamp: new Date().toISOString()
    };
    return res.status(statusCode).json(payload);
  };

  next();
});

// Mock session/token authentication middleware
const sessions: Map<string, User> = new Map();

// Helper to extract authenticated user
export async function getAuthUser(req: Request): Promise<User | null> {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    // Default to admin user for dev requests if no header provided
    const users = await serverRepos.users.getAll();
    return users.find(u => u.role === 'admin') || users[0] || null;
  }

  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  if (sessions.has(token)) {
    return sessions.get(token)!;
  }

  // Check if token matches email or id of a demo user
  const users = await serverRepos.users.getAll();
  const matched = users.find(u => u.id === token || u.email.toLowerCase() === token.toLowerCase());
  if (matched) {
    sessions.set(token, matched);
    return matched;
  }

  return null;
}

// RBAC Guard Middleware
function requireRole(allowedRoles: UserRole[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = await getAuthUser(req);
    if (!user) {
      return (res as any).sendApiResponse(401, false, null, 'Authentication required', 'Please log in to continue');
    }

    if (!allowedRoles.includes(user.role)) {
      return (res as any).sendApiResponse(
        403,
        false,
        null,
        'Access Denied',
        `Role "${user.role}" does not have permission for this operation. Required: ${allowedRoles.join(', ')}`
      );
    }

    (req as any).user = user;
    next();
  };
}

// ==========================================
// 1. Health & Auth Endpoints
// ==========================================

apiRouter.get('/health', (req: Request, res: Response) => {
  return (res as any).sendApiResponse(200, true, {
    status: 'healthy',
    version: '1.2.0-phase2',
    services: {
      persistence: 'active',
      scopeValidator: 'active',
      rdapCollector: 'active',
      dnsCollector: 'active',
      nmapParser: 'active (XXE-protected)',
      openvasParser: 'active (XXE-protected)'
    }
  }, null, 'FootprintIQ Reconnaissance API is fully operational');
});

apiRouter.post('/auth/login', async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) {
    return (res as any).sendApiResponse(400, false, null, 'Email is required', 'Please provide a valid demo email');
  }

  const user = await serverRepos.users.getByEmail(email);
  if (!user) {
    return (res as any).sendApiResponse(404, false, null, 'User not found', 'Unknown account email');
  }

  const token = `token-${user.id}-${Date.now()}`;
  sessions.set(token, user);

  return (res as any).sendApiResponse(200, true, {
    user,
    token
  }, null, `Authenticated successfully as ${user.name} (${user.role})`);
});

apiRouter.get('/auth/me', async (req: Request, res: Response) => {
  const user = await getAuthUser(req);
  if (!user) {
    return (res as any).sendApiResponse(401, false, null, 'Unauthenticated', 'No active session found');
  }
  return (res as any).sendApiResponse(200, true, user, null, 'Session active');
});

// ==========================================
// 2. Investigation CRUD Endpoints
// ==========================================

apiRouter.get('/investigations', async (req: Request, res: Response) => {
  const list = await serverRepos.investigations.getAll();
  return (res as any).sendApiResponse(200, true, list, null, `Retrieved ${list.length} investigations`);
});

apiRouter.get('/investigations/:id', async (req: Request, res: Response) => {
  const inv = await serverRepos.investigations.getById(req.params.id);
  if (!inv) {
    return (res as any).sendApiResponse(404, false, null, 'Not Found', `Investigation ${req.params.id} does not exist`);
  }
  return (res as any).sendApiResponse(200, true, inv, null, 'Investigation loaded');
});

apiRouter.post(
  '/investigations',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    try {
      const user: User = (req as any).user;
      const parsedBody = InvestigationFormSchema.parse(req.body);

      const newInv = await serverRepos.investigations.create({
        id: `inv-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        name: parsedBody.name,
        organizationName: parsedBody.organizationName,
        description: parsedBody.description,
        leadInvestigator: parsedBody.leadInvestigator || user.name,
        teamMembers: parsedBody.teamMembers,
        status: 'active',
        scope: parsedBody.scope,
        authorization: parsedBody.authorization,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdBy: user.id
      });

      return (res as any).sendApiResponse(201, true, newInv, null, 'Investigation created');
    } catch (err) {
      if (err instanceof z.ZodError) {
        return (res as any).sendApiResponse(400, false, null, 'Validation Error', err.errors.map(e => e.message).join(', '));
      }
      console.error('Create investigation error:', err);
      return (res as any).sendApiResponse(500, false, null, 'Server Error', 'Failed to create investigation');
    }
  }
);

apiRouter.patch(
  '/investigations/:id',
  requireRole(['admin', 'investigator', 'reviewer']),
  async (req: Request, res: Response) => {
    const updated = await serverRepos.investigations.update(req.params.id, req.body);
    if (!updated) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }
    return (res as any).sendApiResponse(200, true, updated, null, 'Investigation updated');
  }
);

apiRouter.delete(
  '/investigations/:id',
  requireRole(['admin']),
  async (req: Request, res: Response) => {
    const deleted = await serverRepos.investigations.delete(req.params.id);
    if (!deleted) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }
    return (res as any).sendApiResponse(200, true, null, null, 'Investigation deleted');
  }
);

// ==========================================
// 3. Scope Validation Endpoint
// ==========================================

apiRouter.post(
  '/investigations/:id/validate-scope',
  async (req: Request, res: Response) => {
    const { target, isActiveCheck } = req.body;
    if (!target) {
      return (res as any).sendApiResponse(400, false, null, 'Validation Error', 'Target is required');
    }

    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }

    const validation = await scopeValidator.validate(target, inv.scope, isActiveCheck);

    // Log the validation attempt
    await serverRepos.auditLogs.create({
      investigationId: inv.id,
      userId: (req as any).user?.id || 'unknown',
      action: isActiveCheck ? 'validate_active_scope' : 'validate_passive_scope',
      resourceType: 'scope',
      resourceId: target,
      details: { target, isActiveCheck, valid: validation.valid, reason: validation.reason }
    });

    return (res as any).sendApiResponse(200, true, validation, null, validation.reason);
  }
);

// ==========================================
// 4. Passive Recon Endpoints
// ==========================================

apiRouter.post(
  '/investigations/:id/collect/rdap',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const { domain } = req.body;
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }

    try {
      const targetDomain = domain || inv.scope.ownedDomains[0];
      const rdapData = await passiveReconService.collectRDAP(targetDomain);
      const evidence = await serverRepos.evidence.create({
        investigationId: inv.id,
        type: 'rdap',
        source: `RDAP: ${targetDomain}`,
        rawData: rdapData,
        collectedAt: new Date().toISOString()
      });

      // Normalize and correlate
      await evidenceNormalizer.normalizeAndCorrelate(evidence, inv);

      return (res as any).sendApiResponse(200, true, { rdap: rdapData, evidenceId: evidence.id }, null, 'RDAP collection completed');
    } catch (err) {
      console.error('RDAP collection error:', err);
      return (res as any).sendApiResponse(500, false, null, 'Collection Error', 'Failed to collect RDAP data');
    }
  }
);

apiRouter.post(
  '/investigations/:id/collect/dns',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const { domain } = req.body;
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }

    try {
      const targetDomain = domain || inv.scope.ownedDomains[0];
      const dnsData = await passiveReconService.collectDNS(targetDomain);
      const evidence = await serverRepos.evidence.create({
        investigationId: inv.id,
        type: 'dns',
        source: `DNS: ${targetDomain}`,
        rawData: dnsData,
        collectedAt: new Date().toISOString()
      });

      // Normalize and correlate
      await evidenceNormalizer.normalizeAndCorrelate(evidence, inv);

      return (res as any).sendApiResponse(200, true, { dns: dnsData, evidenceId: evidence.id }, null, 'DNS collection completed');
    } catch (err) {
      console.error('DNS collection error:', err);
      return (res as any).sendApiResponse(500, false, null, 'Collection Error', 'Failed to collect DNS data');
    }
  }
);

// ==========================================
// 5. Active Scan Import Endpoints
// ==========================================

apiRouter.post(
  '/investigations/:id/import/nmap',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const { xmlContent, filename } = req.body;
    if (!xmlContent) {
      return (res as any).sendApiResponse(400, false, null, 'Validation Error', 'XML content is required');
    }

    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }

    try {
      const result = await parseNmapXml(xmlContent, inv.scope, inv.id);
      const evidence = await serverRepos.evidence.create({
        investigationId: inv.id,
        type: 'nmap',
        source: filename || 'nmap_scan.xml',
        rawData: { hosts: result.hosts },
        collectedAt: new Date().toISOString()
      });

      await evidenceNormalizer.normalizeAndCorrelate(evidence, inv);

      return (res as any).sendApiResponse(200, true, { hosts: result.hosts, servicesIngested: result.servicesIngested, evidenceId: evidence.id }, null, `Validated allowlist and ingested ${result.servicesIngested} services`);
    } catch (err) {
      console.error('Nmap import error:', err);
      return (res as any).sendApiResponse(500, false, null, 'Import Error', err instanceof Error ? err.message : 'Failed to parse Nmap XML');
    }
  }
);

apiRouter.post(
  '/investigations/:id/import/openvas',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const { xmlContent, filename } = req.body;
    if (!xmlContent) {
      return (res as any).sendApiResponse(400, false, null, 'Validation Error', 'XML content is required');
    }

    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }

    try {
      const result = await parseOpenVASXml(xmlContent, inv.scope, inv.id);
      const evidence = await serverRepos.evidence.create({
        investigationId: inv.id,
        type: 'openvas',
        source: filename || 'openvas_report.xml',
        rawData: { findings: result.findings },
        collectedAt: new Date().toISOString()
      });

      await evidenceNormalizer.normalizeAndCorrelate(evidence, inv);

      return (res as any).sendApiResponse(200, true, { findingsIngested: result.findings.length, hosts: result.hosts, evidenceId: evidence.id }, null, `Imported ${result.findings.length} vulnerability findings`);
    } catch (err) {
      console.error('OpenVAS import error:', err);
      return (res as any).sendApiResponse(500, false, null, 'Import Error', err instanceof Error ? err.message : 'Failed to parse OpenVAS XML');
    }
  }
);

apiRouter.post(
  '/investigations/:id/import/harvester',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const { content, filename } = req.body;
    if (!content) {
      return (res as any).sendApiResponse(400, false, null, 'Validation Error', 'Content is required');
    }

    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }

    try {
      const result = await parseHarvesterExport(content, inv.id);
      const evidence = await serverRepos.evidence.create({
        investigationId: inv.id,
        type: 'harvester',
        source: filename || 'harvester_export.json',
        rawData: result,
        collectedAt: new Date().toISOString()
      });

      await evidenceNormalizer.normalizeAndCorrelate(evidence, inv);

      return (res as any).sendApiResponse(200, true, { summary: result, evidenceId: evidence.id }, null, `Ingested theHarvester data with ${result.emails?.length || 0} emails`);
    } catch (err) {
      console.error('Harvester import error:', err);
      return (res as any).sendApiResponse(500, false, null, 'Import Error', err instanceof Error ? err.message : 'Failed to parse Harvester data');
    }
  }
);

// ==========================================
// 6. Evidence & Entity Endpoints
// ==========================================

apiRouter.get('/investigations/:id/evidence', async (req: Request, res: Response) => {
  const evidence = await serverRepos.evidence.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, evidence, null, `Retrieved ${evidence.length} evidence records`);
});

apiRouter.post(
  '/investigations/:id/evidence/manual',
  requireRole(['admin', 'investigator', 'reviewer']),
  async (req: Request, res: Response) => {
    const { source, query, resultTitle, resultUrl, snippet } = req.body;
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }

    const evidence = await serverRepos.evidence.create({
      investigationId: inv.id,
      type: 'manual',
      source: `Manual: ${source}`,
      rawData: { query, resultTitle, resultUrl, snippet },
      collectedAt: new Date().toISOString()
    });

    await evidenceNormalizer.normalizeAndCorrelate(evidence, inv);

    return (res as any).sendApiResponse(201, true, evidence, null, 'Manual evidence recorded');
  }
);

apiRouter.get('/investigations/:id/entities', async (req: Request, res: Response) => {
  const entities = await serverRepos.entities.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, entities, null, `Retrieved ${entities.length} entities`);
});

apiRouter.get('/investigations/:id/relationships', async (req: Request, res: Response) => {
  const relationships = await serverRepos.relationships.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, relationships, null, `Retrieved ${relationships.length} relationships`);
});

apiRouter.get('/investigations/:id/services', async (req: Request, res: Response) => {
  const services = await serverRepos.services.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, services, null, `Retrieved ${services.length} services`);
});

// ==========================================
// 7. Findings & Exposure Score Endpoints
// ==========================================

apiRouter.get('/investigations/:id/findings', async (req: Request, res: Response) => {
  const findings = await serverRepos.findings.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, findings, null, `Retrieved ${findings.length} findings`);
});

apiRouter.patch(
  '/investigations/:id/findings/:findingId',
  requireRole(['admin', 'reviewer']),
  async (req: Request, res: Response) => {
    const { status, reviewerNotes } = req.body;
    const updated = await serverRepos.findings.update(req.params.findingId, { status, reviewerNotes });
    if (!updated) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Finding not found');
    }
    return (res as any).sendApiResponse(200, true, updated, null, 'Finding status updated');
  }
);

apiRouter.get('/investigations/:id/score', async (req: Request, res: Response) => {
  const score = await exposureScorer.calculate(req.params.id);
  return (res as any).sendApiResponse(200, true, score, null, 'Exposure score calculated');
});

apiRouter.post(
  '/investigations/:id/score',
  requireRole(['admin', 'reviewer']),
  async (req: Request, res: Response) => {
    const { reviewerNotes } = req.body;
    const score = await exposureScorer.calculate(req.params.id, reviewerNotes);
    return (res as any).sendApiResponse(200, true, score, null, 'Exposure score recalculated');
  }
);

// ==========================================
// 8. Reports Endpoints
// ==========================================

apiRouter.get('/investigations/:id/reports', async (req: Request, res: Response) => {
  const reports = await serverRepos.reports.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, reports, null, `Retrieved ${reports.length} reports`);
});

apiRouter.post(
  '/investigations/:id/reports',
  requireRole(['admin', 'reviewer']),
  async (req: Request, res: Response) => {
    const { title, type = 'full', format = 'pdf' } = req.body;
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }

    try {
      const report = await reportGenerator.generate({
        investigation: inv,
        findings: await serverRepos.findings.getByInvestigationId(inv.id),
        entities: await serverRepos.entities.getByInvestigationId(inv.id),
        evidence: await serverRepos.evidence.getByInvestigationId(inv.id),
        score: await exposureScorer.calculate(inv.id),
        type,
        format,
        title
      });

      const saved = await serverRepos.reports.create({
        investigationId: inv.id,
        title: report.title,
        type,
        format,
        generatedBy: (req as any).user?.name || 'Unknown',
        content: report.content,
        generatedAt: new Date().toISOString()
      });

      return (res as any).sendApiResponse(201, true, saved, null, 'Report generated');
    } catch (err) {
      console.error('Report generation error:', err);
      return (res as any).sendApiResponse(500, false, null, 'Generation Error', 'Failed to generate report');
    }
  }
);

apiRouter.get('/reports/:id/pdf', async (req: Request, res: Response) => {
  const report = await serverRepos.reports.getById(req.params.id);
  if (!report) {
    return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Report not found');
  }
  // PDF generation would go here
  return (res as any).sendApiResponse(501, false, null, 'Not Implemented', 'PDF generation not yet implemented');
});

// ==========================================
// 9. Audit Log Endpoints
// ==========================================

apiRouter.get('/investigations/:id/audit', async (req: Request, res: Response) => {
  const logs = await serverRepos.auditLogs.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, logs, null, `Retrieved ${logs.length} audit events`);
});

// ==========================================
// 10. Workflow & Worker Endpoints
// ==========================================

apiRouter.get('/investigations/:id/workflow', async (req: Request, res: Response) => {
  const runs = await serverRepos.workflowRuns.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, runs, null, `Retrieved ${runs.length} workflow runs`);
});

apiRouter.post(
  '/investigations/:id/workflow/start',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }

    const run = await workflowController.startWorkflow(inv.id, (req as any).user.id);
    return (res as any).sendApiResponse(201, true, run, null, 'Workflow started');
  }
);

apiRouter.post(
  '/workflow/:runId/approve',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const run = await workflowController.approveActiveStage(req.params.runId);
    return (res as any).sendApiResponse(200, true, run, null, 'Active stage approved');
  }
);

apiRouter.post(
  '/workflow/:runId/resume',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const run = await workflowController.resumeWorkflow(req.params.runId);
    return (res as any).sendApiResponse(200, true, run, null, 'Workflow resumed');
  }
);

apiRouter.post(
  '/workflow/:runId/cancel',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const run = await workflowController.cancelWorkflow(req.params.runId);
    return (res as any).sendApiResponse(200, true, run, null, 'Workflow cancelled');
  }
);

// Worker Management
apiRouter.get('/workers', async (req: Request, res: Response) => {
  const workers = await serverRepos.workers.getAll();
  return (res as any).sendApiResponse(200, true, workers, null, `Retrieved ${workers.length} workers`);
});

apiRouter.post(
  '/workers/register',
  requireRole(['admin']),
  async (req: Request, res: Response) => {
    const { name, environment, supportedProfiles, ipAddress } = req.body;
    const worker = await workerManager.registerWorker({
      id: `wkr-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      name,
      environment,
      supportedProfiles,
      ipAddress,
      registeredAt: new Date().toISOString(),
      status: 'active'
    });
    return (res as any).sendApiResponse(201, true, worker, null, 'Worker registered');
  }
);

apiRouter.post(
  '/workers/:workerId/revoke',
  requireRole(['admin']),
  async (req: Request, res: Response) => {
    await workerManager.revokeWorker(req.params.workerId);
    return (res as any).sendApiResponse(200, true, null, null, 'Worker revoked');
  }
);

apiRouter.post(
  '/workers/simulate-job/:jobId',
  requireRole(['admin']),
  async (req: Request, res: Response) => {
    const result = await workerManager.simulateJob(req.params.jobId);
    return (res as any).sendApiResponse(200, true, result, null, 'Job simulated');
  }
);

// ==========================================
// 11. Correlation & Scoring Endpoints
// ==========================================

apiRouter.post(
  '/investigations/:id/correlate',
  requireRole(['admin', 'investigator', 'reviewer']),
  async (req: Request, res: Response) => {
    const result = await correlationEngine.correlate(req.params.id);
    return (res as any).sendApiResponse(200, true, result, null, 'Correlation completed');
  }
);

apiRouter.post(
  '/investigations/:id/score',
  async (req: Request, res: Response) => {
    const { reviewerNotes } = req.body;
    const score = await exposureScorer.calculate(req.params.id, reviewerNotes);
    return (res as any).sendApiResponse(200, true, score, null, 'Exposure score calculated');
  }
);

// ==========================================
// 12. Export Endpoints
// ==========================================

apiRouter.get('/investigations/:id/export/bundle', async (req: Request, res: Response) => {
  const bundle = await serverRepos.exportBundle(req.params.id);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="footprint-bundle-${req.params.id}.json"`);
  res.send(JSON.stringify(bundle, null, 2));
});

apiRouter.get('/investigations/:id/export/findings-csv', async (req: Request, res: Response) => {
  const csv = await serverRepos.exportFindingsCSV(req.params.id);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="findings-${req.params.id}.csv"`);
  res.send(csv);
});

apiRouter.get('/investigations/:id/export/graphml', async (req: Request, res: Response) => {
  const graphml = await serverRepos.exportGraphML(req.params.id);
  res.setHeader('Content-Type', 'application/xml');
  res.setHeader('Content-Disposition', `attachment; filename="graph-${req.params.id}.graphml"`);
  res.send(graphml);
});

// ==========================================
// 13. Demo Endpoint
// ==========================================

apiRouter.post('/demo/run-safe', async (req: Request, res: Response) => {
  // Create a safe demo investigation if it doesn't exist
  let inv = await serverRepos.investigations.getById('inv-demo-001');
  if (!inv) {
    inv = await serverRepos.investigations.create({
      id: 'inv-demo-001',
      name: 'NorthStar Analytics Lab Demo',
      organizationName: 'NorthStar Analytics Lab',
      description: 'Safe demo investigation for lab environment',
      leadInvestigator: 'Demo User',
      teamMembers: [],
      status: 'active',
      scope: {
        ownedDomains: ['lab.example'],
        approvedCIDRs: ['192.168.56.0/24'],
        activeTargets: ['192.168.56.102', 'lab.example']
      },
      authorization: {
        authorizationReference: 'DEMO-2024-001',
        authorizedBy: 'Lab Instructor',
        validFrom: new Date().toISOString(),
        validUntil: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
        activeScanningEnabled: true,
        rulesOfEngagement: 'Demo environment only. No external network access.'
      },
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      createdBy: 'demo-user'
    });
  }

  const run = await workflowController.startWorkflow(inv.id, 'demo-user');
  return (res as any).sendApiResponse(201, true, { run, investigationId: inv.id }, null, 'Safe demo started');
});

export default apiRouter;