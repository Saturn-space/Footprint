import { Router, Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { serverRepos } from '../db/repositories';
import { scopeValidator } from '../services/scopeValidator';
import { passiveReconService } from '../services/passiveRecon';
import { parseNmapXml } from '../services/parsers/nmapParser';
import { parseOpenVASXml } from '../services/parsers/openvasParser';
import { parseHarvesterExport } from '../services/parsers/harvesterParser';
import { evidenceNormalizer } from '../services/normalizer';
import { generateEvidenceHash } from '../../utils/hash';
import { User, UserRole, ApiResponse, Evidence, Finding } from '../../types/models';
import { InvestigationFormSchema } from '../../types/schemas';
import { workflowController } from '../services/workflowController';
import { workerManager } from '../services/workerManager';
import { correlationEngine } from '../services/correlationEngine';
import { exposureScorer } from '../services/exposureScorer';
import { reportGenerator } from '../services/reportGenerator';

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
        modules: parsedBody.modules,
        tags: parsedBody.tags || [],
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });

      await serverRepos.audit.logEvent({
        investigationId: newInv.id,
        timestamp: new Date().toISOString(),
        actor: `${user.name} (${user.role})`,
        action: 'INVESTIGATION_CREATED',
        category: 'authorization',
        targetResource: newInv.organizationName,
        details: `Created investigation "${newInv.name}" with owned domain [${newInv.scope.ownedDomains.join(', ')}].`,
        status: 'allowed'
      });

      return (res as any).sendApiResponse(201, true, newInv, null, 'Investigation created successfully');
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message || 'Validation error', 'Invalid investigation configuration');
    }
  }
);

apiRouter.patch(
  '/investigations/:id',
  requireRole(['admin', 'investigator', 'reviewer']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    const updated = await serverRepos.investigations.update(req.params.id, req.body);
    if (!updated) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
    }

    await serverRepos.audit.logEvent({
      investigationId: updated.id,
      timestamp: new Date().toISOString(),
      actor: `${user.name} (${user.role})`,
      action: 'INVESTIGATION_UPDATED',
      category: 'system',
      targetResource: updated.name,
      details: `Updated investigation configuration.`,
      status: 'allowed'
    });

    return (res as any).sendApiResponse(200, true, updated, null, 'Investigation updated');
  }
);

apiRouter.delete(
  '/investigations/:id',
  requireRole(['admin']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    const success = await serverRepos.investigations.delete(req.params.id);
    if (!success) {
      return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found or already deleted');
    }

    await serverRepos.audit.logEvent({
      investigationId: req.params.id,
      timestamp: new Date().toISOString(),
      actor: `${user.name} (${user.role})`,
      action: 'INVESTIGATION_DELETED',
      category: 'system',
      targetResource: req.params.id,
      details: 'Investigation purged from server repository.',
      status: 'allowed'
    });

    return (res as any).sendApiResponse(200, true, { deletedId: req.params.id }, null, 'Investigation removed');
  }
);

// ==========================================
// 3. Scope Validation Endpoint
// ==========================================

apiRouter.post('/investigations/:id/validate-scope', async (req: Request, res: Response) => {
  const inv = await serverRepos.investigations.getById(req.params.id);
  if (!inv) {
    return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');
  }

  const { target, isActiveCheck } = req.body;
  if (!target) {
    return (res as any).sendApiResponse(400, false, null, 'Target missing', 'Specify target host, domain, or IP');
  }

  const result = await scopeValidator.validateTarget(inv, target, Boolean(isActiveCheck));
  return (res as any).sendApiResponse(200, true, result, null, result.isValid ? 'Target within approved scope' : (result.blockReason || 'Scope violation'));
});

// ==========================================
// 4. Passive Reconnaissance Endpoints
// ==========================================

apiRouter.post(
  '/investigations/:id/collect/rdap',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');

    const domain = req.body.domain || inv.scope.ownedDomains[0];
    const scopeCheck = await scopeValidator.enforceScope(
      inv,
      domain,
      'RDAP Query',
      user.name,
      false,
      (req as any).requestId
    );

    if (!scopeCheck.isValid) {
      return (res as any).sendApiResponse(403, false, null, scopeCheck.blockReason || 'Scope Denied', 'Target domain not authorized for passive recon');
    }

    try {
      const rdapData = await passiveReconService.collectRDAP(domain);

      // Ingest Evidence
      const evidence = await serverRepos.evidence.add({
        id: `ev-rdap-${Date.now()}`,
        investigationId: inv.id,
        type: 'RDAP_REGISTRATION',
        value: `RDAP Record for ${domain} (Registrar: ${rdapData.registrar}, Org: ${rdapData.registrantOrg})`,
        target: domain,
        sourceTool: 'RDAP/WHOIS Server Collector',
        collectedAt: new Date().toISOString(),
        interactionType: 'passive',
        confidence: 0.98,
        authorizedScope: true,
        attributes: rdapData as unknown as Record<string, unknown>,
        evidenceHash: generateEvidenceHash(`${domain}|rdap|${rdapData.registrar}`),
        validationStatus: 'verified'
      });

      // Correlate into graph
      await evidenceNormalizer.correlateEvidence(inv.id, evidence);

      // Audit
      await serverRepos.audit.logEvent({
        investigationId: inv.id,
        timestamp: new Date().toISOString(),
        actor: user.name,
        action: 'RDAP_COLLECTED',
        category: 'data_ingestion',
        targetResource: domain,
        details: `Collected structured RDAP registration data for ${domain} from ${rdapData.registrar}.`,
        status: 'allowed'
      });

      return (res as any).sendApiResponse(200, true, { rdap: rdapData, evidenceId: evidence.id }, null, `RDAP queried successfully for ${domain}`);
    } catch (err: any) {
      return (res as any).sendApiResponse(500, false, null, err.message, 'Failed to complete RDAP query');
    }
  }
);

apiRouter.post(
  '/investigations/:id/collect/dns',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');

    const domain = req.body.domain || inv.scope.ownedDomains[0];
    const scopeCheck = await scopeValidator.enforceScope(
      inv,
      domain,
      'DNS Recon Query',
      user.name,
      false,
      (req as any).requestId
    );

    if (!scopeCheck.isValid) {
      return (res as any).sendApiResponse(403, false, null, scopeCheck.blockReason || 'Scope Denied', 'Target domain not authorized for passive recon');
    }

    try {
      const dnsData = await passiveReconService.collectDNS(domain);

      const evidence = await serverRepos.evidence.add({
        id: `ev-dns-${Date.now()}`,
        investigationId: inv.id,
        type: 'DNS_ZONE_RECORDS',
        value: `DNS Telemetry for ${domain} (${dnsData.records.length} records, DMARC: ${dnsData.dmarcAudit.hasDmarc ? 'Yes' : 'Missing'})`,
        target: domain,
        sourceTool: 'Authoritative DNS Inspector',
        collectedAt: new Date().toISOString(),
        interactionType: 'passive',
        confidence: 1.0,
        authorizedScope: true,
        attributes: dnsData as unknown as Record<string, unknown>,
        evidenceHash: generateEvidenceHash(`${domain}|dns|${dnsData.records.length}`),
        validationStatus: 'verified'
      });

      await evidenceNormalizer.correlateEvidence(inv.id, evidence);

      await serverRepos.audit.logEvent({
        investigationId: inv.id,
        timestamp: new Date().toISOString(),
        actor: user.name,
        action: 'DNS_RECON_COLLECTED',
        category: 'data_ingestion',
        targetResource: domain,
        details: `Resolved ${dnsData.records.length} authoritative DNS records for ${domain}. DMARC status: ${dnsData.dmarcAudit.hasDmarc ? 'Configured' : 'Missing'}.`,
        status: 'allowed'
      });

      return (res as any).sendApiResponse(200, true, { dns: dnsData, evidenceId: evidence.id }, null, `Resolved DNS records for ${domain}`);
    } catch (err: any) {
      return (res as any).sendApiResponse(500, false, null, err.message, 'DNS resolution failure');
    }
  }
);

apiRouter.post(
  '/investigations/:id/evidence/manual',
  requireRole(['admin', 'investigator', 'reviewer']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');

    const { searchQuery, resultTitle, resultUrl, observation, screenshotRef, collectionTime, confidence, reviewerStatus } = req.body;

    if (!resultTitle || !resultUrl) {
      return (res as any).sendApiResponse(400, false, null, 'Missing title or URL', 'Evidence title and source URL are required');
    }

    const cleanUrl = evidenceNormalizer.normalizeURL(resultUrl);
    const hash = generateEvidenceHash(`${searchQuery}|${cleanUrl}|${observation}`);

    const evidence = await serverRepos.evidence.add({
      id: `ev-manual-${Date.now()}`,
      investigationId: inv.id,
      type: 'MANUAL_SEARCH_EVIDENCE',
      value: `Search Query: "${searchQuery || 'Direct Link'}" - Title: "${resultTitle}"`,
      target: cleanUrl,
      sourceTool: 'Manual Search Evidence Logger',
      collectedAt: collectionTime || new Date().toISOString(),
      interactionType: 'passive',
      confidence: typeof confidence === 'number' ? confidence : 0.8,
      authorizedScope: true,
      attributes: {
        searchQuery,
        resultTitle,
        resultUrl: cleanUrl,
        observation,
        screenshotRef,
        reviewerStatus: reviewerStatus || 'unreviewed',
        loggedBy: user.name
      },
      evidenceHash: hash,
      validationStatus: reviewerStatus === 'approved' ? 'verified' : 'unverified'
    });

    await evidenceNormalizer.correlateEvidence(inv.id, evidence);

    await serverRepos.audit.logEvent({
      investigationId: inv.id,
      timestamp: new Date().toISOString(),
      actor: user.name,
      action: 'MANUAL_EVIDENCE_LOGGED',
      category: 'data_ingestion',
      targetResource: cleanUrl,
      details: `Logged manual search discovery: "${resultTitle}". Observation: ${observation?.slice(0, 100) || 'None'}.`,
      status: 'allowed'
    });

    return (res as any).sendApiResponse(201, true, evidence, null, 'Manual search evidence cataloged');
  }
);

// ==========================================
// 5. Ingestion Parsers Endpoints
// ==========================================

apiRouter.post(
  '/investigations/:id/import/harvester',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');

    const { content, filename } = req.body;
    if (!content) {
      return (res as any).sendApiResponse(400, false, null, 'Content missing', 'Provide theHarvester export JSON or XML');
    }

    try {
      const parsed = parseHarvesterExport(content, filename);

      const evidence = await serverRepos.evidence.add({
        id: `ev-harvester-${Date.now()}`,
        investigationId: inv.id,
        type: 'THEHARVESTER_EXPORT',
        value: `theHarvester Dump: ${parsed.emails.length} emails, ${parsed.hosts.length} hosts, ${parsed.ips.length} IPs`,
        target: parsed.targetDomain || inv.scope.ownedDomains[0],
        sourceTool: 'theHarvester Import',
        sourceFile: parsed.sourceFile,
        collectedAt: new Date().toISOString(),
        interactionType: 'passive',
        confidence: 0.88,
        authorizedScope: true,
        attributes: {
          emails: parsed.emails,
          hosts: parsed.hosts,
          ips: parsed.ips,
          sources: parsed.sources
        },
        evidenceHash: generateEvidenceHash(content.slice(0, 500)),
        validationStatus: 'verified'
      });

      const correlated = await evidenceNormalizer.correlateEvidence(inv.id, evidence);

      await serverRepos.audit.logEvent({
        investigationId: inv.id,
        timestamp: new Date().toISOString(),
        actor: user.name,
        action: 'THEHARVESTER_IMPORTED',
        category: 'data_ingestion',
        targetResource: filename || 'theHarvester Export',
        details: `Imported ${parsed.emails.length} emails and ${parsed.hosts.length} subdomains. Graph added ${correlated.entitiesAdded} nodes.`,
        status: 'allowed'
      });

      return (res as any).sendApiResponse(200, true, {
        summary: {
          emailsExtracted: parsed.emails.length,
          hostsExtracted: parsed.hosts.length,
          ipsExtracted: parsed.ips.length,
          entitiesAdded: correlated.entitiesAdded
        },
        evidenceId: evidence.id
      }, null, 'theHarvester export ingested successfully');
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Failed to parse theHarvester export');
    }
  }
);

apiRouter.post(
  '/investigations/:id/import/nmap',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');

    const { xmlContent, filename } = req.body;
    if (!xmlContent) {
      return (res as any).sendApiResponse(400, false, null, 'Missing XML', 'Provide Nmap XML payload');
    }

    try {
      const parsed = parseNmapXml(xmlContent);

      if (parsed.hosts.length === 0) {
        return (res as any).sendApiResponse(400, false, null, 'No hosts found in Nmap XML', 'File parsed but contains no host entries');
      }

      // Check every host against active target allowlist
      for (const h of parsed.hosts) {
        const scopeCheck = await scopeValidator.enforceScope(
          inv,
          h.ip,
          'Nmap XML Ingestion',
          user.name,
          true,
          (req as any).requestId
        );

        if (!scopeCheck.isValid) {
          return (res as any).sendApiResponse(
            403,
            false,
            null,
            `BLOCKED: Host ${h.ip} is outside active allowlist (${inv.scope.activeTargets.join(', ') || 'none'})`,
            'Active scan ingestion blocked by scope safety policy'
          );
        }
      }

      // Ingest Services & Host Entities
      let portsAdded = 0;
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
            banner: p.extraInfo || `${p.serviceName} on port ${p.port}`,
            state: p.state,
            cpe: p.cpe
          });
          portsAdded++;
        }
      }

      const evidence = await serverRepos.evidence.add({
        id: `ev-nmap-${Date.now()}`,
        investigationId: inv.id,
        type: 'NMAP_XML_SCAN',
        value: `Nmap Scan: ${parsed.hosts.length} hosts (${parsed.hosts.map(h => h.ip).join(', ')}), ${portsAdded} services`,
        target: parsed.hosts[0]?.ip || 'Unknown',
        sourceTool: 'Nmap XML Parser',
        sourceFile: filename || 'nmap_out.xml',
        collectedAt: new Date().toISOString(),
        interactionType: 'active',
        confidence: 1.0,
        authorizedScope: true,
        attributes: {
          hostsCount: parsed.hosts.length,
          portsCount: portsAdded,
          scannerVersion: parsed.version
        },
        evidenceHash: generateEvidenceHash(xmlContent.slice(0, 500)),
        validationStatus: 'verified'
      });

      await serverRepos.audit.logEvent({
        investigationId: inv.id,
        timestamp: new Date().toISOString(),
        actor: user.name,
        action: 'NMAP_XML_INGESTED',
        category: 'data_ingestion',
        targetResource: parsed.hosts.map(h => h.ip).join(', '),
        details: `Successfully ingested Nmap scan for allowlisted host(s): ${parsed.hosts.map(h => h.ip).join(', ')}. Registered ${portsAdded} open/filtered services.`,
        status: 'allowed'
      });

      return (res as any).sendApiResponse(200, true, {
        hosts: parsed.hosts.map(h => ({ ip: h.ip, openPorts: h.ports.length })),
        servicesIngested: portsAdded,
        evidenceId: evidence.id
      }, null, 'Nmap XML successfully validated against active allowlist and ingested');
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Failed to parse Nmap XML');
    }
  }
);

apiRouter.post(
  '/investigations/:id/import/openvas',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    const inv = await serverRepos.investigations.getById(req.params.id);
    if (!inv) return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Investigation not found');

    const { xmlContent, filename } = req.body;
    if (!xmlContent) {
      return (res as any).sendApiResponse(400, false, null, 'Missing XML', 'Provide OpenVAS XML payload');
    }

    try {
      const parsed = parseOpenVASXml(xmlContent);

      if (parsed.hostsDetected.length === 0) {
        return (res as any).sendApiResponse(400, false, null, 'No hosts detected in OpenVAS report', 'Report contains zero target hosts');
      }

      // Check allowlist
      for (const host of parsed.hostsDetected) {
        const scopeCheck = await scopeValidator.enforceScope(
          inv,
          host,
          'OpenVAS Report Ingestion',
          user.name,
          true,
          (req as any).requestId
        );

        if (!scopeCheck.isValid) {
          return (res as any).sendApiResponse(
            403,
            false,
            null,
            `BLOCKED: Target host "${host}" is not on the authorized active allowlist`,
            'OpenVAS ingestion rejected by scope safety policy'
          );
        }
      }

      // Ingest Findings
      for (const f of parsed.findings) {
        await serverRepos.findings.addOrMerge({
          id: `fnd-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
          investigationId: inv.id,
          title: f.name,
          category: f.name.toLowerCase().includes('leak') || f.name.toLowerCase().includes('metric')
            ? 'information_disclosure'
            : f.name.toLowerCase().includes('tls') || f.name.toLowerCase().includes('ssl')
            ? 'misconfiguration'
            : 'attack_surface',
          severity: f.severity,
          status: 'open',
          target: `${f.host}:${f.port}`,
          description: f.description || `Scanner detected ${f.name} on ${f.host}:${f.port}`,
          sourceTool: 'OpenVAS / Greenbone XML Parser',
          interactionType: 'active',
          cvss: f.cvss,
          cve: f.cveReferences[0],
          remediationAdvice: f.solution || 'Review vendor security advisories and update service configuration.',
          detectedAt: new Date().toISOString()
        });
      }

      const evidence = await serverRepos.evidence.add({
        id: `ev-openvas-${Date.now()}`,
        investigationId: inv.id,
        type: 'OPENVAS_VULN_REPORT',
        value: `OpenVAS Report: ${parsed.findings.length} vulnerability findings across ${parsed.hostsDetected.join(', ')}`,
        target: parsed.hostsDetected[0] || 'Unknown',
        sourceTool: 'OpenVAS / Greenbone XML Parser',
        sourceFile: filename || 'openvas_report.xml',
        collectedAt: new Date().toISOString(),
        interactionType: 'active',
        confidence: 0.95,
        authorizedScope: true,
        attributes: {
          findingsCount: parsed.findings.length,
          hosts: parsed.hostsDetected
        },
        evidenceHash: generateEvidenceHash(xmlContent.slice(0, 500)),
        validationStatus: 'verified'
      });

      await serverRepos.audit.logEvent({
        investigationId: inv.id,
        timestamp: new Date().toISOString(),
        actor: user.name,
        action: 'OPENVAS_REPORT_INGESTED',
        category: 'data_ingestion',
        targetResource: parsed.hostsDetected.join(', '),
        details: `Imported OpenVAS XML for allowlisted host(s): ${parsed.hostsDetected.join(', ')}. Ingested ${parsed.findings.length} findings.`,
        status: 'allowed'
      });

      return (res as any).sendApiResponse(200, true, {
        findingsIngested: parsed.findings.length,
        hosts: parsed.hostsDetected,
        evidenceId: evidence.id
      }, null, 'OpenVAS report parsed and ingested successfully');
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Failed to parse OpenVAS XML');
    }
  }
);

// ==========================================
// 6. Artifact Retrieval Endpoints
// ==========================================

apiRouter.get('/investigations/:id/entities', async (req: Request, res: Response) => {
  const entities = await serverRepos.entities.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, entities, null, `Retrieved ${entities.length} entities`);
});

apiRouter.get('/investigations/:id/relationships', async (req: Request, res: Response) => {
  const rels = await serverRepos.relationships.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, rels, null, `Retrieved ${rels.length} relationships`);
});

apiRouter.get('/investigations/:id/findings', async (req: Request, res: Response) => {
  const findings = await serverRepos.findings.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, findings, null, `Retrieved ${findings.length} findings`);
});

apiRouter.get('/investigations/:id/services', async (req: Request, res: Response) => {
  const services = await serverRepos.services.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, services, null, `Retrieved ${services.length} services`);
});

apiRouter.get('/investigations/:id/evidence', async (req: Request, res: Response) => {
  const evidence = await serverRepos.evidence.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, evidence, null, `Retrieved ${evidence.length} evidence records`);
});

apiRouter.get('/investigations/:id/score', async (req: Request, res: Response) => {
  const score = await serverRepos.scores.getScore(req.params.id);
  return (res as any).sendApiResponse(200, true, score, null, 'Exposure score calculated');
});

apiRouter.get('/investigations/:id/audit', async (req: Request, res: Response) => {
  const logs = await serverRepos.audit.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, logs, null, `Retrieved ${logs.length} audit events`);
});

// ==========================================
// 7. Semi-Autonomous Workflow Endpoints
// ==========================================

apiRouter.post(
  '/investigations/:id/workflow/start',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    try {
      const run = await workflowController.startWorkflow(req.params.id, `${user.name} (${user.role})`);
      return (res as any).sendApiResponse(
        201,
        true,
        run,
        null,
        `Workflow run ${run.id} started. Stage: ${run.currentState}`
      );
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Failed to start workflow run');
    }
  }
);

apiRouter.get('/investigations/:id/workflow', async (req: Request, res: Response) => {
  const runs = workflowController.getAllRuns(req.params.id);
  return (res as any).sendApiResponse(200, true, runs, null, `Retrieved ${runs.length} workflow runs`);
});

apiRouter.get('/workflow/:runId', async (req: Request, res: Response) => {
  const run = workflowController.getRun(req.params.runId);
  if (!run) {
    return (res as any).sendApiResponse(404, false, null, 'Not Found', 'Workflow run not found');
  }
  return (res as any).sendApiResponse(200, true, run, null, `Workflow run state: ${run.currentState}`);
});

apiRouter.post(
  '/workflow/:runId/approve',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    try {
      const run = await workflowController.approveActiveStage(req.params.runId, `${user.name} (${user.role})`);
      return (res as any).sendApiResponse(
        200,
        true,
        run,
        null,
        'Active reconnaissance stage approved by authorized investigator.'
      );
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Failed to approve active stage');
    }
  }
);

apiRouter.post(
  '/workflow/:runId/resume',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    try {
      const run = await workflowController.resumeWorkflow(req.params.runId, `${user.name} (${user.role})`);
      return (res as any).sendApiResponse(
        200,
        true,
        run,
        null,
        `Workflow resumed from last safe checkpoint: ${run.lastSafeState}`
      );
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Failed to resume workflow run');
    }
  }
);

apiRouter.post(
  '/workflow/:runId/cancel',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    try {
      const run = await workflowController.cancelWorkflow(req.params.runId, `${user.name} (${user.role})`);
      return (res as any).sendApiResponse(200, true, run, null, 'Workflow execution successfully cancelled.');
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Failed to cancel workflow');
    }
  }
);

apiRouter.post('/demo/run-safe', async (req: Request, res: Response) => {
  const user = await getAuthUser(req);
  const actor = user ? `${user.name} (${user.role})` : 'Asip Ali (Admin)';
  try {
    const result = await workflowController.runSafeDemo(actor);
    return (res as any).sendApiResponse(
      200,
      true,
      result,
      null,
      'Safe demonstration workflow launched for NorthStar Analytics Lab.'
    );
  } catch (err: any) {
    return (res as any).sendApiResponse(500, false, null, err.message, 'Failed to launch safe demo');
  }
});

// ==========================================
// 8. Authorized Worker Control Plane Endpoints
// ==========================================

apiRouter.get('/workers', async (req: Request, res: Response) => {
  const workers = workerManager.getAllWorkers();
  return (res as any).sendApiResponse(200, true, workers, null, `Retrieved ${workers.length} registered workers`);
});

apiRouter.post(
  '/workers/register',
  requireRole(['admin']),
  async (req: Request, res: Response) => {
    const { name, environment, supportedProfiles, ipAddress } = req.body;
    if (!name || !supportedProfiles || !Array.isArray(supportedProfiles)) {
      return (res as any).sendApiResponse(
        400,
        false,
        null,
        'Invalid registration data',
        'Worker name and supported profiles list are required'
      );
    }

    try {
      const worker = await workerManager.registerWorker(name, environment || 'local_lab', supportedProfiles, ipAddress);
      return (res as any).sendApiResponse(
        201,
        true,
        worker,
        null,
        `Worker "${worker.name}" registered. Store the secretToken securely.`
      );
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Worker registration failed');
    }
  }
);

apiRouter.post('/workers/heartbeat', async (req: Request, res: Response) => {
  const { workerId, token } = req.body;
  if (!workerId || !token) {
    return (res as any).sendApiResponse(400, false, null, 'Missing credentials', 'Worker ID and token required');
  }

  const ok = await workerManager.recordHeartbeat(workerId, token);
  if (!ok) {
    return (res as any).sendApiResponse(401, false, null, 'Heartbeat rejected', 'Invalid worker token or revoked worker');
  }

  return (res as any).sendApiResponse(200, true, { acknowledged: true, timestamp: new Date().toISOString() }, null, 'Heartbeat acknowledged');
});

apiRouter.post('/workers/jobs/poll', async (req: Request, res: Response) => {
  const { workerId, secretToken } = req.body;
  if (!workerId || !secretToken) {
    return (res as any).sendApiResponse(400, false, null, 'Credentials required', 'Provide workerId and secretToken');
  }

  try {
    const jobs = await workerManager.pollJobs(workerId, secretToken);
    return (res as any).sendApiResponse(200, true, jobs, null, `Polled ${jobs.length} pending queued jobs`);
  } catch (err: any) {
    return (res as any).sendApiResponse(401, false, null, err.message, 'Job polling failed');
  }
});

apiRouter.post('/workers/jobs/:jobId/accept', async (req: Request, res: Response) => {
  const { token } = req.body;
  if (!token) {
    return (res as any).sendApiResponse(400, false, null, 'Job token required', 'Provide job authorization token');
  }

  try {
    const job = await workerManager.acceptJob(req.params.jobId, token);
    return (res as any).sendApiResponse(200, true, job, null, `Job ${job.id} accepted for execution`);
  } catch (err: any) {
    return (res as any).sendApiResponse(403, false, null, err.message, 'Failed to accept job');
  }
});

apiRouter.post('/workers/jobs/:jobId/progress', async (req: Request, res: Response) => {
  const { token, progressPercent } = req.body;
  if (!token || typeof progressPercent !== 'number') {
    return (res as any).sendApiResponse(400, false, null, 'Invalid payload', 'Provide token and progressPercent (number)');
  }

  try {
    const job = await workerManager.updateProgress(req.params.jobId, token, progressPercent);
    return (res as any).sendApiResponse(200, true, job, null, `Progress updated to ${job.progressPercent}%`);
  } catch (err: any) {
    return (res as any).sendApiResponse(400, false, null, err.message, 'Progress update failed');
  }
});

apiRouter.post('/workers/jobs/:jobId/result', async (req: Request, res: Response) => {
  const { token, reportedTarget, resultPayload, providedHash } = req.body;
  if (!token || !reportedTarget || !resultPayload) {
    return (res as any).sendApiResponse(
      400,
      false,
      null,
      'Incomplete result',
      'Requires token, reportedTarget, and resultPayload XML'
    );
  }

  try {
    const job = await workerManager.submitResult(
      req.params.jobId,
      token,
      reportedTarget,
      resultPayload,
      providedHash
    );
    return (res as any).sendApiResponse(
      200,
      true,
      job,
      null,
      `Result accepted and verified with SHA-256 digest: ${job.resultHash}`
    );
  } catch (err: any) {
    return (res as any).sendApiResponse(400, false, null, err.message, 'Result upload rejected by security verifier');
  }
});

apiRouter.get('/workers/jobs/:jobId', async (req: Request, res: Response) => {
  const job = workerManager.getJob(req.params.jobId);
  if (!job) {
    return (res as any).sendApiResponse(404, false, null, 'Job not found', 'Invalid job ID');
  }
  return (res as any).sendApiResponse(200, true, job, null, `Job status: ${job.status}`);
});

apiRouter.post(
  '/workers/:workerId/revoke',
  requireRole(['admin']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    const ok = await workerManager.revokeWorker(req.params.workerId, user.name);
    if (!ok) {
      return (res as any).sendApiResponse(404, false, null, 'Worker not found', 'Invalid worker ID');
    }
    return (res as any).sendApiResponse(200, true, { revoked: true }, null, `Worker ${req.params.workerId} revoked.`);
  }
);

apiRouter.post(
  '/workers/simulate-job/:jobId',
  requireRole(['admin', 'investigator']),
  async (req: Request, res: Response) => {
    try {
      const job = await workerManager.executeSimulatedJob(req.params.jobId);
      return (res as any).sendApiResponse(200, true, job, null, 'Simulated job executed successfully in sandbox.');
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Simulated job execution failed');
    }
  }
);

// ==========================================
// 9. Multi-Factor Correlation & 5-Factor Exposure Scoring
// ==========================================

apiRouter.post(
  '/investigations/:id/correlate',
  requireRole(['admin', 'investigator', 'reviewer']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    try {
      const result = await correlationEngine.correlateInvestigation(req.params.id);
      await serverRepos.audit.logEvent({
        investigationId: req.params.id,
        timestamp: new Date().toISOString(),
        actor: user.name,
        action: 'CORRELATION_ENGINE_RUN',
        category: 'correlation',
        targetResource: req.params.id,
        details: `Correlated ${result.entitiesCount} entities and established ${result.newRelationshipsAdded} new relationships.`,
        status: 'allowed'
      });
      return (res as any).sendApiResponse(
        200,
        true,
        result,
        null,
        `Multi-factor correlation mapped ${result.relationshipsCount} relationships across ${result.entitiesCount} entities.`
      );
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Correlation failed');
    }
  }
);

apiRouter.post(
  '/investigations/:id/score',
  requireRole(['admin', 'investigator', 'reviewer']),
  async (req: Request, res: Response) => {
    const { reviewerNotes } = req.body;
    try {
      const findings = await serverRepos.findings.getByInvestigationId(req.params.id);
      const entities = await serverRepos.entities.getByInvestigationId(req.params.id);
      const services = await serverRepos.services.getByInvestigationId(req.params.id);
      const evidenceList = await serverRepos.evidence.getByInvestigationId(req.params.id);

      const score = exposureScorer.calculateScore(findings, entities, services, evidenceList, reviewerNotes);
      return (res as any).sendApiResponse(
        200,
        true,
        score,
        null,
        `5-factor exposure score calculated: ${score.totalScore}/100 (${score.tier}).`
      );
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Exposure score calculation failed');
    }
  }
);

// ==========================================
// 10. Comprehensive 20-Section Reporting & Exports
// ==========================================

apiRouter.post(
  '/investigations/:id/reports',
  requireRole(['admin', 'investigator', 'reviewer']),
  async (req: Request, res: Response) => {
    const user: User = (req as any).user;
    const { title } = req.body;
    try {
      const report = await reportGenerator.generateComprehensiveReport(
        req.params.id,
        title || 'FootprintIQ Comprehensive Reconnaissance Dossier',
        `${user.name} (${user.role})`
      );
      return (res as any).sendApiResponse(
        201,
        true,
        report,
        null,
        `Comprehensive 20-section report "${report.title}" generated.`
      );
    } catch (err: any) {
      return (res as any).sendApiResponse(400, false, null, err.message, 'Report generation failed');
    }
  }
);

apiRouter.get('/investigations/:id/reports', async (req: Request, res: Response) => {
  const reports = await serverRepos.reports.getByInvestigationId(req.params.id);
  return (res as any).sendApiResponse(200, true, reports, null, `Retrieved ${reports.length} reports`);
});

apiRouter.get('/reports/:reportId', async (req: Request, res: Response) => {
  const report = await serverRepos.reports.getById(req.params.reportId);
  if (!report) {
    return (res as any).sendApiResponse(404, false, null, 'Report not found', 'Invalid report ID');
  }
  return (res as any).sendApiResponse(200, true, report, null, 'Report retrieved');
});

apiRouter.get('/reports/:reportId/pdf', async (req: Request, res: Response) => {
  const report = await serverRepos.reports.getById(req.params.reportId);
  if (!report) {
    return res.status(404).json({ error: 'Report not found' });
  }

  const inv = await serverRepos.investigations.getById(report.investigationId);
  if (!inv) {
    return res.status(404).json({ error: 'Investigation not found' });
  }

  try {
    const pdfBytes = await reportGenerator.buildBinaryPdf(report, inv);
    const filename = `${report.title.replace(/[^a-zA-Z0-9_-]/g, '_').toLowerCase()}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.send(Buffer.from(pdfBytes));
  } catch (err: any) {
    return res.status(500).json({ error: 'PDF generation failed', details: err.message });
  }
});

apiRouter.get('/investigations/:id/export/bundle', async (req: Request, res: Response) => {
  const inv = await serverRepos.investigations.getById(req.params.id);
  if (!inv) return res.status(404).json({ error: 'Investigation not found' });

  const [entities, relationships, findings, services, evidenceList, score, audit] = await Promise.all([
    serverRepos.entities.getByInvestigationId(inv.id),
    serverRepos.relationships.getByInvestigationId(inv.id),
    serverRepos.findings.getByInvestigationId(inv.id),
    serverRepos.services.getByInvestigationId(inv.id),
    serverRepos.evidence.getByInvestigationId(inv.id),
    serverRepos.scores.getScore(inv.id),
    serverRepos.audit.getByInvestigationId(inv.id)
  ]);

  const bundle = {
    exportVersion: '3.0.0',
    exportedAt: new Date().toISOString(),
    investigation: inv,
    metrics: {
      entitiesCount: entities.length,
      relationshipsCount: relationships.length,
      findingsCount: findings.length,
      servicesCount: services.length,
      evidenceCount: evidenceList.length,
      exposureScore: score.totalScore,
      exposureTier: score.tier
    },
    entities,
    relationships,
    findings,
    services,
    evidence: evidenceList,
    exposureScore: score,
    auditTrail: audit
  };

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="footprintiq_bundle_${inv.id}.json"`);
  return res.json(bundle);
});

apiRouter.get('/investigations/:id/export/findings-csv', async (req: Request, res: Response) => {
  const csv = await reportGenerator.exportFindingsCSV(req.params.id);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="findings_${req.params.id}.csv"`);
  return res.send(csv);
});

apiRouter.get('/investigations/:id/export/nodes-csv', async (req: Request, res: Response) => {
  const csv = await reportGenerator.exportNodesCSV(req.params.id);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="nodes_${req.params.id}.csv"`);
  return res.send(csv);
});

apiRouter.get('/investigations/:id/export/edges-csv', async (req: Request, res: Response) => {
  const csv = await reportGenerator.exportEdgesCSV(req.params.id);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="edges_${req.params.id}.csv"`);
  return res.send(csv);
});

apiRouter.get('/investigations/:id/export/graphml', async (req: Request, res: Response) => {
  const xml = await reportGenerator.exportGraphML(req.params.id);
  res.setHeader('Content-Type', 'application/xml');
  res.setHeader('Content-Disposition', `attachment; filename="knowledge_graph_${req.params.id}.graphml"`);
  return res.send(xml);
});

