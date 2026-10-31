import {
  User,
  Investigation,
  Target,
  Evidence,
  Entity,
  Relationship,
  Service,
  Vulnerability,
  Finding,
  ExposureScoreBreakdown,
  Report,
  AuditEvent,
  CollectorRun,
  Scope,
  Authorization
} from '../../types/models';
import { serverDb } from './database';
import { calculateExposureScore } from '../../utils/scoring';
import { generateAuditHash } from '../../utils/hash';

export class UserRepository {
  async getAll(): Promise<User[]> {
    return serverDb.getSchema().users;
  }

  async getById(id: string): Promise<User | null> {
    return serverDb.getSchema().users.find(u => u.id === id) || null;
  }

  async getByEmail(email: string): Promise<User | null> {
    const normalized = email.trim().toLowerCase();
    return serverDb.getSchema().users.find(u => u.email.toLowerCase() === normalized) || null;
  }

  async create(user: User): Promise<User> {
    const now = new Date().toISOString();
    const newUser = {
      ...user,
      createdAt: user.createdAt || now,
      updatedAt: now
    };
    serverDb.getSchema().users.push(newUser);
    serverDb.saveToDisk();
    return newUser;
  }
}

export class InvestigationRepository {
  async getAll(): Promise<Investigation[]> {
    return serverDb.getSchema().investigations;
  }

  async getById(id: string): Promise<Investigation | null> {
    return serverDb.getSchema().investigations.find(i => i.id === id) || null;
  }

  async create(inv: Investigation): Promise<Investigation> {
    const now = new Date().toISOString();
    const record: Investigation = {
      ...inv,
      createdAt: inv.createdAt || now,
      updatedAt: now
    };
    serverDb.getSchema().investigations.unshift(record);

    // Initialize targets from scope
    for (const domain of record.scope.ownedDomains) {
      serverDb.getSchema().targets.push({
        id: `tgt-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        investigationId: record.id,
        type: 'domain',
        value: domain,
        interactionAllowed: ['passive'],
        isAllowlisted: true,
        addedAt: now,
        addedBy: record.leadInvestigator
      });
    }

    for (const ip of record.scope.activeTargets) {
      serverDb.getSchema().targets.push({
        id: `tgt-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        investigationId: record.id,
        type: 'ip',
        value: ip,
        interactionAllowed: ['passive', 'active'],
        isAllowlisted: true,
        addedAt: now,
        addedBy: record.leadInvestigator
      });
    }

    serverDb.saveToDisk();
    return record;
  }

  async update(id: string, updates: Partial<Investigation>): Promise<Investigation | null> {
    const list = serverDb.getSchema().investigations;
    const index = list.findIndex(i => i.id === id);
    if (index === -1) return null;

    const existing = list[index];
    const updated: Investigation = {
      ...existing,
      ...updates,
      scope: updates.scope ? { ...existing.scope, ...updates.scope } : existing.scope,
      authorization: updates.authorization ? { ...existing.authorization, ...updates.authorization } : existing.authorization,
      modules: updates.modules ? { ...existing.modules, ...updates.modules } : existing.modules,
      updatedAt: new Date().toISOString()
    };
    list[index] = updated;
    serverDb.saveToDisk();
    return updated;
  }

  async delete(id: string): Promise<boolean> {
    const db = serverDb.getSchema();
    const prevLen = db.investigations.length;
    db.investigations = db.investigations.filter(i => i.id !== id);
    db.targets = db.targets.filter(t => t.investigationId !== id);
    db.evidence = db.evidence.filter(e => e.investigationId !== id);
    db.entities = db.entities.filter(e => e.investigationId !== id);
    db.relationships = db.relationships.filter(r => r.investigationId !== id);
    db.services = db.services.filter(s => s.investigationId !== id);
    db.findings = db.findings.filter(f => f.investigationId !== id);
    db.reports = db.reports.filter(r => r.investigationId !== id);
    db.auditEvents = db.auditEvents.filter(a => a.investigationId !== id);
    db.collectorRuns = db.collectorRuns.filter(c => c.investigationId !== id);
    delete db.scores[id];
    serverDb.saveToDisk();
    return db.investigations.length < prevLen;
  }
}

export class TargetRepository {
  async getByInvestigationId(investigationId: string): Promise<Target[]> {
    return serverDb.getSchema().targets.filter(t => t.investigationId === investigationId);
  }

  async add(target: Target): Promise<Target> {
    serverDb.getSchema().targets.push(target);
    serverDb.saveToDisk();
    return target;
  }
}

export class EvidenceRepository {
  async getByInvestigationId(investigationId: string): Promise<Evidence[]> {
    return serverDb.getSchema().evidence.filter(e => e.investigationId === investigationId);
  }

  async add(evidence: Evidence): Promise<Evidence> {
    serverDb.getSchema().evidence.push(evidence);
    serverDb.saveToDisk();
    return evidence;
  }

  async findDuplicate(investigationId: string, type: string, value: string, target: string): Promise<Evidence | null> {
    return serverDb.getSchema().evidence.find(
      e => e.investigationId === investigationId && e.type === type && e.value === value && e.target === target
    ) || null;
  }
}

export class EntityRepository {
  async getByInvestigationId(investigationId: string): Promise<Entity[]> {
    return serverDb.getSchema().entities.filter(e => e.investigationId === investigationId);
  }

  async addOrMerge(entity: Entity): Promise<Entity> {
    const list = serverDb.getSchema().entities;
    const existing = list.find(
      e => e.investigationId === entity.investigationId &&
           e.type === entity.type &&
           e.primaryValue.toLowerCase() === entity.primaryValue.toLowerCase()
    );

    if (existing) {
      // Merge provenance & update verification
      existing.sourceEvidenceIds = Array.from(new Set([...existing.sourceEvidenceIds, ...entity.sourceEvidenceIds]));
      existing.metadata = { ...existing.metadata, ...entity.metadata };
      existing.lastVerifiedAt = new Date().toISOString();
      serverDb.saveToDisk();
      return existing;
    }

    list.push(entity);
    serverDb.saveToDisk();
    return entity;
  }
}

export class RelationshipRepository {
  async getByInvestigationId(investigationId: string): Promise<Relationship[]> {
    return serverDb.getSchema().relationships.filter(r => r.investigationId === investigationId);
  }

  async addOrMerge(rel: Relationship): Promise<Relationship> {
    const list = serverDb.getSchema().relationships;
    const existing = list.find(
      r => r.investigationId === rel.investigationId &&
           r.sourceEntityId === rel.sourceEntityId &&
           r.targetEntityId === rel.targetEntityId &&
           r.type === rel.type
    );

    if (existing) {
      existing.evidenceIds = Array.from(new Set([...existing.evidenceIds, ...rel.evidenceIds]));
      serverDb.saveToDisk();
      return existing;
    }

    list.push(rel);
    serverDb.saveToDisk();
    return rel;
  }
}

export class ServiceRepository {
  async getByInvestigationId(investigationId: string): Promise<Service[]> {
    return serverDb.getSchema().services.filter(s => s.investigationId === investigationId);
  }

  async addOrUpdate(service: Service): Promise<Service> {
    const list = serverDb.getSchema().services;
    const existing = list.find(
      s => s.investigationId === service.investigationId &&
           s.ip === service.ip &&
           s.port === service.port &&
           s.protocol === service.protocol
    );

    if (existing) {
      Object.assign(existing, service);
      serverDb.saveToDisk();
      return existing;
    }

    list.push(service);
    serverDb.saveToDisk();
    return service;
  }
}

export class VulnerabilityRepository {
  async getAll(): Promise<Vulnerability[]> {
    return serverDb.getSchema().vulnerabilities;
  }

  async add(vuln: Vulnerability): Promise<Vulnerability> {
    const list = serverDb.getSchema().vulnerabilities;
    const existing = list.find(v => (v.cveId && v.cveId === vuln.cveId) || v.title === vuln.title);
    if (existing) return existing;
    list.push(vuln);
    serverDb.saveToDisk();
    return vuln;
  }
}

export class FindingRepository {
  async getByInvestigationId(investigationId: string): Promise<Finding[]> {
    return serverDb.getSchema().findings.filter(f => f.investigationId === investigationId);
  }

  async addOrMerge(finding: Finding): Promise<Finding> {
    const list = serverDb.getSchema().findings;
    // Deduplicate by target, cve, and title
    const existing = list.find(
      f => f.investigationId === finding.investigationId &&
           f.target === finding.target &&
           ((f.cve && finding.cve && f.cve === finding.cve) || f.title === finding.title)
    );

    if (existing) {
      // Update description / cvss
      existing.description = finding.description;
      if (finding.cvss) existing.cvss = Math.max(existing.cvss || 0, finding.cvss);
      serverDb.saveToDisk();
      return existing;
    }

    list.push(finding);
    serverDb.saveToDisk();
    return finding;
  }

  async updateStatus(id: string, status: Finding['status']): Promise<Finding | null> {
    const list = serverDb.getSchema().findings;
    const finding = list.find(f => f.id === id);
    if (!finding) return null;
    finding.status = status;
    serverDb.saveToDisk();
    return finding;
  }
}

export class ExposureRepository {
  private findingRepo = new FindingRepository();
  private entityRepo = new EntityRepository();
  private serviceRepo = new ServiceRepository();

  async getScore(investigationId: string): Promise<ExposureScoreBreakdown> {
    const findings = await this.findingRepo.getByInvestigationId(investigationId);
    const entities = await this.entityRepo.getByInvestigationId(investigationId);
    const services = await this.serviceRepo.getByInvestigationId(investigationId);
    const score = calculateExposureScore(findings, entities, services);
    serverDb.getSchema().scores[investigationId] = score;
    serverDb.saveToDisk();
    return score;
  }
}

export class AuditRepository {
  async getByInvestigationId(investigationId: string): Promise<AuditEvent[]> {
    return serverDb.getSchema().auditEvents.filter(a => a.investigationId === investigationId);
  }

  async logEvent(event: Omit<AuditEvent, 'id' | 'auditHash'>): Promise<AuditEvent> {
    const id = `aud-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const auditHash = generateAuditHash(event.actor, event.action, event.timestamp);
    const record: AuditEvent = {
      ...event,
      id,
      auditHash
    };
    serverDb.getSchema().auditEvents.unshift(record);
    serverDb.saveToDisk();
    return record;
  }
}

export class ReportRepository {
  async getById(id: string): Promise<Report | null> {
    const rep = serverDb.getSchema().reports.find(r => r.id === id);
    return rep || null;
  }

  async getByInvestigationId(investigationId: string): Promise<Report[]> {
    return serverDb.getSchema().reports.filter(r => r.investigationId === investigationId);
  }

  async create(report: Report): Promise<Report> {
    serverDb.getSchema().reports.unshift(report);
    serverDb.saveToDisk();
    return report;
  }
}

export class CollectorRunRepository {
  async getByInvestigationId(investigationId: string): Promise<CollectorRun[]> {
    return serverDb.getSchema().collectorRuns.filter(c => c.investigationId === investigationId);
  }

  async create(run: CollectorRun): Promise<CollectorRun> {
    serverDb.getSchema().collectorRuns.unshift(run);
    serverDb.saveToDisk();
    return run;
  }

  async update(id: string, updates: Partial<CollectorRun>): Promise<CollectorRun | null> {
    const run = serverDb.getSchema().collectorRuns.find(c => c.id === id);
    if (!run) return null;
    Object.assign(run, updates, { updatedAt: new Date().toISOString() });
    serverDb.saveToDisk();
    return run;
  }
}

export const serverRepos = {
  users: new UserRepository(),
  investigations: new InvestigationRepository(),
  targets: new TargetRepository(),
  evidence: new EvidenceRepository(),
  entities: new EntityRepository(),
  relationships: new RelationshipRepository(),
  services: new ServiceRepository(),
  vulnerabilities: new VulnerabilityRepository(),
  findings: new FindingRepository(),
  scores: new ExposureRepository(),
  reports: new ReportRepository(),
  audit: new AuditRepository(),
  collectorRuns: new CollectorRunRepository()
};
