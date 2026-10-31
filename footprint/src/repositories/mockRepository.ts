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
  ExposureScoreBreakdown
} from '../types/models';
import {
  IInvestigationRepository,
  ITargetRepository,
  IEvidenceRepository,
  IEntityRepository,
  IFindingRepository,
  IAuditRepository,
  IExposureRepository,
  IReportRepository
} from './interfaces';
import {
  INITIAL_INVESTIGATION,
  INITIAL_TARGETS,
  INITIAL_EVIDENCE,
  INITIAL_ENTITIES,
  INITIAL_RELATIONSHIPS,
  INITIAL_SERVICES,
  INITIAL_FINDINGS,
  INITIAL_AUDIT_LOGS
} from '../data/seedData';
import { calculateExposureScore } from '../utils/scoring';
import { generateAuditHash } from '../utils/hash';

const STORAGE_KEYS = {
  INVESTIGATIONS: 'footprintiq_investigations_v1',
  TARGETS: 'footprintiq_targets_v1',
  EVIDENCE: 'footprintiq_evidence_v1',
  ENTITIES: 'footprintiq_entities_v1',
  RELATIONSHIPS: 'footprintiq_relationships_v1',
  SERVICES: 'footprintiq_services_v1',
  FINDINGS: 'footprintiq_findings_v1',
  AUDIT_LOGS: 'footprintiq_audit_logs_v1',
  REPORTS: 'footprintiq_reports_v1'
};

function getItem<T>(key: string, defaultValue: T): T {
  try {
    const val = localStorage.getItem(key);
    if (!val) return defaultValue;
    return JSON.parse(val) as T;
  } catch {
    return defaultValue;
  }
}

function setItem<T>(key: string, value: T): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch (e) {
    console.error(`Failed to persist key ${key} to localStorage:`, e);
  }
}

// Initialize seed data if not present
export function initializeStorage(): void {
  if (!localStorage.getItem(STORAGE_KEYS.INVESTIGATIONS)) {
    setItem(STORAGE_KEYS.INVESTIGATIONS, [INITIAL_INVESTIGATION]);
  }
  if (!localStorage.getItem(STORAGE_KEYS.TARGETS)) {
    setItem(STORAGE_KEYS.TARGETS, INITIAL_TARGETS);
  }
  if (!localStorage.getItem(STORAGE_KEYS.EVIDENCE)) {
    setItem(STORAGE_KEYS.EVIDENCE, INITIAL_EVIDENCE);
  }
  if (!localStorage.getItem(STORAGE_KEYS.ENTITIES)) {
    setItem(STORAGE_KEYS.ENTITIES, INITIAL_ENTITIES);
  }
  if (!localStorage.getItem(STORAGE_KEYS.RELATIONSHIPS)) {
    setItem(STORAGE_KEYS.RELATIONSHIPS, INITIAL_RELATIONSHIPS);
  }
  if (!localStorage.getItem(STORAGE_KEYS.SERVICES)) {
    setItem(STORAGE_KEYS.SERVICES, INITIAL_SERVICES);
  }
  if (!localStorage.getItem(STORAGE_KEYS.FINDINGS)) {
    setItem(STORAGE_KEYS.FINDINGS, INITIAL_FINDINGS);
  }
  if (!localStorage.getItem(STORAGE_KEYS.AUDIT_LOGS)) {
    setItem(STORAGE_KEYS.AUDIT_LOGS, INITIAL_AUDIT_LOGS);
  }
  if (!localStorage.getItem(STORAGE_KEYS.REPORTS)) {
    setItem(STORAGE_KEYS.REPORTS, []);
  }
}

export class MockInvestigationRepository implements IInvestigationRepository {
  async getAll(): Promise<Investigation[]> {
    return getItem<Investigation[]>(STORAGE_KEYS.INVESTIGATIONS, [INITIAL_INVESTIGATION]);
  }

  async getById(id: string): Promise<Investigation | null> {
    const list = await this.getAll();
    return list.find(item => item.id === id) || null;
  }

  async create(investigation: Investigation): Promise<Investigation> {
    const list = await this.getAll();
    const updated = [investigation, ...list];
    setItem(STORAGE_KEYS.INVESTIGATIONS, updated);
    return investigation;
  }

  async update(investigation: Investigation): Promise<Investigation> {
    const list = await this.getAll();
    const updated = list.map(item => item.id === investigation.id ? investigation : item);
    setItem(STORAGE_KEYS.INVESTIGATIONS, updated);
    return investigation;
  }

  async delete(id: string): Promise<boolean> {
    const list = await this.getAll();
    const updated = list.filter(item => item.id !== id);
    setItem(STORAGE_KEYS.INVESTIGATIONS, updated);
    return true;
  }
}

export class MockTargetRepository implements ITargetRepository {
  async getByInvestigationId(investigationId: string): Promise<Target[]> {
    const all = getItem<Target[]>(STORAGE_KEYS.TARGETS, INITIAL_TARGETS);
    return all.filter(t => t.investigationId === investigationId);
  }

  async add(target: Target): Promise<Target> {
    const all = getItem<Target[]>(STORAGE_KEYS.TARGETS, INITIAL_TARGETS);
    const updated = [target, ...all];
    setItem(STORAGE_KEYS.TARGETS, updated);
    return target;
  }

  async delete(id: string): Promise<boolean> {
    const all = getItem<Target[]>(STORAGE_KEYS.TARGETS, INITIAL_TARGETS);
    setItem(STORAGE_KEYS.TARGETS, all.filter(t => t.id !== id));
    return true;
  }

  async isTargetAllowlistedForActive(investigationId: string, targetHost: string): Promise<boolean> {
    const targets = await this.getByInvestigationId(investigationId);
    const normalizedHost = targetHost.trim().toLowerCase();
    
    // Check if target is explicitly allowlisted for active interaction
    return targets.some(t => {
      const matchValue = t.value.trim().toLowerCase();
      const allowsActive = t.interactionAllowed.includes('active');
      return t.isAllowlisted && allowsActive && (matchValue === normalizedHost || normalizedHost.startsWith(matchValue));
    });
  }
}

export class MockEvidenceRepository implements IEvidenceRepository {
  async getByInvestigationId(investigationId: string): Promise<Evidence[]> {
    const all = getItem<Evidence[]>(STORAGE_KEYS.EVIDENCE, INITIAL_EVIDENCE);
    return all.filter(e => e.investigationId === investigationId);
  }

  async add(evidence: Evidence): Promise<Evidence> {
    const all = getItem<Evidence[]>(STORAGE_KEYS.EVIDENCE, INITIAL_EVIDENCE);
    const updated = [evidence, ...all];
    setItem(STORAGE_KEYS.EVIDENCE, updated);
    return evidence;
  }

  async getById(id: string): Promise<Evidence | null> {
    const all = getItem<Evidence[]>(STORAGE_KEYS.EVIDENCE, INITIAL_EVIDENCE);
    return all.find(e => e.id === id) || null;
  }
}

export class MockEntityRepository implements IEntityRepository {
  async getEntities(investigationId: string): Promise<Entity[]> {
    const all = getItem<Entity[]>(STORAGE_KEYS.ENTITIES, INITIAL_ENTITIES);
    return all.filter(e => e.investigationId === investigationId);
  }

  async getRelationships(investigationId: string): Promise<Relationship[]> {
    const all = getItem<Relationship[]>(STORAGE_KEYS.RELATIONSHIPS, INITIAL_RELATIONSHIPS);
    return all.filter(r => r.investigationId === investigationId);
  }

  async addEntity(entity: Entity): Promise<Entity> {
    const all = getItem<Entity[]>(STORAGE_KEYS.ENTITIES, INITIAL_ENTITIES);
    const updated = [entity, ...all];
    setItem(STORAGE_KEYS.ENTITIES, updated);
    return entity;
  }

  async addRelationship(relationship: Relationship): Promise<Relationship> {
    const all = getItem<Relationship[]>(STORAGE_KEYS.RELATIONSHIPS, INITIAL_RELATIONSHIPS);
    const updated = [relationship, ...all];
    setItem(STORAGE_KEYS.RELATIONSHIPS, updated);
    return relationship;
  }
}

export class MockFindingRepository implements IFindingRepository {
  async getByInvestigationId(investigationId: string): Promise<Finding[]> {
    const all = getItem<Finding[]>(STORAGE_KEYS.FINDINGS, INITIAL_FINDINGS);
    return all.filter(f => f.investigationId === investigationId);
  }

  async getServices(investigationId: string): Promise<Service[]> {
    const all = getItem<Service[]>(STORAGE_KEYS.SERVICES, INITIAL_SERVICES);
    return all.filter(s => s.investigationId === investigationId);
  }

  async addFinding(finding: Finding): Promise<Finding> {
    const all = getItem<Finding[]>(STORAGE_KEYS.FINDINGS, INITIAL_FINDINGS);
    const updated = [finding, ...all];
    setItem(STORAGE_KEYS.FINDINGS, updated);
    return finding;
  }

  async updateFindingStatus(id: string, status: Finding['status']): Promise<Finding> {
    const all = getItem<Finding[]>(STORAGE_KEYS.FINDINGS, INITIAL_FINDINGS);
    let updatedItem: Finding | null = null;
    const updated = all.map(f => {
      if (f.id === id) {
        updatedItem = { ...f, status };
        return updatedItem;
      }
      return f;
    });
    setItem(STORAGE_KEYS.FINDINGS, updated);
    if (!updatedItem) throw new Error(`Finding ${id} not found`);
    return updatedItem;
  }

  async addService(service: Service): Promise<Service> {
    const all = getItem<Service[]>(STORAGE_KEYS.SERVICES, INITIAL_SERVICES);
    const updated = [service, ...all];
    setItem(STORAGE_KEYS.SERVICES, updated);
    return service;
  }
}

export class MockAuditRepository implements IAuditRepository {
  async getByInvestigationId(investigationId: string): Promise<AuditEvent[]> {
    const all = getItem<AuditEvent[]>(STORAGE_KEYS.AUDIT_LOGS, INITIAL_AUDIT_LOGS);
    return all.filter(a => a.investigationId === investigationId);
  }

  async logEvent(event: Omit<AuditEvent, 'id' | 'auditHash'>): Promise<AuditEvent> {
    const all = getItem<AuditEvent[]>(STORAGE_KEYS.AUDIT_LOGS, INITIAL_AUDIT_LOGS);
    const id = `aud-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const auditHash = generateAuditHash(event.actor, event.action, event.timestamp);
    const newRecord: AuditEvent = {
      ...event,
      id,
      auditHash
    };
    setItem(STORAGE_KEYS.AUDIT_LOGS, [newRecord, ...all]);
    return newRecord;
  }
}

export class MockExposureRepository implements IExposureRepository {
  private findingRepo = new MockFindingRepository();
  private entityRepo = new MockEntityRepository();

  async getScore(investigationId: string): Promise<ExposureScoreBreakdown> {
    const findings = await this.findingRepo.getByInvestigationId(investigationId);
    const entities = await this.entityRepo.getEntities(investigationId);
    const services = await this.findingRepo.getServices(investigationId);
    return calculateExposureScore(findings, entities, services);
  }
}

export class MockReportRepository implements IReportRepository {
  async getByInvestigationId(investigationId: string): Promise<Report[]> {
    const all = getItem<Report[]>(STORAGE_KEYS.REPORTS, []);
    return all.filter(r => r.investigationId === investigationId);
  }

  async create(report: Report): Promise<Report> {
    const all = getItem<Report[]>(STORAGE_KEYS.REPORTS, []);
    const updated = [report, ...all];
    setItem(STORAGE_KEYS.REPORTS, updated);
    return report;
  }
}
