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

export interface IInvestigationRepository {
  getAll(): Promise<Investigation[]>;
  getById(id: string): Promise<Investigation | null>;
  create(investigation: Investigation): Promise<Investigation>;
  update(investigation: Investigation): Promise<Investigation>;
  delete(id: string): Promise<boolean>;
}

export interface ITargetRepository {
  getByInvestigationId(investigationId: string): Promise<Target[]>;
  add(target: Target): Promise<Target>;
  delete(id: string): Promise<boolean>;
  isTargetAllowlistedForActive(investigationId: string, targetHost: string): Promise<boolean>;
}

export interface IEvidenceRepository {
  getByInvestigationId(investigationId: string): Promise<Evidence[]>;
  add(evidence: Evidence): Promise<Evidence>;
  getById(id: string): Promise<Evidence | null>;
}

export interface IEntityRepository {
  getEntities(investigationId: string): Promise<Entity[]>;
  getRelationships(investigationId: string): Promise<Relationship[]>;
  addEntity(entity: Entity): Promise<Entity>;
  addRelationship(relationship: Relationship): Promise<Relationship>;
}

export interface IFindingRepository {
  getByInvestigationId(investigationId: string): Promise<Finding[]>;
  getServices(investigationId: string): Promise<Service[]>;
  addFinding(finding: Finding): Promise<Finding>;
  updateFindingStatus(id: string, status: Finding['status']): Promise<Finding>;
  addService(service: Service): Promise<Service>;
}

export interface IAuditRepository {
  getByInvestigationId(investigationId: string): Promise<AuditEvent[]>;
  logEvent(event: Omit<AuditEvent, 'id' | 'auditHash'>): Promise<AuditEvent>;
}

export interface IExposureRepository {
  getScore(investigationId: string): Promise<ExposureScoreBreakdown>;
}

export interface IReportRepository {
  getByInvestigationId(investigationId: string): Promise<Report[]>;
  create(report: Report): Promise<Report>;
}
