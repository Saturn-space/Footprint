/**
 * FootprintIQ: OSINT Recon Toolkit — Data Models
 * Strictly typed interfaces for cybersecurity reconnaissance management
 */

export type InteractionType = 'passive' | 'active';

export type ValidationStatus = 'verified' | 'unverified' | 'flagged';

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingStatus = 'open' | 'under_review' | 'mitigated' | 'false_positive' | 'accepted_risk';

export type InvestigationStatus = 'active' | 'archived' | 'completed' | 'draft';

export type TargetType = 'domain' | 'subdomain' | 'ip' | 'cidr' | 'email' | 'url' | 'asn';

export type EntityType =
  | 'Organization'
  | 'Domain'
  | 'Subdomain'
  | 'IP address'
  | 'Email'
  | 'Person'
  | 'URL'
  | 'Document'
  | 'Port'
  | 'Service'
  | 'Technology'
  | 'Vulnerability';

export type RelationshipType =
  | 'owns'
  | 'has_subdomain'
  | 'resolves_to'
  | 'uses_mail_server'
  | 'uses_name_server'
  | 'associated_with'
  | 'exposes'
  | 'runs_service'
  | 'affected_by'
  | 'supported_by_evidence';

export type UserRole = 'admin' | 'investigator' | 'reviewer' | 'viewer';

export interface User {
  id: string;
  name: string;
  studentId?: string;
  email: string;
  role: UserRole;
  organization: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface Target {
  id: string;
  investigationId: string;
  type: TargetType;
  value: string;
  description?: string;
  interactionAllowed: InteractionType[]; // ['passive'] or ['passive', 'active']
  isAllowlisted: boolean;
  addedAt: string;
  addedBy: string;
}

export interface Scope {
  ownedDomains: string[];
  approvedIPs: string[];
  approvedCIDRs: string[];
  passiveOnlyTargets: string[];
  activeTargets: string[];
  excludedTargets: string[];
}

export interface Authorization {
  activeScanningEnabled: boolean;
  approvedBy: string;
  authorizationReference: string;
  startDate: string;
  expiryDate: string;
  rulesOfEngagementConfirmed: boolean;
  ownershipOrWrittenPermissionConfirmed: boolean;
  notes?: string;
}

export interface InvestigationModules {
  rdapWhois: boolean;
  dnsRecon: boolean;
  theHarvesterImport: boolean;
  searchEvidence: boolean;
  nmapXmlImport: boolean;
  openvasXmlImport: boolean;
  entityCorrelation: boolean;
  exposureScoring: boolean;
  pdfReporting: boolean;
}

export interface Investigation {
  id: string;
  name: string;
  organizationName: string;
  description: string;
  leadInvestigator: string;
  teamMembers: string[];
  status: InvestigationStatus;
  scope: Scope;
  authorization: Authorization;
  modules: InvestigationModules;
  createdAt: string;
  updatedAt: string;
  tags: string[];
}

export interface Evidence {
  id: string;
  investigationId: string;
  type: string;
  value: string;
  target: string;
  sourceTool: string;
  sourceFile?: string;
  collectedAt: string;
  interactionType: InteractionType;
  confidence: number; // 0 to 1
  authorizedScope: boolean;
  attributes: Record<string, unknown>;
  evidenceHash: string;
  validationStatus: ValidationStatus;
}

export interface Entity {
  id: string;
  investigationId: string;
  name: string;
  type: EntityType;
  primaryValue: string;
  confidence: number;
  metadata: Record<string, string | number | boolean | null>;
  sourceEvidenceIds: string[];
  firstDiscoveredAt: string;
  lastVerifiedAt: string;
}

export interface Relationship {
  id: string;
  investigationId: string;
  sourceEntityId: string;
  targetEntityId: string;
  type: RelationshipType;
  label?: string;
  confidence: number;
  evidenceIds: string[];
  createdAt: string;
}

export interface Service {
  id: string;
  investigationId: string;
  ip: string;
  port: number;
  protocol: 'tcp' | 'udp';
  serviceName: string;
  product?: string;
  version?: string;
  banner?: string;
  state: 'open' | 'filtered' | 'closed';
  cpe?: string;
}

export interface Vulnerability {
  id: string;
  cveId?: string;
  title: string;
  description: string;
  cvssScore: number;
  severity: FindingSeverity;
  remediation: string;
  references: string[];
}

export interface Finding {
  id: string;
  investigationId: string;
  title: string;
  category: 'attack_surface' | 'misconfiguration' | 'credential_leak' | 'network_exposure' | 'information_disclosure';
  severity: FindingSeverity;
  status: FindingStatus;
  target: string;
  affectedEntityId?: string;
  description: string;
  evidenceId?: string;
  sourceTool: string;
  interactionType: InteractionType;
  cvss?: number;
  cve?: string;
  remediationAdvice: string;
  detectedAt: string;
  assignedReviewer?: string;
  reviewerNotes?: string;
  observation?: string;
  impact?: string;
  firstObserved?: string;
  lastObserved?: string;
  confidence?: number;
}

export interface ExposureScoreBreakdown {
  attackSurfaceScore?: number;      // 0 - 25 (legacy compat)
  vulnerabilityImpactScore?: number;// 0 - 35 (legacy compat)
  credentialLeakScore?: number;     // 0 - 20 (legacy compat)
  configurationHygieneScore?: number; // 0 - 20 (legacy compat)
  P: number; // Public footprint (0.20)
  D: number; // Domain hygiene (0.15)
  S: number; // Service exposure (0.25)
  V: number; // Vulnerability severity (0.35)
  C: number; // Correlation confidence (0.05)
  totalScore: number;              // 0 - 100
  tier: 'Minimal' | 'Low' | 'Moderate' | 'High' | 'Critical' | 'Low Risk' | 'Moderate Risk' | 'Elevated Risk' | 'High Risk' | 'Critical Risk';
  formulaVersion: string;
  scoreVersion: string;
  reviewerNotes?: string;
  calculationDate: string;
}

export * from './workflow';

export interface AuditEvent {
  id: string;
  investigationId: string;
  timestamp: string;
  actor: string;
  action: string;
  category: 'authorization' | 'scope_change' | 'data_ingestion' | 'correlation' | 'export' | 'system';
  targetResource?: string;
  details: string;
  status: 'allowed' | 'denied' | 'verified';
  auditHash: string;
}

export interface Report {
  id: string;
  investigationId: string;
  title: string;
  reportType: 'executive_summary' | 'technical_recon' | 'compliance_authorization' | 'full_osint_dossier';
  generatedAt: string;
  generatedBy: string;
  summary: string;
  sections: {
    title: string;
    content: string;
  }[];
  fileFormat: 'JSON' | 'PDF_HTML' | 'CSV';
}

export interface CollectorStatus {
  id: string;
  name: string;
  type: InteractionType;
  status: 'ready' | 'idle' | 'restricted' | 'offline';
  lastRun?: string;
  supportedFormats: string[];
  description: string;
}

export interface CollectorRun {
  id: string;
  investigationId: string;
  collectorName: string;
  type: InteractionType;
  target: string;
  status: 'running' | 'completed' | 'failed' | 'blocked';
  startedAt: string;
  completedAt?: string;
  itemsDiscovered: number;
  errorMessage?: string;
  rawOutputSnippet?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ScopeValidationResult {
  isValid: boolean;
  target: string;
  normalizedTarget: string;
  targetType: 'domain' | 'ipv4' | 'ipv6' | 'cidr' | 'email' | 'url' | 'unknown';
  isAllowlistedForPassive: boolean;
  isAllowlistedForActive: boolean;
  resolvedIPs?: string[];
  authorizationExpired: boolean;
  authorizationValidUntil: string;
  blockReason?: string;
  scopeMatches: {
    matchedDomain?: string;
    matchedCIDR?: string;
    matchedIP?: string;
  };
}

export interface ManualEvidenceInput {
  searchQuery: string;
  resultTitle: string;
  resultUrl: string;
  observation: string;
  screenshotRef?: string;
  collectionTime: string;
  confidence: number;
  reviewerStatus: 'unreviewed' | 'approved' | 'rejected';
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  data: T | null;
  error: string | null;
  message?: string;
  requestId: string;
  timestamp: string;
}

