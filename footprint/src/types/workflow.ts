export type WorkflowState =
  | 'CREATED'
  | 'SCOPE_VALIDATED'
  | 'PASSIVE_RUNNING'
  | 'PASSIVE_COMPLETE'
  | 'WAITING_FOR_APPROVAL'
  | 'NMAP_QUEUED'
  | 'NMAP_RUNNING'
  | 'NMAP_COMPLETE'
  | 'OPENVAS_QUEUED'
  | 'OPENVAS_RUNNING'
  | 'OPENVAS_COMPLETE'
  | 'CORRELATING'
  | 'SCORING'
  | 'REPORTING'
  | 'COMPLETED'
  | 'PARTIALLY_COMPLETED'
  | 'FAILED'
  | 'RETRYING'
  | 'CANCELLED'
  | 'BLOCKED_OUT_OF_SCOPE';

export type ApprovedScanProfile =
  | 'host-discovery'
  | 'safe-service-detection'
  | 'safe-os-detection'
  | 'openvas-basic'
  | 'openvas-full-and-fast';

export interface ScanProfileDefinition {
  id: ApprovedScanProfile;
  name: string;
  scanner: 'nmap' | 'openvas';
  description: string;
  fixedArgs: string[];
  estimatedDurationSeconds: number;
  safetyLevel: 'strictly_passive_safe' | 'low_impact_active' | 'authenticated_vulnerability_probe';
}

export interface WorkflowRun {
  id: string;
  investigationId: string;
  currentState: WorkflowState;
  stateHistory: {
    state: WorkflowState;
    timestamp: string;
    message?: string;
    details?: Record<string, unknown>;
  }[];
  activeStage?: string;
  stageProgressPercent: number;
  passiveCollectionCompleted: boolean;
  activeApprovedBy?: string;
  activeApprovedAt?: string;
  assignedWorkerId?: string;
  nmapJobId?: string;
  openvasJobId?: string;
  retriesRemaining: number;
  errorMessage?: string;
  lastSafeState: WorkflowState;
  createdAt: string;
  updatedAt: string;
}

export interface WorkerRegistration {
  workerId: string;
  name: string;
  environment: 'local_lab' | 'simulated_preview';
  supportedProfiles: ApprovedScanProfile[];
  secretToken: string;
  lastHeartbeat: string;
  status: 'active' | 'revoked' | 'disconnected';
  ipAddress?: string;
  registeredAt: string;
}

export interface WorkerJob {
  id: string;
  investigationId: string;
  workflowRunId: string;
  workerId: string;
  target: string;
  profile: ApprovedScanProfile;
  status: 'queued' | 'assigned' | 'running' | 'completed' | 'failed' | 'cancelled';
  token: string;
  tokenExpiresAt: string;
  progressPercent: number;
  resultHash?: string;
  rawResultPayload?: string;
  errorMessage?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ExposureScoreComponents {
  P: number; // Public footprint (0.20)
  D: number; // Domain hygiene (0.15)
  S: number; // Service exposure (0.25)
  V: number; // Vulnerability severity (0.35)
  C: number; // Correlation confidence (0.05)
  totalScore: number;
  tier: 'Minimal' | 'Low' | 'Moderate' | 'High' | 'Critical';
  formulaVersion: string;
  scoreVersion: string;
  reviewerNotes?: string;
  calculatedAt: string;
}
