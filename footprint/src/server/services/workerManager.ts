import {
  WorkerRegistration,
  WorkerJob,
  ApprovedScanProfile
} from '../../types/workflow';
import { generateEvidenceHash } from '../../utils/hash';
import { SAMPLE_NMAP_XML, SAMPLE_OPENVAS_XML } from '../../data/sampleScanFiles';
import { serverRepos } from '../db/repositories';
import { scopeValidator } from './scopeValidator';

export class WorkerManagerService {
  private workers: Map<string, WorkerRegistration> = new Map();
  private jobs: Map<string, WorkerJob> = new Map();

  constructor() {
    this.initDefaultMockWorker();
  }

  private initDefaultMockWorker() {
    // Default simulated worker for Google AI Studio preview
    const simulatedWorker: WorkerRegistration = {
      workerId: 'worker-sim-lab01',
      name: 'Simulated Lab Worker (AI Studio Preview)',
      environment: 'simulated_preview',
      supportedProfiles: [
        'host-discovery',
        'safe-service-detection',
        'safe-os-detection',
        'openvas-basic',
        'openvas-full-and-fast'
      ],
      secretToken: 'sec-sim-worker-998811',
      lastHeartbeat: new Date().toISOString(),
      status: 'active',
      ipAddress: '192.168.56.200',
      registeredAt: '2026-09-01T08:00:00Z'
    };
    this.workers.set(simulatedWorker.workerId, simulatedWorker);
  }

  /**
   * Register a new worker daemon
   */
  async registerWorker(
    name: string,
    environment: 'local_lab' | 'simulated_preview',
    supportedProfiles: ApprovedScanProfile[],
    ipAddress?: string
  ): Promise<WorkerRegistration> {
    const workerId = `worker-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
    const secretToken = `sec-${generateEvidenceHash(workerId + Date.now()).substring(7, 27)}`;

    const worker: WorkerRegistration = {
      workerId,
      name,
      environment,
      supportedProfiles,
      secretToken,
      lastHeartbeat: new Date().toISOString(),
      status: 'active',
      ipAddress,
      registeredAt: new Date().toISOString()
    };

    this.workers.set(workerId, worker);
    return worker;
  }

  /**
   * Revoke worker credentials
   */
  async revokeWorker(workerId: string, actor: string): Promise<boolean> {
    const worker = this.workers.get(workerId);
    if (!worker) return false;
    worker.status = 'revoked';

    // Cancel all queued or running jobs for this worker
    for (const job of this.jobs.values()) {
      if (job.workerId === workerId && (job.status === 'queued' || job.status === 'running')) {
        job.status = 'cancelled';
        job.errorMessage = 'Worker revoked by administrator';
      }
    }

    return true;
  }

  /**
   * Worker heartbeat
   */
  async recordHeartbeat(workerId: string, token: string): Promise<boolean> {
    const worker = this.workers.get(workerId);
    if (!worker || worker.status === 'revoked' || worker.secretToken !== token) {
      return false;
    }
    worker.lastHeartbeat = new Date().toISOString();
    return true;
  }

  /**
   * Get all registered workers
   */
  getAllWorkers(): WorkerRegistration[] {
    return Array.from(this.workers.values());
  }

  /**
   * Create an authorized worker job bound to a validated target and profile
   */
  async createJob(
    investigationId: string,
    workflowRunId: string,
    target: string,
    profile: ApprovedScanProfile,
    workerId = 'worker-sim-lab01'
  ): Promise<WorkerJob> {
    const worker = this.workers.get(workerId);
    if (!worker || worker.status === 'revoked') {
      throw new Error(`Worker "${workerId}" is unavailable or revoked`);
    }

    const jobId = `job-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`;
    const token = `jobtok-${generateEvidenceHash(jobId + target + Date.now()).substring(7, 31)}`;
    const tokenExpiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString(); // 15 min TTL

    const job: WorkerJob = {
      id: jobId,
      investigationId,
      workflowRunId,
      workerId,
      target,
      profile,
      status: 'queued',
      token,
      tokenExpiresAt,
      progressPercent: 0,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    this.jobs.set(jobId, job);
    return job;
  }

  /**
   * Worker polls for assigned pending jobs
   */
  async pollJobs(workerId: string, secretToken: string): Promise<WorkerJob[]> {
    const worker = this.workers.get(workerId);
    if (!worker || worker.status !== 'active' || worker.secretToken !== secretToken) {
      throw new Error('Unauthorized worker access');
    }
    worker.lastHeartbeat = new Date().toISOString();

    return Array.from(this.jobs.values()).filter(
      j => j.workerId === workerId && j.status === 'queued'
    );
  }

  /**
   * Worker accepts a job and starts execution
   */
  async acceptJob(jobId: string, token: string): Promise<WorkerJob> {
    const job = this.jobs.get(jobId);
    if (!job) throw new Error('Job not found');
    if (job.token !== token) throw new Error('Invalid job token');

    const now = new Date();
    if (new Date(job.tokenExpiresAt).getTime() < now.getTime()) {
      job.status = 'failed';
      job.errorMessage = 'Job token expired prior to acceptance';
      throw new Error('Job token has expired');
    }

    job.status = 'running';
    job.progressPercent = 10;
    job.updatedAt = now.toISOString();
    return job;
  }

  /**
   * Worker reports incremental progress
   */
  async updateProgress(jobId: string, token: string, percent: number): Promise<WorkerJob> {
    const job = this.jobs.get(jobId);
    if (!job || job.token !== token) throw new Error('Job unauthorized');
    job.progressPercent = Math.min(100, Math.max(0, percent));
    job.updatedAt = new Date().toISOString();
    return job;
  }

  /**
   * Upload and cryptographically verify result payload from worker
   */
  async submitResult(
    jobId: string,
    token: string,
    reportedTarget: string,
    resultPayload: string,
    providedHash?: string
  ): Promise<WorkerJob> {
    const job = this.jobs.get(jobId);
    if (!job) throw new Error('Job not found');
    if (job.token !== token) throw new Error('Unauthorized job token');

    const now = new Date();
    if (new Date(job.tokenExpiresAt).getTime() < now.getTime()) {
      job.status = 'failed';
      job.errorMessage = 'Result rejected: Job token expired';
      throw new Error('Job token has expired');
    }

    // Safety check: target binding must match assigned target
    const cleanAssigned = job.target.trim().toLowerCase();
    const cleanReported = reportedTarget.trim().toLowerCase();
    if (cleanReported !== cleanAssigned) {
      job.status = 'failed';
      job.errorMessage = `TARGET MISMATCH: Reported target "${reportedTarget}" does not match assigned target "${job.target}"`;
      throw new Error(job.errorMessage);
    }

    // Verify SHA-256 hash
    const computedHash = generateEvidenceHash(resultPayload);
    if (providedHash && providedHash !== computedHash) {
      job.status = 'failed';
      job.errorMessage = `HASH INTEGRITY FAILURE: Provided hash does not match computed payload digest`;
      throw new Error(job.errorMessage);
    }

    job.status = 'completed';
    job.progressPercent = 100;
    job.resultHash = computedHash;
    job.rawResultPayload = resultPayload;
    job.updatedAt = now.toISOString();

    return job;
  }

  /**
   * Mock execution for Google AI Studio preview
   */
  async executeSimulatedJob(jobId: string): Promise<WorkerJob> {
    const job = this.jobs.get(jobId);
    if (!job) throw new Error('Job not found');

    job.status = 'running';
    job.progressPercent = 35;

    // Pick appropriate safe fixture
    let fixture = SAMPLE_NMAP_XML;
    if (job.profile.startsWith('openvas')) {
      fixture = SAMPLE_OPENVAS_XML;
    }

    // Bind target if needed
    if (job.target !== '192.168.56.102' && /^\d{1,3}(\.\d{1,3}){3}$/.test(job.target)) {
      fixture = fixture.replace(/192\.168\.56\.102/g, job.target);
    }

    job.progressPercent = 85;
    const computedHash = generateEvidenceHash(fixture);
    job.status = 'completed';
    job.progressPercent = 100;
    job.resultHash = computedHash;
    job.rawResultPayload = fixture;
    job.updatedAt = new Date().toISOString();

    return job;
  }

  getJob(jobId: string): WorkerJob | null {
    return this.jobs.get(jobId) || null;
  }
}

export const workerManager = new WorkerManagerService();
