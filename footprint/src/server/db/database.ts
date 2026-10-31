import fs from 'fs';
import path from 'path';
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
  CollectorRun
} from '../../types/models';
import {
  INITIAL_INVESTIGATION,
  INITIAL_TARGETS,
  INITIAL_EVIDENCE,
  INITIAL_ENTITIES,
  INITIAL_RELATIONSHIPS,
  INITIAL_SERVICES,
  INITIAL_FINDINGS,
  INITIAL_AUDIT_LOGS,
  DEMO_USERS
} from '../../data/seedData';
import { calculateExposureScore } from '../../utils/scoring';
import { generateAuditHash } from '../../utils/hash';

export interface DatabaseSchema {
  users: User[];
  investigations: Investigation[];
  targets: Target[];
  evidence: Evidence[];
  entities: Entity[];
  relationships: Relationship[];
  services: Service[];
  vulnerabilities: Vulnerability[];
  findings: Finding[];
  scores: Record<string, ExposureScoreBreakdown>;
  reports: Report[];
  auditEvents: AuditEvent[];
  collectorRuns: CollectorRun[];
}

const DATA_DIR = path.resolve(process.cwd(), '.data');
const DB_FILE = path.resolve(DATA_DIR, 'footprintiq_db.json');

class ServerDatabase {
  private data: DatabaseSchema;
  private isLoaded: boolean = false;

  constructor() {
    this.data = this.getDefaultSeedData();
    this.init();
  }

  private getDefaultSeedData(): DatabaseSchema {
    const now = new Date().toISOString();
    return {
      users: DEMO_USERS,
      investigations: [INITIAL_INVESTIGATION],
      targets: INITIAL_TARGETS,
      evidence: INITIAL_EVIDENCE,
      entities: INITIAL_ENTITIES,
      relationships: INITIAL_RELATIONSHIPS,
      services: INITIAL_SERVICES,
      vulnerabilities: [
        {
          id: 'vuln-01',
          cveId: 'CVE-2023-38606',
          title: 'Jenkins Remote Unauthenticated Metrics Disclosure',
          description: 'Jenkins instance exposes unauthenticated /prometheus endpoint disclosing workspace details.',
          cvssScore: 5.3,
          severity: 'medium',
          remediation: 'Configure Prometheus metrics access token or bind behind authenticated reverse proxy.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2023-38606']
        },
        {
          id: 'vuln-02',
          cveId: 'CVE-2011-3389',
          title: 'Deprecated TLSv1.0 Protocol Enabled',
          description: 'Web service negotiates legacy TLSv1.0 protocol susceptible to BEAST cipher attacks.',
          cvssScore: 5.0,
          severity: 'medium',
          remediation: 'Enforce TLS 1.2 or TLS 1.3 in web server SSL configuration.',
          references: ['https://nvd.nist.gov/vuln/detail/CVE-2011-3389']
        }
      ],
      findings: INITIAL_FINDINGS,
      scores: {
        [INITIAL_INVESTIGATION.id]: calculateExposureScore(INITIAL_FINDINGS, INITIAL_ENTITIES, INITIAL_SERVICES)
      },
      reports: [],
      auditEvents: INITIAL_AUDIT_LOGS,
      collectorRuns: [
        {
          id: 'run-01',
          investigationId: INITIAL_INVESTIGATION.id,
          collectorName: 'RDAP Collector',
          type: 'passive',
          target: 'lab.example',
          status: 'completed',
          startedAt: '2026-09-15T10:00:00Z',
          completedAt: '2026-09-15T10:00:02Z',
          itemsDiscovered: 4,
          rawOutputSnippet: 'Registrar: LabSafe Registry IANA, Registrant: NorthStar Analytics Lab',
          createdAt: '2026-09-15T10:00:00Z',
          updatedAt: '2026-09-15T10:00:02Z'
        },
        {
          id: 'run-02',
          investigationId: INITIAL_INVESTIGATION.id,
          collectorName: 'DNS Recon Collector',
          type: 'passive',
          target: 'lab.example',
          status: 'completed',
          startedAt: '2026-09-15T10:15:00Z',
          completedAt: '2026-09-15T10:15:01Z',
          itemsDiscovered: 6,
          rawOutputSnippet: 'A: 192.168.56.102, MX: mail.lab.example, TXT: v=spf1',
          createdAt: '2026-09-15T10:15:00Z',
          updatedAt: '2026-09-15T10:15:01Z'
        }
      ]
    };
  }

  private init(): void {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        this.data = {
          ...this.getDefaultSeedData(),
          ...parsed
        };
      } else {
        this.saveToDisk();
      }
      this.isLoaded = true;
    } catch (err) {
      console.warn('Failed to load DB file from disk, using in-memory store:', err);
      this.data = this.getDefaultSeedData();
    }
  }

  public saveToDisk(): void {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      const tmpFile = `${DB_FILE}.tmp`;
      fs.writeFileSync(tmpFile, JSON.stringify(this.data, null, 2), 'utf-8');
      fs.renameSync(tmpFile, DB_FILE);
    } catch (err) {
      console.error('Failed to write database to disk:', err);
    }
  }

  public getSchema(): DatabaseSchema {
    return this.data;
  }
}

export const serverDb = new ServerDatabase();
