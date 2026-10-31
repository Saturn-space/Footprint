import {
  Investigation,
  Target,
  Evidence,
  Entity,
  Relationship,
  Service,
  Finding,
  AuditEvent,
  User,
  CollectorStatus
} from '../types/models';
import { generateEvidenceHash, generateAuditHash } from '../utils/hash';

export const CURRENT_USER: User = {
  id: 'usr-admin-01',
  name: 'Asip Ali',
  studentId: '251347048',
  email: 'admin@footprintiq.lab',
  role: 'admin',
  organization: 'Cybersecurity Recon Research Lab',
  createdAt: '2026-09-01T08:00:00Z',
  updatedAt: '2026-10-02T14:35:00Z'
};

export const DEMO_USERS: User[] = [
  CURRENT_USER,
  {
    id: 'usr-investigator-01',
    name: 'Mohan Prasad',
    studentId: '251347070',
    email: 'investigator@footprintiq.lab',
    role: 'investigator',
    organization: 'Cybersecurity Recon Research Lab',
    createdAt: '2026-09-01T08:00:00Z',
    updatedAt: '2026-10-02T14:35:00Z'
  },
  {
    id: 'usr-reviewer-01',
    name: 'Dr. Marcus Vance',
    email: 'reviewer@footprintiq.lab',
    role: 'reviewer',
    organization: 'Faculty Recon Review Board',
    createdAt: '2026-09-01T08:00:00Z',
    updatedAt: '2026-10-02T14:35:00Z'
  },
  {
    id: 'usr-viewer-01',
    name: 'Auditor Guest',
    email: 'viewer@footprintiq.lab',
    role: 'viewer',
    organization: 'Educational Oversight Committee',
    createdAt: '2026-09-01T08:00:00Z',
    updatedAt: '2026-10-02T14:35:00Z'
  }
];

export const TEAM_MEMBERS: User[] = DEMO_USERS;

export const INITIAL_INVESTIGATION_ID = 'inv-northstar-01';

export const INITIAL_INVESTIGATION: Investigation = {
  id: INITIAL_INVESTIGATION_ID,
  name: 'NorthStar Analytics Lab Footprint Audit',
  organizationName: 'NorthStar Analytics Lab',
  description: 'Authorized baseline passive OSINT reconnaissance and isolated active host auditing for the team-controlled dummy research company.',
  leadInvestigator: 'Asip Ali (ID: 251347048)',
  teamMembers: ['Asip Ali (ID: 251347048)', 'Mohan Prasad (ID: 251347070)'],
  status: 'active',
  scope: {
    ownedDomains: ['lab.example'],
    approvedIPs: ['192.168.56.102', '192.168.56.105'],
    approvedCIDRs: ['192.168.56.0/24'],
    passiveOnlyTargets: ['lab.example', 'research.lab.example', 'auth.lab.example'],
    activeTargets: ['192.168.56.102'],
    excludedTargets: ['*.gov', '*.mil', 'unauthorized.external.com']
  },
  authorization: {
    activeScanningEnabled: true,
    approvedBy: 'Lab Safety Committee & Dr. Marcus Vance',
    authorizationReference: 'AUTH-LAB-2026-NS8812',
    startDate: '2026-09-01T08:00:00Z',
    expiryDate: '2026-12-31T23:59:59Z',
    rulesOfEngagementConfirmed: true,
    ownershipOrWrittenPermissionConfirmed: true,
    notes: 'Isolated environment test bench. Active scanning permitted strictly on private host 192.168.56.102.'
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
  createdAt: '2026-09-15T09:00:00Z',
  updatedAt: '2026-10-02T14:35:00Z',
  tags: ['lab-assessment', 'dummy-org', 'osint-baseline', 'authorized-scope']
};

export const INITIAL_TARGETS: Target[] = [
  {
    id: 'tgt-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    type: 'domain',
    value: 'lab.example',
    description: 'Primary apex lab domain registered for dummy organization',
    interactionAllowed: ['passive'],
    isAllowlisted: true,
    addedAt: '2026-09-15T09:05:00Z',
    addedBy: 'Asip Ali'
  },
  {
    id: 'tgt-02',
    investigationId: INITIAL_INVESTIGATION_ID,
    type: 'ip',
    value: '192.168.56.102',
    description: 'Isolated test bench server for active service auditing',
    interactionAllowed: ['passive', 'active'],
    isAllowlisted: true,
    addedAt: '2026-09-15T09:10:00Z',
    addedBy: 'Asip Ali'
  },
  {
    id: 'tgt-03',
    investigationId: INITIAL_INVESTIGATION_ID,
    type: 'cidr',
    value: '192.168.56.0/24',
    description: 'Team internal lab subnet',
    interactionAllowed: ['passive'],
    isAllowlisted: true,
    addedAt: '2026-09-15T09:12:00Z',
    addedBy: 'Mohan Prasad'
  }
];

export const INITIAL_EVIDENCE: Evidence[] = [
  {
    id: 'ev-whois-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    type: 'RDAP_REGISTRATION',
    value: 'Domain: lab.example, Registrar: LabSafe Registry IANA, Org: NorthStar Analytics Lab',
    target: 'lab.example',
    sourceTool: 'RDAP/WHOIS Client',
    collectedAt: '2026-09-15T10:00:00Z',
    interactionType: 'passive',
    confidence: 0.98,
    authorizedScope: true,
    attributes: {
      registrar: 'LabSafe Registry IANA',
      createdDate: '2023-04-12T10:00:00Z',
      dnssec: 'unsigned',
      registrantOrg: 'NorthStar Analytics Lab',
      adminEmail: 'domain-admin@lab.example'
    },
    evidenceHash: generateEvidenceHash('ev-whois-01-lab.example'),
    validationStatus: 'verified'
  },
  {
    id: 'ev-dns-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    type: 'DNS_RECORDS',
    value: 'A: 192.168.56.102; MX: mail.lab.example (10); NS: ns1.lab.example, ns2.lab.example; TXT: v=spf1 include:_spf.lab.example ~all',
    target: 'lab.example',
    sourceTool: 'DNS Recon Collector',
    collectedAt: '2026-09-15T10:15:00Z',
    interactionType: 'passive',
    confidence: 1.0,
    authorizedScope: true,
    attributes: {
      aRecord: '192.168.56.102',
      mxRecord: 'mail.lab.example',
      nsRecords: ['ns1.lab.example', 'ns2.lab.example'],
      spf: 'v=spf1 include:_spf.lab.example ~all',
      dmarc: 'none'
    },
    evidenceHash: generateEvidenceHash('ev-dns-01-dns-lab.example'),
    validationStatus: 'verified'
  },
  {
    id: 'ev-harvester-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    type: 'OSINT_EMAILS_HOSTS',
    value: 'Emails: elena.rostova@lab.example, m.vance@lab.example, devops@lab.example; Subdomains: research.lab.example, auth.lab.example, vpn.lab.example',
    target: 'lab.example',
    sourceTool: 'theHarvester Import',
    sourceFile: 'theharvester_lab_export.json',
    collectedAt: '2026-09-16T11:20:00Z',
    interactionType: 'passive',
    confidence: 0.88,
    authorizedScope: true,
    attributes: {
      harvestedEmails: ['elena.rostova@lab.example', 'm.vance@lab.example', 'devops@lab.example'],
      harvestedHosts: ['research.lab.example', 'auth.lab.example', 'vpn.lab.example']
    },
    evidenceHash: generateEvidenceHash('ev-harvester-01-theharvester'),
    validationStatus: 'verified'
  },
  {
    id: 'ev-search-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    type: 'SEARCH_INDEX_RECORD',
    value: 'Exposed PDF: "NorthStar Internal Architecture Whitepaper v1.2" referencing internal hostnames and Jenkins build pipeline',
    target: 'lab.example',
    sourceTool: 'Search Evidence Harvester',
    collectedAt: '2026-09-16T14:40:00Z',
    interactionType: 'passive',
    confidence: 0.92,
    authorizedScope: true,
    attributes: {
      documentTitle: 'NorthStar Internal Architecture Whitepaper v1.2',
      url: 'https://lab.example/docs/internal-architecture-v1.2.pdf',
      indexedBy: 'Public Academic Repository'
    },
    evidenceHash: generateEvidenceHash('ev-search-01-whitepaper'),
    validationStatus: 'verified'
  },
  {
    id: 'ev-nmap-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    type: 'PORT_SCAN_XML',
    value: 'Nmap 7.94 scan on 192.168.56.102: Ports 22/tcp (OpenSSH 8.9p1), 80/tcp (nginx 1.18.0), 443/tcp (nginx 1.18.0 SSL), 5432/tcp (PostgreSQL 14.9), 8080/tcp (Jetty 9.4.43 Jenkins)',
    target: '192.168.56.102',
    sourceTool: 'Nmap XML Parser',
    sourceFile: 'nmap_host102.xml',
    collectedAt: '2026-09-18T16:00:00Z',
    interactionType: 'active',
    confidence: 1.0,
    authorizedScope: true,
    attributes: {
      commandArgs: 'nmap -sV -sC -p 22,80,443,5432,8080 -oX nmap_out.xml 192.168.56.102',
      openPorts: [22, 80, 443, 5432, 8080],
      osFamily: 'Linux 5.x Ubuntu'
    },
    evidenceHash: generateEvidenceHash('ev-nmap-01-host102'),
    validationStatus: 'verified'
  },
  {
    id: 'ev-openvas-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    type: 'VULN_SCAN_XML',
    value: 'OpenVAS Report: 1 Medium finding (Deprecated TLSv1.0), 1 Medium finding (Jenkins Unauthenticated Prometheus Metrics CVE-2023-38606)',
    target: '192.168.56.102',
    sourceTool: 'OpenVAS XML Parser',
    sourceFile: 'openvas_rep847291.xml',
    collectedAt: '2026-09-19T09:30:00Z',
    interactionType: 'active',
    confidence: 0.95,
    authorizedScope: true,
    attributes: {
      cveList: ['CVE-2011-3389', 'CVE-2023-38606'],
      threatLevel: 'Medium'
    },
    evidenceHash: generateEvidenceHash('ev-openvas-01-report'),
    validationStatus: 'verified'
  }
];

export const INITIAL_SERVICES: Service[] = [
  {
    id: 'srv-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    ip: '192.168.56.102',
    port: 22,
    protocol: 'tcp',
    serviceName: 'ssh',
    product: 'OpenSSH',
    version: '8.9p1 Ubuntu 3ubuntu0.6',
    banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
    state: 'open',
    cpe: 'cpe:/a:openbsd:openssh:8.9p1'
  },
  {
    id: 'srv-02',
    investigationId: INITIAL_INVESTIGATION_ID,
    ip: '192.168.56.102',
    port: 80,
    protocol: 'tcp',
    serviceName: 'http',
    product: 'nginx',
    version: '1.18.0',
    banner: 'nginx/1.18.0 (Ubuntu)',
    state: 'open',
    cpe: 'cpe:/a:igor_sysoev:nginx:1.18.0'
  },
  {
    id: 'srv-03',
    investigationId: INITIAL_INVESTIGATION_ID,
    ip: '192.168.56.102',
    port: 443,
    protocol: 'tcp',
    serviceName: 'https',
    product: 'nginx',
    version: '1.18.0',
    banner: 'TLSv1.0, TLSv1.2, TLSv1.3 enabled',
    state: 'open',
    cpe: 'cpe:/a:igor_sysoev:nginx:1.18.0'
  },
  {
    id: 'srv-04',
    investigationId: INITIAL_INVESTIGATION_ID,
    ip: '192.168.56.102',
    port: 5432,
    protocol: 'tcp',
    serviceName: 'postgresql',
    product: 'PostgreSQL DB',
    version: '14.9',
    banner: 'PostgreSQL Database Server 14.9',
    state: 'open',
    cpe: 'cpe:/a:postgresql:postgresql:14.9'
  },
  {
    id: 'srv-05',
    investigationId: INITIAL_INVESTIGATION_ID,
    ip: '192.168.56.102',
    port: 8080,
    protocol: 'tcp',
    serviceName: 'http-proxy/jenkins',
    product: 'Jetty / Jenkins',
    version: '9.4.43.v20210629',
    banner: 'Jenkins Automation Core 2.401',
    state: 'open',
    cpe: 'cpe:/a:jenkins:jenkins:2.401'
  }
];

export const INITIAL_FINDINGS: Finding[] = [
  {
    id: 'fnd-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    title: 'Exposed Database Listener on External Lab Interface',
    category: 'network_exposure',
    severity: 'high',
    status: 'open',
    target: '192.168.56.102:5432',
    description: 'PostgreSQL database service port 5432 is publicly exposed on the lab host interface without IP firewalling, potentially inviting unauthorized brute force or protocol probes.',
    sourceTool: 'Nmap XML Parser',
    interactionType: 'active',
    cvss: 7.5,
    remediationAdvice: 'Bind PostgreSQL to localhost (127.0.0.1) or restrict access via iptables/UFW to authorized application nodes only.',
    detectedAt: '2026-09-18T16:05:00Z'
  },
  {
    id: 'fnd-02',
    investigationId: INITIAL_INVESTIGATION_ID,
    title: 'Jenkins Prometheus Metric Endpoint Unauthenticated Disclosure',
    category: 'information_disclosure',
    severity: 'medium',
    status: 'open',
    target: '192.168.56.102:8080/prometheus',
    description: 'Continuous Integration server exposes system performance metrics, internal project names, build executor IDs, and filesystem paths without requiring authentication.',
    sourceTool: 'OpenVAS XML Parser',
    interactionType: 'active',
    cvss: 5.3,
    cve: 'CVE-2023-38606',
    remediationAdvice: 'Enable endpoint authentication in Jenkins security settings or restrict port 8080 access using a reverse proxy with basic authentication.',
    detectedAt: '2026-09-19T09:35:00Z'
  },
  {
    id: 'fnd-03',
    investigationId: INITIAL_INVESTIGATION_ID,
    title: 'Deprecated TLSv1.0 Cryptographic Protocol Enabled',
    category: 'misconfiguration',
    severity: 'medium',
    status: 'under_review',
    target: '192.168.56.102:443',
    description: 'The web server accepts connections negotiating TLSv1.0, vulnerable to known cipher block chaining weaknesses (e.g., BEAST).',
    sourceTool: 'OpenVAS XML Parser',
    interactionType: 'active',
    cvss: 5.0,
    cve: 'CVE-2011-3389',
    remediationAdvice: 'Update nginx configuration ssl_protocols directive to include only TLSv1.2 and TLSv1.3.',
    detectedAt: '2026-09-19T09:40:00Z'
  },
  {
    id: 'fnd-04',
    investigationId: INITIAL_INVESTIGATION_ID,
    title: 'Missing DMARC Email Anti-Spoofing Policy',
    category: 'misconfiguration',
    severity: 'low',
    status: 'open',
    target: 'lab.example',
    description: 'Domain publishes an SPF record but lacks a valid _dmarc TXT record. Lack of DMARC enforcement allows threat actors to forge emails spoofing the lab domain.',
    sourceTool: 'DNS Recon Collector',
    interactionType: 'passive',
    cvss: 4.1,
    remediationAdvice: 'Publish a TXT record at _dmarc.lab.example with policy p=quarantine or p=reject and specify a rua mailto report address.',
    detectedAt: '2026-09-15T10:20:00Z'
  },
  {
    id: 'fnd-05',
    investigationId: INITIAL_INVESTIGATION_ID,
    title: 'Internal Whitepaper Leaking Pipeline Paths in Search Index',
    category: 'credential_leak',
    severity: 'low',
    status: 'mitigated',
    target: 'lab.example/docs/internal-architecture-v1.2.pdf',
    description: 'Publicly indexed internal PDF document disclosed team email addresses, private IP subnets, and Jenkins worker hostnames.',
    sourceTool: 'Search Evidence Harvester',
    interactionType: 'passive',
    cvss: 3.5,
    remediationAdvice: 'Remove internal whitepaper from public directory and configure robots.txt Disallow rule for /docs/internal/ folder.',
    detectedAt: '2026-09-16T14:45:00Z'
  },
  {
    id: 'fnd-06',
    investigationId: INITIAL_INVESTIGATION_ID,
    title: 'Nginx Default Server Banner Discloses Precise Version',
    category: 'information_disclosure',
    severity: 'info',
    status: 'open',
    target: '192.168.56.102:80',
    description: 'Server HTTP response headers include "Server: nginx/1.18.0 (Ubuntu)", aiding automated vulnerability matching.',
    sourceTool: 'Nmap XML Parser',
    interactionType: 'active',
    cvss: 2.1,
    remediationAdvice: 'Set server_tokens off; in nginx.conf to suppress banner version leaks.',
    detectedAt: '2026-09-18T16:10:00Z'
  }
];

export const INITIAL_ENTITIES: Entity[] = [
  {
    id: 'ent-org-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'NorthStar Analytics Lab',
    type: 'Organization',
    primaryValue: 'NorthStar Analytics Lab',
    confidence: 1.0,
    metadata: {
      jurisdiction: 'Dummy Research Sandbox',
      sector: 'Scientific Data Analytics',
      employeeCount: 45
    },
    sourceEvidenceIds: ['ev-whois-01'],
    firstDiscoveredAt: '2026-09-15T10:00:00Z',
    lastVerifiedAt: '2026-09-15T10:00:00Z'
  },
  {
    id: 'ent-dom-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'lab.example',
    type: 'Domain',
    primaryValue: 'lab.example',
    confidence: 1.0,
    metadata: {
      registrar: 'LabSafe Registry IANA',
      status: 'active'
    },
    sourceEvidenceIds: ['ev-whois-01', 'ev-dns-01'],
    firstDiscoveredAt: '2026-09-15T10:00:00Z',
    lastVerifiedAt: '2026-09-15T10:15:00Z'
  },
  {
    id: 'ent-sub-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'research.lab.example',
    type: 'Subdomain',
    primaryValue: 'research.lab.example',
    confidence: 0.95,
    metadata: {
      cname: 'lab.example',
      purpose: 'Lab Research Portal'
    },
    sourceEvidenceIds: ['ev-harvester-01'],
    firstDiscoveredAt: '2026-09-16T11:20:00Z',
    lastVerifiedAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'ent-sub-02',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'auth.lab.example',
    type: 'Subdomain',
    primaryValue: 'auth.lab.example',
    confidence: 0.92,
    metadata: {
      purpose: 'Identity & SSO Gateway'
    },
    sourceEvidenceIds: ['ev-harvester-01'],
    firstDiscoveredAt: '2026-09-16T11:20:00Z',
    lastVerifiedAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'ent-sub-03',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'vpn.lab.example',
    type: 'Subdomain',
    primaryValue: 'vpn.lab.example',
    confidence: 0.9,
    metadata: {
      purpose: 'Remote Access Gateway'
    },
    sourceEvidenceIds: ['ev-harvester-01'],
    firstDiscoveredAt: '2026-09-16T11:20:00Z',
    lastVerifiedAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'ent-ip-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: '192.168.56.102',
    type: 'IP address',
    primaryValue: '192.168.56.102',
    confidence: 1.0,
    metadata: {
      cidr: '192.168.56.0/24',
      hostname: 'lab-dev-node01.lab.example',
      environment: 'Private Lab Hypervisor'
    },
    sourceEvidenceIds: ['ev-dns-01', 'ev-nmap-01'],
    firstDiscoveredAt: '2026-09-15T10:15:00Z',
    lastVerifiedAt: '2026-09-18T16:00:00Z'
  },
  {
    id: 'ent-person-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'Elena Rostova',
    type: 'Person',
    primaryValue: 'Elena Rostova',
    confidence: 0.9,
    metadata: {
      title: 'Lab Director',
      affiliation: 'NorthStar Analytics Lab'
    },
    sourceEvidenceIds: ['ev-harvester-01'],
    firstDiscoveredAt: '2026-09-16T11:20:00Z',
    lastVerifiedAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'ent-person-02',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'Dr. Marcus Vance',
    type: 'Person',
    primaryValue: 'Dr. Marcus Vance',
    confidence: 0.92,
    metadata: {
      title: 'Chief Scientist',
      affiliation: 'NorthStar Analytics Lab'
    },
    sourceEvidenceIds: ['ev-harvester-01', 'ev-search-01'],
    firstDiscoveredAt: '2026-09-16T11:20:00Z',
    lastVerifiedAt: '2026-09-16T14:40:00Z'
  },
  {
    id: 'ent-email-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'elena.rostova@lab.example',
    type: 'Email',
    primaryValue: 'elena.rostova@lab.example',
    confidence: 0.95,
    metadata: {
      owner: 'Elena Rostova',
      deliverable: true
    },
    sourceEvidenceIds: ['ev-harvester-01'],
    firstDiscoveredAt: '2026-09-16T11:20:00Z',
    lastVerifiedAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'ent-email-02',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'm.vance@lab.example',
    type: 'Email',
    primaryValue: 'm.vance@lab.example',
    confidence: 0.95,
    metadata: {
      owner: 'Dr. Marcus Vance',
      deliverable: true
    },
    sourceEvidenceIds: ['ev-harvester-01'],
    firstDiscoveredAt: '2026-09-16T11:20:00Z',
    lastVerifiedAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'ent-doc-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'Architecture Whitepaper v1.2',
    type: 'Document',
    primaryValue: 'internal-architecture-v1.2.pdf',
    confidence: 0.98,
    metadata: {
      format: 'application/pdf',
      fileSize: '2.4 MB',
      leakType: 'OSINT Public Document'
    },
    sourceEvidenceIds: ['ev-search-01'],
    firstDiscoveredAt: '2026-09-16T14:40:00Z',
    lastVerifiedAt: '2026-09-16T14:40:00Z'
  },
  {
    id: 'ent-port-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'TCP/5432 (PostgreSQL)',
    type: 'Port',
    primaryValue: '5432/tcp',
    confidence: 1.0,
    metadata: {
      state: 'open',
      service: 'postgresql'
    },
    sourceEvidenceIds: ['ev-nmap-01'],
    firstDiscoveredAt: '2026-09-18T16:00:00Z',
    lastVerifiedAt: '2026-09-18T16:00:00Z'
  },
  {
    id: 'ent-port-02',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'TCP/8080 (Jenkins)',
    type: 'Port',
    primaryValue: '8080/tcp',
    confidence: 1.0,
    metadata: {
      state: 'open',
      service: 'http-proxy'
    },
    sourceEvidenceIds: ['ev-nmap-01'],
    firstDiscoveredAt: '2026-09-18T16:00:00Z',
    lastVerifiedAt: '2026-09-18T16:00:00Z'
  },
  {
    id: 'ent-vuln-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'CVE-2023-38606 (Metrics Disclosure)',
    type: 'Vulnerability',
    primaryValue: 'CVE-2023-38606',
    confidence: 0.95,
    metadata: {
      cvss: 5.3,
      threat: 'Medium',
      impact: 'Information Disclosure'
    },
    sourceEvidenceIds: ['ev-openvas-01'],
    firstDiscoveredAt: '2026-09-19T09:30:00Z',
    lastVerifiedAt: '2026-09-19T09:30:00Z'
  },
  {
    id: 'ent-tech-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    name: 'nginx 1.18.0',
    type: 'Technology',
    primaryValue: 'nginx/1.18.0',
    confidence: 1.0,
    metadata: {
      category: 'Web Server',
      os: 'Ubuntu Linux'
    },
    sourceEvidenceIds: ['ev-nmap-01'],
    firstDiscoveredAt: '2026-09-18T16:00:00Z',
    lastVerifiedAt: '2026-09-18T16:00:00Z'
  }
];

export const INITIAL_RELATIONSHIPS: Relationship[] = [
  {
    id: 'rel-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-org-01',
    targetEntityId: 'ent-dom-01',
    type: 'owns',
    label: 'owns apex domain',
    confidence: 1.0,
    evidenceIds: ['ev-whois-01'],
    createdAt: '2026-09-15T10:00:00Z'
  },
  {
    id: 'rel-02',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-dom-01',
    targetEntityId: 'ent-sub-01',
    type: 'has_subdomain',
    label: 'research zone',
    confidence: 0.95,
    evidenceIds: ['ev-harvester-01'],
    createdAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'rel-03',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-dom-01',
    targetEntityId: 'ent-sub-02',
    type: 'has_subdomain',
    label: 'SSO portal',
    confidence: 0.92,
    evidenceIds: ['ev-harvester-01'],
    createdAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'rel-04',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-dom-01',
    targetEntityId: 'ent-sub-03',
    type: 'has_subdomain',
    label: 'VPN portal',
    confidence: 0.9,
    evidenceIds: ['ev-harvester-01'],
    createdAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'rel-05',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-dom-01',
    targetEntityId: 'ent-ip-01',
    type: 'resolves_to',
    label: 'A record',
    confidence: 1.0,
    evidenceIds: ['ev-dns-01'],
    createdAt: '2026-09-15T10:15:00Z'
  },
  {
    id: 'rel-06',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-org-01',
    targetEntityId: 'ent-person-01',
    type: 'associated_with',
    label: 'employs director',
    confidence: 0.9,
    evidenceIds: ['ev-harvester-01'],
    createdAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'rel-07',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-person-01',
    targetEntityId: 'ent-email-01',
    type: 'associated_with',
    label: 'uses primary email',
    confidence: 0.95,
    evidenceIds: ['ev-harvester-01'],
    createdAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'rel-08',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-org-01',
    targetEntityId: 'ent-person-02',
    type: 'associated_with',
    label: 'employs chief scientist',
    confidence: 0.92,
    evidenceIds: ['ev-harvester-01'],
    createdAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'rel-09',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-person-02',
    targetEntityId: 'ent-email-02',
    type: 'associated_with',
    label: 'uses primary email',
    confidence: 0.95,
    evidenceIds: ['ev-harvester-01'],
    createdAt: '2026-09-16T11:20:00Z'
  },
  {
    id: 'rel-10',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-dom-01',
    targetEntityId: 'ent-doc-01',
    type: 'exposes',
    label: 'hosts whitepaper',
    confidence: 0.98,
    evidenceIds: ['ev-search-01'],
    createdAt: '2026-09-16T14:40:00Z'
  },
  {
    id: 'rel-11',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-ip-01',
    targetEntityId: 'ent-port-01',
    type: 'runs_service',
    label: 'listens on 5432',
    confidence: 1.0,
    evidenceIds: ['ev-nmap-01'],
    createdAt: '2026-09-18T16:00:00Z'
  },
  {
    id: 'rel-12',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-ip-01',
    targetEntityId: 'ent-port-02',
    type: 'runs_service',
    label: 'listens on 8080',
    confidence: 1.0,
    evidenceIds: ['ev-nmap-01'],
    createdAt: '2026-09-18T16:00:00Z'
  },
  {
    id: 'rel-13',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-port-02',
    targetEntityId: 'ent-vuln-01',
    type: 'affected_by',
    label: 'unauthenticated metrics',
    confidence: 0.95,
    evidenceIds: ['ev-openvas-01'],
    createdAt: '2026-09-19T09:30:00Z'
  },
  {
    id: 'rel-14',
    investigationId: INITIAL_INVESTIGATION_ID,
    sourceEntityId: 'ent-ip-01',
    targetEntityId: 'ent-tech-01',
    type: 'runs_service',
    label: 'runs web daemon',
    confidence: 1.0,
    evidenceIds: ['ev-nmap-01'],
    createdAt: '2026-09-18T16:00:00Z'
  }
];

export const INITIAL_AUDIT_LOGS: AuditEvent[] = [
  {
    id: 'aud-01',
    investigationId: INITIAL_INVESTIGATION_ID,
    timestamp: '2026-09-15T09:00:00Z',
    actor: 'Asip Ali (ID: 251347048)',
    action: 'INVESTIGATION_CREATED',
    category: 'authorization',
    targetResource: 'NorthStar Analytics Lab',
    details: 'Initiated authorized investigation with scope verification for lab.example and 192.168.56.102.',
    status: 'verified',
    auditHash: generateAuditHash('Asip Ali', 'INVESTIGATION_CREATED', '2026-09-15T09:00:00Z')
  },
  {
    id: 'aud-02',
    investigationId: INITIAL_INVESTIGATION_ID,
    timestamp: '2026-09-15T09:15:00Z',
    actor: 'Asip Ali (ID: 251347048)',
    action: 'SCOPE_ALLOWLIST_COMMITTED',
    category: 'scope_change',
    targetResource: 'Allowlist Policy',
    details: 'Approved targets committed: lab.example (Passive) and 192.168.56.102 (Passive + Active). Excluded wildcards: *.gov, *.mil.',
    status: 'allowed',
    auditHash: generateAuditHash('Asip Ali', 'SCOPE_ALLOWLIST_COMMITTED', '2026-09-15T09:15:00Z')
  },
  {
    id: 'aud-03',
    investigationId: INITIAL_INVESTIGATION_ID,
    timestamp: '2026-09-15T10:00:00Z',
    actor: 'Mohan Prasad (ID: 251347070)',
    action: 'PASSIVE_RECON_INGESTED',
    category: 'data_ingestion',
    targetResource: 'lab.example',
    details: 'RDAP/WHOIS and authoritative DNS records query executed. Verified registrant and name server delegation.',
    status: 'allowed',
    auditHash: generateAuditHash('Mohan Prasad', 'PASSIVE_RECON_INGESTED', '2026-09-15T10:00:00Z')
  },
  {
    id: 'aud-04',
    investigationId: INITIAL_INVESTIGATION_ID,
    timestamp: '2026-09-16T11:25:00Z',
    actor: 'Asip Ali (ID: 251347048)',
    action: 'OSINT_IMPORT_VALIDATED',
    category: 'data_ingestion',
    targetResource: 'theHarvester Import',
    details: 'Ingested 3 subdomains and 3 public email identifiers from verified OSINT dump theharvester_lab_export.json.',
    status: 'allowed',
    auditHash: generateAuditHash('Asip Ali', 'OSINT_IMPORT_VALIDATED', '2026-09-16T11:25:00Z')
  },
  {
    id: 'aud-05',
    investigationId: INITIAL_INVESTIGATION_ID,
    timestamp: '2026-09-18T16:02:00Z',
    actor: 'Asip Ali (ID: 251347048)',
    action: 'ACTIVE_SCAN_RESULT_IMPORTED',
    category: 'data_ingestion',
    targetResource: '192.168.56.102',
    details: 'Imported Nmap XML port scan results. Host matched active target allowlist. 5 open ports registered.',
    status: 'allowed',
    auditHash: generateAuditHash('Asip Ali', 'ACTIVE_SCAN_RESULT_IMPORTED', '2026-09-18T16:02:00Z')
  },
  {
    id: 'aud-06',
    investigationId: INITIAL_INVESTIGATION_ID,
    timestamp: '2026-09-19T09:42:00Z',
    actor: 'Mohan Prasad (ID: 251347070)',
    action: 'VULN_DATA_CORRELATED',
    category: 'correlation',
    targetResource: 'OpenVAS Report',
    details: 'OpenVAS findings linked to host 192.168.56.102 and service port 8080. Exposure Score recalculated.',
    status: 'allowed',
    auditHash: generateAuditHash('Mohan Prasad', 'VULN_DATA_CORRELATED', '2026-09-19T09:42:00Z')
  }
];

export const COLLECTOR_STATUSES: CollectorStatus[] = [
  {
    id: 'col-rdap',
    name: 'RDAP / WHOIS Collector',
    type: 'passive',
    status: 'ready',
    lastRun: '2026-09-15T10:00:00Z',
    supportedFormats: ['JSON', 'RDAP Protocol'],
    description: 'Queries IANA accredited registries and RDAP gateways for domain registrant information without querying target infrastructure.'
  },
  {
    id: 'col-dns',
    name: 'Authoritative DNS Inspector',
    type: 'passive',
    status: 'ready',
    lastRun: '2026-09-15T10:15:00Z',
    supportedFormats: ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'],
    description: 'Performs passive recursive DNS resolutions against public resolvers to map infrastructure and mail routing records.'
  },
  {
    id: 'col-harvester',
    name: 'theHarvester OSINT Importer',
    type: 'passive',
    status: 'ready',
    lastRun: '2026-09-16T11:20:00Z',
    supportedFormats: ['JSON', 'XML', 'HTML'],
    description: 'Parses sanitized theHarvester reconnaissance exports to ingest harvested emails, employee aliases, and public subdomains.'
  },
  {
    id: 'col-search',
    name: 'Search Engine Index Collector',
    type: 'passive',
    status: 'ready',
    lastRun: '2026-09-16T14:40:00Z',
    supportedFormats: ['URLs', 'Cached PDF Snippets', 'Search Evidence'],
    description: 'Indexes public search engine metadata, document mentions, and cached artifacts without interacting with target systems.'
  },
  {
    id: 'col-nmap',
    name: 'Nmap XML Ingestion Engine',
    type: 'active',
    status: 'ready',
    lastRun: '2026-09-18T16:00:00Z',
    supportedFormats: ['Nmap XML (-oX)', 'Grepable Output'],
    description: 'Ingests structured Nmap port and service scan results. Strictly validates target IP against active authorization allowlist.'
  },
  {
    id: 'col-openvas',
    name: 'OpenVAS / GVM XML Parser',
    type: 'active',
    status: 'ready',
    lastRun: '2026-09-19T09:30:00Z',
    supportedFormats: ['OpenVAS XML', 'GVM Report XML'],
    description: 'Imports vulnerability scanner reports, CVE associations, CVSS base metrics, and vendor remediation advice.'
  }
];
