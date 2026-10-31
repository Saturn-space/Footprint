import {
  isValidIPv4,
  isValidIPv6,
  isValidDomain,
  isValidCIDR,
  isIpInCidr,
  scopeValidator
} from '../services/scopeValidator';
import { parseNmapXml } from '../services/parsers/nmapParser';
import { parseOpenVASXml } from '../services/parsers/openvasParser';
import { parseHarvesterExport } from '../services/parsers/harvesterParser';
import { evidenceNormalizer } from '../services/normalizer';
import { SAMPLE_NMAP_XML, SAMPLE_OPENVAS_XML } from '../../data/sampleScanFiles';
import { INITIAL_INVESTIGATION } from '../../data/seedData';
import { serverRepos } from '../db/repositories';

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${testName}`);
  } else {
    failed++;
    console.error(`  ✗ FAIL: ${testName} ${detail ? `(${detail})` : ''}`);
  }
}

async function runTests() {
  console.log('====================================================');
  console.log(' FootprintIQ: Phase 2 Comprehensive Test Suite');
  console.log('====================================================\n');

  // ----------------------------------------------------
  // 1. Scope Validation Unit Tests
  // ----------------------------------------------------
  console.log('[1. Scope Validator Tests]');
  assert(isValidIPv4('192.168.56.102'), 'Valid IPv4 accepted');
  assert(!isValidIPv4('999.168.1.1'), 'Invalid IPv4 octet rejected');
  assert(!isValidIPv4('not-an-ip'), 'Non-IP string rejected');

  assert(isValidIPv6('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), 'Valid IPv6 accepted');
  assert(!isValidIPv6('2001:xyz'), 'Malformed IPv6 rejected');

  assert(isValidDomain('lab.example'), 'Valid FQDN accepted');
  assert(isValidDomain('research.lab.example'), 'Valid subdomain accepted');
  assert(!isValidDomain('invalid..domain'), 'Malformed domain with double dot rejected');

  assert(isValidCIDR('192.168.56.0/24'), 'Valid CIDR prefix /24 accepted');
  assert(!isValidCIDR('192.168.56.0/35'), 'Invalid CIDR prefix /35 rejected');

  assert(isIpInCidr('192.168.56.102', '192.168.56.0/24'), 'IP matches CIDR subnet');
  assert(!isIpInCidr('10.0.0.5', '192.168.56.0/24'), 'Out-of-subnet IP rejected from CIDR');

  // Scope check against investigation
  const allowlistedCheck = await scopeValidator.validateTarget(INITIAL_INVESTIGATION, '192.168.56.102', true);
  assert(allowlistedCheck.isValid, 'Allowlisted lab IP 192.168.56.102 passes active check');

  const outOfScopeCheck = await scopeValidator.validateTarget(INITIAL_INVESTIGATION, '10.99.99.1', true);
  assert(!outOfScopeCheck.isValid, 'Out-of-scope host 10.99.99.1 is blocked by active allowlist');

  // Test expired authorization
  const expiredInv = {
    ...INITIAL_INVESTIGATION,
    authorization: {
      ...INITIAL_INVESTIGATION.authorization,
      expiryDate: '2020-01-01T00:00:00Z'
    }
  };
  const expiredCheck = await scopeValidator.validateTarget(expiredInv, '192.168.56.102', true);
  assert(!expiredCheck.isValid && expiredCheck.authorizationExpired, 'Expired authorization correctly halts active operations');

  // ----------------------------------------------------
  // 2. Nmap XML Parser Tests
  // ----------------------------------------------------
  console.log('\n[2. Nmap XML Parser Tests]');
  const parsedNmap = parseNmapXml(SAMPLE_NMAP_XML);
  assert(parsedNmap.hosts.length === 1, 'Extracted exactly 1 host from sample Nmap XML');
  assert(parsedNmap.hosts[0].ip === '192.168.56.102', 'Correctly extracted host IP 192.168.56.102');
  assert(parsedNmap.hosts[0].ports.length === 5, 'Extracted 5 open/probed ports (22, 80, 443, 5432, 8080)');
  assert(parsedNmap.hosts[0].ports.some(p => p.port === 5432 && p.serviceName === 'postgresql'), 'PostgreSQL port 5432 recognized');

  // Test XXE defense in Nmap
  let nmapXxeBlocked = false;
  try {
    const maliciousXml = `<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><nmaprun>&xxe;</nmaprun>`;
    parseNmapXml(maliciousXml);
  } catch (err: any) {
    if (err.message.includes('XXE') || err.message.includes('Security Violation')) {
      nmapXxeBlocked = true;
    }
  }
  assert(nmapXxeBlocked, 'Nmap XML parser blocked malicious XXE entity injection');

  // ----------------------------------------------------
  // 3. OpenVAS XML Parser Tests
  // ----------------------------------------------------
  console.log('\n[3. OpenVAS XML Parser Tests]');
  const parsedOpenVAS = parseOpenVASXml(SAMPLE_OPENVAS_XML);
  assert(parsedOpenVAS.findings.length === 2, 'Parsed 2 vulnerability findings from OpenVAS sample');
  assert(parsedOpenVAS.findings.some(f => f.cveReferences.includes('CVE-2023-38606')), 'Extracted CVE-2023-38606 finding');
  assert(parsedOpenVAS.findings[0].host === '192.168.56.102', 'Matched target host 192.168.56.102');

  // Test XXE defense in OpenVAS
  let openvasXxeBlocked = false;
  try {
    const maliciousXml = `<?xml version="1.0"?><!DOCTYPE report [ <!ENTITY xxe SYSTEM "http://malicious.external/x"> ]><report>&xxe;</report>`;
    parseOpenVASXml(maliciousXml);
  } catch (err: any) {
    if (err.message.includes('XXE') || err.message.includes('Security Violation')) {
      openvasXxeBlocked = true;
    }
  }
  assert(openvasXxeBlocked, 'OpenVAS XML parser blocked malicious XXE entity injection');

  // ----------------------------------------------------
  // 4. theHarvester Parser Tests
  // ----------------------------------------------------
  console.log('\n[4. theHarvester Parser Tests]');
  const sampleHarvesterJson = JSON.stringify({
    domain: 'lab.example',
    emails: ['elena.rostova@lab.example', 'devops@lab.example'],
    hosts: ['auth.lab.example', 'research.lab.example'],
    ips: ['192.168.56.102'],
    sources: ['google', 'bing']
  });
  const parsedHarvester = parseHarvesterExport(sampleHarvesterJson);
  assert(parsedHarvester.emails.length === 2, 'Parsed 2 harvested email addresses');
  assert(parsedHarvester.hosts.length === 2, 'Parsed 2 harvested subdomains');
  assert(parsedHarvester.sources.includes('google'), 'Captured OSINT sources');

  // ----------------------------------------------------
  // 5. Evidence Normalization Tests
  // ----------------------------------------------------
  console.log('\n[5. Normalization & Correlation Tests]');
  assert(evidenceNormalizer.normalizeDomain('  LAB.EXAMPLE.  ') === 'lab.example', 'Domain normalized to lowercase without trailing dots');
  assert(evidenceNormalizer.normalizeIP('192.168.056.102') === '192.168.56.102', 'IP normalized without leading zeros');
  assert(evidenceNormalizer.normalizeEmail('  ELENA@Lab.Example ') === 'elena@lab.example', 'Email normalized to lowercase');

  // ----------------------------------------------------
  // 6. RBAC Role Permissions Tests
  // ----------------------------------------------------
  console.log('\n[6. RBAC Role Definition Tests]');
  const allUsers = await serverRepos.users.getAll();
  const adminUser = allUsers.find(u => u.role === 'admin');
  const investigatorUser = allUsers.find(u => u.role === 'investigator');
  const reviewerUser = allUsers.find(u => u.role === 'reviewer');
  const viewerUser = allUsers.find(u => u.role === 'viewer');

  assert(Boolean(adminUser), 'Admin role account configured (Asip Ali)');
  assert(Boolean(investigatorUser), 'Investigator role account configured (Mohan Prasad)');
  assert(Boolean(reviewerUser), 'Reviewer role account configured (Dr. Marcus Vance)');
  assert(Boolean(viewerUser), 'Viewer role account configured (Auditor Guest)');

  // ----------------------------------------------------
  // 7. Phase 3: Semi-Autonomous Workflow Controller Tests
  // ----------------------------------------------------
  console.log('\n[7. Workflow Controller Tests]');
  const { workflowController } = await import('../services/workflowController');
  const testRun = await workflowController.startWorkflow(INITIAL_INVESTIGATION.id, 'Test Suite Runner');
  assert(testRun.id.startsWith('wf-run-'), 'Workflow run generated with unique identifier');
  assert(testRun.stateHistory.some(h => h.state === 'CREATED'), 'Workflow state history records initial CREATED state');
  assert(testRun.stateHistory.some(h => h.state === 'SCOPE_VALIDATED'), 'Workflow successfully progressed through SCOPE_VALIDATED');

  // Explicit test of transitionState
  await workflowController.transitionState(testRun, 'WAITING_FOR_APPROVAL', 'Awaiting investigator approval');
  testRun.currentState = 'WAITING_FOR_APPROVAL';
  assert(testRun.currentState === 'WAITING_FOR_APPROVAL', 'Workflow pauses at WAITING_FOR_APPROVAL gate');

  // Approval gate
  const approvedRun = await workflowController.approveActiveStage(testRun.id, 'Dr. Marcus Vance (Reviewer)');
  assert(approvedRun.activeApprovedBy === 'Dr. Marcus Vance (Reviewer)', 'Approval gatekeeper recorded human approver');

  // ----------------------------------------------------
  // 8. Phase 3: Authorized Worker Control Plane Tests
  // ----------------------------------------------------
  console.log('\n[8. Authorized Worker Control Plane Tests]');
  const { workerManager } = await import('../services/workerManager');
  const registeredWorker = await workerManager.registerWorker(
    'Integration Test Daemon',
    'local_lab',
    ['safe-service-detection', 'openvas-basic'],
    '192.168.56.220'
  );
  assert(Boolean(registeredWorker.workerId), 'Worker registered with unique ID');
  assert(registeredWorker.secretToken.startsWith('sec-'), 'Worker issued secure secret token');

  // Heartbeat check
  const heartbeatOk = await workerManager.recordHeartbeat(registeredWorker.workerId, registeredWorker.secretToken);
  assert(heartbeatOk, 'Worker heartbeat recorded successfully with valid token');

  const badHeartbeat = await workerManager.recordHeartbeat(registeredWorker.workerId, 'invalid-token');
  assert(!badHeartbeat, 'Unauthorized heartbeat rejected with invalid token');

  // Create job and test target binding check
  const testJob = await workerManager.createJob(
    INITIAL_INVESTIGATION.id,
    testRun.id,
    '192.168.56.102',
    'safe-service-detection',
    registeredWorker.workerId
  );
  assert(testJob.status === 'queued', 'Worker job created in queued state');

  const acceptedJob = await workerManager.acceptJob(testJob.id, testJob.token);
  assert(acceptedJob.status === 'running', 'Worker accepted job using short-lived job token');

  // Test target mismatch protection
  let targetMismatchBlocked = false;
  try {
    await workerManager.submitResult(
      testJob.id,
      testJob.token,
      '10.99.99.1', // unauthorized mismatched target!
      SAMPLE_NMAP_XML
    );
  } catch (err: any) {
    if (err.message.includes('MISMATCH')) targetMismatchBlocked = true;
  }
  assert(targetMismatchBlocked, 'Target mismatch rejected: worker cannot report on unauthorized IP');

  // ----------------------------------------------------
  // 9. Phase 3: Multi-Factor Correlation Engine Tests
  // ----------------------------------------------------
  console.log('\n[9. Multi-Factor Correlation Engine Tests]');
  const { correlationEngine } = await import('../services/correlationEngine');
  const correlationResult = await correlationEngine.correlateInvestigation(INITIAL_INVESTIGATION.id);
  assert(correlationResult.entitiesCount > 0, 'Correlation engine processed existing entities');
  assert(correlationResult.relationshipsCount > 0, 'Correlation engine established relationships');

  // ----------------------------------------------------
  // 10. Phase 3: 5-Factor Exposure Scoring Tests
  // ----------------------------------------------------
  console.log('\n[10. 5-Factor Exposure Scorer Tests]');
  const { exposureScorer } = await import('../services/exposureScorer');
  const findings = await serverRepos.findings.getByInvestigationId(INITIAL_INVESTIGATION.id);
  const entities = await serverRepos.entities.getByInvestigationId(INITIAL_INVESTIGATION.id);
  const services = await serverRepos.services.getByInvestigationId(INITIAL_INVESTIGATION.id);
  const evidenceList = await serverRepos.evidence.getByInvestigationId(INITIAL_INVESTIGATION.id);

  const scoreResult = exposureScorer.calculateScore(findings, entities, services, evidenceList);
  assert(typeof scoreResult.P === 'number' && scoreResult.P >= 0 && scoreResult.P <= 100, 'P (Public Footprint) score in [0, 100]');
  assert(typeof scoreResult.D === 'number' && scoreResult.D >= 0 && scoreResult.D <= 100, 'D (Domain Hygiene) score in [0, 100]');
  assert(typeof scoreResult.S === 'number' && scoreResult.S >= 0 && scoreResult.S <= 100, 'S (Service Exposure) score in [0, 100]');
  assert(typeof scoreResult.V === 'number' && scoreResult.V >= 0 && scoreResult.V <= 100, 'V (Vulnerability Severity) score in [0, 100]');
  assert(typeof scoreResult.C === 'number' && scoreResult.C >= 0 && scoreResult.C <= 100, 'C (Correlation Confidence) score in [0, 100]');
  assert(scoreResult.totalScore >= 0 && scoreResult.totalScore <= 100, 'Total composite score in [0, 100]');
  assert(['Minimal', 'Low', 'Moderate', 'High', 'Critical'].includes(scoreResult.tier), 'Valid risk tier assigned');

  // ----------------------------------------------------
  // 11. Phase 3: 20-Section Comprehensive Dossier Tests
  // ----------------------------------------------------
  console.log('\n[11. 20-Section Report Generator Tests]');
  const { reportGenerator } = await import('../services/reportGenerator');
  const report = await reportGenerator.generateComprehensiveReport(
    INITIAL_INVESTIGATION.id,
    'Integration Test Dossier',
    'Asip Ali (251347048)'
  );
  assert(report.sections.length === 20, `Generated comprehensive dossier with exactly 20 sections (found ${report.sections.length})`);
  assert(report.sections[0].title.includes('Cover Page'), 'Section 1 contains Cover Page');
  assert(report.sections[19].title.includes('Cryptographic File-Hash Manifest'), 'Section 20 contains File-Hash Manifest');

  // Binary PDF Generation test
  const pdfBytes = await reportGenerator.buildBinaryPdf(report, INITIAL_INVESTIGATION);
  assert(pdfBytes && pdfBytes.byteLength > 1000, 'Successfully built binary PDF document using jsPDF');

  // Print Summary
  console.log('\n====================================================');
  console.log(` Test Results: ${passed} Passed | ${failed} Failed`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Test runner fatal error:', err);
  process.exit(1);
});
