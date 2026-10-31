import { XMLParser } from 'fast-xml-parser';
import { FindingSeverity } from '../../../types/models';

export interface ParsedOpenVASFinding {
  id: string;
  name: string;
  host: string;
  port: number;
  protocol: 'tcp' | 'udp';
  rawSeverity: string;
  cvss: number;
  severity: FindingSeverity;
  cveReferences: string[];
  description: string;
  solution?: string;
  impact?: string;
  qod?: number; // Quality of detection
  status: 'scanner_detected';
}

export interface ParsedOpenVASReport {
  reportId: string;
  scanner: string;
  findings: ParsedOpenVASFinding[];
  hostsDetected: string[];
}

const MAX_XML_SIZE = 5 * 1024 * 1024; // 5 MB

export function mapOpenVASSeverity(cvss: number, threatStr: string): FindingSeverity {
  const normThreat = (threatStr || '').toLowerCase();
  if (cvss >= 9.0 || normThreat === 'critical') return 'critical';
  if (cvss >= 7.0 || normThreat === 'high') return 'high';
  if (cvss >= 4.0 || normThreat === 'medium') return 'medium';
  if (cvss > 0.0 || normThreat === 'low') return 'low';
  return 'info';
}

export function parseOpenVASXml(xmlContent: string): ParsedOpenVASReport {
  if (!xmlContent || typeof xmlContent !== 'string') {
    throw new Error('OpenVAS XML content must be a non-empty string');
  }

  if (Buffer.byteLength(xmlContent, 'utf8') > MAX_XML_SIZE) {
    throw new Error('Upload rejected: OpenVAS XML exceeds maximum allowed size (5MB)');
  }

  // XXE Defense
  if (/<!ENTITY/i.test(xmlContent) || /SYSTEM\s+["'][^"']+["']/i.test(xmlContent) || /PUBLIC\s+["'][^"']+["']/i.test(xmlContent)) {
    throw new Error('Security Violation: External XML Entities (XXE) are strictly prohibited');
  }

  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    processEntities: false,
    allowBooleanAttributes: false,
    trimValues: true
  });

  const parsed = parser.parse(xmlContent);
  const report = parsed?.report;
  if (!report) {
    throw new Error('Invalid OpenVAS XML: Missing root <report> element');
  }

  const resultsList = Array.isArray(report.results?.result)
    ? report.results.result
    : report.results?.result
    ? [report.results.result]
    : [];

  const findings: ParsedOpenVASFinding[] = [];
  const hostsDetectedSet = new Set<string>();
  const seenFindingKeys = new Set<string>();

  for (const r of resultsList) {
    const rawHost = String(r.host?.['#text'] || r.host || '').trim();
    if (!rawHost) continue;
    hostsDetectedSet.add(rawHost);

    // Port and protocol: e.g. "8080/tcp" or "general/tcp"
    const portStr = String(r.port || '0/tcp');
    const portMatch = portStr.match(/^(\d+)\/(tcp|udp)$/i);
    const port = portMatch ? parseInt(portMatch[1], 10) : 0;
    const protocol = portMatch && portMatch[2].toLowerCase() === 'udp' ? 'udp' : 'tcp';

    const nvt = r.nvt || {};
    const title = String(r.name || nvt.name || 'Unspecified Vulnerability').trim();
    const cvss = parseFloat(String(nvt.cvss_base || r.severity || '0.0')) || 0.0;
    const rawThreat = String(r.threat || 'Low');
    const severity = mapOpenVASSeverity(cvss, rawThreat);

    // CVE refs
    const cveRaw = nvt.cve || '';
    const cveReferences: string[] = [];
    if (typeof cveRaw === 'string' && cveRaw.trim()) {
      cveReferences.push(...cveRaw.split(/[\s,]+/).filter((c: string) => /^CVE-\d{4}-\d+$/i.test(c)));
    }

    const description = String(r.description || nvt.description || '').trim();
    const solution = String(nvt.solution || '').trim();
    const impact = String(nvt.impact || '').trim();
    const qod = parseInt(String(nvt.qod?.value || '70'), 10) || 70;

    // Deduplication Key: host + port + title + primary cve
    const dedupeKey = `${rawHost}:${port}:${title}:${cveReferences[0] || 'nocve'}`;
    if (seenFindingKeys.has(dedupeKey)) continue;
    seenFindingKeys.add(dedupeKey);

    findings.push({
      id: r['@_id'] || `ov-${findings.length + 1}`,
      name: title,
      host: rawHost,
      port,
      protocol,
      rawSeverity: rawThreat,
      cvss,
      severity,
      cveReferences,
      description,
      solution: solution || undefined,
      impact: impact || undefined,
      qod,
      status: 'scanner_detected'
    });
  }

  return {
    reportId: report['@_id'] || `openvas-rep-${Date.now()}`,
    scanner: 'OpenVAS / Greenbone Vulnerability Manager',
    findings,
    hostsDetected: Array.from(hostsDetectedSet)
  };
}
