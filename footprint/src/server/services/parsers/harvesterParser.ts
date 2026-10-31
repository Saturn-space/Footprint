import { XMLParser } from 'fast-xml-parser';

export interface ParsedHarvesterData {
  sourceFile?: string;
  targetDomain?: string;
  emails: string[];
  hosts: string[];
  ips: string[];
  urls: string[];
  sources: string[];
}

const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

export function parseHarvesterExport(rawContent: string, filename?: string): ParsedHarvesterData {
  if (!rawContent || typeof rawContent !== 'string') {
    throw new Error('theHarvester export payload must be a non-empty string');
  }

  if (Buffer.byteLength(rawContent, 'utf8') > MAX_FILE_SIZE) {
    throw new Error('File exceeds maximum upload size (5MB)');
  }

  const emailsSet = new Set<string>();
  const hostsSet = new Set<string>();
  const ipsSet = new Set<string>();
  const urlsSet = new Set<string>();
  const sourcesSet = new Set<string>();

  const trimmed = rawContent.trim();

  // 1. Try JSON parsing first
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      const data = JSON.parse(trimmed);
      const parsedData = Array.isArray(data) ? data[0] : data;

      // Extract emails
      const rawEmails = parsedData.emails || parsedData.interesting_emails || [];
      if (Array.isArray(rawEmails)) {
        for (const em of rawEmails) {
          if (typeof em === 'string' && em.includes('@')) {
            emailsSet.add(em.trim().toLowerCase());
          }
        }
      }

      // Extract hosts/subdomains
      const rawHosts = parsedData.hosts || parsedData.subdomains || [];
      if (Array.isArray(rawHosts)) {
        for (const h of rawHosts) {
          const val = typeof h === 'string' ? h : h?.host || h?.subdomain;
          if (typeof val === 'string' && val.includes('.')) {
            hostsSet.add(val.trim().toLowerCase().replace(/\.$/, ''));
          }
        }
      }

      // Extract IPs
      const rawIps = parsedData.ips || [];
      if (Array.isArray(rawIps)) {
        for (const ip of rawIps) {
          if (typeof ip === 'string' && /^\d{1,3}(\.\d{1,3}){3}$/.test(ip.trim())) {
            ipsSet.add(ip.trim());
          }
        }
      }

      // Extract sources
      if (Array.isArray(parsedData.sources)) {
        for (const s of parsedData.sources) {
          if (typeof s === 'string') sourcesSet.add(s);
        }
      }

      return {
        sourceFile: filename || 'theharvester_export.json',
        targetDomain: parsedData.target || parsedData.domain,
        emails: Array.from(emailsSet),
        hosts: Array.from(hostsSet),
        ips: Array.from(ipsSet),
        urls: Array.from(urlsSet),
        sources: Array.from(sourcesSet)
      };
    } catch (jsonErr: any) {
      // If not valid JSON, proceed to XML check
    }
  }

  // 2. Try XML parsing
  if (trimmed.startsWith('<')) {
    if (/<!ENTITY/i.test(trimmed)) {
      throw new Error('Security Violation: External XML Entities (XXE) are prohibited');
    }

    const parser = new XMLParser({
      ignoreAttributes: false,
      processEntities: false,
      trimValues: true
    });
    const parsedXml = parser.parse(trimmed);
    const root = parsedXml?.theHarvester || parsedXml?.harvester;
    if (!root) {
      throw new Error('Invalid theHarvester export format (expected JSON or XML root)');
    }

    const emailNodes = Array.isArray(root.email) ? root.email : root.email ? [root.email] : [];
    for (const e of emailNodes) {
      const val = typeof e === 'string' ? e : e?.['#text'];
      if (typeof val === 'string' && val.includes('@')) emailsSet.add(val.trim().toLowerCase());
    }

    const hostNodes = Array.isArray(root.host) ? root.host : root.host ? [root.host] : [];
    for (const h of hostNodes) {
      const val = typeof h === 'string' ? h : h?.hostname || h?.['#text'];
      if (typeof val === 'string' && val.includes('.')) hostsSet.add(val.trim().toLowerCase());
    }

    return {
      sourceFile: filename || 'theharvester_export.xml',
      emails: Array.from(emailsSet),
      hosts: Array.from(hostsSet),
      ips: Array.from(ipsSet),
      urls: Array.from(urlsSet),
      sources: ['theHarvester']
    };
  }

  throw new Error('Unsupported format: theHarvester export must be valid JSON or XML');
}
