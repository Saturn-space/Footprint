import { XMLParser } from 'fast-xml-parser';

export interface ParsedNmapPort {
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
  serviceName: string;
  product?: string;
  version?: string;
  extraInfo?: string;
  cpe?: string;
}

export interface ParsedNmapHost {
  ip: string;
  mac?: string;
  hostnames: string[];
  status: 'up' | 'down';
  ports: ParsedNmapPort[];
  osMatch?: string;
  scanStartTime?: string;
  scanEndTime?: string;
}

export interface ParsedNmapResult {
  scanner: string;
  version: string;
  args: string;
  hosts: ParsedNmapHost[];
  totalHostsScanned: number;
}

const MAX_XML_SIZE = 5 * 1024 * 1024; // 5 MB

export function parseNmapXml(xmlContent: string): ParsedNmapResult {
  if (!xmlContent || typeof xmlContent !== 'string') {
    throw new Error('Nmap XML content must be a non-empty string');
  }

  if (Buffer.byteLength(xmlContent, 'utf8') > MAX_XML_SIZE) {
    throw new Error('Upload rejected: Nmap XML exceeds maximum allowed size (5MB)');
  }

  // XXE Defense: Check for dangerous DOCTYPE entity expansions
  if (/<!ENTITY/i.test(xmlContent) || /SYSTEM\s+["'][^"']+["']/i.test(xmlContent) || /PUBLIC\s+["'][^"']+["']/i.test(xmlContent)) {
    throw new Error('Security Violation: External XML Entities (XXE) are strictly prohibited');
  }

  // Configure fast-xml-parser securely without external entity resolution
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    processEntities: false, // Prevents XML entity expansion / XXE
    allowBooleanAttributes: false,
    trimValues: true
  });

  const parsed = parser.parse(xmlContent);
  const nmaprun = parsed?.nmaprun;
  if (!nmaprun) {
    throw new Error('Invalid Nmap XML: Missing root <nmaprun> element');
  }

  const hostsList = Array.isArray(nmaprun.host)
    ? nmaprun.host
    : nmaprun.host
    ? [nmaprun.host]
    : [];

  const hosts: ParsedNmapHost[] = [];

  for (const h of hostsList) {
    // Extract IP address
    const addressNodes = Array.isArray(h.address) ? h.address : h.address ? [h.address] : [];
    let ip = '';
    let mac: string | undefined;

    for (const addr of addressNodes) {
      if (addr['@_addrtype'] === 'ipv4' || addr['@_addrtype'] === 'ipv6') {
        ip = addr['@_addr'];
      } else if (addr['@_addrtype'] === 'mac') {
        mac = addr['@_addr'];
      }
    }

    if (!ip) continue;

    // Status
    const status = h.status?.['@_state'] === 'up' ? 'up' : 'down';

    // Hostnames
    const hostnameNodes = Array.isArray(h.hostnames?.hostname)
      ? h.hostnames.hostname
      : h.hostnames?.hostname
      ? [h.hostnames.hostname]
      : [];
    const hostnames: string[] = hostnameNodes
      .map((hn: any) => hn['@_name'])
      .filter(Boolean);

    // Ports
    const portNodes = Array.isArray(h.ports?.port)
      ? h.ports.port
      : h.ports?.port
      ? [h.ports.port]
      : [];
    const ports: ParsedNmapPort[] = [];

    for (const p of portNodes) {
      const portId = parseInt(p['@_portid'], 10);
      const protocol = p['@_protocol'] === 'udp' ? 'udp' : 'tcp';
      const state = p.state?.['@_state'] === 'open' ? 'open' : p.state?.['@_state'] === 'filtered' ? 'filtered' : 'closed';
      const s = p.service || {};

      const cpeVal = Array.isArray(s.cpe) ? s.cpe[0] : s.cpe;

      ports.push({
        port: portId,
        protocol,
        state,
        serviceName: s['@_name'] || 'unknown',
        product: s['@_product'],
        version: s['@_version'],
        extraInfo: s['@_extrainfo'],
        cpe: typeof cpeVal === 'string' ? cpeVal : undefined
      });
    }

    // OS guess
    const osMatch = h.os?.osmatch?.[0]?.['@_name'] || h.os?.osmatch?.['@_name'];

    hosts.push({
      ip,
      mac,
      hostnames,
      status,
      ports,
      osMatch: typeof osMatch === 'string' ? osMatch : undefined,
      scanStartTime: h['@_starttime'],
      scanEndTime: h['@_endtime']
    });
  }

  return {
    scanner: 'nmap',
    version: nmaprun['@_version'] || '7.x',
    args: nmaprun['@_args'] || '',
    hosts,
    totalHostsScanned: hosts.length
  };
}
