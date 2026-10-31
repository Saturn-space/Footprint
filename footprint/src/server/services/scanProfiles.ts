import { ApprovedScanProfile, ScanProfileDefinition } from '../../types/workflow';

export const APPROVED_SCAN_PROFILES: Record<ApprovedScanProfile, ScanProfileDefinition> = {
  'host-discovery': {
    id: 'host-discovery',
    name: 'Host Discovery (Safe ICMP/Echo)',
    scanner: 'nmap',
    description: 'Discovers responsive active hosts using safe ICMP echo and standard TCP probes without port inspection.',
    fixedArgs: ['-sn', '-PE', '-PS22,80,443', '--max-retries', '1', '-oX'],
    estimatedDurationSeconds: 15,
    safetyLevel: 'strictly_passive_safe'
  },
  'safe-service-detection': {
    id: 'safe-service-detection',
    name: 'Safe Service & Port Banner Probe',
    scanner: 'nmap',
    description: 'Probes common authorized service ports (22, 80, 443, 5432, 8080) and inspects service version banners using full TCP handshake.',
    fixedArgs: ['-sV', '-sT', '-p', '22,80,443,5432,8080', '--version-light', '--max-retries', '1', '-oX'],
    estimatedDurationSeconds: 30,
    safetyLevel: 'low_impact_active'
  },
  'safe-os-detection': {
    id: 'safe-os-detection',
    name: 'Safe OS Fingerprint Identification',
    scanner: 'nmap',
    description: 'Passively analyzes IP packet header nuances to identify the host operating system family without aggressive timing.',
    fixedArgs: ['-O', '--osscan-limit', '--max-os-tries', '1', '-oX'],
    estimatedDurationSeconds: 25,
    safetyLevel: 'low_impact_active'
  },
  'openvas-basic': {
    id: 'openvas-basic',
    name: 'OpenVAS Baseline Vulnerability Audit',
    scanner: 'openvas',
    description: 'Audits host for default configuration disclosures, weak TLS parameters, and missing security headers.',
    fixedArgs: ['--config', 'Base', '--timeout', '60', '--max-hosts', '1', '-oX'],
    estimatedDurationSeconds: 45,
    safetyLevel: 'authenticated_vulnerability_probe'
  },
  'openvas-full-and-fast': {
    id: 'openvas-full-and-fast',
    name: 'OpenVAS Full & Fast Vulnerability Assessment',
    scanner: 'openvas',
    description: 'Comprehensive vulnerability scan checking known NVD CVEs against probed service versions using standard Greenbone signatures.',
    fixedArgs: ['--config', 'Full and fast', '--timeout', '120', '--max-hosts', '1', '-oX'],
    estimatedDurationSeconds: 60,
    safetyLevel: 'authenticated_vulnerability_probe'
  }
};

export function getScanProfile(profileId: string): ScanProfileDefinition | null {
  if (profileId in APPROVED_SCAN_PROFILES) {
    return APPROVED_SCAN_PROFILES[profileId as ApprovedScanProfile];
  }
  return null;
}

export function isValidScanProfile(profileId: string): profileId is ApprovedScanProfile {
  return profileId in APPROVED_SCAN_PROFILES;
}
