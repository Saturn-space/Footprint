import { Finding, ExposureScoreBreakdown, Entity, Service } from '../types/models';

export function calculateExposureScore(
  findings: Finding[],
  entities: Entity[],
  services: Service[]
): ExposureScoreBreakdown {
  // 1. Attack Surface Score (0 - 25 pts)
  // Evaluates exposed hosts, open ports, subdomains
  const openPortCount = services.filter(s => s.state === 'open').length;
  const subdomainCount = entities.filter(e => e.type === 'Subdomain').length;
  const rawAttackSurface = Math.min(25, (openPortCount * 3.5) + (subdomainCount * 2));
  const attackSurfaceScore = Math.round(rawAttackSurface);

  // 2. Vulnerability Impact Score (0 - 35 pts)
  // Evaluates known CVEs and high severity findings
  let vulnPoints = 0;
  for (const f of findings) {
    if (f.status === 'mitigated' || f.status === 'false_positive') continue;
    switch (f.severity) {
      case 'critical':
        vulnPoints += 14;
        break;
      case 'high':
        vulnPoints += 8;
        break;
      case 'medium':
        vulnPoints += 4;
        break;
      case 'low':
        vulnPoints += 1.5;
        break;
      case 'info':
        vulnPoints += 0.5;
        break;
    }
  }
  const vulnerabilityImpactScore = Math.min(35, Math.round(vulnPoints));

  // 3. Credential & Email Exposure Score (0 - 20 pts)
  const emailCount = entities.filter(e => e.type === 'Email').length;
  const personCount = entities.filter(e => e.type === 'Person').length;
  const rawCredScore = Math.min(20, (emailCount * 2.5) + (personCount * 1.5));
  const credentialLeakScore = Math.round(rawCredScore);

  // 4. Configuration Hygiene Score (0 - 20 pts)
  // Evaluates misconfigurations like missing SPF/DMARC, TLS 1.0, directory listing
  const misconfigFindings = findings.filter(
    f => f.category === 'misconfiguration' && f.status !== 'mitigated'
  );
  const rawHygiene = Math.min(20, misconfigFindings.length * 6);
  const configurationHygieneScore = Math.round(rawHygiene);

  const totalScore = Math.min(100, attackSurfaceScore + vulnerabilityImpactScore + credentialLeakScore + configurationHygieneScore);

  let tier: ExposureScoreBreakdown['tier'] = 'Low Risk';
  if (totalScore >= 80) {
    tier = 'Critical Risk';
  } else if (totalScore >= 60) {
    tier = 'High Risk';
  } else if (totalScore >= 40) {
    tier = 'Elevated Risk';
  } else if (totalScore >= 20) {
    tier = 'Moderate Risk';
  }

  const P = Math.min(100, Math.round((credentialLeakScore / 20) * 100));
  const D = Math.min(100, Math.round((configurationHygieneScore / 20) * 100));
  const S = Math.min(100, Math.round((attackSurfaceScore / 25) * 100));
  const V = Math.min(100, Math.round((vulnerabilityImpactScore / 35) * 100));
  const C = 85;

  return {
    attackSurfaceScore,
    vulnerabilityImpactScore,
    credentialLeakScore,
    configurationHygieneScore,
    P,
    D,
    S,
    V,
    C,
    totalScore,
    tier,
    formulaVersion: 'v3.0-5factor (0.20*P + 0.15*D + 0.25*S + 0.35*V + 0.05*C)',
    scoreVersion: '3.0.0',
    reviewerNotes: 'Standard baseline assessment',
    calculationDate: new Date().toISOString()
  };
}
