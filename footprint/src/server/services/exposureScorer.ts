import {
  Finding,
  Entity,
  Service,
  Evidence,
  ExposureScoreBreakdown
} from '../../types/models';
import { ExposureScoreComponents } from '../../types/workflow';

export interface ScorerWeights {
  wP: number; // 0.20
  wD: number; // 0.15
  wS: number; // 0.25
  wV: number; // 0.35
  wC: number; // 0.05
}

export const DEFAULT_SCORER_WEIGHTS: ScorerWeights = {
  wP: 0.20,
  wD: 0.15,
  wS: 0.25,
  wV: 0.35,
  wC: 0.05
};

export class ExposureScorerService {
  private weights: ScorerWeights = DEFAULT_SCORER_WEIGHTS;

  /**
   * Calculate Phase 3 5-factor exposure score
   */
  calculateScore(
    findings: Finding[],
    entities: Entity[],
    services: Service[],
    evidenceList: Evidence[],
    reviewerNotes?: string
  ): ExposureScoreBreakdown {
    // 1. P: Public Footprint (0 - 100)
    const emailCount = entities.filter(e => e.type === 'Email').length;
    const personCount = entities.filter(e => e.type === 'Person').length;
    const docCount = entities.filter(e => e.type === 'Document').length;
    const searchEvidenceCount = evidenceList.filter(e => e.type.includes('SEARCH')).length;

    const rawP = (emailCount * 12) + (personCount * 8) + (docCount * 18) + (searchEvidenceCount * 10);
    const P = Math.min(100, Math.round(rawP));

    // 2. D: Domain Hygiene (0 - 100)
    const subdomains = entities.filter(e => e.type === 'Subdomain');
    const misconfigFindings = findings.filter(
      f => f.category === 'misconfiguration' && f.status !== 'mitigated' && f.status !== 'false_positive'
    );
    const missingDmarc = findings.some(f => f.title.toLowerCase().includes('dmarc') && f.status !== 'mitigated');

    let rawD = subdomains.length * 10;
    rawD += misconfigFindings.length * 15;
    if (missingDmarc) rawD += 25;
    const D = Math.min(100, Math.round(rawD));

    // 3. S: Service Exposure (0 - 100)
    const openServices = services.filter(s => s.state === 'open');
    let rawS = openServices.length * 14;

    // Penalty for exposed administrative or database ports
    for (const s of openServices) {
      if (s.port === 5432 || s.port === 3306 || s.port === 27017) rawS += 20; // Database
      if (s.port === 8080 || s.port === 8443 || s.port === 9090) rawS += 15; // Admin / CI / Metrics
      if (s.port === 80) rawS += 5; // Cleartext HTTP
    }
    const S = Math.min(100, Math.round(rawS));

    // 4. V: Vulnerability Severity (0 - 100)
    let rawV = 0;
    const activeFindings = findings.filter(
      f => f.status !== 'mitigated' && f.status !== 'false_positive'
    );

    for (const f of activeFindings) {
      const conf = f.confidence ?? 1.0;
      let points = 0;
      switch (f.severity) {
        case 'critical':
          points = 35;
          break;
        case 'high':
          points = 22;
          break;
        case 'medium':
          points = 12;
          break;
        case 'low':
          points = 5;
          break;
        case 'info':
          points = 1;
          break;
      }
      rawV += points * conf;
    }
    const V = Math.min(100, Math.round(rawV));

    // 5. C: Correlation Confidence (0 - 100)
    // Measures evidence corroboration across independent collectors
    const distinctTools = new Set(evidenceList.map(e => e.sourceTool)).size;
    const avgConfidence = evidenceList.length > 0
      ? evidenceList.reduce((acc, ev) => acc + (ev.confidence || 0.8), 0) / evidenceList.length
      : 0.5;

    const rawC = Math.min(100, (distinctTools * 18) + (avgConfidence * 30));
    const C = Math.round(rawC);

    // Compute composite exposure score using formula
    const compositeScore = (this.weights.wP * P) +
                           (this.weights.wD * D) +
                           (this.weights.wS * S) +
                           (this.weights.wV * V) +
                           (this.weights.wC * C);

    const totalScore = Math.min(100, Math.max(0, Math.round(compositeScore)));

    // Risk tier assignment
    let tier: ExposureScoreBreakdown['tier'] = 'Minimal';
    if (totalScore >= 80) {
      tier = 'Critical';
    } else if (totalScore >= 60) {
      tier = 'High';
    } else if (totalScore >= 40) {
      tier = 'Moderate';
    } else if (totalScore >= 20) {
      tier = 'Low';
    } else {
      tier = 'Minimal';
    }

    return {
      P,
      D,
      S,
      V,
      C,
      // Legacy compat properties for Phase 1 charts
      attackSurfaceScore: Math.round((S / 100) * 25),
      vulnerabilityImpactScore: Math.round((V / 100) * 35),
      credentialLeakScore: Math.round((P / 100) * 20),
      configurationHygieneScore: Math.round((D / 100) * 20),
      totalScore,
      tier,
      formulaVersion: 'v3.0-5factor (0.20*P + 0.15*D + 0.25*S + 0.35*V + 0.05*C)',
      scoreVersion: '3.0.0',
      reviewerNotes: reviewerNotes || 'Standard algorithm assessment against authorized scope baseline.',
      calculationDate: new Date().toISOString()
    };
  }
}

export const exposureScorer = new ExposureScorerService();
