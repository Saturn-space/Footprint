import { generateEvidenceHash } from '../../utils/hash';
import {
  Entity,
  Relationship,
  Evidence,
  Service,
  Finding,
  EntityType,
  RelationshipType
} from '../../types/models';
import { serverRepos } from '../db/repositories';

export class EvidenceNormalizerService {
  normalizeDomain(domain: string): string {
    return domain.trim().toLowerCase().replace(/\.$/, '');
  }

  normalizeIP(ip: string): string {
    const trimmed = ip.trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) return trimmed;
    return trimmed.split('.').map(part => parseInt(part, 10).toString()).join('.');
  }

  normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  normalizeURL(url: string): string {
    try {
      const parsed = new URL(url.trim());
      return parsed.toString();
    } catch {
      return url.trim().toLowerCase();
    }
  }

  /**
   * Correlates an evidence record into graph entities and relationships
   */
  async correlateEvidence(
    investigationId: string,
    evidence: Evidence
  ): Promise<{ entitiesAdded: number; relationshipsAdded: number }> {
    let entitiesAdded = 0;
    let relationshipsAdded = 0;
    const now = new Date().toISOString();

    // 1. If target is a domain, ensure Domain entity exists
    if (evidence.target && evidence.target.includes('.') && !/^\d+\.\d+/.test(evidence.target)) {
      const normDomain = this.normalizeDomain(evidence.target);
      const isSubdomain = normDomain.split('.').length > 2;
      const entityType: EntityType = isSubdomain ? 'Subdomain' : 'Domain';

      const domEntity = await serverRepos.entities.addOrMerge({
        id: `ent-dom-${normDomain.replace(/[^a-z0-9]/g, '-')}`,
        investigationId,
        name: normDomain,
        type: entityType,
        primaryValue: normDomain,
        confidence: evidence.confidence,
        metadata: {
          discoveredBy: evidence.sourceTool,
          lastVerified: now
        },
        sourceEvidenceIds: [evidence.id],
        firstDiscoveredAt: now,
        lastVerifiedAt: now
      });
      entitiesAdded++;

      // If subdomain, link to apex
      if (isSubdomain) {
        const parts = normDomain.split('.');
        const apexDomain = parts.slice(-2).join('.');
        const apexEntityId = `ent-dom-${apexDomain.replace(/[^a-z0-9]/g, '-')}`;

        await serverRepos.relationships.addOrMerge({
          id: `rel-${apexEntityId}-${domEntity.id}`,
          investigationId,
          sourceEntityId: apexEntityId,
          targetEntityId: domEntity.id,
          type: 'has_subdomain',
          label: 'subdomain zone',
          confidence: 0.95,
          evidenceIds: [evidence.id],
          createdAt: now
        });
        relationshipsAdded++;
      }
    }

    // 2. If target is an IP, ensure IP entity exists
    if (evidence.target && /^\d{1,3}(\.\d{1,3}){3}$/.test(evidence.target.trim())) {
      const normIp = this.normalizeIP(evidence.target);
      const ipEntity = await serverRepos.entities.addOrMerge({
        id: `ent-ip-${normIp.replace(/\./g, '-')}`,
        investigationId,
        name: normIp,
        type: 'IP address',
        primaryValue: normIp,
        confidence: evidence.confidence,
        metadata: {
          discoveredBy: evidence.sourceTool,
          lastVerified: now
        },
        sourceEvidenceIds: [evidence.id],
        firstDiscoveredAt: now,
        lastVerifiedAt: now
      });
      entitiesAdded++;
    }

    // 3. Process theHarvester attribute emails and hosts
    if (evidence.attributes) {
      const harvestedEmails = (evidence.attributes.harvestedEmails || evidence.attributes.emails || []) as string[];
      for (const email of harvestedEmails) {
        const normEmail = this.normalizeEmail(email);
        const namePart = normEmail.split('@')[0].replace(/[._]/g, ' ');
        const capName = namePart.split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');

        const emailEntity = await serverRepos.entities.addOrMerge({
          id: `ent-email-${normEmail.replace(/[^a-z0-9]/g, '-')}`,
          investigationId,
          name: normEmail,
          type: 'Email',
          primaryValue: normEmail,
          confidence: 0.9,
          metadata: { deliverable: true },
          sourceEvidenceIds: [evidence.id],
          firstDiscoveredAt: now,
          lastVerifiedAt: now
        });
        entitiesAdded++;

        // Person entity
        const personEntity = await serverRepos.entities.addOrMerge({
          id: `ent-person-${namePart.replace(/[^a-z0-9]/g, '-')}`,
          investigationId,
          name: capName,
          type: 'Person',
          primaryValue: capName,
          confidence: 0.85,
          metadata: { inferredFromEmail: normEmail },
          sourceEvidenceIds: [evidence.id],
          firstDiscoveredAt: now,
          lastVerifiedAt: now
        });
        entitiesAdded++;

        // Relate Person -> Email
        await serverRepos.relationships.addOrMerge({
          id: `rel-${personEntity.id}-${emailEntity.id}`,
          investigationId,
          sourceEntityId: personEntity.id,
          targetEntityId: emailEntity.id,
          type: 'associated_with',
          label: 'uses primary email',
          confidence: 0.9,
          evidenceIds: [evidence.id],
          createdAt: now
        });
        relationshipsAdded++;
      }
    }

    return { entitiesAdded, relationshipsAdded };
  }
}

export const evidenceNormalizer = new EvidenceNormalizerService();
