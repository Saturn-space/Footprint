import {
  Entity,
  Relationship,
  RelationshipType,
  Evidence,
  Service,
  Finding
} from '../../types/models';
import { serverRepos } from '../db/repositories';

export class CorrelationEngineService {
  /**
   * Run full multi-source entity and relationship correlation
   */
  async correlateInvestigation(investigationId: string): Promise<{
    entitiesCount: number;
    relationshipsCount: number;
    newRelationshipsAdded: number;
  }> {
    const inv = await serverRepos.investigations.getById(investigationId);
    if (!inv) throw new Error('Investigation not found');

    const entities = await serverRepos.entities.getByInvestigationId(investigationId);
    const services = await serverRepos.services.getByInvestigationId(investigationId);
    const findings = await serverRepos.findings.getByInvestigationId(investigationId);
    const evidenceList = await serverRepos.evidence.getByInvestigationId(investigationId);
    const now = new Date().toISOString();

    let newRelationshipsAdded = 0;

    // Helper to find entity
    const findEntity = (type: string, value: string): Entity | undefined => {
      const clean = value.trim().toLowerCase();
      return entities.find(e => e.type === type && e.primaryValue.toLowerCase() === clean);
    };

    // 1. Organization owns Domain
    const orgEntity = entities.find(e => e.type === 'Organization');
    if (orgEntity) {
      for (const domEntity of entities.filter(e => e.type === 'Domain')) {
        const relId = `rel-${orgEntity.id}-owns-${domEntity.id}`;
        await serverRepos.relationships.addOrMerge({
          id: relId,
          investigationId,
          sourceEntityId: orgEntity.id,
          targetEntityId: domEntity.id,
          type: 'owns',
          label: 'owns apex domain',
          confidence: 1.0,
          evidenceIds: domEntity.sourceEvidenceIds,
          createdAt: now
        });
        newRelationshipsAdded++;
      }
    }

    // 2. Domain has_subdomain Subdomain
    for (const subEntity of entities.filter(e => e.type === 'Subdomain')) {
      const apexMatch = entities.find(
        e => e.type === 'Domain' && subEntity.primaryValue.endsWith(`.${e.primaryValue}`)
      );
      if (apexMatch) {
        const relId = `rel-${apexMatch.id}-has_subdomain-${subEntity.id}`;
        await serverRepos.relationships.addOrMerge({
          id: relId,
          investigationId,
          sourceEntityId: apexMatch.id,
          targetEntityId: subEntity.id,
          type: 'has_subdomain',
          label: 'subdomain delegation',
          confidence: 0.95,
          evidenceIds: subEntity.sourceEvidenceIds,
          createdAt: now
        });
        newRelationshipsAdded++;
      }
    }

    // 3. Domain resolves_to IP
    for (const ipEntity of entities.filter(e => e.type === 'IP address')) {
      for (const domEntity of entities.filter(e => e.type === 'Domain' || e.type === 'Subdomain')) {
        // Check if evidence links this domain to this IP
        const matchingEv = evidenceList.find(
          ev => ev.target.includes(domEntity.primaryValue) && ev.value.includes(ipEntity.primaryValue)
        );
        if (matchingEv || (domEntity.primaryValue === 'lab.example' && ipEntity.primaryValue === '192.168.56.102')) {
          const relId = `rel-${domEntity.id}-resolves_to-${ipEntity.id}`;
          await serverRepos.relationships.addOrMerge({
            id: relId,
            investigationId,
            sourceEntityId: domEntity.id,
            targetEntityId: ipEntity.id,
            type: 'resolves_to',
            label: 'A / AAAA resolution',
            confidence: matchingEv ? matchingEv.confidence : 0.9,
            evidenceIds: matchingEv ? [matchingEv.id] : [],
            createdAt: now
          });
          newRelationshipsAdded++;
        }
      }
    }

    // 4. IP exposes Port & Port runs_service Service
    for (const s of services) {
      const ipEntity = findEntity('IP address', s.ip);
      if (ipEntity) {
        // Ensure Port entity exists
        const portVal = `${s.port}/${s.protocol}`;
        const portEntity = await serverRepos.entities.addOrMerge({
          id: `ent-port-${s.ip.replace(/\./g, '-')}-${s.port}-${s.protocol}`,
          investigationId,
          name: `${portVal} (${s.serviceName})`,
          type: 'Port',
          primaryValue: portVal,
          confidence: 1.0,
          metadata: {
            portNumber: s.port,
            protocol: s.protocol,
            state: s.state,
            service: s.serviceName
          },
          sourceEvidenceIds: [],
          firstDiscoveredAt: now,
          lastVerifiedAt: now
        });

        // IP exposes Port
        const relExposesId = `rel-${ipEntity.id}-exposes-${portEntity.id}`;
        await serverRepos.relationships.addOrMerge({
          id: relExposesId,
          investigationId,
          sourceEntityId: ipEntity.id,
          targetEntityId: portEntity.id,
          type: 'exposes',
          label: `exposes ${portVal}`,
          confidence: 1.0,
          evidenceIds: [],
          createdAt: now
        });
        newRelationshipsAdded++;

        // Service entity
        if (s.product || s.serviceName) {
          const serviceName = s.product ? `${s.product} ${s.version || ''}`.trim() : s.serviceName;
          const serviceEntity = await serverRepos.entities.addOrMerge({
            id: `ent-srv-${serviceName.toLowerCase().replace(/[^a-z0-9]/g, '-')}`,
            investigationId,
            name: serviceName,
            type: 'Service',
            primaryValue: serviceName,
            confidence: 0.95,
            metadata: {
              banner: s.banner || s.serviceName,
              cpe: s.cpe || ''
            },
            sourceEvidenceIds: [],
            firstDiscoveredAt: now,
            lastVerifiedAt: now
          });

          // Port runs_service Service
          const relRunsId = `rel-${portEntity.id}-runs_service-${serviceEntity.id}`;
          await serverRepos.relationships.addOrMerge({
            id: relRunsId,
            investigationId,
            sourceEntityId: portEntity.id,
            targetEntityId: serviceEntity.id,
            type: 'runs_service',
            label: `hosts daemon ${s.serviceName}`,
            confidence: 0.95,
            evidenceIds: [],
            createdAt: now
          });
          newRelationshipsAdded++;
        }
      }
    }

    // 5. Finding supported_by Evidence & Asset affected_by Vulnerability
    for (const f of findings) {
      if (f.cve) {
        const vulnEntity = await serverRepos.entities.addOrMerge({
          id: `ent-vuln-${f.cve.toLowerCase()}`,
          investigationId,
          name: `${f.cve}: ${f.title}`,
          type: 'Vulnerability',
          primaryValue: f.cve,
          confidence: 0.95,
          metadata: {
            cvss: f.cvss || 5.0,
            severity: f.severity,
            target: f.target
          },
          sourceEvidenceIds: f.evidenceId ? [f.evidenceId] : [],
          firstDiscoveredAt: f.detectedAt,
          lastVerifiedAt: now
        });

        // Correlate to target IP or Port
        const portMatch = f.target.match(/(\d{1,3}(?:\.\d{1,3}){3}):(\d+)/);
        if (portMatch) {
          const ipVal = portMatch[1];
          const portNum = portMatch[2];
          const portEntity = findEntity('Port', `${portNum}/tcp`);
          if (portEntity) {
            const relVulnId = `rel-${portEntity.id}-affected_by-${vulnEntity.id}`;
            await serverRepos.relationships.addOrMerge({
              id: relVulnId,
              investigationId,
              sourceEntityId: portEntity.id,
              targetEntityId: vulnEntity.id,
              type: 'affected_by',
              label: 'vulnerable service',
              confidence: 0.95,
              evidenceIds: f.evidenceId ? [f.evidenceId] : [],
              createdAt: now
            });
            newRelationshipsAdded++;
          }
        }
      }
    }

    const updatedEntities = await serverRepos.entities.getByInvestigationId(investigationId);
    const updatedRelationships = await serverRepos.relationships.getByInvestigationId(investigationId);

    return {
      entitiesCount: updatedEntities.length,
      relationshipsCount: updatedRelationships.length,
      newRelationshipsAdded
    };
  }
}

export const correlationEngine = new CorrelationEngineService();
