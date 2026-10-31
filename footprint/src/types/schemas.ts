/**
 * FootprintIQ: OSINT Recon Toolkit — Zod Validation Schemas
 */
import { z } from 'zod';

export const ScopeSchema = z.object({
  ownedDomains: z.array(z.string().min(3)).min(1, 'At least one owned domain is required'),
  approvedIPs: z.array(z.string().regex(/^(\d{1,3}\.){3}\d{1,3}$/, 'Must be a valid IPv4 address')).default([]),
  approvedCIDRs: z.array(z.string().regex(/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/, 'Must be a valid CIDR')).default([]),
  passiveOnlyTargets: z.array(z.string()).default([]),
  activeTargets: z.array(z.string()).default([]),
  excludedTargets: z.array(z.string()).default([])
});

export const AuthorizationSchema = z.object({
  activeScanningEnabled: z.boolean().default(false),
  approvedBy: z.string().min(2, 'Approver name is required'),
  authorizationReference: z.string().min(3, 'Authorization document or ticket reference is required'),
  startDate: z.string().min(1, 'Start date is required'),
  expiryDate: z.string().min(1, 'Expiry date is required'),
  rulesOfEngagementConfirmed: z.boolean().refine(val => val === true, {
    message: 'Rules of Engagement must be confirmed'
  }),
  ownershipOrWrittenPermissionConfirmed: z.boolean().refine(val => val === true, {
    message: 'Ownership or written authorization is strictly required'
  }),
  notes: z.string().optional()
});

export const ModulesSchema = z.object({
  rdapWhois: z.boolean().default(true),
  dnsRecon: z.boolean().default(true),
  theHarvesterImport: z.boolean().default(true),
  searchEvidence: z.boolean().default(true),
  nmapXmlImport: z.boolean().default(true),
  openvasXmlImport: z.boolean().default(false),
  entityCorrelation: z.boolean().default(true),
  exposureScoring: z.boolean().default(true),
  pdfReporting: z.boolean().default(true)
});

export const InvestigationFormSchema = z.object({
  name: z.string().min(3, 'Investigation title must be at least 3 characters').max(80),
  organizationName: z.string().min(2, 'Organization name is required').max(80),
  description: z.string().min(10, 'Provide a meaningful purpose or description (min 10 chars)'),
  leadInvestigator: z.string().min(2, 'Lead investigator name is required'),
  teamMembers: z.array(z.string()).default([]),
  scope: ScopeSchema,
  authorization: AuthorizationSchema,
  modules: ModulesSchema,
  tags: z.array(z.string()).default([])
});

export type InvestigationFormValues = z.infer<typeof InvestigationFormSchema>;

export const EvidenceRecordSchema = z.object({
  id: z.string().min(1),
  investigationId: z.string().min(1),
  type: z.string().min(1),
  value: z.string().min(1),
  target: z.string().min(1),
  sourceTool: z.string().min(1),
  sourceFile: z.string().optional(),
  collectedAt: z.string(),
  interactionType: z.enum(['passive', 'active']),
  confidence: z.number().min(0).max(1),
  authorizedScope: z.boolean(),
  attributes: z.record(z.string(), z.unknown()),
  evidenceHash: z.string().min(1),
  validationStatus: z.enum(['verified', 'unverified', 'flagged'])
});
