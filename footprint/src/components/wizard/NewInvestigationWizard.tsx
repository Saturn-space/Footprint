import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield,
  Target,
  FileCheck,
  Cpu,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  Info
} from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { InvestigationFormSchema, InvestigationFormValues } from '../../types/schemas';
import { Investigation } from '../../types/models';

export const NewInvestigationWizard: React.FC = () => {
  const navigate = useNavigate();
  const { currentUser, createInvestigation } = useInvestigation();

  const [currentStep, setCurrentStep] = useState<number>(1);
  const [formData, setFormData] = useState<InvestigationFormValues>({
    name: 'Lab Security Audit — Sandbox Environment',
    organizationName: 'NorthStar Analytics Lab',
    description: 'Educational reconnaissance to assess external digital footprint exposure of the lab environment.',
    leadInvestigator: `${currentUser.name} (${currentUser.studentId})`,
    teamMembers: ['Mohan Prasad (ID: 251347070)'],
    scope: {
      ownedDomains: ['lab.example'],
      approvedIPs: ['192.168.56.102'],
      approvedCIDRs: ['192.168.56.0/24'],
      passiveOnlyTargets: ['lab.example', 'research.lab.example'],
      activeTargets: ['192.168.56.102'],
      excludedTargets: ['*.gov', '*.mil']
    },
    authorization: {
      activeScanningEnabled: true,
      approvedBy: 'Lab Safety Committee & Dr. Marcus Vance',
      authorizationReference: 'AUTH-2026-LAB-099',
      startDate: new Date().toISOString().split('T')[0],
      expiryDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
      rulesOfEngagementConfirmed: true,
      ownershipOrWrittenPermissionConfirmed: true,
      notes: 'Authorized sandbox assessment strictly within isolated lab environment.'
    },
    modules: {
      rdapWhois: true,
      dnsRecon: true,
      theHarvesterImport: true,
      searchEvidence: true,
      nmapXmlImport: true,
      openvasXmlImport: false,
      entityCorrelation: true,
      exposureScoring: true,
      pdfReporting: true
    },
    tags: ['educational', 'lab-audit', 'osint']
  });

  const [errors, setErrors] = useState<Record<string, string>>({});
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Quick state updaters
  const updateScopeField = (field: keyof typeof formData.scope, rawValue: string) => {
    const items = rawValue.split(',').map(s => s.trim()).filter(Boolean);
    setFormData(prev => ({
      ...prev,
      scope: {
        ...prev.scope,
        [field]: items
      }
    }));
  };

  const validateCurrentStep = (): boolean => {
    const newErrors: Record<string, string> = {};

    if (currentStep === 1) {
      if (!formData.name || formData.name.length < 3) {
        newErrors.name = 'Investigation name must be at least 3 characters.';
      }
      if (!formData.organizationName || formData.organizationName.length < 2) {
        newErrors.organizationName = 'Organization name is required.';
      }
      if (!formData.description || formData.description.length < 10) {
        newErrors.description = 'Provide a meaningful purpose description (min 10 characters).';
      }
      if (!formData.leadInvestigator) {
        newErrors.leadInvestigator = 'Lead investigator is required.';
      }
    }

    if (currentStep === 2) {
      if (!formData.scope.ownedDomains || formData.scope.ownedDomains.length === 0) {
        newErrors.ownedDomains = 'At least one owned target domain is required.';
      }
    }

    if (currentStep === 3) {
      if (!formData.authorization.approvedBy) {
        newErrors.approvedBy = 'Approver or authorizing body name is required.';
      }
      if (!formData.authorization.authorizationReference) {
        newErrors.authorizationReference = 'Authorization reference or ticket number is required.';
      }
      if (!formData.authorization.rulesOfEngagementConfirmed) {
        newErrors.rulesOfEngagementConfirmed = 'You must confirm adherence to the Rules of Engagement.';
      }
      if (!formData.authorization.ownershipOrWrittenPermissionConfirmed) {
        newErrors.ownershipOrWrittenPermissionConfirmed = 'Explicit ownership or written lab permission is required.';
      }
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleNext = () => {
    if (validateCurrentStep()) {
      setCurrentStep(prev => Math.min(5, prev + 1));
    }
  };

  const handleBack = () => {
    setCurrentStep(prev => Math.max(1, prev - 1));
  };

  const handleFinalSubmit = async () => {
    try {
      setIsSubmitting(true);
      const validated = InvestigationFormSchema.parse(formData);

      const newInv: Investigation = {
        id: `inv-${Date.now()}`,
        name: validated.name,
        organizationName: validated.organizationName,
        description: validated.description,
        leadInvestigator: validated.leadInvestigator,
        teamMembers: validated.teamMembers,
        status: 'active',
        scope: validated.scope,
        authorization: validated.authorization,
        modules: validated.modules,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        tags: validated.tags
      };

      await createInvestigation(newInv);
      navigate('/investigations');
    } catch (err: unknown) {
      console.error('Validation or submission error:', err);
      setErrors({ submit: 'Failed to create investigation. Please review configuration.' });
    } finally {
      setIsSubmitting(false);
    }
  };

  const steps = [
    { num: 1, title: 'Basic Details', icon: Shield },
    { num: 2, title: 'Target Scope', icon: Target },
    { num: 3, title: 'Authorization', icon: FileCheck },
    { num: 4, title: 'Modules', icon: Cpu },
    { num: 5, title: 'Review & Commit', icon: CheckCircle2 }
  ];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden shadow-xl">
      {/* Wizard Step Bar */}
      <div className="bg-slate-950/70 border-b border-slate-800 px-4 py-3 sm:px-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-base font-semibold text-slate-100">
              New Authorized Investigation Wizard
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Establish governance boundaries, approved target scopes, and active scanning rules.
            </p>
          </div>
          <span className="text-xs font-mono text-cyan-400 bg-cyan-950/40 border border-cyan-800/50 px-2 py-0.5 rounded">
            Step {currentStep} of 5
          </span>
        </div>

        {/* Step indicator pills */}
        <div className="mt-4 grid grid-cols-5 gap-2">
          {steps.map(s => {
            const Icon = s.icon;
            const isCompleted = currentStep > s.num;
            const isCurrent = currentStep === s.num;
            return (
              <button
                key={s.num}
                type="button"
                onClick={() => {
                  if (s.num < currentStep) setCurrentStep(s.num);
                }}
                disabled={s.num > currentStep}
                className={`flex items-center gap-2 p-2 rounded text-left transition-colors ${
                  isCurrent
                    ? 'bg-slate-800 border border-cyan-500/50 text-cyan-300'
                    : isCompleted
                    ? 'bg-slate-900 border border-slate-800 text-slate-300 hover:bg-slate-850'
                    : 'bg-slate-950/40 border border-slate-900 text-slate-400 opacity-60'
                }`}
              >
                <div
                  className={`w-5 h-5 rounded-full flex items-center justify-center text-xs font-mono shrink-0 ${
                    isCompleted
                      ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      : isCurrent
                      ? 'bg-cyan-950 text-cyan-400 border border-cyan-700'
                      : 'bg-slate-900 text-slate-400 border border-slate-800'
                  }`}
                >
                  {isCompleted ? '✓' : s.num}
                </div>
                <div className="hidden md:block truncate">
                  <div className="text-[11px] font-medium truncate">{s.title}</div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Wizard Step Body */}
      <div className="p-6">
        {/* STEP 1: Basic Details */}
        {currentStep === 1 && (
          <div className="space-y-4 max-w-2xl">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Investigation Name <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                value={formData.name}
                onChange={e => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded focus:border-cyan-500 focus:outline-hidden text-slate-100"
                placeholder="e.g. NorthStar Analytics Lab Footprint Audit"
              />
              {errors.name && <p className="text-xs text-rose-400 mt-1">{errors.name}</p>}
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Organization / Subject Entity <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                value={formData.organizationName}
                onChange={e => setFormData({ ...formData, organizationName: e.target.value })}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded focus:border-cyan-500 focus:outline-hidden text-slate-100"
                placeholder="e.g. NorthStar Analytics Lab"
              />
              {errors.organizationName && (
                <p className="text-xs text-rose-400 mt-1">{errors.organizationName}</p>
              )}
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Description & Recon Objective <span className="text-rose-400">*</span>
              </label>
              <textarea
                rows={3}
                value={formData.description}
                onChange={e => setFormData({ ...formData, description: e.target.value })}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded focus:border-cyan-500 focus:outline-hidden text-slate-100 leading-relaxed"
                placeholder="State the research scope, hypothesis, and lab parameters..."
              />
              {errors.description && (
                <p className="text-xs text-rose-400 mt-1">{errors.description}</p>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Lead Investigator <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  value={formData.leadInvestigator}
                  onChange={e => setFormData({ ...formData, leadInvestigator: e.target.value })}
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded focus:border-cyan-500 focus:outline-hidden text-slate-100"
                />
                {errors.leadInvestigator && (
                  <p className="text-xs text-rose-400 mt-1">{errors.leadInvestigator}</p>
                )}
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Team Members (comma separated)
                </label>
                <input
                  type="text"
                  value={formData.teamMembers.join(', ')}
                  onChange={e =>
                    setFormData({
                      ...formData,
                      teamMembers: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                    })
                  }
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded focus:border-cyan-500 focus:outline-hidden text-slate-100"
                  placeholder="e.g. Mohan Prasad (ID: 251347070)"
                />
              </div>
            </div>
          </div>
        )}

        {/* STEP 2: Target Scope */}
        {currentStep === 2 && (
          <div className="space-y-4 max-w-2xl">
            <div className="p-3 bg-slate-950/60 border border-slate-800 rounded text-xs text-slate-300 flex items-start gap-2.5">
              <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span>
                Targets entered here define the boundaries for passive evidence collection and active allowlisting. Any target outside these ranges will be blocked from active tools.
              </span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Owned Domain(s) <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                value={formData.scope.ownedDomains.join(', ')}
                onChange={e => updateScopeField('ownedDomains', e.target.value)}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded font-mono text-cyan-300 focus:border-cyan-500 focus:outline-hidden"
                placeholder="lab.example, mylab.local"
              />
              <span className="text-[11px] text-slate-400">Comma-separated apex domains.</span>
              {errors.ownedDomains && <p className="text-xs text-rose-400 mt-1">{errors.ownedDomains}</p>}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Approved IP Addresses
                </label>
                <input
                  type="text"
                  value={formData.scope.approvedIPs.join(', ')}
                  onChange={e => updateScopeField('approvedIPs', e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded font-mono text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                  placeholder="192.168.56.102, 192.168.56.105"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Approved CIDR Subnets
                </label>
                <input
                  type="text"
                  value={formData.scope.approvedCIDRs.join(', ')}
                  onChange={e => updateScopeField('approvedCIDRs', e.target.value)}
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded font-mono text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                  placeholder="192.168.56.0/24"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Passive-Only Target Identifiers
              </label>
              <input
                type="text"
                value={formData.scope.passiveOnlyTargets.join(', ')}
                onChange={e => updateScopeField('passiveOnlyTargets', e.target.value)}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded font-mono text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                placeholder="lab.example, research.lab.example, auth.lab.example"
              />
              <span className="text-[11px] text-slate-400">Targets restricted strictly to non-intrusive metadata queries.</span>
            </div>

            <div>
              <label className="block text-xs font-medium text-amber-300 mb-1">
                Active Scanning Allowlist Targets
              </label>
              <input
                type="text"
                value={formData.scope.activeTargets.join(', ')}
                onChange={e => updateScopeField('activeTargets', e.target.value)}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-amber-900/60 rounded font-mono text-amber-200 focus:border-amber-500 focus:outline-hidden"
                placeholder="192.168.56.102"
              />
              <span className="text-[11px] text-amber-400/80">
                Explicit hosts allowed for Nmap/OpenVAS result ingestion in this lab assessment.
              </span>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Excluded Targets & Wildcards
              </label>
              <input
                type="text"
                value={formData.scope.excludedTargets.join(', ')}
                onChange={e => updateScopeField('excludedTargets', e.target.value)}
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded font-mono text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                placeholder="*.gov, *.mil, 10.0.0.1"
              />
            </div>
          </div>
        )}

        {/* STEP 3: Authorization */}
        {currentStep === 3 && (
          <div className="space-y-5 max-w-2xl">
            <div className="border border-amber-800/80 bg-amber-950/20 p-4 rounded-lg">
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-xs font-semibold text-amber-300 uppercase tracking-wider">
                    Enable Active Reconnaissance Modules
                  </div>
                  <p className="text-xs text-slate-300 mt-0.5">
                    Permits ingestion of port scanner and vulnerability assessment XML logs.
                  </p>
                </div>
                <label className="relative inline-flex items-center cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.authorization.activeScanningEnabled}
                    onChange={e =>
                      setFormData({
                        ...formData,
                        authorization: {
                          ...formData.authorization,
                          activeScanningEnabled: e.target.checked
                        }
                      })
                    }
                    className="sr-only peer"
                  />
                  <div className="w-11 h-6 bg-slate-800 peer-focus:outline-hidden rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-amber-600"></div>
                </label>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Authorized / Approved By <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  value={formData.authorization.approvedBy}
                  onChange={e =>
                    setFormData({
                      ...formData,
                      authorization: { ...formData.authorization, approvedBy: e.target.value }
                    })
                  }
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded focus:border-cyan-500 focus:outline-hidden text-slate-100"
                  placeholder="e.g. Lab Safety Committee & Dr. Marcus Vance"
                />
                {errors.approvedBy && <p className="text-xs text-rose-400 mt-1">{errors.approvedBy}</p>}
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Authorization Reference <span className="text-rose-400">*</span>
                </label>
                <input
                  type="text"
                  value={formData.authorization.authorizationReference}
                  onChange={e =>
                    setFormData({
                      ...formData,
                      authorization: {
                        ...formData.authorization,
                        authorizationReference: e.target.value
                      }
                    })
                  }
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded font-mono text-cyan-300 focus:border-cyan-500 focus:outline-hidden"
                  placeholder="e.g. AUTH-2026-LAB-099"
                />
                {errors.authorizationReference && (
                  <p className="text-xs text-rose-400 mt-1">{errors.authorizationReference}</p>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Start Date</label>
                <input
                  type="date"
                  value={formData.authorization.startDate}
                  onChange={e =>
                    setFormData({
                      ...formData,
                      authorization: { ...formData.authorization, startDate: e.target.value }
                    })
                  }
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Expiry Date</label>
                <input
                  type="date"
                  value={formData.authorization.expiryDate}
                  onChange={e =>
                    setFormData({
                      ...formData,
                      authorization: { ...formData.authorization, expiryDate: e.target.value }
                    })
                  }
                  className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded text-slate-200 focus:border-cyan-500 focus:outline-hidden"
                />
              </div>
            </div>

            {/* Checkboxes required */}
            <div className="space-y-3 pt-2">
              <label className="flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.authorization.rulesOfEngagementConfirmed}
                  onChange={e =>
                    setFormData({
                      ...formData,
                      authorization: {
                        ...formData.authorization,
                        rulesOfEngagementConfirmed: e.target.checked
                      }
                    })
                  }
                  className="mt-0.5 rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-0"
                />
                <div className="text-xs text-slate-300">
                  <span className="font-semibold text-slate-100">
                    Rules of Engagement (RoE) Adherence:
                  </span>{' '}
                  I confirm that all activities will follow strict ethical guidelines. No denial of service, password attacks, or exploitation will be conducted.
                </div>
              </label>
              {errors.rulesOfEngagementConfirmed && (
                <p className="text-xs text-rose-400">{errors.rulesOfEngagementConfirmed}</p>
              )}

              <label className="flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={formData.authorization.ownershipOrWrittenPermissionConfirmed}
                  onChange={e =>
                    setFormData({
                      ...formData,
                      authorization: {
                        ...formData.authorization,
                        ownershipOrWrittenPermissionConfirmed: e.target.checked
                      }
                    })
                  }
                  className="mt-0.5 rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-0"
                />
                <div className="text-xs text-slate-300">
                  <span className="font-semibold text-slate-100">
                    Ownership / Written Authorization:
                  </span>{' '}
                  I explicitly verify that our team controls the target dummy environment or holds written authorization for these assets.
                </div>
              </label>
              {errors.ownershipOrWrittenPermissionConfirmed && (
                <p className="text-xs text-rose-400">
                  {errors.ownershipOrWrittenPermissionConfirmed}
                </p>
              )}
            </div>
          </div>
        )}

        {/* STEP 4: Modules */}
        {currentStep === 4 && (
          <div className="space-y-4 max-w-2xl">
            <p className="text-xs text-slate-400 mb-3">
              Select which reconnaissance collectors, import engines, and analytical modules to enable for this investigation.
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              {[
                { key: 'rdapWhois', label: 'RDAP / WHOIS Collector', desc: 'Domain registrar and registrant details (Passive)' },
                { key: 'dnsRecon', label: 'Authoritative DNS Inspector', desc: 'A, MX, NS, TXT, SPF inspection (Passive)' },
                { key: 'theHarvesterImport', label: 'theHarvester OSINT Import', desc: 'Ingest harvested emails and subdomains (Passive)' },
                { key: 'searchEvidence', label: 'Search Index Harvester', desc: 'Indexed public documents and cached assets (Passive)' },
                { key: 'nmapXmlImport', label: 'Nmap XML Ingestion Engine', desc: 'Port and service discovery XML parser (Active)' },
                { key: 'openvasXmlImport', label: 'OpenVAS / GVM XML Parser', desc: 'Vulnerability and CVE parser (Active)' },
                { key: 'entityCorrelation', label: 'Entity Knowledge Correlation', desc: 'Correlate relationships across graph nodes' },
                { key: 'exposureScoring', label: 'Exposure Scoring Algorithm', desc: 'Compute 0-100 risk score based on findings' },
                { key: 'pdfReporting', label: 'Dossier & Executive Reporting', desc: 'Export PDF-ready and JSON dossiers' }
              ].map(mod => {
                const isEnabled = formData.modules[mod.key as keyof typeof formData.modules];
                return (
                  <div
                    key={mod.key}
                    onClick={() =>
                      setFormData({
                        ...formData,
                        modules: {
                          ...formData.modules,
                          [mod.key]: !isEnabled
                        }
                      })
                    }
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      isEnabled
                        ? 'border-cyan-800/80 bg-slate-950/80'
                        : 'border-slate-800 bg-slate-950/30 opacity-70'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-slate-200">{mod.label}</span>
                      <input
                        type="checkbox"
                        checked={isEnabled}
                        onChange={() => {}} // handled by card click
                        className="rounded border-slate-700 bg-slate-900 text-cyan-500 pointer-events-none"
                      />
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1">{mod.desc}</p>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* STEP 5: Review & Final Confirmation */}
        {currentStep === 5 && (
          <div className="space-y-5 max-w-3xl">
            <div className="border border-slate-800 rounded-lg p-4 bg-slate-950/60 divide-y divide-slate-800/60 text-xs">
              <div className="pb-3 flex justify-between items-center">
                <div>
                  <span className="text-slate-400">Investigation Title:</span>{' '}
                  <strong className="text-slate-100">{formData.name}</strong>
                </div>
                <span className="font-mono text-cyan-400">{formData.organizationName}</span>
              </div>

              <div className="py-3 grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <span className="text-slate-400">Lead Investigator:</span>{' '}
                  <span className="text-slate-200">{formData.leadInvestigator}</span>
                </div>
                <div>
                  <span className="text-slate-400">Authorization Reference:</span>{' '}
                  <span className="font-mono text-cyan-300">
                    {formData.authorization.authorizationReference}
                  </span>
                </div>
              </div>

              <div className="py-3">
                <span className="text-slate-400 block mb-1">Target Scope & Allowlist:</span>
                <div className="flex flex-wrap gap-2">
                  {formData.scope.ownedDomains.map(d => (
                    <span
                      key={d}
                      className="px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-800/60 text-cyan-300 font-mono text-[11px]"
                    >
                      Domain: {d}
                    </span>
                  ))}
                  {formData.scope.activeTargets.map(ip => (
                    <span
                      key={ip}
                      className="px-2 py-0.5 rounded bg-amber-950/40 border border-amber-800/60 text-amber-300 font-mono text-[11px]"
                    >
                      Active Host: {ip}
                    </span>
                  ))}
                </div>
              </div>

              <div className="py-3 flex items-center justify-between">
                <div>
                  <span className="text-slate-400">Active Scanning Policy:</span>{' '}
                  <span
                    className={`font-semibold ${
                      formData.authorization.activeScanningEnabled
                        ? 'text-amber-400'
                        : 'text-slate-300'
                    }`}
                  >
                    {formData.authorization.activeScanningEnabled ? 'ENABLED (STRICT ALLOWLIST)' : 'DISABLED'}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400">
                  Valid from {formData.authorization.startDate} to {formData.authorization.expiryDate}
                </div>
              </div>
            </div>

            {formData.authorization.activeScanningEnabled && (
              <div className="flex items-start gap-2.5 p-3 rounded-lg border border-amber-800/80 bg-amber-950/20 text-xs text-amber-200">
                <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
                <span>
                  <strong>Safety Notice:</strong> Active scanning is authorized only for IP targets explicitly listed in the scope ({formData.scope.activeTargets.join(', ')}). No arbitrary network scanning is permitted.
                </span>
              </div>
            )}

            {errors.submit && (
              <p className="text-xs text-rose-400">{errors.submit}</p>
            )}
          </div>
        )}
      </div>

      {/* Wizard Footer Controls */}
      <div className="bg-slate-950/80 border-t border-slate-800 px-6 py-4 flex items-center justify-between">
        <button
          type="button"
          onClick={handleBack}
          disabled={currentStep === 1}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-300 hover:text-white bg-slate-900 border border-slate-800 rounded disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back</span>
        </button>

        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => navigate('/investigations')}
            className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            Cancel
          </button>

          {currentStep < 5 ? (
            <button
              type="button"
              onClick={handleNext}
              className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
            >
              <span>Continue</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          ) : (
            <button
              type="button"
              onClick={handleFinalSubmit}
              disabled={isSubmitting}
              className="flex items-center gap-1.5 px-5 py-2 text-xs font-semibold text-slate-900 bg-emerald-400 hover:bg-emerald-300 rounded shadow-md transition-colors"
            >
              <CheckCircle2 className="w-4 h-4 stroke-[2.5]" />
              <span>{isSubmitting ? 'Registering...' : 'Confirm & Commit Investigation'}</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
