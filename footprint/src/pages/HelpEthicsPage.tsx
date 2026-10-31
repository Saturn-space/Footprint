import React from 'react';
import {
  Scale,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  FileCheck,
  Eye,
  Radio,
  BookOpen
} from 'lucide-react';

export const HelpEthicsPage: React.FC = () => {
  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-lg font-bold text-slate-100">Legal, Ethical & Educational Framework</h1>
        <p className="text-xs text-slate-400 mt-0.5">
          Rules of Engagement (RoE), legal reconnaissance boundaries, and institutional lab guidelines.
        </p>
      </div>

      {/* Prominent Educational Notice */}
      <div className="p-4 bg-cyan-950/20 border border-cyan-800/80 rounded-lg flex items-start gap-3 text-xs text-cyan-200">
        <Scale className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <strong className="text-cyan-100 uppercase tracking-wide">
            Authorized Educational & Research Purpose
          </strong>
          <p className="text-slate-300 leading-relaxed">
            FootprintIQ is engineered exclusively for authorized academic, lab, and ethical security assessments. All capabilities operate strictly within defensive reconnaissance bounds. Offensive actions, vulnerability exploitation, credential attacks, phishing, and denial-of-service are prohibited.
          </p>
        </div>
      </div>

      {/* Passive vs Active Comparison */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
        <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2 pb-2 border-b border-slate-800">
          <BookOpen className="w-4 h-4 text-cyan-400" />
          <span>The Passive vs. Active Reconnaissance Boundary</span>
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          {/* Passive */}
          <div className="p-4 bg-slate-950/60 border border-cyan-900/40 rounded-lg space-y-2">
            <div className="flex items-center gap-2 text-cyan-400 font-semibold uppercase text-[11px]">
              <Eye className="w-4 h-4" />
              <span>1. Passive Reconnaissance</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              Interrogates third-party caches, public registries, and search engines without transmitting network packets to the subject organization's endpoints.
            </p>
            <ul className="text-slate-400 space-y-1 text-[11px] pt-1">
              <li>• RDAP & WHOIS queries to ICANN/IANA registries</li>
              <li>• Recursive DNS resolutions via public caching resolvers</li>
              <li>• OSINT document indexing & public repository searches</li>
              <li>• <strong>Legal Status:</strong> Generally non-intrusive public data analysis</li>
            </ul>
          </div>

          {/* Active */}
          <div className="p-4 bg-slate-950/60 border border-amber-900/40 rounded-lg space-y-2">
            <div className="flex items-center gap-2 text-amber-400 font-semibold uppercase text-[11px]">
              <Radio className="w-4 h-4" />
              <span>2. Active Reconnaissance</span>
            </div>
            <p className="text-slate-300 leading-relaxed">
              Sends direct IP packets, TCP handshakes, or protocol probes to target systems to determine port states, services, and versions.
            </p>
            <ul className="text-slate-400 space-y-1 text-[11px] pt-1">
              <li>• Nmap SYN/Connect port scanning</li>
              <li>• Service banner grabbing & OpenVAS vulnerability probing</li>
              <li>• <strong>Strict Prerequisite:</strong> Explicit written authorization & target allowlisting</li>
              <li>• <strong>Lab Guardrail:</strong> Disabled without verified allowlist matching</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Rules of Engagement Checklist */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4 text-xs">
        <h2 className="text-sm font-semibold text-slate-100 pb-2 border-b border-slate-800 flex items-center gap-2">
          <FileCheck className="w-4 h-4 text-emerald-400" />
          <span>Rules of Engagement (RoE) Checklist</span>
        </h2>

        <div className="space-y-2.5 text-slate-300">
          {[
            {
              title: 'Explicit Scope Definition',
              desc: 'Never target hosts or subdomains without verifying they are enumerated in the approved investigation scope.'
            },
            {
              title: 'Verification of Asset Ownership',
              desc: 'Confirm the target belongs to the team-controlled dummy company (e.g. NorthStar Analytics Lab) or isolated test hypervisor.'
            },
            {
              title: 'No Denial of Service or Exploitation',
              desc: 'Testing is strictly limited to discovering exposures; never exploit weaknesses or transmit excessive packet rates.'
            },
            {
              title: 'Auditable Activity Ledger',
              desc: 'Every investigator action must remain logged in the cryptographic audit ledger for instructor and peer review.'
            }
          ].map((item, idx) => (
            <div key={idx} className="flex items-start gap-3 p-3 bg-slate-950/40 border border-slate-800/80 rounded">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-slate-200 block">{item.title}</strong>
                <span className="text-slate-400 text-[11px] leading-relaxed">{item.desc}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Project Attribution */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-lg text-xs space-y-2">
        <h3 className="font-semibold text-slate-200">Academic Project Information</h3>
        <p className="text-slate-400 text-[11px] leading-relaxed">
          Developed as Phase 1 of the FootprintIQ OSINT Reconnaissance Management Platform.
        </p>
        <div className="pt-2 border-t border-slate-800 flex flex-wrap gap-6 text-[11px] text-slate-300">
          <div>Lead Investigator: <strong>Asip Ali</strong> (Student ID: 251347048)</div>
          <div>Co-Investigator: <strong>Mohan Prasad</strong> (Student ID: 251347070)</div>
        </div>
      </div>
    </div>
  );
};
