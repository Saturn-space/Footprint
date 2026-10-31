import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  FolderKanban,
  PlusCircle,
  Eye,
  Radio,
  Network,
  AlertOctagon,
  Gauge,
  FileText,
  History,
  Settings,
  Scale,
  ShieldCheck,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';

interface SidebarProps {
  isCollapsed: boolean;
  onToggle: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isCollapsed, onToggle }) => {
  const { investigations, findings } = useInvestigation();

  const openFindingsCount = findings.filter(f => f.status === 'open').length;

  const navItems = [
    { label: 'Dashboard', path: '/', icon: LayoutDashboard },
    {
      label: 'Investigations',
      path: '/investigations',
      icon: FolderKanban,
      count: investigations.length
    },
    { label: 'New Investigation', path: '/new-investigation', icon: PlusCircle },
    { label: 'Passive Recon', path: '/passive-recon', icon: Eye },
    {
      label: 'Active Scanning',
      path: '/active-scanning',
      icon: Radio,
      alert: true
    },
    { label: 'Entity Graph', path: '/entity-graph', icon: Network },
    {
      label: 'Findings',
      path: '/findings',
      icon: AlertOctagon,
      count: openFindingsCount > 0 ? openFindingsCount : undefined,
      countVariant: 'amber'
    },
    { label: 'Exposure Score', path: '/exposure-score', icon: Gauge },
    { label: 'Reports', path: '/reports', icon: FileText },
    { label: 'Audit Log', path: '/audit-log', icon: History },
    { label: 'Settings', path: '/settings', icon: Settings },
    { label: 'Help and Ethics', path: '/help-ethics', icon: Scale }
  ];

  return (
    <aside
      className={`relative flex flex-col bg-slate-950 border-r border-slate-800/80 transition-all duration-200 z-40 select-none ${
        isCollapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Brand Header */}
      <div className="h-14 flex items-center px-4 border-b border-slate-800/80 justify-between">
        {!isCollapsed && (
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
            <div>
              <div className="font-bold text-sm text-slate-100 tracking-tight flex items-center gap-1.5">
                <span>FootprintIQ</span>
                <span className="text-[10px] text-cyan-400 font-mono font-normal">v1.0</span>
              </div>
              <div className="text-[10px] text-slate-400 truncate">OSINT Recon Toolkit</div>
            </div>
          </div>
        )}
        {isCollapsed && (
          <div className="mx-auto w-7 h-7 rounded bg-cyan-950 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
        )}
      </div>

      {/* Navigation links */}
      <div className="flex-1 overflow-y-auto py-3 px-2 space-y-1">
        {navItems.map(item => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              title={isCollapsed ? item.label : undefined}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                  isActive
                    ? 'bg-cyan-950/40 text-cyan-300 border-l-2 border-cyan-400 pl-2.5'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/80'
                } ${isCollapsed ? 'justify-center px-2' : ''}`
              }
            >
              <Icon className="w-4 h-4 shrink-0" />
              {!isCollapsed && (
                <div className="flex-1 flex items-center justify-between truncate">
                  <span className="truncate">{item.label}</span>
                  {item.count !== undefined && (
                    <span className="ml-auto text-[11px] font-mono px-1.5 py-0.2 rounded bg-slate-900 border border-slate-800 text-slate-300">
                      {item.count}
                    </span>
                  )}
                  {item.alert && (
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0 ml-1" />
                  )}
                </div>
              )}
            </NavLink>
          );
        })}
      </div>

      {/* Collapse Toggle Bar & Team Credentials Footer */}
      <div className="p-3 border-t border-slate-800/80 bg-slate-950/60">
        {!isCollapsed && (
          <div className="mb-2 text-[10px] text-slate-400 leading-tight">
            <div className="font-semibold text-slate-300">Lab Research Team</div>
            <div className="truncate">Asip Ali (251347048)</div>
            <div className="truncate">Mohan Prasad (251347070)</div>
          </div>
        )}
        <button
          onClick={onToggle}
          className="w-full flex items-center justify-center p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-900 rounded-md transition-colors"
          title={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>
    </aside>
  );
};
