import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Menu,
  Bell,
  Plus,
  Shield,
  User,
  ChevronDown,
  Check,
  X,
  Users,
  Activity,
  LogOut
} from 'lucide-react';
import { useInvestigation } from '../../context/InvestigationContext';
import { useAuth } from '../../context/AuthContext';
import { AuthSwitchModal } from '../auth/AuthSwitchModal';

interface HeaderProps {
  onToggleSidebar: () => void;
  isSidebarCollapsed: boolean;
}

export const Header: React.FC<HeaderProps> = ({ onToggleSidebar }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { currentUser, logout, canCreateInvestigation } = useAuth();
  const {
    investigations,
    activeInvestigation,
    selectInvestigation,
    notifications,
    dismissNotification,
    isServerConnected
  } = useInvestigation();

  const [isInvestPickerOpen, setIsInvestPickerOpen] = useState(false);
  const [isNotifOpen, setIsNotifOpen] = useState(false);
  const [isProfileOpen, setIsProfileOpen] = useState(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);

  // Map path to human-readable breadcrumb
  const getPageTitle = () => {
    const path = location.pathname;
    if (path === '/') return 'Dashboard';
    if (path === '/investigations') return 'Investigations';
    if (path === '/new-investigation') return 'New Investigation Wizard';
    if (path === '/passive-recon') return 'Passive Reconnaissance';
    if (path === '/active-scanning') return 'Active Scanning Safety Hub';
    if (path === '/entity-graph') return 'Entity Knowledge Graph';
    if (path === '/findings') return 'Findings & Exposure';
    if (path === '/exposure-score') return 'Exposure Score Analysis';
    if (path === '/reports') return 'Recon Dossier & Reports';
    if (path === '/audit-log') return 'Tamper-Evident Audit Log';
    if (path === '/settings') return 'System Settings';
    if (path === '/help-ethics') return 'Help & Ethics';
    return 'Dashboard';
  };

  return (
    <>
      <header className="sticky top-0 z-30 h-14 bg-slate-950 border-b border-slate-800/80 px-4 flex items-center justify-between gap-4">
        {/* Left zone: Hamburger + Context Breadcrumb + Server status */}
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={onToggleSidebar}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-900 rounded-md transition-colors"
            title="Toggle Sidebar Navigation"
            aria-label="Toggle Sidebar Navigation"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex items-center gap-2 text-xs truncate">
            <span className="text-slate-400 hidden sm:inline">FootprintIQ</span>
            <span className="text-slate-600 hidden sm:inline" aria-hidden="true">/</span>
            <span className="text-slate-300 font-medium truncate">{getPageTitle()}</span>
          </div>

          {/* Server Connection Badge */}
          <div className="hidden lg:flex items-center gap-1.5 pl-2 text-[11px] font-mono text-slate-400 border-l border-slate-800">
            <span className={`w-1.5 h-1.5 rounded-full ${isServerConnected ? 'bg-emerald-400 animate-pulse' : 'bg-cyan-400'}`} />
            <span>{isServerConnected ? 'API Live (Phase 2)' : 'Local Engine'}</span>
          </div>
        </div>

        {/* Right zone: Investigation switcher, Global New, Notifications, User */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Active Investigation Dropdown */}
          <div className="relative">
            <button
              onClick={() => setIsInvestPickerOpen(!isInvestPickerOpen)}
              className="flex items-center gap-2 px-2.5 py-1.5 text-xs text-slate-200 bg-slate-900/90 border border-slate-800 rounded-md hover:border-slate-700 hover:bg-slate-800/50 transition-colors max-w-56 sm:max-w-64"
            >
              <Shield className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
              <span className="truncate text-left font-medium">
                {activeInvestigation?.name || 'Select Investigation'}
              </span>
              <ChevronDown className="w-3 h-3 text-slate-400 shrink-0 ml-1" />
            </button>

            {isInvestPickerOpen && (
              <div
                className="absolute right-0 mt-1.5 w-72 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl py-1 z-50 animate-in fade-in zoom-in-95 duration-100"
                onMouseLeave={() => setIsInvestPickerOpen(false)}
              >
                <div className="px-3 py-1.5 text-[11px] font-medium uppercase tracking-wider text-slate-400 border-b border-slate-800/80">
                  Investigations Scope
                </div>
                <div className="max-h-60 overflow-y-auto py-1">
                  {investigations.map(inv => (
                    <button
                      key={inv.id}
                      onClick={() => {
                        selectInvestigation(inv.id);
                        setIsInvestPickerOpen(false);
                      }}
                      className={`w-full px-3 py-2 text-left text-xs flex items-center justify-between hover:bg-slate-800/70 transition-colors ${
                        inv.id === activeInvestigation?.id ? 'text-cyan-300 bg-cyan-950/20' : 'text-slate-300'
                      }`}
                    >
                      <div className="truncate pr-2">
                        <div className="font-medium truncate">{inv.name}</div>
                        <div className="text-[11px] text-slate-400 truncate">{inv.organizationName}</div>
                      </div>
                      {inv.id === activeInvestigation?.id && (
                        <Check className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      )}
                    </button>
                  ))}
                </div>
                {canCreateInvestigation && (
                  <div className="border-t border-slate-800/80 p-1.5">
                    <button
                      onClick={() => {
                        setIsInvestPickerOpen(false);
                        navigate('/new-investigation');
                      }}
                      className="w-full flex items-center justify-center gap-1.5 px-2 py-1.5 text-xs text-cyan-400 hover:text-cyan-300 hover:bg-cyan-950/30 rounded transition-colors"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      <span>Start New Lab Investigation</span>
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Global New Investigation Button (RBAC protected) */}
          {canCreateInvestigation && (
            <button
              onClick={() => navigate('/new-investigation')}
              className="hidden md:flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-900 bg-cyan-400 hover:bg-cyan-300 rounded-md transition-colors shadow-xs"
            >
              <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
              <span>New Investigation</span>
            </button>
          )}

          {/* Notifications Drawer Toggle */}
          <div className="relative">
            <button
              onClick={() => setIsNotifOpen(!isNotifOpen)}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-900 rounded-md transition-colors relative"
              title="System & Audit Alerts"
              aria-label="System & Audit Alerts"
            >
              <Bell className="w-4 h-4" />
              {notifications.length > 0 && (
                <span className="absolute top-1 right-1 w-2 h-2 bg-cyan-400 rounded-full" />
              )}
            </button>

            {isNotifOpen && (
              <div
                className="absolute right-0 mt-1.5 w-80 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl z-50 animate-in fade-in zoom-in-95 duration-100"
                onMouseLeave={() => setIsNotifOpen(false)}
              >
                <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800">
                  <span className="text-xs font-semibold text-slate-200">Recon Activity Alerts</span>
                  <span className="text-[11px] text-slate-400 font-mono tabular-nums">{notifications.length} events</span>
                </div>
                <div className="max-h-64 overflow-y-auto p-1 divide-y divide-slate-800/50">
                  {notifications.length === 0 ? (
                    <div className="py-6 text-center text-xs text-slate-400">
                      No active notifications
                    </div>
                  ) : (
                    notifications.map(n => (
                      <div key={n.id} className="p-2.5 text-xs hover:bg-slate-800/40 transition-colors relative group">
                        <div className="flex items-center justify-between gap-1 mb-1">
                          <span className={`font-medium ${
                            n.type === 'error' ? 'text-rose-400' :
                            n.type === 'warning' ? 'text-amber-400' :
                            n.type === 'success' ? 'text-emerald-400' : 'text-cyan-400'
                          }`}>
                            {n.title}
                          </span>
                          <button
                            onClick={() => dismissNotification(n.id)}
                            className="opacity-0 group-hover:opacity-100 p-0.5 text-slate-400 hover:text-slate-200 transition-opacity"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </div>
                        <p className="text-slate-300 text-[11px] leading-relaxed">{n.message}</p>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>

          {/* User / Team Profile Menu & Role Badge */}
          <div className="relative">
            <button
              onClick={() => setIsProfileOpen(!isProfileOpen)}
              className="flex items-center gap-2 p-1.5 text-slate-300 hover:text-slate-100 rounded-md hover:bg-slate-900 transition-colors"
            >
              <div className="w-6 h-6 rounded bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 font-mono text-xs font-semibold">
                {currentUser.name.split(' ').map(n => n[0]).join('').slice(0, 2)}
              </div>
              <div className="hidden lg:flex flex-col text-left">
                <span className="text-xs font-medium leading-none">{currentUser.name}</span>
                <span className="text-[10px] font-mono text-cyan-400 uppercase leading-tight mt-0.5">
                  {currentUser.role}
                </span>
              </div>
              <ChevronDown className="w-3 h-3 text-slate-400 hidden lg:inline" />
            </button>

            {isProfileOpen && (
              <div
                className="absolute right-0 mt-1.5 w-64 bg-slate-900 border border-slate-800 rounded-lg shadow-2xl p-3 z-50 text-xs"
                onMouseLeave={() => setIsProfileOpen(false)}
              >
                <div className="pb-2 border-b border-slate-800">
                  <div className="font-semibold text-slate-100">{currentUser.name}</div>
                  <div className="text-[11px] text-cyan-400 font-mono capitalize">
                    Role: {currentUser.role}
                  </div>
                  <div className="text-[11px] text-slate-400">{currentUser.email}</div>
                </div>

                <div className="py-2 border-b border-slate-800 text-[11px] text-slate-300 space-y-1">
                  <div className="text-slate-400 uppercase tracking-wider font-semibold text-[10px]">Project Team</div>
                  <div>• Asip Ali (ID: 251347048)</div>
                  <div>• Mohan Prasad (ID: 251347070)</div>
                </div>

                <div className="pt-2 space-y-1.5">
                  <button
                    onClick={() => {
                      setIsProfileOpen(false);
                      setIsAuthModalOpen(true);
                    }}
                    className="w-full flex items-center justify-center gap-1.5 py-1.5 px-2 bg-slate-800 hover:bg-slate-750 text-cyan-300 rounded text-xs transition-colors"
                  >
                    <Users className="w-3.5 h-3.5" />
                    <span>Switch Role / Account</span>
                  </button>

                  <button
                    onClick={() => {
                      setIsProfileOpen(false);
                      logout();
                    }}
                    className="w-full flex items-center justify-center gap-1.5 py-1.5 px-2 bg-slate-950 hover:bg-slate-900 text-slate-400 hover:text-slate-200 rounded text-xs transition-colors"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    <span>Sign Out (Viewer Mode)</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </header>

      {/* RBAC Modal */}
      <AuthSwitchModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
      />
    </>
  );
};
