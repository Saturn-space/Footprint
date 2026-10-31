import React from 'react';
import { Shield, User, Check, Key, Lock, Users } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { UserRole } from '../../types/models';
import { Modal } from '../common/Modal';

interface AuthSwitchModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const AuthSwitchModal: React.FC<AuthSwitchModalProps> = ({ isOpen, onClose }) => {
  const { currentUser, demoUsers, loginAs } = useAuth();

  const roleDescriptions: Record<UserRole, { badge: string; color: string; permissions: string[] }> = {
    admin: {
      badge: 'Full Platform Admin',
      color: 'text-rose-400 border-rose-800/80 bg-rose-950/40',
      permissions: ['Manage system settings', 'Create & delete investigations', 'Import active & passive scans', 'Full audit ledger access']
    },
    investigator: {
      badge: 'Lead Investigator',
      color: 'text-cyan-400 border-cyan-800/80 bg-cyan-950/40',
      permissions: ['Create investigations', 'Execute passive RDAP & DNS queries', 'Import Nmap & OpenVAS XML', 'Log manual evidence']
    },
    reviewer: {
      badge: 'Security Reviewer',
      color: 'text-amber-400 border-amber-800/80 bg-amber-950/40',
      permissions: ['Triage finding statuses', 'Review exposure scores', 'Sign-off reports', 'View all evidence']
    },
    viewer: {
      badge: 'Auditor & Guest (Read-Only)',
      color: 'text-slate-400 border-slate-700 bg-slate-800/60',
      permissions: ['Read completed investigations', 'Inspect entity graph', 'Read executive reports', 'No data modification allowed']
    }
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Role-Based Access Control (RBAC) Switcher"
      subtitle="Select a demo account to test role permissions on server and client"
      maxWidth="xl"
    >
      <div className="space-y-4 text-xs">
        <div className="p-3 bg-slate-950/60 border border-slate-800 rounded text-slate-300 flex items-start gap-2.5">
          <Key className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <span>
            Server-side route middleware enforces strict authorization. Switching accounts will update your session token and test API access constraints.
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {demoUsers.map(u => {
            const isCurrent = u.id === currentUser.id;
            const meta = roleDescriptions[u.role];
            return (
              <button
                key={u.id}
                onClick={async () => {
                  await loginAs(u);
                  onClose();
                }}
                className={`p-3.5 rounded-lg border text-left transition-all relative ${
                  isCurrent
                    ? 'border-cyan-500 bg-slate-800/90 shadow-md ring-1 ring-cyan-500/40'
                    : 'border-slate-800 bg-slate-950 hover:border-slate-700 hover:bg-slate-900'
                }`}
              >
                <div className="flex items-center justify-between gap-1 mb-1">
                  <span className="font-semibold text-slate-100">{u.name}</span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase ${meta.color}`}>
                    {u.role}
                  </span>
                </div>

                <div className="text-[11px] text-slate-400 font-mono">{u.email}</div>
                <div className="text-[10px] text-slate-500 mt-1">{u.organization}</div>

                <div className="mt-2.5 pt-2 border-t border-slate-800/80 space-y-1">
                  {meta.permissions.map((p, idx) => (
                    <div key={idx} className="text-[10px] text-slate-400 flex items-center gap-1.5">
                      <span className="w-1 h-1 rounded-full bg-cyan-400" />
                      <span>{p}</span>
                    </div>
                  ))}
                </div>

                {isCurrent && (
                  <div className="absolute top-2 right-2 flex items-center gap-1 text-[10px] text-cyan-400 font-medium bg-cyan-950/80 px-1.5 py-0.5 rounded border border-cyan-800">
                    <Check className="w-3 h-3" /> Active
                  </div>
                )}
              </button>
            );
          })}
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs text-slate-300 bg-slate-800 hover:bg-slate-700 rounded transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </Modal>
  );
};
