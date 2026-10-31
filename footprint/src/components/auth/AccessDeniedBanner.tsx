import React from 'react';
import { ShieldAlert, Lock, ArrowRight } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { UserRole } from '../../types/models';

interface AccessDeniedBannerProps {
  requiredRoles: UserRole[];
  actionDescription: string;
  onOpenSwitcher?: () => void;
}

export const AccessDeniedBanner: React.FC<AccessDeniedBannerProps> = ({
  requiredRoles,
  actionDescription,
  onOpenSwitcher
}) => {
  const { currentUser } = useAuth();

  return (
    <div className="p-4 bg-slate-900 border border-amber-800/80 rounded-lg text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-md my-4">
      <div className="flex items-start gap-3">
        <Lock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <div className="font-semibold text-amber-300">
            Permission Restricted: Role "{currentUser.role.toUpperCase()}"
          </div>
          <p className="text-slate-300 text-xs">
            {actionDescription} requires one of the following server-enforced roles:{' '}
            <strong className="text-cyan-400">{requiredRoles.join(', ')}</strong>.
          </p>
        </div>
      </div>

      {onOpenSwitcher && (
        <button
          onClick={onOpenSwitcher}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-900 bg-amber-400 hover:bg-amber-300 rounded transition-colors shrink-0"
        >
          <span>Switch Account</span>
          <ArrowRight className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  );
};
