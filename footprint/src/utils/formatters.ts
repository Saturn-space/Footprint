import { FindingSeverity, InteractionType, ValidationStatus } from '../types/models';

export function formatDate(dateString: string): string {
  try {
    const d = new Date(dateString);
    return d.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  } catch {
    return dateString;
  }
}

export function formatShortDate(dateString: string): string {
  try {
    const d = new Date(dateString);
    return d.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  } catch {
    return dateString;
  }
}

export function getSeverityBadgeStyles(severity: FindingSeverity): { bg: string; text: string; border: string } {
  switch (severity) {
    case 'critical':
      return { bg: 'bg-rose-950/40', text: 'text-rose-400', border: 'border-rose-800/60' };
    case 'high':
      return { bg: 'bg-amber-950/40', text: 'text-amber-400', border: 'border-amber-800/60' };
    case 'medium':
      return { bg: 'bg-yellow-950/40', text: 'text-yellow-400', border: 'border-yellow-800/60' };
    case 'low':
      return { bg: 'bg-blue-950/40', text: 'text-blue-400', border: 'border-blue-800/60' };
    case 'info':
    default:
      return { bg: 'bg-slate-900', text: 'text-slate-400', border: 'border-slate-800' };
  }
}

export function getInteractionBadgeStyles(type: InteractionType): { bg: string; text: string; border: string } {
  if (type === 'passive') {
    return { bg: 'bg-cyan-950/40', text: 'text-cyan-400', border: 'border-cyan-800/50' };
  }
  return { bg: 'bg-amber-950/40', text: 'text-amber-400', border: 'border-amber-800/50' };
}

export function getValidationBadgeStyles(status: ValidationStatus): { bg: string; text: string; border: string } {
  switch (status) {
    case 'verified':
      return { bg: 'bg-emerald-950/40', text: 'text-emerald-400', border: 'border-emerald-800/50' };
    case 'flagged':
      return { bg: 'bg-rose-950/40', text: 'text-rose-400', border: 'border-rose-800/50' };
    case 'unverified':
    default:
      return { bg: 'bg-slate-900', text: 'text-slate-400', border: 'border-slate-800' };
  }
}
