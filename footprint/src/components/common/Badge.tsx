import React from 'react';
import { FindingSeverity, InteractionType, ValidationStatus } from '../../types/models';
import { getSeverityBadgeStyles, getInteractionBadgeStyles, getValidationBadgeStyles } from '../../utils/formatters';

interface SeverityBadgeProps {
  severity: FindingSeverity;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const styles = getSeverityBadgeStyles(severity);
  const px = size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 font-medium rounded border ${styles.bg} ${styles.text} ${styles.border} ${px}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" aria-hidden="true" />
      <span className="capitalize">{severity}</span>
    </span>
  );
};

interface InteractionBadgeProps {
  type: InteractionType;
}

export const InteractionBadge: React.FC<InteractionBadgeProps> = ({ type }) => {
  const styles = getInteractionBadgeStyles(type);
  return (
    <span className={`inline-flex items-center gap-1 font-mono text-xs uppercase px-2 py-0.5 rounded border ${styles.bg} ${styles.text} ${styles.border}`}>
      <span>{type}</span>
    </span>
  );
};

interface ValidationBadgeProps {
  status: ValidationStatus;
}

export const ValidationBadge: React.FC<ValidationBadgeProps> = ({ status }) => {
  const styles = getValidationBadgeStyles(status);
  return (
    <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border ${styles.bg} ${styles.text} ${styles.border}`}>
      <span className="capitalize">{status}</span>
    </span>
  );
};
