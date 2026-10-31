import React from 'react';
import { NewInvestigationWizard } from '../components/wizard/NewInvestigationWizard';

export const NewInvestigationPage: React.FC = () => {
  return (
    <div className="space-y-4">
      <NewInvestigationWizard />
    </div>
  );
};
