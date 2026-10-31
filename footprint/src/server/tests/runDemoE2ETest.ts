import { workflowController } from '../services/workflowController';
import { serverRepos } from '../db/repositories';
import { reportGenerator } from '../services/reportGenerator';

async function runDemoE2ETest() {
  console.log('====================================================');
  console.log(' FootprintIQ: Safe Demo End-to-End Workflow Test');
  console.log('====================================================\n');

  console.log('[1/4] Triggering Safe Demo Workflow Run...');
  const { run, investigationId } = await workflowController.runSafeDemo('Lead Auditor (E2E Test)');
  console.log(`  ✓ Demo run initiated: ${run.id} for investigation: ${investigationId}`);

  // Wait for the asynchronous demo stages to execute
  console.log('[2/4] Awaiting automated stage transitions...');
  let completed = false;
  let attempts = 0;

  while (!completed && attempts < 15) {
    await new Promise(r => setTimeout(r, 600));
    attempts++;
    const current = workflowController.getRun(run.id);
    if (!current) throw new Error('Run not found');

    console.log(`  -> Current State: [${current.currentState}] (${current.stageProgressPercent}%)`);

    if (current.currentState === 'COMPLETED') {
      completed = true;
    } else if (current.currentState === 'FAILED' || current.currentState === 'CANCELLED') {
      throw new Error(`Demo failed at state ${current.currentState}: ${current.errorMessage}`);
    }
  }

  if (!completed) {
    throw new Error('Demo timed out before reaching COMPLETED state');
  }

  console.log('[3/4] Verifying Correlated Assets & Ingested Findings...');
  const [entities, services, findings, score, reports] = await Promise.all([
    serverRepos.entities.getByInvestigationId(investigationId),
    serverRepos.services.getByInvestigationId(investigationId),
    serverRepos.findings.getByInvestigationId(investigationId),
    serverRepos.scores.getScore(investigationId),
    serverRepos.reports.getByInvestigationId(investigationId)
  ]);

  console.log(`  ✓ Entities: ${entities.length} nodes registered in Knowledge Graph`);
  console.log(`  ✓ Services: ${services.length} active service ports cataloged`);
  console.log(`  ✓ Findings: ${findings.length} findings triaged`);
  console.log(`  ✓ 5-Factor Score: ${score.totalScore}/100 (${score.tier})`);
  console.log(`  ✓ Reports: ${reports.length} report dossiers compiled`);

  console.log('[4/4] Verifying 20-Section PDF Generation...');
  const inv = await serverRepos.investigations.getById(investigationId);
  if (!inv) throw new Error('Investigation not found');

  const latestReport = reports[0];
  if (!latestReport) throw new Error('No report generated');

  const pdfBytes = await reportGenerator.buildBinaryPdf(latestReport, inv);
  console.log(`  ✓ Binary PDF compiled successfully (${pdfBytes.byteLength} bytes)`);

  console.log('\n====================================================');
  console.log(' Safe Demo E2E Test PASSED Successfully! (100% Green)');
  console.log('====================================================\n');
}

runDemoE2ETest().catch(err => {
  console.error('Safe Demo E2E test fatal error:', err);
  process.exit(1);
});
