import { afterAll, expect, it, vi } from 'vitest';
import { makeFixtureProject } from '../testUtils.js';

vi.mock('../../src/security/ruleRegistry.js', async (importOriginal) => {
  const original = await importOriginal<typeof import('../../src/security/ruleRegistry.js')>();
  return {
    ...original,
    getSecurityRules: () => [...original.getSecurityRules(), {
      id: 'CS-NODE-999', category: 'security_configuration', title: 'Synthetic failure',
      description: 'Only exercises the rule failure reporting path.', severity: 'low', confidence: 'low',
      evidenceRequirements: 'Synthetic test rule.', remediation: 'No action.', falsePositiveGuidance: 'Test only.',
      languages: ['node'], run: async () => { throw new Error('synthetic rule failure'); },
    }],
  };
});

import { scanProject } from '../../src/security/scanner.js';

const project = makeFixtureProject();
afterAll(() => project.cleanup());

it('reports a failed rule separately from successfully executed rules', async () => {
  const result = await scanProject(project.config);
  if (!result.ok) throw new Error(result.error.message);
  expect(result.data.ruleExecution).toMatchObject({ executed: 25, skipped: 0, failed: 1 });
  expect(result.data.rulesRun).not.toContain('CS-NODE-999');
  expect(result.data.rulesFailed).toEqual([{ ruleId: 'CS-NODE-999', reason: 'synthetic rule failure' }]);
  expect(result.data.limitations.join(' ')).toMatch(/rule.*failed/i);
});
