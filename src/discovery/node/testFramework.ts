import type { DetectedItem } from '../types.js';
import { fileExists } from '../manifestReader.js';
import { hasDep, depVersion, type NodeAnalysisContext } from './context.js';

interface TestSpec {
  name: string;
  depNames: string[];
  configFiles: string[];
}

const TEST_SPECS: TestSpec[] = [
  { name: 'Jest', depNames: ['jest', 'ts-jest'], configFiles: ['jest.config.js', 'jest.config.ts', 'jest.config.mjs'] },
  { name: 'Vitest', depNames: ['vitest'], configFiles: ['vitest.config.ts', 'vitest.config.js'] },
  { name: 'Mocha', depNames: ['mocha'], configFiles: ['.mocharc.json', '.mocharc.js', '.mocharc.yml'] },
  { name: 'Jasmine', depNames: ['jasmine'], configFiles: ['jasmine.json'] },
  { name: 'AVA', depNames: ['ava'], configFiles: [] },
];

export function detectTestFrameworks(root: string, ctx: NodeAnalysisContext): DetectedItem[] {
  const results: DetectedItem[] = [];
  for (const spec of TEST_SPECS) {
    const matchedDep = spec.depNames.find((d) => hasDep(ctx, d));
    const matchedConfig = spec.configFiles.find((f) => fileExists(root, f));
    if (!matchedDep && !matchedConfig) continue;

    const evidence = [];
    if (matchedDep) {
      evidence.push({
        source: 'package.json dependencies',
        detail: `"${matchedDep}"${depVersion(ctx, matchedDep) ? ` (${depVersion(ctx, matchedDep)})` : ''} listed as a dependency`,
      });
    }
    if (matchedConfig) {
      evidence.push({ source: `file:${matchedConfig}`, detail: `${matchedConfig} is present` });
    }
    const confidence = matchedDep && matchedConfig ? 'high' : matchedDep ? 'high' : 'medium';
    results.push({ name: spec.name, confidence, evidence });
  }
  return results;
}
