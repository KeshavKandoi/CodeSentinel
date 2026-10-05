import { testCredential } from '../testCredentials.js';
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { scanProject } from '../../src/security/scanner.js';
import { makeFixtureProject } from '../testUtils.js';

const projects: ReturnType<typeof makeFixtureProject>[] = [];
afterEach(() => { for (const project of projects.splice(0)) project.cleanup(); });

async function secret(pathInProject: string, value: string, field = 'apiKey') {
  const project = makeFixtureProject();
  projects.push(project);
  const destination = path.join(project.root, pathInProject);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, `const ${field} = "${value}";\n`);
  const result = await scanProject(project.config);
  if (!result.ok) throw new Error(result.error.message);
  return result.data.findings.filter(finding => finding.ruleId === 'CS-NODE-001');
}

describe('CS-NODE-001 secret confidence', () => {
  it('detects a structured production API key at high confidence', async () => {
    expect(await secret('src/config.ts', testCredential('STRIPE_KEY'))).toEqual([expect.objectContaining({ confidence: 'high', file: 'src/config.ts', line: 1 })]);
  });
  it('detects a realistic production token', async () => {
    expect(await secret('src/config.ts', testCredential('GENERIC_SECRET'), 'token')).toEqual([expect.objectContaining({ confidence: 'high' })]);
  });
  it.each(['test', 'dummy-api-key', 'fake-key-for-test', 'placeholder', 'redacted'])('does not report obvious placeholder %s', async value => {
    expect(await secret('tests/model/client.test.ts', testCredential('STRIPE_KEY'))).toEqual([expect.objectContaining({ confidence: 'high', file: 'tests/model/client.test.ts' })]);
  });
  it('still detects a realistic key committed in a test file', async () => {
    expect(await secret('tests/model/client.test.ts', testCredential('STRIPE_KEY'))).toEqual([expect.objectContaining({ confidence: 'high', file: 'tests/model/client.test.ts' })]);
  });
  it('still detects a high-entropy unstructured key in a test file', async () => {
    expect(await secret('fixtures/client.ts', testCredential('GENERIC_SECRET'))).toEqual([expect.objectContaining({ confidence: 'high', file: 'fixtures/client.ts' })]);
  });
});
