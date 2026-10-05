import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { afterEach, expect, it } from 'vitest';
import { scanProject } from '../../src/security/scanner.js';
import { toolDefinitions } from '../../src/tools/registry.js';
import { makeFixtureProject } from '../testUtils.js';

const projects: ReturnType<typeof makeFixtureProject>[] = [];
afterEach(() => { for (const project of projects.splice(0)) project.cleanup(); });

it('reports an honest clean Node scan with coverage, rule counts, and no target writes', async () => {
  const project = makeFixtureProject();
  projects.push(project);
  const before = fs.readFileSync(path.join(project.root, 'src/index.js'), 'utf8');
  const entriesBefore = fs.readdirSync(project.root, { recursive: true }).map(String).sort();
  const result = await scanProject(project.config);
  if (!result.ok) throw new Error(result.error.message);
  expect(result.data.project).toMatchObject({ root: project.root, name: 'fixture', ecosystem: 'node', support: 'supported', nestedProjects: [] });
  expect(result.data.project.packageManager).toBe('npm');
  expect(result.data.project.gitStatus).toBe('not_checked');
  expect(result.data.summary.total).toBe(0);
  expect(result.data.summary.byConfidence).toEqual({ high: 0, medium: 0, low: 0 });
  expect(result.data.ruleExecution).toMatchObject({ executed: 25, skipped: 0, failed: 0 });
  expect(result.data.rulesRun).toHaveLength(25);
  expect(result.data.fileAnalysis.analyzed).toBeGreaterThan(0);
  expect(result.data.message).toMatch(/No vulnerabilities were detected by the enabled static-analysis rules/i);
  expect(result.data.runtimeVerificationPerformed).toBe(false);
  expect(result.data.limitations.join(' ')).toMatch(/static|runtime/i);
  expect(fs.readFileSync(path.join(project.root, 'src/index.js'), 'utf8')).toBe(before);
  expect(fs.readdirSync(project.root, { recursive: true }).map(String).sort()).toEqual(entriesBefore);
});

it('serializes a source-backed finding with impact, remediation, and static verification state', async () => {
  const project = makeFixtureProject();
  projects.push(project);
  fs.writeFileSync(path.join(project.root, 'src/config.ts'), 'const apiKey = "sk_live_X7d2pN8qR4vK6mT9wY3z";\n');
  const scan = await scanProject(project.config);
  if (!scan.ok) throw new Error(scan.error.message);
  const finding = scan.data.findings.find(item => item.ruleId === 'CS-NODE-001');
  expect(finding).toMatchObject({ ruleId: 'CS-NODE-001', severity: 'high', confidence: 'high', file: 'src/config.ts', line: 1, status: 'suspected', verificationStatus: 'not_verified' });
  expect(finding?.impact.length).toBeGreaterThan(10);
  expect(finding?.remediation.length).toBeGreaterThan(10);
  expect(finding?.evidence[0]?.context).toContain('[REDACTED]');
  expect(scan.data.summary.bySeverity.high).toBeGreaterThan(0);
  expect(scan.data.summary.byConfidence.high).toBeGreaterThan(0);
});

it('parses valid TSX and JSX without malformed-source warnings', async () => {
  const project = makeFixtureProject();
  projects.push(project);
  fs.writeFileSync(path.join(project.root, 'src/View.tsx'), 'export const View = () => <main>Safe</main>;\n');
  fs.writeFileSync(path.join(project.root, 'src/Other.jsx'), 'export const Other = () => <div>Safe</div>;\n');
  const scan = await scanProject(project.config);
  if (!scan.ok) throw new Error(scan.error.message);
  expect(scan.data.warnings.join(' ')).not.toMatch(/malformed source/i);
  expect(scan.data.fileAnalysis.skippedFiles).not.toEqual(expect.arrayContaining([expect.objectContaining({ file: 'src/View.tsx' })]));
});

it('reports source files skipped beyond the AST walk depth limit', async () => {
  const project = makeFixtureProject();
  projects.push(project);
  const deep = path.join(project.root, 'src', ...Array.from({ length: 16 }, (_, index) => `d${index}`));
  fs.mkdirSync(deep, { recursive: true });
  fs.writeFileSync(path.join(deep, 'deep.ts'), 'const deep = true;\n');
  const scan = await scanProject(project.config);
  if (!scan.ok) throw new Error(scan.error.message);
  expect(scan.data.warnings.join(' ')).toContain('depth limit');
  expect(scan.data.rulesFailed).toHaveLength(0);
});

it('explains an empty root and skipped Node rules', async () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-empty-')));
  try {
    const project = makeFixtureProject();
    projects.push(project);
    const result = await scanProject({ ...project.config, projectRoot: root });
    if (!result.ok) throw new Error(result.error.message);
    expect(result.data.project).toMatchObject({ ecosystem: 'unknown', support: 'unknown', nestedProjects: [] });
    expect(result.data.ruleExecution).toMatchObject({ executed: 0, skipped: 25, failed: 0 });
    expect(result.data.rulesSkipped[0]).toMatchObject({ reason: expect.stringMatching(/ecosystem/i) });
    expect(result.data.message).toMatch(/could not be determined/i);
    expect(result.data.fileAnalysis).toMatchObject({ discovered: 0, analyzed: 0, skipped: 0 });
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

it.each([['go.mod', 'go'], ['Cargo.toml', 'rust']] as const)('recognizes unsupported %s projects without running Node rules', async (manifest, ecosystem) => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'codesentinel-unsupported-')));
  try {
    fs.writeFileSync(path.join(root, manifest), 'example');
    const project = makeFixtureProject();
    projects.push(project);
    const result = await scanProject({ ...project.config, projectRoot: root });
    if (!result.ok) throw new Error(result.error.message);
    expect(result.data.project).toMatchObject({ ecosystem, support: 'unsupported' });
    expect(result.data.ruleExecution).toMatchObject({ executed: 0, skipped: 25, failed: 0 });
    expect(result.data.message).toMatch(/No security rules ran/i);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

it('returns a useful MCP error for a nonexistent project root', async () => {
  const tool = toolDefinitions.find(item => item.name === 'scan_project');
  if (!tool) throw new Error('scan_project missing');
  const project = makeFixtureProject();
  projects.push(project);
  const response = await tool.handler(project.config, { projectRoot: path.join(project.root, 'missing') });
  expect(response.isError).toBe(true);
  expect(JSON.parse(response.content[0]!.text)).toMatchObject({ error: 'NOT_FOUND', message: expect.stringMatching(/does not exist/i) });
  const direct = await scanProject({ ...project.config, projectRoot: path.join(project.root, 'missing') });
  expect(direct).toMatchObject({ ok: false, error: { code: 'NOT_FOUND' } });
});

it('rejects file and symlink project roots before scanning', async () => {
  const tool = toolDefinitions.find(item => item.name === 'scan_project');
  if (!tool) throw new Error('scan_project missing');
  const project = makeFixtureProject();
  projects.push(project);
  const fileResponse = await tool.handler(project.config, { projectRoot: path.join(project.root, 'package.json') });
  expect(JSON.parse(fileResponse.content[0]!.text).error).toBe('NOT_A_DIRECTORY');
  const link = path.join(project.root, 'project-link');
  fs.symlinkSync(project.root, link);
  const linkResponse = await tool.handler(project.config, { projectRoot: link });
  expect(JSON.parse(linkResponse.content[0]!.text).error).toBe('INVALID_INPUT');
});
