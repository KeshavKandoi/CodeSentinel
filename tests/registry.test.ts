import { describe, it, expect, afterAll } from 'vitest';
import { toolDefinitions } from '../src/tools/registry.js';
import { makeFixtureProject } from './testUtils.js';

const { config, cleanup } = makeFixtureProject();
afterAll(() => cleanup());

function getTool(name: string) {
  const tool = toolDefinitions.find((t) => t.name === name);
  if (!tool) throw new Error(`test setup error: tool "${name}" not found`);
  return tool;
}

describe('tool registry shape', () => {
  it('exposes the Phase 1 tools plus Phase 2 through 9 tools', () => {
    const names = toolDefinitions.map((t) => t.name).sort();
    expect(names).toEqual(
      ['analyze_access_control', 'analyze_project', 'apply_remediation', 'discover_routes', 'generate_security_report', 'get_investigation', 'get_project_info', 'get_security_agent_instructions', 'get_security_finding', 'list_files', 'list_verification_cases', 'propose_remediation', 'read_file', 'record_security_hypothesis', 'request_runtime_verification', 'rollback_remediation', 'run_command', 'run_security_analysis', 'scan_project', 'search_files', 'start_security_investigation', 'verify_finding', 'verify_remediation'].sort()
    );
  });

  it('every tool has a non-empty description and inputSchema', () => {
    for (const tool of toolDefinitions) {
      expect(tool.description.length).toBeGreaterThan(10);
      expect(tool.inputSchema).toBeTypeOf('object');
    }
  });
});

describe('list_files handler', () => {
  it('returns a well-formed success response', async () => {
    const response = await getTool('list_files').handler(config, { path: '.' });
    expect(response.isError).toBe(false);
    const parsed = JSON.parse(response.content[0].text);
    expect(Array.isArray(parsed)).toBe(true);
  });

  it('returns a well-formed error response for malformed input', async () => {
    const response = await getTool('list_files').handler(config, { path: 123 });
    expect(response.isError).toBe(true);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.error).toBe('INVALID_INPUT');
  });

  it('blocks path traversal end-to-end', async () => {
    const response = await getTool('list_files').handler(config, { path: '../../etc' });
    expect(response.isError).toBe(true);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.error).toBe('PATH_OUTSIDE_ROOT');
  });
});

describe('read_file handler', () => {
  it('reads a file end-to-end', async () => {
    const response = await getTool('read_file').handler(config, { path: 'README.md' });
    expect(response.isError).toBe(false);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.content).toContain('Fixture project');
  });

  it('rejects missing required field', async () => {
    const response = await getTool('read_file').handler(config, {});
    expect(response.isError).toBe(true);
  });
});

describe('search_files handler', () => {
  it('finds matches end-to-end', async () => {
    const response = await getTool('search_files').handler(config, { query: 'TODO' });
    expect(response.isError).toBe(false);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.length).toBeGreaterThan(0);
  });
});

describe('get_project_info handler', () => {
  it('detects the node project type', async () => {
    const response = await getTool('get_project_info').handler(config, {});
    expect(response.isError).toBe(false);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.detectedTypes).toContain('node');
    expect(parsed.hasGit).toBe(true);
    expect(parsed.gitBranch).toBe('main');
  });
});

describe('run_command handler', () => {
  it('runs an allowlisted command end-to-end', async () => {
    const response = await getTool('run_command').handler(config, { command: 'echo', args: ['ok'] });
    expect(response.isError).toBe(false);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.stdout.trim()).toBe('ok');
  });

  it('blocks a disallowed command end-to-end', async () => {
    const response = await getTool('run_command').handler(config, { command: 'rm', args: ['-rf', '/'] });
    expect(response.isError).toBe(true);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.error).toBe('COMMAND_NOT_ALLOWED');
  });

  it('rejects malformed input end-to-end', async () => {
    const response = await getTool('run_command').handler(config, { args: [] });
    expect(response.isError).toBe(true);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.error).toBe('INVALID_INPUT');
  });

  it('returns UNKNOWN_TOOL-shaped behavior is out of scope here (handled in index.ts), but confirms handler never throws on odd input', async () => {
    const response = await getTool('run_command').handler(config, null);
    expect(response.isError).toBe(true);
  });
});

describe('analyze_project handler', () => {
  it('returns a well-formed ProjectProfile for the configured project root', async () => {
    const response = await getTool('analyze_project').handler(config, {});
    expect(response.isError).toBe(false);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.ecosystem).toBe('node');
    expect(parsed.projectName).toBe('fixture');
    expect(Array.isArray(parsed.languages)).toBe(true);
    expect(Array.isArray(parsed.dependencies)).toBe(true);
    expect(parsed).toHaveProperty('frameworks');
    expect(parsed).toHaveProperty('docker');
    expect(parsed).toHaveProperty('warnings');
  });

  it('rejects unexpected input fields (strict schema, no params expected)', async () => {
    const response = await getTool('analyze_project').handler(config, { extra: 'nope' });
    expect(response.isError).toBe(true);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.error).toBe('INVALID_INPUT');
  });

  it('never throws even if called with null input', async () => {
    const response = await getTool('analyze_project').handler(config, null);
    expect(response.isError).toBe(false); // null coerces to {} default, same as get_project_info's pattern
  });
});

describe('scan_project handler', () => {
  it('returns a well-formed SecurityScanResult for the configured project root', async () => {
    const response = await getTool('scan_project').handler(config, {});
    expect(response.isError).toBe(false);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.project.ecosystem).toBe('node');
    expect(Array.isArray(parsed.rulesRun)).toBe(true);
    expect(Array.isArray(parsed.findings)).toBe(true);
    expect(parsed.summary).toHaveProperty('total');
  });

  it('rejects unexpected input fields (strict schema, no params expected)', async () => {
    const response = await getTool('scan_project').handler(config, { extra: 'nope' });
    expect(response.isError).toBe(true);
    const parsed = JSON.parse(response.content[0].text);
    expect(parsed.error).toBe('INVALID_INPUT');
  });
});
