import { testCredential } from './testCredentials.js';
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
  it('exposes the Phase 1 tools plus Phase 2 through 10 tools', () => {
    const names = toolDefinitions.map((t) => t.name).sort();
    expect(names).toEqual(
      [
      'analyze_access_control',
      'analyze_project',
      'apply_remediation',
      'complete_security_audit',
      'dispatch_security_action',
      'discover_routes',
      'generate_security_audit_report',
      'generate_security_report',
      'get_investigation',
      'get_project_info',
      'get_security_agent_instructions',
      'get_security_audit_state',
      'get_security_finding',
      'get_security_graph',
      'list_files',
      'list_verification_cases',
      'list_security_proof_cases',
      'plan_security_investigation',
      'propose_remediation',
      'prove_security_finding',
      'read_file',
      'record_audit_hypothesis',
      'record_security_hypothesis',
      'remediate_finding',
      'retest_finding',
      'request_audit_verification',
      'request_runtime_verification',
      'rollback_remediation',
      'run_audit_analysis',
      'run_command',
      'run_deep_security_audit', 'run_full_security_audit',
      'run_security_analysis',
      'scan_project',
      'search_files',
      'start_security_audit',
      'start_security_investigation',
      'verify_finding',
      'verify_remediation',
    ].sort()
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
    expect(response.isError).toBe(false);
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

import fs from 'node:fs';
import path from 'node:path';
import { vi } from 'vitest';
import { logger } from '../src/logger.js';

describe('phase 1 MCP boundary', () => {
  const fx = makeFixtureProject();
  fs.writeFileSync(path.join(fx.root, '.env'), `API_KEY=${testCredential('API_KEY')}\n`);
  fs.symlinkSync(path.join(fx.root, '.env'), path.join(fx.root, 'envlink.txt'));
  fs.mkdirSync(path.join(fx.root, '.ssh'));
  fs.writeFileSync(path.join(fx.root, '.ssh', 'id_rsa'), `${testCredential('DB_PASSWORD')}\n`);
  afterAll(() => fx.cleanup());

  const call = async (name: string, input: unknown) => {
    const response = await getTool(name).handler(fx.config, input);
    return { isError: response.isError, raw: response.content[0].text, body: JSON.parse(response.content[0].text) };
  };

  it.each([
    ['list_files', { path: '.', allowSensitive: true }],
    ['list_files', { root: '/' }],
    ['read_file', { path: 'README.md', allowSensitive: true }],
    ['read_file', { path: 'README.md', cwd: '/' }],
    ['search_files', { query: 'x', allowSensitive: true }],
    ['run_command', { command: 'ls', args: [], cwd: '/' }],
    ['run_command', { command: 'ls', env: { PATH: '/tmp' } }],
  ])('rejects unexpected or privileged fields on %s', async (name, input) => {
    const result = await call(name, input);
    expect(result.isError).toBe(true);
    expect(result.body.error).toBe('INVALID_INPUT');
  });

  it('treats projectRoot on read_file as a root selector, not a way to escape it', async () => {
    const rootFile = await call('read_file', { path: 'README.md', projectRoot: '/' });
    expect(rootFile.isError).toBe(true);
    expect(rootFile.body.error).toBe('NOT_FOUND');
    const relative = await call('read_file', { path: 'README.md', projectRoot: '.' });
    expect(relative.isError).toBe(true);
    expect(relative.body.error).toBe('INVALID_INPUT');
    const traversal = await call('read_file', { path: '../etc/passwd', projectRoot: fx.root });
    expect(traversal.isError).toBe(true);
    expect(traversal.raw).not.toContain('root:');
  });

  it.each([
    ['read_file', { path: ['a'] }],
    ['read_file', { path: 'a\0b' }],
    ['read_file', { path: 'x'.repeat(5000) }],
    ['read_file', null],
    ['read_file', 'string'],
    ['search_files', { query: 123 }],
    ['search_files', { query: 'x', maxResults: -1 }],
    ['list_files', { maxResults: 1e9 }],
    ['run_command', { command: 'ls', args: 'x' }],
    ['run_command', { command: 'ls', args: [1] }],
    ['run_command', { command: {} }],
  ])('rejects malformed input on %s', async (name, input) => {
    const result = await call(name, input);
    expect(result.isError).toBe(true);
    expect(result.body.error).toBe('INVALID_INPUT');
  });

  it.each([
    ['read_file', { path: '/etc/passwd' }],
    ['read_file', { path: '../x' }],
    ['read_file', { path: '..\\x' }],
    ['read_file', { path: 'C:\\Windows\\win.ini' }],
    ['list_files', { path: '/' }],
    ['search_files', { query: 'x', path: '..' }],
  ])('blocks path escape on %s end-to-end without leaking the host root', async (name, input) => {
    const result = await call(name, input);
    expect(result.isError).toBe(true);
    expect(result.body.error).toBe('PATH_OUTSIDE_ROOT');
    expect(result.raw).not.toContain(fx.root);
  });

  it.each([
    ['read_file', { path: '.env' }],
    ['read_file', { path: '.ENV' }],
    ['read_file', { path: 'envlink.txt' }],
    ['list_files', { path: '.ssh' }],
    ['search_files', { query: testCredential('DB_PASSWORD').slice(0, 12), path: '.ssh' }],
  ])('refuses sensitive paths on %s', async (name, input) => {
    const result = await call(name, input);
    expect(result.isError).toBe(true);
    expect(result.body.error).toBe('INVALID_INPUT');
    expect(result.raw).not.toContain(testCredential('DB_PASSWORD').slice(0, 12));
  });

  it('never surfaces sensitive content through search_files, list_files, or run_command', async () => {
    const search = await call('search_files', { query: testCredential('DB_PASSWORD').slice(0, 12) });
    expect(search.isError).toBe(false);
    expect(search.body).toEqual([]);
    const listing = await call('list_files', { path: '.', recursive: true });
    expect(listing.isError).toBe(false);
    const names = listing.body.map((entry: { path: string }) => entry.path);
    expect(names).not.toContain('.env');
    expect(names).not.toContain('.ssh/id_rsa');
    const command = await call('run_command', { command: 'cat', args: ['.env'] });
    expect(command.isError).toBe(true);
    expect(command.body.error).toBe('COMMAND_NOT_ALLOWED');
    expect(command.raw).not.toContain(testCredential('DB_PASSWORD').slice(0, 12));
  });

  it('writes diagnostics to stderr only and never to stdout', () => {
    const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      logger.info('phase1_probe', { token: testCredential('OPENAI_KEY') });
      expect(stdout).not.toHaveBeenCalled();
      expect(stderr).toHaveBeenCalledTimes(1);
      expect(String(stderr.mock.calls[0]?.[0])).not.toContain(testCredential('OPENAI_KEY').slice(3, 15));
    } finally {
      stdout.mockRestore();
      stderr.mockRestore();
    }
  });
});

describe('Phase 9 MCP contract', () => {
  it('registers exactly 39 tools and rejects unknown arguments on every one', async () => {
    expect(toolDefinitions.length).toBe(39);
    for (const definition of toolDefinitions) {
      const response = await definition.handler(config, { unexpectedPhase9Key: 1 });
      expect(response.isError, definition.name).toBe(true);
      expect(JSON.parse(response.content[0]!.text).error, definition.name).toBe('INVALID_INPUT');
    }
  });
});
