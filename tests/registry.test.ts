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
  it('exposes exactly the five Phase 1 tools', () => {
    const names = toolDefinitions.map((t) => t.name).sort();
    expect(names).toEqual(['get_project_info', 'list_files', 'read_file', 'run_command', 'search_files'].sort());
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
