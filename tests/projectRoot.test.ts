import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadConfigAllowUnset, type AppConfig } from '../src/config.js';
import { resolveToolRoot } from '../src/projectRoot.js';
import { toolDefinitions } from '../src/tools/registry.js';

const made: string[] = [];
afterEach(() => {
  for (const dir of made.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function mk(files: Record<string, string>): string {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-root-')));
  made.push(dir);
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

const cfg = (projectRoot: string): AppConfig => ({ projectRoot, commandTimeoutMs: 5000, maxOutputBytes: 1_000_000, maxReadFileBytes: 2_000_000, maxListResults: 2_000 });

async function call(name: string, config: AppConfig, input: unknown) {
  const tool = toolDefinitions.find((item) => item.name === name);
  if (!tool) throw new Error(`missing tool ${name}`);
  const response = await tool.handler(config, input);
  return { isError: response.isError, body: JSON.parse(response.content[0]!.text) };
}

describe('Phase 1 explicit projectRoot', () => {
  it('A: accepts a valid absolute project root', async () => {
    const root = mk({ 'package.json': '{"name":"a"}' });
    const resolved = resolveToolRoot(cfg(''), root);
    expect(resolved.ok && resolved.data).toBe(root);
    const info = await call('get_project_info', cfg(''), { projectRoot: root });
    expect(info.isError).toBe(false);
    expect(info.body.projectRoot).toBe(root);
  });

  it('B: rejects a nonexistent root', async () => {
    const result = await call('get_project_info', cfg(''), { projectRoot: path.join(os.tmpdir(), 'cs-does-not-exist-xyz') });
    expect(result.isError).toBe(true);
    expect(result.body.message).toMatch(/^Project root does not exist: /);
  });

  it('C: rejects a file used as a root', async () => {
    const root = mk({ 'file.txt': 'x' });
    const result = await call('scan_project', cfg(''), { projectRoot: path.join(root, 'file.txt') });
    expect(result.isError).toBe(true);
    expect(result.body.message).toMatch(/^Project root is not a directory: /);
  });

  it('D: reads a valid file inside the explicit project', async () => {
    const root = mk({ 'src/index.js': 'const marker = "hello-marker";\n' });
    const result = await call('read_file', cfg(''), { projectRoot: root, path: 'src/index.js' });
    expect(result.isError).toBe(false);
    expect(result.body.content).toContain('hello-marker');
  });

  it('E: blocks ../ traversal under an explicit root', async () => {
    const base = mk({ 'secret.txt': 'TOP-SECRET', 'proj/a.txt': 'a' });
    const result = await call('read_file', cfg(''), { projectRoot: path.join(base, 'proj'), path: '../secret.txt' });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.body)).not.toContain('TOP-SECRET');
  });

  it('F: blocks a symlink that escapes the explicit root', async () => {
    const base = mk({ 'outside/secret.txt': 'TOP-SECRET', 'proj/a.txt': 'a' });
    fs.symlinkSync(path.join(base, 'outside'), path.join(base, 'proj', 'out'));
    const result = await call('read_file', cfg(''), { projectRoot: path.join(base, 'proj'), path: 'out/secret.txt' });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.body)).not.toContain('TOP-SECRET');
  });

  it('F2: rejects a symlinked root', () => {
    const root = mk({ 'a.txt': 'a' });
    const link = path.join(path.dirname(root), `${path.basename(root)}-link`);
    fs.symlinkSync(root, link);
    made.push(link);
    const resolved = resolveToolRoot(cfg(''), link);
    expect(resolved.ok).toBe(false);
    if (!resolved.ok) expect(resolved.error.message).toMatch(/symbolic link/);
  });

  it('G: explicit projectRoot overrides PROJECT_ROOT', async () => {
    const a = mk({ 'a.txt': 'a' });
    const b = mk({ 'b.txt': 'b' });
    const config = loadConfigAllowUnset({ PROJECT_ROOT: a });
    const result = await call('get_project_info', config, { projectRoot: b });
    expect(result.body.projectRoot).toBe(b);
    expect(result.body.topLevelEntries).toContain('b.txt');
  });

  it('H: falls back to PROJECT_ROOT when projectRoot is omitted', async () => {
    const a = mk({ 'a.txt': 'a' });
    const config = loadConfigAllowUnset({ PROJECT_ROOT: a });
    const result = await call('get_project_info', config, {});
    expect(result.body.projectRoot).toBe(a);
  });

  it('H2: errors clearly when neither is provided', async () => {
    const config = loadConfigAllowUnset({});
    expect(config.projectRoot).toBe('');
    const result = await call('scan_project', config, {});
    expect(result.isError).toBe(true);
    expect(result.body.message).toBe('Project root is required: pass projectRoot or set PROJECT_ROOT');
  });

  it('H3: loadConfigAllowUnset still fails fast on an invalid PROJECT_ROOT', () => {
    expect(() => loadConfigAllowUnset({ PROJECT_ROOT: path.join(os.tmpdir(), 'cs-does-not-exist-xyz') })).toThrow(/does not exist/);
  });

  it('I: rejects a relative explicit root', async () => {
    const result = await call('get_project_info', cfg(''), { projectRoot: 'relative/path' });
    expect(result.isError).toBe(true);
    expect(result.body.message).toMatch(/absolute path/);
  });

  it('J: rejects a null byte in the root', async () => {
    const root = mk({ 'a.txt': 'a' });
    const result = await call('get_project_info', cfg(''), { projectRoot: `${root}\0x` });
    expect(result.isError).toBe(true);
    expect(result.body.message).toMatch(/invalid character/);
  });

  it('K: concurrent calls do not leak roots', async () => {
    const a = mk({ 'only-a.txt': 'a' });
    const b = mk({ 'only-b.txt': 'b' });
    const config = cfg('');
    const calls = Array.from({ length: 20 }, (_, i) => call('get_project_info', config, { projectRoot: i % 2 === 0 ? a : b }));
    const results = await Promise.all(calls);
    results.forEach((result, i) => {
      expect(result.body.projectRoot).toBe(i % 2 === 0 ? a : b);
      expect(result.body.topLevelEntries).toContain(i % 2 === 0 ? 'only-a.txt' : 'only-b.txt');
    });
    expect(config.projectRoot).toBe('');
  });

  it('L: run_command rejects projectRoot and does not run without PROJECT_ROOT', async () => {
    const a = mk({ 'a.txt': 'a' });
    const b = mk({ 'b.txt': 'b' });
    const withKey = await call('run_command', cfg(a), { command: 'ls', args: [], projectRoot: b });
    expect(withKey.isError).toBe(true);
    expect(withKey.body.error).toBe('INVALID_INPUT');
    const unset = await call('run_command', cfg(''), { command: 'ls', args: [] });
    expect(unset.isError).toBe(true);
    expect(unset.body.message).toMatch(/PROJECT_ROOT/);
  });

  it('keeps schemas strict and the other tools unchanged', async () => {
    const root = mk({ 'a.txt': 'a' });
    const unknown = await call('scan_project', cfg(''), { projectRoot: root, bogus: 1 });
    expect(unknown.isError).toBe(true);
    for (const name of ['verify_finding', 'prove_security_finding', 'run_full_security_audit', 'run_command', 'start_security_investigation']) {
      const tool = toolDefinitions.find((item) => item.name === name)!;
      expect(Object.keys((tool.inputSchema.properties as Record<string, unknown>) ?? {})).not.toContain('projectRoot');
    }
    for (const name of ['get_project_info', 'scan_project', 'list_files', 'read_file', 'search_files', 'get_security_graph', 'discover_routes', 'analyze_access_control', 'analyze_project', 'run_deep_security_audit', 'list_verification_cases', 'list_security_proof_cases']) {
      const tool = toolDefinitions.find((item) => item.name === name)!;
      expect(Object.keys(tool.inputSchema.properties as Record<string, unknown>)).toContain('projectRoot');
    }
  });
});
