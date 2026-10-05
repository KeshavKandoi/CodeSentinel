import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

describe('MCP stdio with PROJECT_ROOT unset', () => {
  let child: ChildProcessWithoutNullStreams;
  let buffer = '';
  let nextId = 1;
  const pending = new Map<number, (value: any) => void>();
  let project = '';

  const request = (method: string, params: unknown): Promise<any> =>
    new Promise((resolve, reject) => {
      const id = nextId++;
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`timeout waiting for ${method}`)); }, 30_000);
      pending.set(id, (value) => { clearTimeout(timer); resolve(value); });
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });

  beforeAll(async () => {
    project = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-mcp-root-')));
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'mcp-target', version: '1.0.0' }));
    fs.writeFileSync(path.join(project, 'marker.txt'), 'explicit-root-marker\n');
    const env = { ...process.env };
    delete env.PROJECT_ROOT;
    execFileSync('npm', ['run', 'build'], { cwd: path.resolve('.'), stdio: 'pipe' });
    child = spawn(process.execPath, [path.resolve('dist', 'index.js')], { cwd: path.resolve('.'), env });
    child.stdout.on('data', (chunk: Buffer) => {
      buffer += chunk.toString();
      let index;
      while ((index = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        if (!line) continue;
        try {
          const message = JSON.parse(line);
          if (typeof message.id === 'number') pending.get(message.id)?.(message);
        } catch { /* non-json */ }
      }
    });
    child.stderr.on('data', () => undefined);
    await request('initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'test', version: '1.0.0' } });
    child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' })}\n`);
  }, 60_000);

  afterAll(() => {
    child?.kill();
    fs.rmSync(project, { recursive: true, force: true });
  });

  it('operates on an explicit projectRoot when PROJECT_ROOT is unset', async () => {
    const response = await request('tools/call', { name: 'get_project_info', arguments: { projectRoot: project } });
    expect(response.result.isError).toBe(false);
    const body = JSON.parse(response.result.content[0].text);
    expect(body.projectRoot).toBe(project);
    expect(body.topLevelEntries).toContain('marker.txt');
    const read = await request('tools/call', { name: 'read_file', arguments: { projectRoot: project, path: 'marker.txt' } });
    expect(JSON.parse(read.result.content[0].text).content).toContain('explicit-root-marker');
  });

  it('returns a clear error without projectRoot and refuses tools outside the approved set', async () => {
    const missing = await request('tools/call', { name: 'scan_project', arguments: {} });
    expect(missing.result.isError).toBe(true);
    expect(JSON.parse(missing.result.content[0].text).message).toBe('Project root is required: pass projectRoot or set PROJECT_ROOT');
    const command = await request('tools/call', { name: 'run_command', arguments: { command: 'ls', args: [], projectRoot: project } });
    expect(command.result.isError).toBe(true);
  });

  it('audits the explicit project through the built server without PROJECT_ROOT or target writes', async () => {
    const source = path.join(project, 'audit-marker.js');
    fs.writeFileSync(source, "const password = 'unique-audit-fixture-secret';\n");
    const before = fs.readFileSync(source, 'utf8');
    const response = await request('tools/call', { name: 'run_full_security_audit', arguments: { projectRoot: project } });
    expect(response.result.isError).toBe(false);
    const body = JSON.parse(response.result.content[0].text);
    expect(body.project.name).toBe('mcp-target');
    expect(body.stages.find((stage: any) => stage.stage === 'static_scan').status).toBe('completed');
    expect(body.stages.find((stage: any) => stage.stage === 'deep_analysis').status).toBe('completed');
    expect(body.summary.total).toBe(body.findings.length);
    expect(body.readOnly.filesChecked).toBeGreaterThan(0);
    expect(body.domainCoverage.some((domain: any) => domain.status === 'unsupported')).toBe(true);
    expect(body.readOnly.sourceTreeUnchanged).toBe(true);
    expect(fs.readFileSync(source, 'utf8')).toBe(before);
    const start = await request('tools/call', { name: 'start_security_audit', arguments: { projectRoot: project, objective: 'Review project security' } });
    expect(start.result.isError).toBe(false);
    const state = JSON.parse(start.result.content[0].text);
    expect(state.status).toBe('created');
    const plan = await request('tools/call', { name: 'plan_security_investigation', arguments: { investigationId: state.investigationId } });
    expect(plan.result.isError).toBe(false);
    const analysis = await request('tools/call', { name: 'run_audit_analysis', arguments: { investigationId: state.investigationId } });
    expect(analysis.result.isError).toBe(false);
    expect(JSON.parse(analysis.result.content[0].text).completedCapabilities).toContain('run_audit_analysis');
  }, 60_000);
});
