import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
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
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`timeout waiting for ${method}`)); }, 8000);
      pending.set(id, (value) => { clearTimeout(timer); resolve(value); });
      child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', id, method, params })}\n`);
    });

  beforeAll(async () => {
    project = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cs-mcp-root-')));
    fs.writeFileSync(path.join(project, 'package.json'), JSON.stringify({ name: 'mcp-target', version: '1.0.0' }));
    fs.writeFileSync(path.join(project, 'marker.txt'), 'explicit-root-marker\n');
    const env = { ...process.env };
    delete env.PROJECT_ROOT;
    child = spawn(path.resolve('node_modules', '.bin', 'tsx'), [path.resolve('src', 'index.ts')], { cwd: path.resolve('.'), env });
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
  }, 15_000);

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
});
